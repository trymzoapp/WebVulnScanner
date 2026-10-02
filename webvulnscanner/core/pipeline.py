"""Generic pipeline stage coordination and continuation rules."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import WebVulnScannerError
from webvulnscanner.utils.time import as_utc, utc_now


class StageName(StrEnum):
    """Planned scanner-independent pipeline stages."""

    PASSIVE = "passive"
    FINGERPRINT = "fingerprint"
    ROUTING = "routing"
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"
    PARSE = "parse"
    AGGREGATE = "aggregate"
    REPORT = "report"


class StageStatus(StrEnum):
    """Terminal status of one pipeline stage."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class FailurePolicy(StrEnum):
    """Whether pipeline execution may continue after a stage failure."""

    CONTINUE = "continue"
    STOP = "stop"


class PipelineStatus(StrEnum):
    """Aggregate pipeline execution state."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """Typed outcome and artifacts from one pipeline stage."""

    name: StageName
    status: StageStatus
    started_at: datetime
    completed_at: datetime
    errors: tuple[str, ...] = ()
    artifacts: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType({})
    )
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, StageName):
            raise TypeError("stage name must be a StageName")
        if not isinstance(self.status, StageStatus):
            raise TypeError("stage status must be a StageStatus")
        started = as_utc(self.started_at, field_name="stage started_at")
        completed = as_utc(self.completed_at, field_name="stage completed_at")
        if completed < started:
            raise ValueError("stage completed_at must not precede started_at")
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        if not isinstance(self.errors, tuple) or any(
            not isinstance(error, str) or not error.strip() for error in self.errors
        ):
            raise ValueError("stage errors must be a tuple of non-empty strings")
        if not isinstance(self.artifacts, Mapping):
            raise TypeError("stage artifacts must be a mapping")
        object.__setattr__(self, "artifacts", MappingProxyType(dict(self.artifacts)))
        if self.reason is not None and (
            not isinstance(self.reason, str) or not self.reason.strip()
        ):
            raise ValueError("stage reason must be a non-empty string or None")
        if self.status is StageStatus.SUCCESS and (self.errors or self.reason):
            raise ValueError("successful stage cannot contain errors or a reason")
        if self.status is StageStatus.FAILED and not self.errors:
            raise ValueError("failed stage requires at least one error")
        if self.status is StageStatus.SKIPPED and self.reason is None:
            raise ValueError("skipped stage requires a reason")


class PipelineStage(Protocol):
    """Narrow interface implemented by stage registries in later tasks."""

    name: StageName
    dependencies: tuple[StageName, ...]
    failure_policy: FailurePolicy

    async def run(
        self,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        """Execute a stage using typed prior outcomes."""


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Ordered outcomes and aggregate pipeline status."""

    status: PipelineStatus
    outcomes: tuple[StageOutcome, ...]

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(error for outcome in self.outcomes for error in outcome.errors)


class Pipeline:
    """Execute registered stages without concrete scanner knowledge."""

    def __init__(
        self,
        stages: Sequence[PipelineStage],
        *,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        if isinstance(stages, (str, bytes)) or not isinstance(stages, Sequence):
            raise TypeError("stages must be a sequence")
        self._stages = tuple(stages)
        self._time_provider = time_provider
        self._validate_stages()

    async def run(self, context: ScanContext) -> PipelineResult:
        """Execute stages in registration order with dependency-aware skipping."""
        outcomes: list[StageOutcome] = []
        previous: dict[StageName, StageOutcome] = {}
        stopped_by: StageName | None = None

        for stage in self._stages:
            if stopped_by is not None:
                outcome = self._skipped(
                    stage.name,
                    f"pipeline stopped after {stopped_by.value} failed",
                )
            else:
                unavailable = [
                    dependency
                    for dependency in stage.dependencies
                    if previous[dependency].status is not StageStatus.SUCCESS
                ]
                if unavailable:
                    names = ", ".join(dependency.value for dependency in unavailable)
                    outcome = self._skipped(
                        stage.name,
                        f"required stage did not succeed: {names}",
                    )
                else:
                    outcome = await self._run_stage(stage, context, previous)
                    if (
                        outcome.status is StageStatus.FAILED
                        and stage.failure_policy is FailurePolicy.STOP
                    ):
                        stopped_by = stage.name
            outcomes.append(outcome)
            previous[stage.name] = outcome

        return PipelineResult(
            status=_pipeline_status(outcomes, stopped_by),
            outcomes=tuple(outcomes),
        )

    async def _run_stage(
        self,
        stage: PipelineStage,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        started = self._now()
        try:
            outcome = await stage.run(
                context,
                MappingProxyType(dict(previous)),
            )
            if not isinstance(outcome, StageOutcome):
                raise TypeError("pipeline stage returned a non-StageOutcome value")
            if outcome.name is not stage.name:
                raise ValueError("pipeline stage returned an outcome for another stage")
            return outcome
        except asyncio.CancelledError:
            raise
        except WebVulnScannerError as error:
            message = str(error)
        except Exception:
            message = "stage raised an unexpected exception"
        return StageOutcome(
            name=stage.name,
            status=StageStatus.FAILED,
            started_at=started,
            completed_at=self._now(),
            errors=(message,),
        )

    def _skipped(self, name: StageName, reason: str) -> StageOutcome:
        now = self._now()
        return StageOutcome(
            name=name,
            status=StageStatus.SKIPPED,
            started_at=now,
            completed_at=now,
            reason=reason,
        )

    def _validate_stages(self) -> None:
        known: set[StageName] = set()
        for stage in self._stages:
            if not isinstance(stage.name, StageName):
                raise TypeError("stage name must be a StageName")
            if stage.name in known:
                raise ValueError(f"duplicate pipeline stage: {stage.name.value}")
            if not isinstance(stage.dependencies, tuple) or any(
                not isinstance(dependency, StageName)
                for dependency in stage.dependencies
            ):
                raise TypeError(
                    "stage dependencies must be a tuple of StageName values"
                )
            missing = set(stage.dependencies) - known
            if missing:
                names = ", ".join(sorted(item.value for item in missing))
                raise ValueError(
                    f"stage dependencies must be registered earlier: {names}"
                )
            if not isinstance(stage.failure_policy, FailurePolicy):
                raise TypeError("stage failure_policy must be a FailurePolicy")
            known.add(stage.name)

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="pipeline timestamp")


def _pipeline_status(
    outcomes: Sequence[StageOutcome],
    stopped_by: StageName | None,
) -> PipelineStatus:
    if stopped_by is not None:
        return PipelineStatus.FAILED
    if any(
        outcome.status in {StageStatus.FAILED, StageStatus.SKIPPED}
        for outcome in outcomes
    ):
        return PipelineStatus.PARTIAL
    return PipelineStatus.COMPLETED


__all__ = [
    "FailurePolicy",
    "Pipeline",
    "PipelineResult",
    "PipelineStage",
    "PipelineStatus",
    "StageName",
    "StageOutcome",
    "StageStatus",
]
