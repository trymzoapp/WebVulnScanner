"""Tests for generic pipeline stage coordination."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.core.context import ScanContext, ScanContextFactory
from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.core.pipeline import (
    FailurePolicy,
    Pipeline,
    PipelineStatus,
    StageName,
    StageOutcome,
    StageStatus,
)
from webvulnscanner.models.target import Target

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def context(tmp_path: Path) -> ScanContext:
    return ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("example.com"),
        profile_name="safe",
        scanner_configuration={},
    )


class FakeStage:
    def __init__(
        self,
        name: StageName,
        calls: list[StageName],
        *,
        dependencies: tuple[StageName, ...] = (),
        failure_policy: FailurePolicy = FailurePolicy.CONTINUE,
        status: StageStatus = StageStatus.SUCCESS,
        error: Exception | None = None,
    ) -> None:
        self.name = name
        self.dependencies = dependencies
        self.failure_policy = failure_policy
        self.status = status
        self.error = error
        self.calls = calls

    async def run(
        self,
        scan_context: ScanContext,
        previous: Any,
    ) -> StageOutcome:
        self.calls.append(self.name)
        assert scan_context.target.host == "example.com"
        if self.error is not None:
            raise self.error
        if self.status is StageStatus.FAILED:
            return StageOutcome(
                name=self.name,
                status=self.status,
                started_at=NOW,
                completed_at=NOW,
                errors=(f"{self.name.value} failed",),
            )
        return StageOutcome(
            name=self.name,
            status=self.status,
            started_at=NOW,
            completed_at=NOW,
            artifacts={"prior_count": len(previous)},
        )


def test_successful_stages_run_in_registration_order(tmp_path: Path) -> None:
    calls: list[StageName] = []
    stages = [
        FakeStage(StageName.PASSIVE, calls),
        FakeStage(
            StageName.FINGERPRINT,
            calls,
            dependencies=(StageName.PASSIVE,),
        ),
        FakeStage(
            StageName.ROUTING,
            calls,
            dependencies=(StageName.FINGERPRINT,),
        ),
    ]

    result = asyncio.run(
        Pipeline(stages, time_provider=lambda: NOW).run(context(tmp_path))
    )

    assert calls == [
        StageName.PASSIVE,
        StageName.FINGERPRINT,
        StageName.ROUTING,
    ]
    assert result.status is PipelineStatus.COMPLETED
    assert all(outcome.status is StageStatus.SUCCESS for outcome in result.outcomes)
    assert result.outcomes[2].artifacts["prior_count"] == 2


def test_recoverable_failure_skips_dependents_but_runs_eligible_stages(
    tmp_path: Path,
) -> None:
    calls: list[StageName] = []
    stages = [
        FakeStage(
            StageName.PASSIVE,
            calls,
            status=StageStatus.FAILED,
        ),
        FakeStage(
            StageName.FINGERPRINT,
            calls,
            dependencies=(StageName.PASSIVE,),
        ),
        FakeStage(StageName.ROUTING, calls),
    ]

    result = asyncio.run(
        Pipeline(stages, time_provider=lambda: NOW).run(context(tmp_path))
    )

    assert calls == [StageName.PASSIVE, StageName.ROUTING]
    assert [outcome.status for outcome in result.outcomes] == [
        StageStatus.FAILED,
        StageStatus.SKIPPED,
        StageStatus.SUCCESS,
    ]
    assert "passive" in (result.outcomes[1].reason or "")
    assert result.status is PipelineStatus.PARTIAL
    assert result.errors == ("passive failed",)


def test_fatal_failure_stops_all_later_stages(tmp_path: Path) -> None:
    calls: list[StageName] = []
    stages = [
        FakeStage(
            StageName.PASSIVE,
            calls,
            failure_policy=FailurePolicy.STOP,
            status=StageStatus.FAILED,
        ),
        FakeStage(StageName.FINGERPRINT, calls),
        FakeStage(StageName.ROUTING, calls),
    ]

    result = asyncio.run(
        Pipeline(stages, time_provider=lambda: NOW).run(context(tmp_path))
    )

    assert calls == [StageName.PASSIVE]
    assert result.status is PipelineStatus.FAILED
    assert [item.status for item in result.outcomes] == [
        StageStatus.FAILED,
        StageStatus.SKIPPED,
        StageStatus.SKIPPED,
    ]


def test_stage_exceptions_become_safe_failed_outcomes(tmp_path: Path) -> None:
    calls: list[StageName] = []
    controlled = FakeStage(
        StageName.PASSIVE,
        calls,
        error=ScannerValidationError("controlled safe message"),
    )
    unexpected = FakeStage(
        StageName.FINGERPRINT,
        calls,
        error=RuntimeError("sensitive detail"),
    )

    result = asyncio.run(
        Pipeline(
            [controlled, unexpected],
            time_provider=lambda: NOW,
        ).run(context(tmp_path))
    )

    assert result.outcomes[0].errors == ("controlled safe message",)
    assert result.outcomes[1].errors == ("stage raised an unexpected exception",)
    assert "sensitive detail" not in result.outcomes[1].errors[0]


def test_dependency_must_be_registered_before_dependent_stage() -> None:
    calls: list[StageName] = []
    stage = FakeStage(
        StageName.ROUTING,
        calls,
        dependencies=(StageName.FINGERPRINT,),
    )

    with pytest.raises(ValueError, match="registered earlier"):
        Pipeline([stage])


def test_duplicate_stage_is_rejected() -> None:
    calls: list[StageName] = []

    with pytest.raises(ValueError, match="duplicate"):
        Pipeline(
            [
                FakeStage(StageName.PASSIVE, calls),
                FakeStage(StageName.PASSIVE, calls),
            ]
        )


def test_empty_pipeline_completes() -> None:
    class DummyContext:
        pass

    result = asyncio.run(
        Pipeline([], time_provider=lambda: NOW).run(DummyContext())  # type: ignore[arg-type]
    )

    assert result.status is PipelineStatus.COMPLETED
    assert result.outcomes == ()
