"""Tests for scanner-agnostic orchestration and metadata finalization."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContext, ScanContextFactory
from webvulnscanner.core.exceptions import StorageError
from webvulnscanner.core.orchestrator import Orchestrator
from webvulnscanner.core.pipeline import (
    FailurePolicy,
    Pipeline,
    PipelineStatus,
    StageName,
    StageOutcome,
    StageStatus,
)
from webvulnscanner.models.report import ScanStatus
from webvulnscanner.models.target import Target

STARTED = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
COMPLETED = STARTED + timedelta(seconds=5)


class StaticStage:
    dependencies: tuple[StageName, ...] = ()
    failure_policy = FailurePolicy.CONTINUE

    def __init__(
        self,
        name: StageName,
        status: StageStatus = StageStatus.SUCCESS,
    ) -> None:
        self.name = name
        self.status = status

    async def run(
        self,
        context: ScanContext,
        previous: Any,
    ) -> StageOutcome:
        if self.status is StageStatus.FAILED:
            return StageOutcome(
                name=self.name,
                status=self.status,
                started_at=STARTED,
                completed_at=STARTED,
                errors=(f"{self.name.value} failed",),
            )
        return StageOutcome(
            name=self.name,
            status=self.status,
            started_at=STARTED,
            completed_at=STARTED,
        )


def factory(tmp_path: Path) -> ScanContextFactory:
    return ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: STARTED,
        id_provider=lambda: "scan-00000001",
    )


def test_orchestrator_creates_context_runs_pipeline_and_finalizes_metadata(
    tmp_path: Path,
) -> None:
    pipeline = Pipeline(
        [
            StaticStage(StageName.PASSIVE),
            StaticStage(StageName.FINGERPRINT),
        ],
        time_provider=lambda: STARTED,
    )
    orchestrator = Orchestrator(
        configuration=load_config(),
        context_factory=factory(tmp_path),
        pipeline=pipeline,
        time_provider=lambda: COMPLETED,
    )

    result = asyncio.run(orchestrator.run(Target("example.com")))

    assert result.status is ScanStatus.COMPLETED
    assert result.pipeline is not None
    assert result.pipeline.status is PipelineStatus.COMPLETED
    assert result.metadata is not None
    assert result.metadata.completed_at == COMPLETED
    assert result.errors == ()
    assert result.context is not None
    stored = json.loads(result.context.metadata_path.read_text(encoding="utf-8"))
    assert stored["status"] == "completed"
    assert stored["completed_at"] == "2026-09-29T12:00:05Z"
    assert stored["profile"] == "safe"
    assert stored["scanner_configuration"]["nuclei"]["timeout"] == 600
    assert stored["scanner_configuration"]["nuclei"]["executable"] == "nuclei"


def test_recoverable_stage_failure_finalizes_partial_scan(tmp_path: Path) -> None:
    pipeline = Pipeline(
        [
            StaticStage(StageName.PASSIVE, StageStatus.FAILED),
            StaticStage(StageName.ROUTING),
        ],
        time_provider=lambda: STARTED,
    )
    orchestrator = Orchestrator(
        configuration=load_config(),
        context_factory=factory(tmp_path),
        pipeline=pipeline,
        time_provider=lambda: COMPLETED,
    )

    result = asyncio.run(orchestrator.run(Target("example.com")))

    assert result.status is ScanStatus.PARTIAL
    assert result.errors == ("passive failed",)
    assert result.metadata is not None
    assert result.metadata.status is ScanStatus.PARTIAL
    assert result.context is not None
    stored = json.loads(result.context.metadata_path.read_text(encoding="utf-8"))
    assert stored["status"] == "partial"
    assert stored["errors"] == ["passive failed"]


def test_fatal_context_setup_failure_stops_before_pipeline() -> None:
    class FailingFactory:
        def create(self, *args: Any, **kwargs: Any) -> ScanContext:
            raise StorageError("storage root is unavailable")

    class TrackingPipeline:
        called = False

        async def run(self, context: ScanContext) -> Any:
            self.called = True
            raise AssertionError("pipeline must not run")

    pipeline = TrackingPipeline()
    orchestrator = Orchestrator(
        configuration=load_config(),
        context_factory=FailingFactory(),
        pipeline=pipeline,  # type: ignore[arg-type]
        time_provider=lambda: COMPLETED,
    )

    result = asyncio.run(orchestrator.run(Target("example.com")))

    assert result.status is ScanStatus.FAILED
    assert result.context is None
    assert result.pipeline is None
    assert result.metadata is None
    assert result.errors == ("storage root is unavailable",)
    assert pipeline.called is False


def test_unexpected_context_failure_is_safe_and_stops_pipeline() -> None:
    class FailingFactory:
        def create(self, *args: Any, **kwargs: Any) -> ScanContext:
            raise RuntimeError("sensitive internal path")

    orchestrator = Orchestrator(
        configuration=load_config(),
        context_factory=FailingFactory(),
        pipeline=Pipeline([]),
        time_provider=lambda: COMPLETED,
    )

    result = asyncio.run(orchestrator.run(Target("example.com")))

    assert result.status is ScanStatus.FAILED
    assert result.errors == ("scan context creation failed unexpectedly",)
    assert "sensitive internal path" not in result.errors[0]


def test_metadata_write_failure_is_returned_as_fatal_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_write(*args: Any, **kwargs: Any) -> Path:
        raise StorageError("metadata finalization failed")

    monkeypatch.setattr(
        "webvulnscanner.core.orchestrator.atomic_write_json",
        fail_write,
    )
    orchestrator = Orchestrator(
        configuration=load_config(),
        context_factory=factory(tmp_path),
        pipeline=Pipeline([], time_provider=lambda: STARTED),
        time_provider=lambda: COMPLETED,
    )

    result = asyncio.run(orchestrator.run(Target("example.com")))

    assert result.status is ScanStatus.FAILED
    assert result.context is not None
    assert result.metadata is None
    assert result.errors == ("metadata finalization failed",)
