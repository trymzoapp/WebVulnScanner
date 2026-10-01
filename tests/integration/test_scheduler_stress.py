"""Stress tests for pipeline scheduling, cancellation, and concurrent scan isolation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

import pytest

from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.pipeline import (
    FailurePolicy,
    Pipeline,
    PipelineStatus,
    StageName,
    StageOutcome,
    StageStatus,
)
from webvulnscanner.models.target import Target


class SlowStage:
    """A stage that sleeps to test cancellation."""

    def __init__(self, name: StageName, duration: float) -> None:
        self.name = name
        self.dependencies = ()
        self.failure_policy = FailurePolicy.CONTINUE
        self.duration = duration

    async def run(
        self,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        start = datetime.now(timezone.utc)
        await asyncio.sleep(self.duration)
        end = datetime.now(timezone.utc)
        return StageOutcome(
            name=self.name,
            status=StageStatus.SUCCESS,
            started_at=start,
            completed_at=end,
        )


class FastStage:
    """A stage that finishes immediately."""

    def __init__(self, name: StageName, succeed: bool = True) -> None:
        self.name = name
        self.dependencies = ()
        self.failure_policy = FailurePolicy.CONTINUE
        self.succeed = succeed

    async def run(
        self,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        now = datetime.now(timezone.utc)
        if not self.succeed:
            return StageOutcome(
                name=self.name,
                status=StageStatus.FAILED,
                started_at=now,
                completed_at=now,
                errors=("Simulated stage failure",),
            )
        return StageOutcome(
            name=self.name,
            status=StageStatus.SUCCESS,
            started_at=now,
            completed_at=now,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pipeline_cancellation_under_stress() -> None:
    """Cancelling a pipeline execution must cancel running stage tasks without leaking."""
    slow_stage = SlowStage(StageName.PASSIVE, duration=10.0)
    pipeline = Pipeline(stages=[slow_stage])

    target = Target("https://example.com")
    context = ScanContext(
        scan_id="20261001-cancel-stress",
        target=target,
        storage_root=Path("runs"),
        profile_name="safe",
        started_at=None,
    )

    task = asyncio.create_task(pipeline.run(context))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrent_target_scans_isolation(tmp_path: Path) -> None:
    """Running multiple pipeline scans concurrently for different targets must remain isolated."""
    targets = [
        Target(f"https://target{i}.example.com")
        for i in range(4)
    ]

    async def run_scan_for_target(t: Target, index: int) -> tuple[int, PipelineStatus]:
        ctx = ScanContext(
            scan_id=f"20261001-concurrent-{index}",
            target=t,
            storage_root=tmp_path / "runs",
            profile_name="safe",
            started_at=None,
        )
        pipe = Pipeline(
            stages=[
                FastStage(StageName.PASSIVE),
                FastStage(StageName.FINGERPRINT),
            ]
        )
        res = await pipe.run(ctx)
        return index, res.status

    results = await asyncio.gather(
        *(run_scan_for_target(t, i) for i, t in enumerate(targets))
    )

    assert len(results) == 4
    for idx, status in results:
        assert status == PipelineStatus.COMPLETED


@pytest.mark.integration
@pytest.mark.asyncio
async def test_partial_pipeline_with_failing_stage() -> None:
    """Failure in one stage when policy is CONTINUE does not abort subsequent independent stages."""
    stages = [
        FastStage(StageName.PASSIVE, succeed=False),
        FastStage(StageName.FINGERPRINT, succeed=True),
    ]
    pipeline = Pipeline(stages=stages)
    context = ScanContext(
        scan_id="20261001-partial-stress",
        target=Target("https://example.com"),
        storage_root=Path("runs"),
        profile_name="safe",
        started_at=None,
    )

    result = await pipeline.run(context)
    assert result.status == PipelineStatus.PARTIAL
    assert len(result.outcomes) == 2
    assert result.outcomes[0].status == StageStatus.FAILED
    assert result.outcomes[1].status == StageStatus.SUCCESS
