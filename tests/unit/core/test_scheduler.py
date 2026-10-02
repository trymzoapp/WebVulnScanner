"""Tests for concurrent scanner scheduling and failure isolation."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.core.scheduler import ScannerScheduler
from webvulnscanner.models.scan_result import (
    ScanError,
    ScannerStatus,
    ScanResult,
)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def success(name: str) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.SUCCESS,
        started_at=NOW,
        completed_at=NOW,
    )


def failed(name: str) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.FAILED,
        started_at=NOW,
        completed_at=NOW,
        errors=(ScanError(code="fake_failure", message="controlled failure"),),
    )


class ResultScanner:
    def __init__(
        self,
        name: str,
        result: ScanResult,
        *,
        delay: float = 0,
    ) -> None:
        self.name = name
        self.result = result
        self.delay = delay

    async def run(self) -> ScanResult:
        await asyncio.sleep(self.delay)
        return self.result


class RaisingScanner:
    def __init__(self, name: str, error: Exception) -> None:
        self.name = name
        self.error = error

    async def run(self) -> ScanResult:
        raise self.error


def test_mixed_outcomes_preserve_input_order_and_isolate_exceptions() -> None:
    async def scenario() -> None:
        scheduler = ScannerScheduler(
            max_concurrency=3,
            time_provider=lambda: NOW,
        )
        scanners = [
            ResultScanner("slow-success", success("slow-success"), delay=0.03),
            RaisingScanner(
                "controlled",
                ScannerValidationError("safe validation message"),
            ),
            ResultScanner("returned-failure", failed("returned-failure")),
            RaisingScanner("unexpected", RuntimeError("sensitive internal detail")),
            ResultScanner("fast-success", success("fast-success")),
        ]

        results = await scheduler.run(scanners)

        assert [result.scanner for result in results] == [
            "slow-success",
            "controlled",
            "returned-failure",
            "unexpected",
            "fast-success",
        ]
        assert [result.status for result in results] == [
            ScannerStatus.SUCCESS,
            ScannerStatus.FAILED,
            ScannerStatus.FAILED,
            ScannerStatus.FAILED,
            ScannerStatus.SUCCESS,
        ]
        assert results[1].errors[0].code == "scanner_exception"
        assert results[1].errors[0].message == "safe validation message"
        assert results[3].errors[0].code == "unexpected_exception"
        assert "sensitive internal detail" not in results[3].errors[0].message

    asyncio.run(scenario())


def test_maximum_concurrency_is_never_exceeded() -> None:
    async def scenario() -> None:
        release = asyncio.Event()
        started = asyncio.Event()
        active = 0
        maximum = 0

        class BlockingScanner:
            def __init__(self, index: int) -> None:
                self.name = f"scanner-{index}"

            async def run(self) -> ScanResult:
                nonlocal active, maximum
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    started.set()
                try:
                    await release.wait()
                    return success(self.name)
                finally:
                    active -= 1

        scheduler = ScannerScheduler(
            max_concurrency=2,
            time_provider=lambda: NOW,
        )
        task = asyncio.create_task(
            scheduler.run([BlockingScanner(index) for index in range(6)])
        )
        await asyncio.wait_for(started.wait(), timeout=1)

        assert active == 2
        assert scheduler.active_count == 2
        release.set()
        results = await task

        assert len(results) == 6
        assert maximum == 2
        assert scheduler.max_observed_concurrency == 2
        assert scheduler.active_count == 0

    asyncio.run(scenario())


def test_cancelling_schedule_cancels_started_scanners_and_cleans_up() -> None:
    async def scenario() -> None:
        blocker = asyncio.Event()
        started = asyncio.Event()
        cancelled: set[str] = set()
        running = 0

        class CancellableScanner:
            def __init__(self, index: int) -> None:
                self.name = f"scanner-{index}"

            async def run(self) -> ScanResult:
                nonlocal running
                running += 1
                if running == 3:
                    started.set()
                try:
                    await blocker.wait()
                    return success(self.name)
                except asyncio.CancelledError:
                    cancelled.add(self.name)
                    raise
                finally:
                    running -= 1

        scheduler = ScannerScheduler(
            max_concurrency=3,
            time_provider=lambda: NOW,
        )
        task = asyncio.create_task(
            scheduler.run([CancellableScanner(index) for index in range(3)])
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled == {"scanner-0", "scanner-1", "scanner-2"}
        assert scheduler.active_count == 0

    asyncio.run(scenario())


def test_invalid_scanner_return_becomes_failed_result() -> None:
    class InvalidScanner:
        name = "invalid"

        async def run(self) -> Any:
            return "not a scan result"

    results = asyncio.run(
        ScannerScheduler(
            max_concurrency=1,
            time_provider=lambda: NOW,
        ).run([InvalidScanner()])
    )

    assert results[0].status is ScannerStatus.FAILED
    assert results[0].errors[0].code == "unexpected_exception"


def test_empty_schedule_returns_empty_tuple() -> None:
    result = asyncio.run(
        ScannerScheduler(
            max_concurrency=1,
            time_provider=lambda: NOW,
        ).run([])
    )

    assert result == ()


@pytest.mark.parametrize("max_concurrency", [0, -1, True, 1.5])
def test_invalid_concurrency_is_rejected(max_concurrency: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        ScannerScheduler(max_concurrency=max_concurrency)
