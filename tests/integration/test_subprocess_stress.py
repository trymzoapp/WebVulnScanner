"""Stress and resilience integration tests for AsyncSubprocessRunner."""

from __future__ import annotations

import asyncio
import time

import pytest

from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.utils.command import Command


@pytest.mark.integration
@pytest.mark.asyncio
async def test_simultaneous_timeouts() -> None:
    """Simultaneous subprocess timeouts must terminate cleanly without hanging."""
    runner = AsyncSubprocessRunner(
        max_concurrency=4,
        default_timeout=0.2,
        termination_grace_seconds=0.2,
    )

    sleep_code = "import time; time.sleep(10)"
    commands = [Command("python", ("-c", sleep_code)) for _ in range(6)]

    start = time.monotonic()
    results = await asyncio.gather(*(runner.run(cmd) for cmd in commands))
    elapsed = time.monotonic() - start

    assert len(results) == 6
    for result in results:
        assert result.timed_out is True
        assert result.return_code != 0
    # 6 commands with concurrency 4 should finish in roughly 2 batches: ~0.4s to ~3s max
    assert elapsed < 5.0
    assert runner.active_count == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_subprocess_cancellation_cleans_up() -> None:
    """Cancelling a running subprocess task must terminate the process and reap streams."""
    runner = AsyncSubprocessRunner(
        max_concurrency=2,
        default_timeout=10.0,
        termination_grace_seconds=0.2,
    )

    sleep_cmd = Command("python", ("-c", "import time; time.sleep(10)"))
    task = asyncio.create_task(runner.run(sleep_cmd))

    # Allow process to start
    await asyncio.sleep(0.1)
    assert runner.active_count == 1

    # Cancel task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Give event loop a tick to ensure reaping
    await asyncio.sleep(0.1)
    assert runner.active_count == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_large_output_stream_bounding() -> None:
    """Large stdout and stderr streams must be truncated at max_output_bytes without unbounded memory."""
    max_bytes = 32_768
    runner = AsyncSubprocessRunner(
        max_concurrency=2,
        default_timeout=5.0,
        max_output_bytes=max_bytes,
    )

    # Produce 200KB of stdout and 200KB of stderr
    script = (
        "import sys\n"
        "sys.stdout.write('O' * 200_000)\n"
        "sys.stderr.write('E' * 200_000)\n"
        "sys.stdout.flush()\n"
        "sys.stderr.flush()\n"
    )
    cmd = Command("python", ("-c", script))

    result = await runner.run(cmd)
    assert result.succeeded
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert len(result.stdout.encode("utf-8")) <= max_bytes
    assert len(result.stderr.encode("utf-8")) <= max_bytes


@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrency_ceiling_enforced() -> None:
    """Active process count must never exceed configured max_concurrency."""
    concurrency_limit = 3
    runner = AsyncSubprocessRunner(
        max_concurrency=concurrency_limit,
        default_timeout=5.0,
    )

    script = "import time; time.sleep(0.15)"
    commands = [Command("python", ("-c", script)) for _ in range(8)]

    results = await asyncio.gather(*(runner.run(cmd) for cmd in commands))
    assert len(results) == 8
    assert all(res.succeeded for res in results)
    assert runner.max_observed_concurrency <= concurrency_limit
    assert runner.active_count == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nonzero_exit_with_error_capture() -> None:
    """Nonzero exits must return captured stderr and exit codes reliably."""
    runner = AsyncSubprocessRunner(
        max_concurrency=2,
        default_timeout=5.0,
    )

    script = "import sys; sys.stderr.write('critical tool error\\n'); sys.exit(7)"
    cmd = Command("python", ("-c", script))

    result = await runner.run(cmd)
    assert result.succeeded is False
    assert result.return_code == 7
    assert "critical tool error" in result.stderr
