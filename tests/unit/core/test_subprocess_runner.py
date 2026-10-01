"""Tests for bounded asynchronous subprocess execution."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.core.exceptions import SubprocessExecutionError
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.utils.command import Command


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def python_command(source: str, *arguments: str) -> Command:
    return Command(sys.executable, ("-c", source, *arguments))


def test_success_captures_stdout_stderr_and_return_code() -> None:
    runner = AsyncSubprocessRunner(max_concurrency=1, default_timeout=5)
    command = python_command(
        "import sys; print('output'); print('diagnostic', file=sys.stderr)"
    )

    result = run(runner.run(command))

    assert result.succeeded is True
    assert result.return_code == 0
    assert result.stdout.strip() == "output"
    assert result.stderr.strip() == "diagnostic"
    assert result.duration_seconds >= 0
    assert result.timed_out is False


def test_nonzero_exit_is_a_controlled_result_and_runner_remains_available() -> None:
    async def scenario() -> None:
        runner = AsyncSubprocessRunner(max_concurrency=1, default_timeout=5)
        failed = await runner.run(
            python_command("import sys; print('failed', file=sys.stderr); sys.exit(7)")
        )
        succeeded = await runner.run(python_command("print('later success')"))

        assert failed.return_code == 7
        assert failed.succeeded is False
        assert failed.stderr.strip() == "failed"
        assert succeeded.succeeded is True
        assert runner.active_count == 0

    run(scenario())


def test_arguments_with_spaces_and_shell_metacharacters_remain_literal() -> None:
    arguments = ("space value", "$(not-executed)", "& echo not-executed", "semi;colon")
    command = python_command(
        "import json, sys; print(json.dumps(sys.argv[1:]))",
        *arguments,
    )
    runner = AsyncSubprocessRunner(max_concurrency=1, default_timeout=5)

    result = run(runner.run(command))

    assert json.loads(result.stdout) == list(arguments)
    assert result.stderr == ""


def test_timeout_terminates_reaps_and_releases_runner() -> None:
    async def scenario() -> None:
        runner = AsyncSubprocessRunner(
            max_concurrency=1,
            default_timeout=0.1,
            termination_grace_seconds=0.2,
        )
        timed_out = await runner.run(
            python_command("import time; print('started', flush=True); time.sleep(10)")
        )
        later = await runner.run(python_command("print('available')"), timeout=2)

        assert timed_out.timed_out is True
        assert timed_out.return_code is not None
        assert timed_out.stdout.strip() == "started"
        assert later.succeeded is True
        assert runner.active_count == 0

    run(scenario())


def test_cancellation_terminates_reaps_and_releases_runner() -> None:
    async def scenario() -> None:
        runner = AsyncSubprocessRunner(
            max_concurrency=1,
            default_timeout=10,
            termination_grace_seconds=0.2,
        )
        task = asyncio.create_task(
            runner.run(python_command("import time; time.sleep(10)"))
        )
        await asyncio.sleep(0.15)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        later = await runner.run(python_command("print('available')"), timeout=2)
        assert later.succeeded is True
        assert runner.active_count == 0

    run(scenario())


def test_shared_semaphore_enforces_concurrency_limit() -> None:
    async def scenario() -> None:
        runner = AsyncSubprocessRunner(max_concurrency=2, default_timeout=5)
        command = python_command("import time; time.sleep(0.15)")
        results = await asyncio.gather(*(runner.run(command) for _ in range(5)))

        assert all(result.succeeded for result in results)
        assert runner.max_observed_concurrency == 2
        assert runner.active_count == 0

    run(scenario())


def test_output_is_bounded_while_streams_are_drained() -> None:
    runner = AsyncSubprocessRunner(
        max_concurrency=1,
        default_timeout=5,
        max_output_bytes=32,
    )
    command = python_command(
        "import sys; sys.stdout.write('a' * 1000); sys.stderr.write('b' * 1000)"
    )

    result = run(runner.run(command))

    assert result.succeeded is True
    assert result.stdout == "a" * 32
    assert result.stderr == "b" * 32
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True


def test_missing_executable_raises_typed_controlled_error(tmp_path: Path) -> None:
    runner = AsyncSubprocessRunner(max_concurrency=1, default_timeout=1)
    command = Command(str(tmp_path / "definitely-missing-executable"))

    with pytest.raises(SubprocessExecutionError, match="unable to start"):
        run(runner.run(command))
    assert runner.active_count == 0


@pytest.mark.parametrize(
    "values",
    [
        (),
        ("",),
        ("tool\x00name",),
    ],
)
def test_invalid_commands_are_rejected(values: tuple[str, ...]) -> None:
    with pytest.raises((TypeError, ValueError)):
        Command.from_sequence(values)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_concurrency": 0, "default_timeout": 1},
        {"max_concurrency": True, "default_timeout": 1},
        {"max_concurrency": 1, "default_timeout": 0},
        {"max_concurrency": 1, "default_timeout": float("inf")},
        {"max_concurrency": 1, "default_timeout": 1, "max_output_bytes": 0},
    ],
)
def test_invalid_runner_limits_are_rejected(kwargs: dict[str, Any]) -> None:
    with pytest.raises((TypeError, ValueError)):
        AsyncSubprocessRunner(**kwargs)
