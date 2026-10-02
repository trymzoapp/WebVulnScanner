"""Bounded asynchronous execution of external tools."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from webvulnscanner.core.exceptions import SubprocessExecutionError
from webvulnscanner.core.logging import log_event
from webvulnscanner.utils.command import Command


@dataclass(frozen=True, slots=True)
class SubprocessResult:
    """Captured outcome of one external process."""

    command: tuple[str, ...]
    stdout: str
    stderr: str
    return_code: int | None
    duration_seconds: float
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.return_code == 0


class AsyncSubprocessRunner:
    """Run literal argument vectors under shared concurrency and timeout limits."""

    def __init__(
        self,
        *,
        max_concurrency: int,
        default_timeout: float,
        max_output_bytes: int = 1_048_576,
        termination_grace_seconds: float = 1.0,
        logger: logging.Logger | logging.LoggerAdapter[logging.Logger] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
            raise TypeError("max_concurrency must be an integer")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        _positive_finite("default_timeout", default_timeout)
        _positive_finite("termination_grace_seconds", termination_grace_seconds)
        if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int):
            raise TypeError("max_output_bytes must be an integer")
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be at least 1")

        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._default_timeout = float(default_timeout)
        self._max_output_bytes = max_output_bytes
        self._termination_grace_seconds = float(termination_grace_seconds)
        self._logger = logger
        self._monotonic = monotonic
        self._active_count = 0
        self._max_observed_concurrency = 0

    @property
    def active_count(self) -> int:
        return self._active_count

    @property
    def max_observed_concurrency(self) -> int:
        return self._max_observed_concurrency

    async def run(
        self,
        command: Command | Sequence[str],
        *,
        timeout: float | None = None,
    ) -> SubprocessResult:
        """Execute a command and return a bounded result for every exit status."""
        normalized = (
            command if isinstance(command, Command) else Command.from_sequence(command)
        )
        effective_timeout = self._default_timeout if timeout is None else timeout
        _positive_finite("timeout", effective_timeout)

        async with self._semaphore:
            self._active_count += 1
            self._max_observed_concurrency = max(
                self._max_observed_concurrency,
                self._active_count,
            )
            try:
                return await self._run_process(normalized, float(effective_timeout))
            finally:
                self._active_count -= 1

    async def _run_process(
        self,
        command: Command,
        timeout: float,
    ) -> SubprocessResult:
        started = self._monotonic()
        self._log(
            logging.DEBUG,
            "subprocess_started",
            "External process started",
            executable=command.executable,
            timeout_seconds=timeout,
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command.argv,
                cwd=None if command.cwd is None else str(command.cwd),
                env=(
                    None if command.environment is None else dict(command.environment)
                ),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (OSError, ValueError) as error:
            raise SubprocessExecutionError(
                "unable to start external process",
                component=command.executable,
                operation="execute",
                cause=error,
            ) from error

        if process.stdout is None or process.stderr is None:
            await self._stop_process(process)
            raise SubprocessExecutionError(
                "external process streams were unavailable",
                component=command.executable,
                operation="execute",
            )

        stdout_task = asyncio.create_task(self._read_bounded(process.stdout))
        stderr_task = asyncio.create_task(self._read_bounded(process.stderr))
        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout)
        except TimeoutError:
            timed_out = True
            await self._stop_process(process)
        except asyncio.CancelledError:
            await self._stop_process(process)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            self._log(
                logging.WARNING,
                "subprocess_cancelled",
                "External process was cancelled and reaped",
                executable=command.executable,
            )
            raise

        stdout_capture, stderr_capture = await asyncio.gather(
            stdout_task,
            stderr_task,
        )
        duration = max(0.0, self._monotonic() - started)
        result = SubprocessResult(
            command=command.argv,
            stdout=stdout_capture[0].decode("utf-8", errors="replace"),
            stderr=stderr_capture[0].decode("utf-8", errors="replace"),
            return_code=process.returncode,
            duration_seconds=duration,
            timed_out=timed_out,
            stdout_truncated=stdout_capture[1],
            stderr_truncated=stderr_capture[1],
        )
        self._log(
            logging.WARNING if timed_out or process.returncode else logging.DEBUG,
            "subprocess_completed",
            "External process completed",
            executable=command.executable,
            return_code=process.returncode,
            timed_out=timed_out,
            duration_seconds=duration,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
        )
        return result

    async def _read_bounded(
        self,
        stream: asyncio.StreamReader,
    ) -> tuple[bytes, bool]:
        retained = bytearray()
        truncated = False
        while True:
            chunk = await stream.read(65_536)
            if not chunk:
                break
            remaining = self._max_output_bytes - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
        return bytes(retained), truncated

    async def _stop_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            await process.wait()
            return
        try:
            process.terminate()
        except ProcessLookupError:
            await process.wait()
            return
        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=self._termination_grace_seconds,
            )
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()

    def _log(
        self,
        level: int,
        event: str,
        message: str,
        **fields: object,
    ) -> None:
        if self._logger is not None:
            log_event(self._logger, level, event, message, **fields)


def _positive_finite(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise ValueError(f"{name} must be finite and greater than zero")


__all__ = ["AsyncSubprocessRunner", "SubprocessResult"]
