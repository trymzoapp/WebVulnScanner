"""Concurrent scanner scheduling with deterministic failure isolation."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Protocol

from webvulnscanner.core.exceptions import WebVulnScannerError
from webvulnscanner.core.logging import log_event
from webvulnscanner.models.scan_result import ScanError, ScannerStatus, ScanResult
from webvulnscanner.utils.time import as_utc, utc_now


class SchedulableScanner(Protocol):
    """Narrow scanner interface consumed by the scheduler."""

    name: str

    async def run(self) -> ScanResult:
        """Run and return one scanner result."""


class ScannerScheduler:
    """Run scanners concurrently while preserving input result order."""

    def __init__(
        self,
        *,
        max_concurrency: int,
        time_provider: Callable[[], datetime] = utc_now,
        logger: logging.Logger | logging.LoggerAdapter[logging.Logger] | None = None,
    ) -> None:
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
            raise TypeError("max_concurrency must be an integer")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._time_provider = time_provider
        self._logger = logger
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
        scanners: Sequence[SchedulableScanner],
    ) -> tuple[ScanResult, ...]:
        """Schedule scanners and isolate ordinary scanner failures."""
        if isinstance(scanners, (str, bytes)) or not isinstance(scanners, Sequence):
            raise TypeError("scanners must be a sequence")
        tasks = [asyncio.create_task(self._run_one(scanner)) for scanner in scanners]
        if not tasks:
            return ()
        try:
            results = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return tuple(results)

    async def _run_one(self, scanner: SchedulableScanner) -> ScanResult:
        name = getattr(scanner, "name", "")
        if not isinstance(name, str) or not name.strip():
            name = type(scanner).__name__
        async with self._semaphore:
            self._active_count += 1
            self._max_observed_concurrency = max(
                self._max_observed_concurrency,
                self._active_count,
            )
            started_at = self._now()
            try:
                result = await scanner.run()
                if not isinstance(result, ScanResult):
                    raise TypeError("scanner returned a non-ScanResult value")
                return result
            except asyncio.CancelledError:
                raise
            except WebVulnScannerError as error:
                return self._failure(
                    name,
                    started_at,
                    "scanner_exception",
                    str(error),
                    type(error).__name__,
                )
            except Exception as error:
                return self._failure(
                    name,
                    started_at,
                    "unexpected_exception",
                    "scanner raised an unexpected exception",
                    type(error).__name__,
                )
            finally:
                self._active_count -= 1

    def _failure(
        self,
        scanner: str,
        started_at: datetime,
        code: str,
        message: str,
        exception_type: str,
    ) -> ScanResult:
        self._log_failure(scanner, code, exception_type)
        return ScanResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            started_at=started_at,
            completed_at=self._now(),
            errors=(ScanError(code=code, message=message),),
        )

    def _log_failure(
        self,
        scanner: str,
        code: str,
        exception_type: str,
    ) -> None:
        if self._logger is not None:
            log_event(
                self._logger,
                logging.ERROR,
                "scanner_failed",
                "Scanner failure was isolated by the scheduler",
                scanner=scanner,
                failure_code=code,
                exception_type=exception_type,
            )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="scheduler timestamp")


__all__ = ["SchedulableScanner", "ScannerScheduler"]
