"""Common scanner lifecycle and dependency contracts."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Protocol

from webvulnscanner.config.loader import AppConfig, ScannerConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import (
    ParsingError,
    ScannerValidationError,
    WebVulnScannerError,
)
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.finding import Finding
from webvulnscanner.models.scan_result import (
    ScanError,
    ScannerStatus,
    ScanResult,
    SubprocessDetails,
)
from webvulnscanner.models.technology import Technology
from webvulnscanner.parsers.base import BaseParser
from webvulnscanner.utils.command import Command
from webvulnscanner.utils.time import as_utc, utc_now


class SubprocessRunnerProtocol(Protocol):
    """Narrow runner dependency used by scanner implementations."""

    async def run(
        self,
        command: Command,
        *,
        timeout: float | None = None,
    ) -> SubprocessResult:
        """Execute one command."""


@dataclass(frozen=True, slots=True)
class ScannerOutput:
    """Normalized output returned by a scanner's parsing hook."""

    findings: tuple[Finding, ...] = ()
    technologies: tuple[Technology, ...] = ()
    output_paths: tuple[str, ...] = ()
    artifacts: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        _model_tuple("findings", self.findings, Finding)
        _model_tuple("technologies", self.technologies, Technology)
        if not isinstance(self.output_paths, tuple):
            raise TypeError("output_paths must be a tuple")
        if any(
            not isinstance(path, str) or not path.strip() for path in self.output_paths
        ):
            raise ValueError("output_paths must contain non-empty strings")
        if not isinstance(self.artifacts, Mapping):
            raise TypeError("artifacts must be a mapping")


class BaseScanner(ABC):
    """Failure-aware scanner lifecycle with injected dependencies."""

    name: str = ""

    def __init__(
        self,
        *,
        configuration: AppConfig,
        runner: SubprocessRunnerProtocol,
        context: ScanContext,
        parser: BaseParser[Any],
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        if not self.name:
            raise ValueError("scanner classes must define a non-empty name")
        self.configuration = configuration
        self.runner = runner
        self.context = context
        self.parser = parser
        self._time_provider = time_provider

    @property
    def scanner_config(self) -> ScannerConfig:
        return self.configuration.scanner(self.name)

    @abstractmethod
    async def validate(self) -> None:
        """Validate scanner prerequisites or raise ``ScannerValidationError``."""

    @abstractmethod
    def build_command(self) -> Command:
        """Build the scanner's literal external-tool command."""

    @abstractmethod
    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        """Convert bounded process output into normalized scanner output."""

    async def run(self) -> ScanResult:
        """Run the common scanner lifecycle and return a controlled result."""
        started_at = self._now()
        scanner_config = self.scanner_config
        if not scanner_config.enabled:
            return ScanResult(
                scanner=self.name,
                status=ScannerStatus.SKIPPED,
                started_at=started_at,
                completed_at=self._now(),
                skip_reason="scanner is disabled by configuration",
            )

        try:
            await self.validate()
            command = self.build_command()
            process_result = await self.runner.run(
                command,
                timeout=self.configuration.timeouts.for_scanner(self.name),
            )
            details = _subprocess_details(process_result)
            if process_result.timed_out:
                return self._failed_result(
                    started_at,
                    ScannerStatus.TIMED_OUT,
                    "timeout",
                    "scanner exceeded its configured timeout",
                    details,
                )
            if process_result.return_code != 0:
                return self._failed_result(
                    started_at,
                    ScannerStatus.FAILED,
                    "nonzero_exit",
                    "scanner process exited unsuccessfully",
                    details,
                )
            output = self.parse(process_result)
            return ScanResult(
                scanner=self.name,
                status=ScannerStatus.SUCCESS,
                started_at=started_at,
                completed_at=self._now(),
                output_paths=output.output_paths,
                findings=output.findings,
                technologies=output.technologies,
                subprocess_details=details,
                artifacts=output.artifacts,
            )
        except asyncio.CancelledError:
            raise
        except ScannerValidationError as error:
            return self._failed_result(
                started_at,
                ScannerStatus.FAILED,
                "validation_failed",
                str(error),
            )
        except ParsingError as error:
            return self._failed_result(
                started_at,
                ScannerStatus.FAILED,
                "parse_failed",
                str(error),
            )
        except WebVulnScannerError as error:
            return self._failed_result(
                started_at,
                ScannerStatus.FAILED,
                "scanner_error",
                str(error),
            )

    def _failed_result(
        self,
        started_at: datetime,
        status: ScannerStatus,
        code: str,
        message: str,
        details: SubprocessDetails | None = None,
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            status=status,
            started_at=started_at,
            completed_at=self._now(),
            errors=(ScanError(code=code, message=message),),
            subprocess_details=details,
        )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="scanner timestamp")


def _subprocess_details(result: SubprocessResult) -> SubprocessDetails:
    return SubprocessDetails(
        duration_seconds=result.duration_seconds,
        exit_code=result.return_code,
        timed_out=result.timed_out,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _model_tuple(
    name: str,
    values: object,
    expected_type: type[object],
) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be a tuple")
    if any(not isinstance(value, expected_type) for value in values):
        raise TypeError(f"{name} contains an invalid model")


__all__ = [
    "BaseScanner",
    "ScannerOutput",
    "SubprocessRunnerProtocol",
]
