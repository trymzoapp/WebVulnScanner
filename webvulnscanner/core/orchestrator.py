"""Minimal scanner-agnostic orchestration of context and pipeline execution."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import StorageError, WebVulnScannerError
from webvulnscanner.core.pipeline import Pipeline, PipelineResult, PipelineStatus
from webvulnscanner.models.report import ScanMetadata, ScanStatus
from webvulnscanner.models.target import Target
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import as_utc, utc_now


class ContextFactoryProtocol(Protocol):
    """Narrow context-factory dependency used by the orchestrator."""

    def create(
        self,
        target: Target,
        *,
        profile_name: str,
        scanner_configuration: Mapping[str, object],
        tool_versions: Mapping[str, str] | None = None,
    ) -> ScanContext:
        """Create and persist initial scan context."""


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    """Final orchestration state, including controlled setup failures."""

    status: ScanStatus
    context: ScanContext | None
    pipeline: PipelineResult | None
    metadata: ScanMetadata | None
    errors: tuple[str, ...] = ()


class Orchestrator:
    """Create context, execute generic stages, and finalize scan metadata."""

    def __init__(
        self,
        *,
        configuration: AppConfig,
        context_factory: ContextFactoryProtocol,
        pipeline: Pipeline,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.configuration = configuration
        self.context_factory = context_factory
        self.pipeline = pipeline
        self._time_provider = time_provider

    async def run(self, target: Target) -> OrchestrationResult:
        """Run one target without importing concrete scanner implementations."""
        if not isinstance(target, Target):
            raise TypeError("target must be a Target")
        try:
            context = self.context_factory.create(
                target,
                profile_name=self.configuration.profile.name,
                scanner_configuration=_scanner_snapshot(self.configuration),
                tool_versions={},
            )
        except WebVulnScannerError as error:
            return OrchestrationResult(
                status=ScanStatus.FAILED,
                context=None,
                pipeline=None,
                metadata=None,
                errors=(str(error),),
            )
        except Exception:
            return OrchestrationResult(
                status=ScanStatus.FAILED,
                context=None,
                pipeline=None,
                metadata=None,
                errors=("scan context creation failed unexpectedly",),
            )

        try:
            pipeline_result = await self.pipeline.run(context)
        except asyncio.CancelledError:
            self._finalize(
                context,
                ScanStatus.CANCELLED,
                ("scan orchestration was cancelled",),
            )
            raise
        except Exception:
            pipeline_result = None

        pipeline_errors: tuple[str, ...]
        if pipeline_result is None:
            pipeline_result = PipelineResult(
                status=PipelineStatus.FAILED,
                outcomes=(),
            )
            pipeline_errors = ("pipeline execution failed unexpectedly",)
        else:
            pipeline_errors = pipeline_result.errors

        final_status = _scan_status(pipeline_result.status)
        try:
            metadata = self._finalize(context, final_status, pipeline_errors)
        except StorageError as error:
            return OrchestrationResult(
                status=ScanStatus.FAILED,
                context=context,
                pipeline=pipeline_result,
                metadata=None,
                errors=(*pipeline_errors, str(error)),
            )
        return OrchestrationResult(
            status=final_status,
            context=context,
            pipeline=pipeline_result,
            metadata=metadata,
            errors=pipeline_errors,
        )

    def _finalize(
        self,
        context: ScanContext,
        status: ScanStatus,
        errors: tuple[str, ...],
    ) -> ScanMetadata:
        initial = context.metadata
        metadata = ScanMetadata(
            scan_id=initial.scan_id,
            target_url=initial.target_url,
            normalized_domain=initial.normalized_domain,
            started_at=initial.started_at,
            completed_at=self._now(),
            profile=initial.profile,
            scanner_configuration=initial.scanner_configuration,
            tool_versions=initial.tool_versions,
            status=status,
            errors=errors,
        )
        atomic_write_json(
            context.metadata_path,
            metadata.to_dict(),
            storage_root=context.storage_root,
        )
        return metadata

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="orchestrator timestamp")


def _scan_status(status: PipelineStatus) -> ScanStatus:
    if status is PipelineStatus.COMPLETED:
        return ScanStatus.COMPLETED
    if status is PipelineStatus.PARTIAL:
        return ScanStatus.PARTIAL
    return ScanStatus.FAILED


def _scanner_snapshot(configuration: AppConfig) -> dict[str, object]:
    return {
        name: {
            "enabled": scanner.enabled,
            "executable": scanner.executable,
            "wordlist": None if scanner.wordlist is None else str(scanner.wordlist),
            "timeout": configuration.timeouts.for_scanner(name),
            "concurrency": scanner.concurrency,
            "rate_limit_per_second": scanner.rate_limit_per_second,
        }
        for name, scanner in sorted(configuration.scanners.items())
    }


__all__ = [
    "ContextFactoryProtocol",
    "OrchestrationResult",
    "Orchestrator",
]
