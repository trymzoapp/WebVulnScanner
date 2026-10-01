"""Fingerprint scanner registration and pipeline-stage assembly."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.pipeline import (
    FailurePolicy,
    StageName,
    StageOutcome,
    StageStatus,
)
from webvulnscanner.core.scheduler import (
    SchedulableScanner,
    ScannerScheduler,
)
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.scan_result import (
    ScanError,
    ScanResult,
    ScannerStatus,
)
from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology
from webvulnscanner.scanners.fingerprint.nmap import NmapScanner
from webvulnscanner.scanners.fingerprint.wappalyzer import WappalyzerScanner
from webvulnscanner.utils.time import as_utc, utc_now


FINGERPRINT_SCANNERS = ("wappalyzer", "nmap")
FingerprintScannerFactory = Callable[[ScanContext], SchedulableScanner]


@dataclass(frozen=True, slots=True)
class FingerprintArtifacts:
    """Typed observations consumed by routing and discovery."""

    technologies: tuple[Technology, ...]
    services: tuple[WebService, ...]
    web_services: tuple[WebService, ...]
    urls: tuple[str, ...]
    scanner_results: tuple[ScanResult, ...]


class FingerprintStage:
    """Schedule configured fingerprint scanners and merge normalized evidence."""

    name = StageName.FINGERPRINT
    dependencies = (StageName.PASSIVE,)
    failure_policy = FailurePolicy.CONTINUE

    def __init__(
        self,
        *,
        configuration: AppConfig,
        scanner_factories: Mapping[str, FingerprintScannerFactory],
        scheduler: ScannerScheduler | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.configuration = configuration
        self.scanner_factories = dict(scanner_factories)
        self.scheduler = scheduler or ScannerScheduler(
            max_concurrency=configuration.concurrency.max_scanners,
            time_provider=time_provider,
        )
        self._time_provider = time_provider

    async def run(
        self,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        del previous
        started_at = self._now()
        slots: list[ScanResult | None] = []
        runnable: list[SchedulableScanner] = []
        indices: list[int] = []
        for name in FINGERPRINT_SCANNERS:
            if not self.configuration.scanner(name).enabled:
                slots.append(_skipped(name, started_at))
                continue
            factory = self.scanner_factories.get(name)
            if factory is None:
                slots.append(_failed(name, started_at, "factory_unavailable"))
                continue
            try:
                scanner = factory(context)
            except Exception:
                slots.append(_failed(name, started_at, "factory_error"))
                continue
            indices.append(len(slots))
            runnable.append(scanner)
            slots.append(None)

        scheduled = await self.scheduler.run(runnable)
        for index, result in zip(indices, scheduled):
            slots[index] = result
        results = tuple(item for item in slots if item is not None)
        artifacts = _merge(results)
        attempted = [
            item for item in results if item.status is not ScannerStatus.SKIPPED
        ]
        failed = [
            item
            for item in attempted
            if item.status
            in {
                ScannerStatus.FAILED,
                ScannerStatus.TIMED_OUT,
                ScannerStatus.CANCELLED,
            }
        ]
        if attempted and len(failed) == len(attempted):
            errors = tuple(
                error.message for item in failed for error in item.errors
            ) or ("all enabled fingerprint scanners failed",)
            return StageOutcome(
                name=self.name,
                status=StageStatus.FAILED,
                started_at=started_at,
                completed_at=self._now(),
                errors=errors,
                artifacts={"fingerprint": artifacts},
            )
        return StageOutcome(
            name=self.name,
            status=StageStatus.SUCCESS,
            started_at=started_at,
            completed_at=self._now(),
            artifacts={"fingerprint": artifacts},
        )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="fingerprint stage timestamp")


def create_fingerprint_stage(
    *,
    configuration: AppConfig,
    subprocess_runner: AsyncSubprocessRunner,
    time_provider: Callable[[], datetime] = utc_now,
) -> FingerprintStage:
    """Build concrete fingerprint scanner factories outside orchestration."""
    factories: dict[str, FingerprintScannerFactory] = {
        "wappalyzer": lambda context: WappalyzerScanner(
            configuration=configuration,
            runner=subprocess_runner,
            context=context,
            time_provider=time_provider,
        ),
        "nmap": lambda context: NmapScanner(
            configuration=configuration,
            runner=subprocess_runner,
            context=context,
            time_provider=time_provider,
        ),
    }
    return FingerprintStage(
        configuration=configuration,
        scanner_factories=factories,
        time_provider=time_provider,
    )


def _merge(results: tuple[ScanResult, ...]) -> FingerprintArtifacts:
    technologies: dict[tuple[str, str, str | None], Technology] = {}
    services: dict[tuple[object, ...], WebService] = {}
    web_services: dict[tuple[object, ...], WebService] = {}
    urls: set[str] = set()
    for result in results:
        for technology in result.technologies:
            key = (
                technology.source,
                technology.name.casefold(),
                technology.version,
            )
            existing = technologies.get(key)
            if existing is None or technology.confidence > existing.confidence:
                technologies[key] = technology
        _merge_services(services, result.artifacts.get("services"))
        _merge_services(web_services, result.artifacts.get("web_services"))
        value = result.artifacts.get("urls", ())
        if isinstance(value, tuple):
            urls.update(item for item in value if isinstance(item, str))
    return FingerprintArtifacts(
        technologies=tuple(
            sorted(
                technologies.values(),
                key=lambda item: (
                    item.name.casefold(),
                    item.source,
                    item.version or "",
                ),
            )
        ),
        services=tuple(services.values()),
        web_services=tuple(web_services.values()),
        urls=tuple(sorted(urls)),
        scanner_results=results,
    )


def _merge_services(
    destination: dict[tuple[object, ...], WebService],
    value: object,
) -> None:
    if not isinstance(value, tuple):
        return
    for item in value:
        if not isinstance(item, Mapping):
            continue
        try:
            service = WebService.from_dict(item)
        except (TypeError, ValueError):
            continue
        key = (
            service.host,
            service.protocol,
            service.port,
            service.web_url,
        )
        destination[key] = service


def _skipped(name: str, now: datetime) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.SKIPPED,
        started_at=now,
        completed_at=now,
        skip_reason="scanner is disabled by configuration",
    )


def _failed(name: str, now: datetime, code: str) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.FAILED,
        started_at=now,
        completed_at=now,
        errors=(
            ScanError(
                code=code,
                message="fingerprint scanner initialization failed",
            ),
        ),
    )


__all__ = [
    "FINGERPRINT_SCANNERS",
    "FingerprintArtifacts",
    "FingerprintScannerFactory",
    "FingerprintStage",
    "create_fingerprint_stage",
]
