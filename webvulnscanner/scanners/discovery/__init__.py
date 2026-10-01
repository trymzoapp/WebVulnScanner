"""Discovery scanner registration and routed pipeline-stage assembly."""

from __future__ import annotations

import hashlib
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
from webvulnscanner.models.discovery import DiscoveredResource
from webvulnscanner.models.scan_result import (
    ScanError,
    ScanResult,
    ScannerStatus,
)
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.discovery.dirsearch import DirsearchScanner
from webvulnscanner.scanners.discovery.gobuster import GobusterScanner
from webvulnscanner.scanners.fingerprint import FingerprintArtifacts
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import as_utc, utc_now


DISCOVERY_SCANNERS = ("gobuster", "dirsearch")
DiscoveryScannerFactory = Callable[[ScanContext, str, str], SchedulableScanner]


@dataclass(frozen=True, slots=True)
class DiscoveryArtifacts:
    """Typed discovered resources and retained per-target scanner outcomes."""

    resources: tuple[DiscoveredResource, ...]
    urls: tuple[str, ...]
    scanner_results: tuple[ScanResult, ...]


class DiscoveryStage:
    """Run enabled discovery tools only for confirmed in-scope web services."""

    name = StageName.DISCOVERY
    dependencies = (StageName.FINGERPRINT,)
    failure_policy = FailurePolicy.CONTINUE

    def __init__(
        self,
        *,
        configuration: AppConfig,
        scanner_factories: Mapping[str, DiscoveryScannerFactory],
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
        started_at = self._now()
        targets = _eligible_targets(context, previous.get(StageName.FINGERPRINT))
        if not targets:
            return StageOutcome(
                name=self.name,
                status=StageStatus.SKIPPED,
                started_at=started_at,
                completed_at=self._now(),
                reason="no confirmed in-scope HTTP(S) services",
                artifacts={
                    "discovery": DiscoveryArtifacts((), (), ()),
                },
            )

        scanners: list[SchedulableScanner] = []
        retained: list[ScanResult] = []
        for name in DISCOVERY_SCANNERS:
            if not self.configuration.scanner(name).enabled:
                retained.append(_skipped(name, started_at))
                continue
            factory = self.scanner_factories.get(name)
            if factory is None:
                retained.append(_initialization_failure(name, started_at))
                continue
            for target_url in targets:
                try:
                    scanner = factory(
                        context,
                        target_url,
                        _target_output_name(name, target_url),
                    )
                except Exception:
                    retained.append(_initialization_failure(name, started_at))
                    continue
                scanners.append(scanner)

        if not scanners and all(
            item.status is ScannerStatus.SKIPPED for item in retained
        ):
            return StageOutcome(
                name=self.name,
                status=StageStatus.SKIPPED,
                started_at=started_at,
                completed_at=self._now(),
                reason="all discovery scanners are disabled or unavailable",
                artifacts={
                    "discovery": DiscoveryArtifacts((), (), tuple(retained)),
                },
            )

        scheduled = await self.scheduler.run(scanners)
        results = (*retained, *scheduled)
        artifacts = _merge(results)
        self._persist_tool_summaries(context, targets, results)
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
            ) or ("all discovery scanner executions failed",)
            return StageOutcome(
                name=self.name,
                status=StageStatus.FAILED,
                started_at=started_at,
                completed_at=self._now(),
                errors=errors,
                artifacts={"discovery": artifacts},
            )
        return StageOutcome(
            name=self.name,
            status=StageStatus.SUCCESS,
            started_at=started_at,
            completed_at=self._now(),
            artifacts={"discovery": artifacts},
        )

    def _persist_tool_summaries(
        self,
        context: ScanContext,
        targets: tuple[str, ...],
        results: tuple[ScanResult, ...],
    ) -> None:
        for name in DISCOVERY_SCANNERS:
            if not self.configuration.scanner(name).enabled:
                continue
            matching = tuple(item for item in results if item.scanner == name)
            resources, urls = _merge_result_artifacts(matching)
            atomic_write_json(
                context.stage_directory("discovery") / f"{name}.json",
                {
                    "scanner": name,
                    "targets": list(targets),
                    "resources": [item.to_dict() for item in resources],
                    "urls": list(urls),
                    "executions": [item.to_dict() for item in matching],
                },
                storage_root=context.storage_root,
                overwrite=False,
            )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="discovery stage timestamp")


def create_discovery_stage(
    *,
    configuration: AppConfig,
    subprocess_runner: AsyncSubprocessRunner,
    time_provider: Callable[[], datetime] = utc_now,
) -> DiscoveryStage:
    """Build target-aware discovery factories outside the orchestrator."""
    factories: dict[str, DiscoveryScannerFactory] = {
        "gobuster": lambda context, target_url, output_name: GobusterScanner(
            configuration=configuration,
            runner=subprocess_runner,
            context=context,
            target_url=target_url,
            output_filename=output_name,
            time_provider=time_provider,
        ),
        "dirsearch": lambda context, target_url, output_name: DirsearchScanner(
            configuration=configuration,
            runner=subprocess_runner,
            context=context,
            target_url=target_url,
            output_filename=output_name,
            time_provider=time_provider,
        ),
    }
    return DiscoveryStage(
        configuration=configuration,
        scanner_factories=factories,
        time_provider=time_provider,
    )


def _eligible_targets(
    context: ScanContext,
    fingerprint_outcome: StageOutcome | None,
) -> tuple[str, ...]:
    if (
        fingerprint_outcome is None
        or fingerprint_outcome.status is not StageStatus.SUCCESS
    ):
        return ()
    artifacts = fingerprint_outcome.artifacts.get("fingerprint")
    if not isinstance(artifacts, FingerprintArtifacts):
        return ()
    targets: set[str] = set()
    for value in artifacts.urls:
        try:
            target = Target(value)
        except Exception:
            continue
        if target.host == context.target.host:
            targets.add(target.url)
    return tuple(sorted(targets))


def _target_output_name(scanner: str, target_url: str) -> str:
    digest = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:12]
    return f"{scanner}-{digest}.json"


def _skipped(name: str, now: datetime) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.SKIPPED,
        started_at=now,
        completed_at=now,
        skip_reason="scanner is disabled by configuration",
    )


def _initialization_failure(name: str, now: datetime) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.FAILED,
        started_at=now,
        completed_at=now,
        errors=(
            ScanError(
                code="factory_error",
                message="discovery scanner initialization failed",
            ),
        ),
    )


def _merge(results: tuple[ScanResult, ...]) -> DiscoveryArtifacts:
    resources, urls = _merge_result_artifacts(results)
    return DiscoveryArtifacts(
        resources=resources,
        urls=urls,
        scanner_results=results,
    )


def _merge_result_artifacts(
    results: tuple[ScanResult, ...],
) -> tuple[tuple[DiscoveredResource, ...], tuple[str, ...]]:
    resources: dict[tuple[object, ...], DiscoveredResource] = {}
    urls: set[str] = set()
    for result in results:
        raw_resources = result.artifacts.get("resources", ())
        if isinstance(raw_resources, tuple):
            for item in raw_resources:
                if not isinstance(item, Mapping):
                    continue
                try:
                    resource = DiscoveredResource.from_dict(item)
                except (TypeError, ValueError):
                    continue
                key = (
                    resource.url,
                    resource.source,
                    resource.status_code,
                )
                resources[key] = resource
        raw_urls = result.artifacts.get("urls", ())
        if isinstance(raw_urls, tuple):
            urls.update(item for item in raw_urls if isinstance(item, str))
    ordered = tuple(
        resources[key]
        for key in sorted(resources, key=lambda item: tuple(str(part) for part in item))
    )
    return ordered, tuple(sorted(urls))


__all__ = [
    "DISCOVERY_SCANNERS",
    "DiscoveryArtifacts",
    "DiscoveryScannerFactory",
    "DiscoveryStage",
    "create_discovery_stage",
]
