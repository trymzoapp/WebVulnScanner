"""Passive scanner registration and pipeline-stage assembly."""

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
    ScannerScheduler,
    SchedulableScanner,
)
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.scan_result import (
    ScanError,
    ScannerStatus,
    ScanResult,
)
from webvulnscanner.scanners.passive.headers import (
    HeadersScanner,
    HttpClientProtocol,
)
from webvulnscanner.scanners.passive.robots import RobotsScanner
from webvulnscanner.scanners.passive.subfinder import SubfinderScanner
from webvulnscanner.scanners.passive.wayback import (
    WaybackClientProtocol,
    WaybackScanner,
)
from webvulnscanner.scanners.passive.whois import (
    WhoisClientProtocol,
    WhoisScanner,
)
from webvulnscanner.utils.time import as_utc, utc_now

PASSIVE_SCANNERS = ("headers", "robots", "whois", "wayback", "subfinder")
PassiveScannerFactory = Callable[[ScanContext], SchedulableScanner]


@dataclass(frozen=True, slots=True)
class PassiveArtifacts:
    """Typed passive-stage outputs consumed by later stages."""

    hosts: tuple[str, ...]
    urls: tuple[str, ...]
    query_urls: tuple[str, ...]
    scanner_results: tuple[ScanResult, ...]


class PassiveReconStage:
    """Schedule configured passive scanners and merge typed artifacts."""

    name = StageName.PASSIVE
    dependencies: tuple[StageName, ...] = ()
    failure_policy = FailurePolicy.CONTINUE

    def __init__(
        self,
        *,
        configuration: AppConfig,
        scanner_factories: Mapping[str, PassiveScannerFactory],
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
        runnable_indices: list[int] = []
        for name in PASSIVE_SCANNERS:
            if not self.configuration.scanner(name).enabled:
                slots.append(_skipped_result(name, started_at))
                continue
            factory = self.scanner_factories.get(name)
            if factory is None:
                slots.append(
                    _failed_result(
                        name,
                        started_at,
                        "factory_unavailable",
                        "passive scanner factory is unavailable",
                    )
                )
                continue
            try:
                scanner = factory(context)
            except Exception:
                slots.append(
                    _failed_result(
                        name,
                        started_at,
                        "factory_error",
                        "passive scanner initialization failed",
                    )
                )
                continue
            runnable_indices.append(len(slots))
            runnable.append(scanner)
            slots.append(None)

        scheduled = await self.scheduler.run(runnable)
        for index, result in zip(runnable_indices, scheduled, strict=False):
            slots[index] = result
        results = tuple(result for result in slots if result is not None)
        artifacts = _merge_artifacts(results)

        attempted = [
            result for result in results if result.status is not ScannerStatus.SKIPPED
        ]
        failed = [
            result
            for result in attempted
            if result.status
            in {
                ScannerStatus.FAILED,
                ScannerStatus.TIMED_OUT,
                ScannerStatus.CANCELLED,
            }
        ]
        if attempted and len(failed) == len(attempted):
            errors = tuple(
                error.message for result in failed for error in result.errors
            ) or ("all enabled passive scanners failed",)
            return StageOutcome(
                name=self.name,
                status=StageStatus.FAILED,
                started_at=started_at,
                completed_at=self._now(),
                errors=errors,
                artifacts={"passive": artifacts},
            )
        return StageOutcome(
            name=self.name,
            status=StageStatus.SUCCESS,
            started_at=started_at,
            completed_at=self._now(),
            artifacts={"passive": artifacts},
        )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="passive stage timestamp")


def create_passive_stage(
    *,
    configuration: AppConfig,
    subprocess_runner: AsyncSubprocessRunner,
    headers_client: HttpClientProtocol | None = None,
    robots_client: HttpClientProtocol | None = None,
    whois_client: WhoisClientProtocol | None = None,
    wayback_client: WaybackClientProtocol | None = None,
    time_provider: Callable[[], datetime] = utc_now,
) -> PassiveReconStage:
    """Register concrete passive scanner factories outside the orchestrator."""
    factories: dict[str, PassiveScannerFactory] = {
        "headers": lambda context: HeadersScanner(
            configuration=configuration,
            context=context,
            client=headers_client,
            time_provider=time_provider,
        ),
        "robots": lambda context: RobotsScanner(
            configuration=configuration,
            context=context,
            client=robots_client,
            time_provider=time_provider,
        ),
        "whois": lambda context: WhoisScanner(
            configuration=configuration,
            context=context,
            client=whois_client,
            runner=subprocess_runner,
            time_provider=time_provider,
        ),
        "wayback": lambda context: WaybackScanner(
            configuration=configuration,
            context=context,
            client=wayback_client,
            time_provider=time_provider,
        ),
        "subfinder": lambda context: SubfinderScanner(
            configuration=configuration,
            runner=subprocess_runner,
            context=context,
            time_provider=time_provider,
        ),
    }
    return PassiveReconStage(
        configuration=configuration,
        scanner_factories=factories,
        time_provider=time_provider,
    )


def _merge_artifacts(results: tuple[ScanResult, ...]) -> PassiveArtifacts:
    hosts: set[str] = set()
    urls: set[str] = set()
    query_urls: set[str] = set()
    for result in results:
        hosts.update(_string_artifact(result, "hosts"))
        urls.update(_string_artifact(result, "urls"))
        query_urls.update(_string_artifact(result, "query_urls"))
    return PassiveArtifacts(
        hosts=tuple(sorted(hosts)),
        urls=tuple(sorted(urls)),
        query_urls=tuple(sorted(query_urls)),
        scanner_results=results,
    )


def _string_artifact(result: ScanResult, key: str) -> tuple[str, ...]:
    value = result.artifacts.get(key, ())
    if not isinstance(value, tuple):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _skipped_result(name: str, now: datetime) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.SKIPPED,
        started_at=now,
        completed_at=now,
        skip_reason="scanner is disabled by configuration",
    )


def _failed_result(
    name: str,
    now: datetime,
    code: str,
    message: str,
) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.FAILED,
        started_at=now,
        completed_at=now,
        errors=(ScanError(code=code, message=message),),
    )


__all__ = [
    "PASSIVE_SCANNERS",
    "PassiveArtifacts",
    "PassiveReconStage",
    "PassiveScannerFactory",
    "create_passive_stage",
]
