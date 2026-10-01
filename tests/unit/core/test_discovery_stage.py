"""Tests for routed discovery-stage assembly."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.pipeline import StageName, StageOutcome, StageStatus
from webvulnscanner.models.scan_result import (
    ScanError,
    ScanResult,
    ScannerStatus,
)
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.discovery import (
    DiscoveryArtifacts,
    DiscoveryStage,
)
from webvulnscanner.scanners.fingerprint import FingerprintArtifacts


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class FakeScanner:
    def __init__(self, result: ScanResult) -> None:
        self.name = result.scanner
        self.result = result

    async def run(self) -> ScanResult:
        return self.result


def context(tmp_path: Path):
    return ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("example.com"),
        profile_name="safe",
        scanner_configuration={},
    )


def previous(*urls: str) -> dict[StageName, StageOutcome]:
    artifacts = FingerprintArtifacts(
        technologies=(),
        services=(),
        web_services=(),
        urls=tuple(urls),
        scanner_results=(),
    )
    return {
        StageName.FINGERPRINT: StageOutcome(
            name=StageName.FINGERPRINT,
            status=StageStatus.SUCCESS,
            started_at=NOW,
            completed_at=NOW,
            artifacts={"fingerprint": artifacts},
        )
    }


def result(
    name: str,
    url: str,
    *,
    status: ScannerStatus = ScannerStatus.SUCCESS,
) -> ScanResult:
    if status is not ScannerStatus.SUCCESS:
        return ScanResult(
            scanner=name,
            status=status,
            started_at=NOW,
            completed_at=NOW,
            errors=(ScanError(code="failed", message=f"{name} failed"),),
        )
    resource = {
        "url": f"{url.rstrip('/')}/admin",
        "status_code": 200,
        "source": name,
        "content_length": 10,
    }
    return ScanResult(
        scanner=name,
        status=status,
        started_at=NOW,
        completed_at=NOW,
        artifacts={
            "resources": (resource,),
            "urls": (resource["url"],),
        },
    )


def configuration(*, gobuster: bool = True, dirsearch: bool = True):
    return load_config(
        overrides={
            "scanners": {
                "gobuster": {"enabled": gobuster},
                "dirsearch": {"enabled": dirsearch},
            }
        }
    )


def test_no_confirmed_service_skips_without_constructing_scanners(
    tmp_path: Path,
) -> None:
    called = False

    def forbidden(*args: object) -> FakeScanner:
        nonlocal called
        called = True
        raise AssertionError

    stage = DiscoveryStage(
        configuration=configuration(),
        scanner_factories={"gobuster": forbidden, "dirsearch": forbidden},
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), previous()))

    assert outcome.status is StageStatus.SKIPPED
    assert called is False


def test_deduplicates_targets_honors_tool_disable_and_persists_summary(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, str, str]] = []

    def factory(name: str):
        def create(scan_context: object, url: str, output: str) -> FakeScanner:
            calls.append((name, url, output))
            return FakeScanner(result(name, url))

        return create

    stage = DiscoveryStage(
        configuration=configuration(gobuster=True, dirsearch=False),
        scanner_factories={
            "gobuster": factory("gobuster"),
            "dirsearch": factory("dirsearch"),
        },
        time_provider=lambda: NOW,
    )
    scan_context = context(tmp_path)

    outcome = asyncio.run(
        stage.run(
            scan_context,
            previous(
                "https://example.com/",
                "https://example.com/",
                "https://outside.example/",
            ),
        )
    )

    assert outcome.status is StageStatus.SUCCESS
    assert len(calls) == 1
    assert calls[0][0:2] == ("gobuster", "https://example.com/")
    assert calls[0][2].startswith("gobuster-")
    artifacts = outcome.artifacts["discovery"]
    assert isinstance(artifacts, DiscoveryArtifacts)
    assert artifacts.urls == ("https://example.com/admin",)
    payload = json.loads(
        (
            scan_context.stage_directory("discovery") / "gobuster.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["targets"] == ["https://example.com/"]


def test_partial_failure_retains_success_and_all_failures_fail(
    tmp_path: Path,
) -> None:
    stage = DiscoveryStage(
        configuration=configuration(),
        scanner_factories={
            "gobuster": (
                lambda scan_context, url, output: FakeScanner(
                    result("gobuster", url, status=ScannerStatus.FAILED)
                )
            ),
            "dirsearch": (
                lambda scan_context, url, output: FakeScanner(
                    result("dirsearch", url)
                )
            ),
        },
        time_provider=lambda: NOW,
    )
    outcome = asyncio.run(
        stage.run(context(tmp_path), previous("https://example.com/"))
    )
    assert outcome.status is StageStatus.SUCCESS

    all_failed = DiscoveryStage(
        configuration=configuration(),
        scanner_factories={
            name: (
                lambda scan_context, url, output, name=name: FakeScanner(
                    result(name, url, status=ScannerStatus.FAILED)
                )
            )
            for name in ("gobuster", "dirsearch")
        },
        time_provider=lambda: NOW,
    )
    failed_outcome = asyncio.run(
        all_failed.run(
            context(tmp_path / "failed"),
            previous("https://example.com/"),
        )
    )
    assert failed_outcome.status is StageStatus.FAILED


def test_global_concurrency_limit_is_enforced(tmp_path: Path) -> None:
    async def scenario() -> None:
        active = 0
        maximum = 0
        release = asyncio.Event()
        two_started = asyncio.Event()

        class BlockingScanner:
            def __init__(self, name: str, url: str) -> None:
                self.name = name
                self.url = url

            async def run(self) -> ScanResult:
                nonlocal active, maximum
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    two_started.set()
                try:
                    await release.wait()
                    return result(self.name, self.url)
                finally:
                    active -= 1

        stage = DiscoveryStage(
            configuration=load_config(
                overrides={
                    "concurrency": {"max_scanners": 2},
                    "scanners": {
                        "gobuster": {"enabled": True},
                        "dirsearch": {"enabled": True},
                    },
                }
            ),
            scanner_factories={
                name: (
                    lambda scan_context, url, output, name=name: BlockingScanner(
                        name, url
                    )
                )
                for name in ("gobuster", "dirsearch")
            },
            time_provider=lambda: NOW,
        )
        task = asyncio.create_task(
            stage.run(
                context(tmp_path),
                previous(
                    "http://example.com/",
                    "https://example.com/",
                ),
            )
        )
        await asyncio.wait_for(two_started.wait(), timeout=1)
        assert active == 2
        release.set()
        outcome = await task
        assert outcome.status is StageStatus.SUCCESS
        assert maximum == 2
        assert stage.scheduler.max_observed_concurrency == 2

    asyncio.run(scenario())
