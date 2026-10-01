"""Tests for passive reconnaissance stage assembly."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.pipeline import StageStatus
from webvulnscanner.models.scan_result import (
    ScanError,
    ScanResult,
    ScannerStatus,
)
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive import (
    PASSIVE_SCANNERS,
    PassiveArtifacts,
    PassiveReconStage,
)


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def result(
    name: str,
    status: ScannerStatus = ScannerStatus.SUCCESS,
    *,
    artifacts: dict[str, object] | None = None,
) -> ScanResult:
    if status is ScannerStatus.SKIPPED:
        return ScanResult(
            scanner=name,
            status=status,
            started_at=NOW,
            completed_at=NOW,
            skip_reason="disabled",
        )
    errors = (
        ()
        if status is ScannerStatus.SUCCESS
        else (ScanError(code="missing_tool", message=f"{name} unavailable"),)
    )
    return ScanResult(
        scanner=name,
        status=status,
        started_at=NOW,
        completed_at=NOW,
        errors=errors,
        artifacts={} if artifacts is None else artifacts,
    )


class FakeScanner:
    def __init__(self, scan_result: ScanResult) -> None:
        self.name = scan_result.scanner
        self.scan_result = scan_result

    async def run(self) -> ScanResult:
        return self.scan_result


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


def test_mixed_results_are_retained_and_artifacts_are_merged(
    tmp_path: Path,
) -> None:
    outputs = {
        "headers": result("headers"),
        "robots": result("robots"),
        "whois": result("whois", ScannerStatus.FAILED),
        "wayback": result(
            "wayback",
            artifacts={
                "urls": (
                    "https://example.com/a",
                    "https://example.com/shared",
                ),
                "query_urls": ("https://example.com/a?q=1",),
            },
        ),
        "subfinder": result(
            "subfinder",
            artifacts={"hosts": ("api.example.com", "www.example.com")},
        ),
    }
    factories = {
        name: (lambda scan_context, item=item: FakeScanner(item))
        for name, item in outputs.items()
    }
    stage = PassiveReconStage(
        configuration=load_config(),
        scanner_factories=factories,
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), {}))

    assert outcome.status is StageStatus.SUCCESS
    artifacts = outcome.artifacts["passive"]
    assert isinstance(artifacts, PassiveArtifacts)
    assert artifacts.urls == (
        "https://example.com/a",
        "https://example.com/shared",
    )
    assert artifacts.query_urls == ("https://example.com/a?q=1",)
    assert artifacts.hosts == ("api.example.com", "www.example.com")
    assert [item.scanner for item in artifacts.scanner_results] == list(
        PASSIVE_SCANNERS
    )
    assert artifacts.scanner_results[2].status is ScannerStatus.FAILED


def test_disabled_scanners_are_not_constructed_and_are_retained_as_skipped(
    tmp_path: Path,
) -> None:
    created: list[str] = []

    def factory(name: str):
        def create(scan_context: Any) -> FakeScanner:
            created.append(name)
            return FakeScanner(result(name))

        return create

    configuration = load_config(
        overrides={
            "scanners": {
                "robots": {"enabled": False},
                "whois": {"enabled": False},
            }
        }
    )
    stage = PassiveReconStage(
        configuration=configuration,
        scanner_factories={name: factory(name) for name in PASSIVE_SCANNERS},
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), {}))
    artifacts = outcome.artifacts["passive"]
    assert isinstance(artifacts, PassiveArtifacts)

    assert "robots" not in created
    assert "whois" not in created
    statuses = {
        item.scanner: item.status for item in artifacts.scanner_results
    }
    assert statuses["robots"] is ScannerStatus.SKIPPED
    assert statuses["whois"] is ScannerStatus.SKIPPED


def test_missing_optional_factory_does_not_prevent_other_scanners(
    tmp_path: Path,
) -> None:
    factories = {
        name: (lambda scan_context, name=name: FakeScanner(result(name)))
        for name in PASSIVE_SCANNERS
        if name != "subfinder"
    }
    stage = PassiveReconStage(
        configuration=load_config(),
        scanner_factories=factories,
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), {}))
    artifacts = outcome.artifacts["passive"]
    assert isinstance(artifacts, PassiveArtifacts)

    assert outcome.status is StageStatus.SUCCESS
    subfinder = next(
        item
        for item in artifacts.scanner_results
        if item.scanner == "subfinder"
    )
    assert subfinder.status is ScannerStatus.FAILED
    assert any(
        item.status is ScannerStatus.SUCCESS
        for item in artifacts.scanner_results
    )


def test_all_enabled_failures_fail_the_stage(tmp_path: Path) -> None:
    factories = {
        name: (
            lambda scan_context, name=name: FakeScanner(
                result(name, ScannerStatus.FAILED)
            )
        )
        for name in PASSIVE_SCANNERS
    }
    stage = PassiveReconStage(
        configuration=load_config(),
        scanner_factories=factories,
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), {}))

    assert outcome.status is StageStatus.FAILED
    assert len(outcome.errors) == len(PASSIVE_SCANNERS)


def test_scheduler_enforces_configured_passive_concurrency(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        active = 0
        maximum = 0
        release = asyncio.Event()
        two_started = asyncio.Event()

        class BlockingScanner:
            def __init__(self, name: str) -> None:
                self.name = name

            async def run(self) -> ScanResult:
                nonlocal active, maximum
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    two_started.set()
                try:
                    await release.wait()
                    return result(self.name)
                finally:
                    active -= 1

        configuration = load_config(
            overrides={"concurrency": {"max_scanners": 2}}
        )
        stage = PassiveReconStage(
            configuration=configuration,
            scanner_factories={
                name: (
                    lambda scan_context, name=name: BlockingScanner(name)
                )
                for name in PASSIVE_SCANNERS
            },
            time_provider=lambda: NOW,
        )
        task = asyncio.create_task(stage.run(context(tmp_path), {}))
        await asyncio.wait_for(two_started.wait(), timeout=1)
        assert active == 2
        release.set()
        outcome = await task

        assert outcome.status is StageStatus.SUCCESS
        assert maximum == 2
        assert stage.scheduler.max_observed_concurrency == 2

    asyncio.run(scenario())
