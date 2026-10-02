"""Tests for fingerprint-stage assembly and typed artifact merging."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.pipeline import StageStatus
from webvulnscanner.models.scan_result import (
    ScanError,
    ScannerStatus,
    ScanResult,
)
from webvulnscanner.models.target import Target
from webvulnscanner.models.technology import Technology
from webvulnscanner.scanners.fingerprint import (
    FingerprintArtifacts,
    FingerprintStage,
)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


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


def success(
    name: str,
    *,
    technologies: tuple[Technology, ...] = (),
    artifacts: dict[str, object] | None = None,
) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.SUCCESS,
        started_at=NOW,
        completed_at=NOW,
        technologies=technologies,
        artifacts={} if artifacts is None else artifacts,
    )


def failed(name: str) -> ScanResult:
    return ScanResult(
        scanner=name,
        status=ScannerStatus.FAILED,
        started_at=NOW,
        completed_at=NOW,
        errors=(ScanError(code="missing", message=f"{name} unavailable"),),
    )


def test_merges_technologies_services_and_preserves_provenance(
    tmp_path: Path,
) -> None:
    wordpress_wappalyzer = Technology(
        name="WordPress", source="wappalyzer", confidence=0.95
    )
    wordpress_nmap = Technology(name="WordPress", source="nmap", confidence=0.7)
    service = {
        "host": "example.com",
        "port": 443,
        "protocol": "tcp",
        "service": "http",
        "product": None,
        "version": None,
        "tunnel": "ssl",
        "web_url": "https://example.com/",
    }
    outputs = {
        "wappalyzer": success("wappalyzer", technologies=(wordpress_wappalyzer,)),
        "nmap": success(
            "nmap",
            technologies=(wordpress_nmap,),
            artifacts={
                "services": (service,),
                "web_services": (service,),
                "urls": ("https://example.com/",),
            },
        ),
    }
    stage = FingerprintStage(
        configuration=load_config(),
        scanner_factories={
            name: (lambda scan_context, item=item: FakeScanner(item))
            for name, item in outputs.items()
        },
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), {}))

    assert outcome.status is StageStatus.SUCCESS
    artifacts = outcome.artifacts["fingerprint"]
    assert isinstance(artifacts, FingerprintArtifacts)
    assert [item.source for item in artifacts.technologies] == [
        "nmap",
        "wappalyzer",
    ]
    assert tuple(item.to_dict() for item in artifacts.web_services) == (service,)
    assert artifacts.urls == ("https://example.com/",)


def test_disabled_scanner_is_retained_without_construction(tmp_path: Path) -> None:
    created: list[str] = []

    def factory(name: str):
        def create(scan_context: object) -> FakeScanner:
            created.append(name)
            return FakeScanner(success(name))

        return create

    stage = FingerprintStage(
        configuration=load_config(
            overrides={"scanners": {"wappalyzer": {"enabled": False}}}
        ),
        scanner_factories={
            "wappalyzer": factory("wappalyzer"),
            "nmap": factory("nmap"),
        },
        time_provider=lambda: NOW,
    )

    outcome = asyncio.run(stage.run(context(tmp_path), {}))
    artifacts = outcome.artifacts["fingerprint"]
    assert isinstance(artifacts, FingerprintArtifacts)

    assert created == ["nmap"]
    assert artifacts.scanner_results[0].status is ScannerStatus.SKIPPED
    assert artifacts.scanner_results[1].status is ScannerStatus.SUCCESS


def test_mixed_failure_succeeds_but_all_failures_fail_stage(
    tmp_path: Path,
) -> None:
    mixed = FingerprintStage(
        configuration=load_config(),
        scanner_factories={
            "wappalyzer": lambda scan_context: FakeScanner(failed("wappalyzer")),
            "nmap": lambda scan_context: FakeScanner(success("nmap")),
        },
        time_provider=lambda: NOW,
    )
    assert asyncio.run(mixed.run(context(tmp_path), {})).status is StageStatus.SUCCESS

    all_failed = FingerprintStage(
        configuration=load_config(),
        scanner_factories={
            name: (lambda scan_context, name=name: FakeScanner(failed(name)))
            for name in ("wappalyzer", "nmap")
        },
        time_provider=lambda: NOW,
    )
    assert (
        asyncio.run(all_failed.run(context(tmp_path / "other"), {})).status
        is StageStatus.FAILED
    )
