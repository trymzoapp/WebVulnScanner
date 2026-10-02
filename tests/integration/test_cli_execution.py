"""Offline integration tests for CLI reconnaissance execution and persistence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from webvulnscanner.cli import EXIT_INVALID_INPUT, EXIT_SUCCESS, PipelineFactory, main
from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.pipeline import Pipeline
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.scan_result import ScannerStatus, ScanResult
from webvulnscanner.models.technology import Technology
from webvulnscanner.scanners.discovery import DiscoveryStage
from webvulnscanner.scanners.fingerprint import FingerprintStage
from webvulnscanner.scanners.passive import PassiveReconStage
from webvulnscanner.utils.filesystem import atomic_write_json

NOW = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)


class ArtifactScanner:
    """Test scanner that persists a deterministic artifact without I/O."""

    def __init__(
        self,
        *,
        name: str,
        context: ScanContext,
        stage: str,
        filename: str,
        artifacts: Mapping[str, object] | None = None,
        technologies: tuple[Technology, ...] = (),
        fail: bool = False,
    ) -> None:
        self.name = name
        self.context = context
        self.stage = stage
        self.filename = filename
        self.artifacts = {} if artifacts is None else artifacts
        self.technologies = technologies
        self.fail = fail

    async def run(self) -> ScanResult:
        if self.fail:
            raise RuntimeError("isolated test scanner failure")
        output = atomic_write_json(
            self.context.stage_directory(self.stage) / self.filename,
            {"scanner": self.name, "fixture": True},
            storage_root=self.context.storage_root,
            overwrite=False,
        )
        return ScanResult(
            scanner=self.name,
            status=ScannerStatus.SUCCESS,
            started_at=NOW,
            completed_at=NOW,
            output_paths=(output.relative_to(self.context.scan_directory).as_posix(),),
            technologies=self.technologies,
            artifacts=self.artifacts,
        )


def write_execution_config(tmp_path: Path) -> Path:
    config = tmp_path / "execution.yaml"
    config.write_text(
        """
scanners:
  gobuster:
    enabled: true
    wordlist: "unused-test-wordlist.txt"
  dirsearch:
    enabled: true
    wordlist: "unused-test-wordlist.txt"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config


def pipeline_factory(*, fail_subfinder: bool = False) -> PipelineFactory:
    def build(
        configuration: AppConfig,
        runner: AsyncSubprocessRunner,
    ) -> Pipeline:
        del runner
        passive_names = ("headers", "robots", "whois", "wayback", "subfinder")
        passive = PassiveReconStage(
            configuration=configuration,
            scanner_factories={
                name: (
                    lambda context, name=name: ArtifactScanner(
                        name=name,
                        context=context,
                        stage="passive",
                        filename=f"{name}.json",
                        artifacts=(
                            {"hosts": ("api.example.com",)}
                            if name == "subfinder"
                            else {}
                        ),
                        fail=fail_subfinder and name == "subfinder",
                    )
                )
                for name in passive_names
            },
            time_provider=lambda: NOW,
        )
        service = {
            "host": "example.com",
            "port": 443,
            "protocol": "tcp",
            "service": "http",
            "product": "fixture-server",
            "version": "1",
            "tunnel": "ssl",
            "web_url": "https://example.com/",
        }
        fingerprint = FingerprintStage(
            configuration=configuration,
            scanner_factories={
                "wappalyzer": lambda context: ArtifactScanner(
                    name="wappalyzer",
                    context=context,
                    stage="fingerprint",
                    filename="wappalyzer.json",
                    technologies=(
                        Technology(
                            name="Fixture CMS",
                            source="wappalyzer",
                            confidence=1.0,
                        ),
                    ),
                ),
                "nmap": lambda context: ArtifactScanner(
                    name="nmap",
                    context=context,
                    stage="fingerprint",
                    filename="nmap.json",
                    artifacts={
                        "services": (service,),
                        "web_services": (service,),
                        "urls": ("https://example.com/",),
                    },
                ),
            },
            time_provider=lambda: NOW,
        )

        def discovery_factory(name: str):
            def create(
                context: ScanContext,
                target_url: str,
                output_name: str,
            ) -> ArtifactScanner:
                resource_url = f"{target_url.rstrip('/')}/admin"
                return ArtifactScanner(
                    name=name,
                    context=context,
                    stage="discovery",
                    filename=output_name,
                    artifacts={
                        "resources": (
                            {
                                "url": resource_url,
                                "status_code": 200,
                                "source": name,
                                "content_length": 10,
                            },
                        ),
                        "urls": (resource_url,),
                    },
                )

            return create

        discovery = DiscoveryStage(
            configuration=configuration,
            scanner_factories={
                "gobuster": discovery_factory("gobuster"),
                "dirsearch": discovery_factory("dirsearch"),
            },
            time_provider=lambda: NOW,
        )
        return Pipeline(
            (passive, fingerprint, discovery),
            time_provider=lambda: NOW,
        )

    return build


@pytest.mark.integration
def test_cli_executes_completed_stages_and_persists_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    storage = tmp_path / "custom-runs"

    exit_code = main(
        [
            "scan",
            "https://example.com",
            "--confirm-authorized",
            "--config",
            str(write_execution_config(tmp_path)),
            "--storage-root",
            str(storage),
        ],
        pipeline_factory=pipeline_factory(),
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_SUCCESS
    assert payload["status"] == "completed"
    assert payload["target_url"] == "https://example.com/"
    assert payload["normalized_domain"] == "example.com"
    assert payload["scan_id"]
    assert payload["stages"] == {
        "passive": "success",
        "fingerprint": "success",
        "discovery": "success",
    }
    assert payload["errors"] == []

    scan_directory = Path(payload["scan_directory"])
    assert scan_directory.is_relative_to(storage)
    metadata = json.loads(
        (scan_directory / "metadata.json").read_text(encoding="utf-8")
    )
    target = json.loads((scan_directory / "target.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "completed"
    assert metadata["completed_at"] is not None
    assert target["url"] == "https://example.com/"
    for filename in (
        "headers.json",
        "robots.json",
        "whois.json",
        "wayback.json",
        "subfinder.json",
    ):
        assert (scan_directory / "passive" / filename).is_file()
    for filename in ("wappalyzer.json", "nmap.json"):
        assert (scan_directory / "fingerprint" / filename).is_file()
    for filename in ("gobuster.json", "dirsearch.json"):
        assert (scan_directory / "discovery" / filename).is_file()


@pytest.mark.integration
def test_scanner_failure_is_isolated_and_peer_artifacts_survive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    storage = tmp_path / "runs"

    exit_code = main(
        [
            "scan",
            "example.com",
            "--confirm-authorized",
            "--config",
            str(write_execution_config(tmp_path)),
            "--storage-root",
            str(storage),
        ],
        pipeline_factory=pipeline_factory(fail_subfinder=True),
    )

    payload = json.loads(capsys.readouterr().out)
    scan_directory = Path(payload["scan_directory"])
    assert exit_code == EXIT_SUCCESS
    assert payload["status"] == "completed"
    assert (scan_directory / "passive" / "headers.json").is_file()
    assert not (scan_directory / "passive" / "subfinder.json").exists()
    assert (scan_directory / "fingerprint" / "nmap.json").is_file()
    assert (scan_directory / "discovery" / "gobuster.json").is_file()


@pytest.mark.integration
def test_invalid_target_creates_no_scan_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    storage = tmp_path / "runs"
    called = False

    def forbidden(
        configuration: AppConfig,
        runner: AsyncSubprocessRunner,
    ) -> Pipeline:
        nonlocal called
        called = True
        raise AssertionError

    exit_code = main(
        ["scan", "../escape", "--storage-root", str(storage)],
        pipeline_factory=forbidden,
    )

    assert exit_code == EXIT_INVALID_INPUT
    assert called is False
    assert not storage.exists()
    assert "error:" in capsys.readouterr().err
