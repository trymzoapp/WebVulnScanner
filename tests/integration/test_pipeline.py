"""Offline end-to-end integration tests for the complete web vulnerability scanner pipeline."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Generator

import pytest
import yaml

from webvulnscanner.cli import (
    EXIT_FINDINGS_FOUND,
    EXIT_PARTIAL_COMPLETION,
    EXIT_SUCCESS,
    main,
)
from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.orchestrator import Orchestrator
from webvulnscanner.core.pipeline import StageName
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.report import ScanStatus
from webvulnscanner.models.target import Target
from webvulnscanner.cli import _build_pipeline
from tests.fixtures.http import FixtureServer
from tests.fixtures.tools import get_fake_tool_path


@pytest.fixture
def http_server() -> Generator[FixtureServer, None, None]:
    """Provide a running local fixture HTTP server."""
    with FixtureServer(host="127.0.0.1") as server:
        yield server


@pytest.fixture(autouse=True)
def mock_offline_wayback(
    monkeypatch: pytest.MonkeyPatch,
    http_server: FixtureServer,
) -> None:
    """Ensure Wayback collection is offline and deterministic."""
    async def mock_fetch(
        self: object,
        *,
        endpoint: str,
        domain: str,
        page: int,
        page_size: int,
        timeout: float,
        max_response_bytes: int,
    ) -> tuple[str, ...]:
        return (
            f"http://localhost:{http_server.port}/search?q=test",
            f"http://localhost:{http_server.port}/items?id=42",
        )

    monkeypatch.setattr(
        "webvulnscanner.scanners.passive.wayback.HttpxWaybackClient.fetch_page",
        mock_fetch,
    )


def create_pipeline_config(
    tmp_path: Path,
    server: FixtureServer,
    *,
    storage_root: Path,
    sqlmap_timeout: int = 30,
) -> Path:
    wordlist_path = tmp_path / "wordlist.txt"
    wordlist_path.write_text("admin\nlogin\ndashboard\n", encoding="utf-8")

    config_dict = {
        "timeouts": {
            "default": 30,
            "sqlmap": sqlmap_timeout,
        },
        "storage": {
            "root": str(storage_root),
        },
        "wayback": {
            "endpoint": "https://web.archive.org/cdx/search/cdx",
            "max_records": 500,
            "page_size": 100,
        },
        "fingerprint": {
            "ports": [server.port],
            "timing_template": 2,
            "host_timeout_seconds": 30,
        },
        "discovery": {
            "status_codes": [200, 301, 302],
            "dirsearch_extensions": ["html", "php"],
            "max_recursion_depth": 0,
        },
        "reports": {
            "json": True,
            "markdown": True,
            "html": True,
        },
        "scanners": {
            "headers": {
                "enabled": True,
                "executable": None,
                "wordlist": None,
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "robots": {
                "enabled": True,
                "executable": None,
                "wordlist": None,
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "whois": {
                "enabled": True,
                "executable": get_fake_tool_path("whois"),
                "wordlist": None,
                "concurrency": 1,
                "rate_limit_per_second": 1.0,
            },
            "wayback": {
                "enabled": True,
                "executable": None,
                "wordlist": None,
                "concurrency": 1,
                "rate_limit_per_second": 2.0,
            },
            "subfinder": {
                "enabled": True,
                "executable": get_fake_tool_path("subfinder"),
                "wordlist": None,
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "wappalyzer": {
                "enabled": True,
                "executable": get_fake_tool_path("wappalyzer"),
                "wordlist": None,
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "nmap": {
                "enabled": True,
                "executable": get_fake_tool_path("nmap"),
                "wordlist": None,
                "concurrency": 1,
                "rate_limit_per_second": 2.0,
            },
            "gobuster": {
                "enabled": True,
                "executable": get_fake_tool_path("gobuster"),
                "wordlist": str(wordlist_path),
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "dirsearch": {
                "enabled": True,
                "executable": get_fake_tool_path("dirsearch"),
                "wordlist": str(wordlist_path),
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "nuclei": {
                "enabled": True,
                "executable": get_fake_tool_path("nuclei"),
                "wordlist": None,
                "concurrency": 2,
                "rate_limit_per_second": 5.0,
            },
            "sqlmap": {
                "enabled": True,
                "executable": get_fake_tool_path("sqlmap"),
                "wordlist": None,
                "concurrency": 1,
                "rate_limit_per_second": 1.0,
            },
            "wpscan": {
                "enabled": True,
                "executable": get_fake_tool_path("wpscan"),
                "wordlist": None,
                "concurrency": 1,
                "rate_limit_per_second": 1.0,
            },
        },
    }

    config_path = tmp_path / "test_pipeline_config.yaml"
    config_path.write_text(yaml.safe_dump(config_dict), encoding="utf-8")
    return config_path


@pytest.mark.integration
def test_end_to_end_pipeline_success(
    tmp_path: Path,
    http_server: FixtureServer,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify full end-to-end scan pipeline across all stages and artifacts."""
    storage_root = tmp_path / "scan_storage"
    monkeypatch.setenv("FAKE_TOOL_PORT", str(http_server.port))
    monkeypatch.delenv("FAKE_TOOLS_FAIL", raising=False)
    monkeypatch.delenv("FAKE_TOOLS_TIMEOUT", raising=False)

    config_path = create_pipeline_config(tmp_path, http_server, storage_root=storage_root)
    target_url = f"http://localhost:{http_server.port}"

    exit_code = main(
        [
            "scan",
            target_url,
            "--confirm-authorized",
            "--config",
            str(config_path),
            "--storage-root",
            str(storage_root),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == EXIT_FINDINGS_FOUND

    summary = json.loads(captured.out)
    assert summary["status"] == "completed"
    assert summary["target_url"] == f"http://localhost:{http_server.port}/"
    assert summary["normalized_domain"] == "localhost"
    assert summary["scan_id"]
    assert summary["stages"] == {
        "passive": "success",
        "fingerprint": "success",
        "routing": "success",
        "discovery": "success",
        "vulnerability": "success",
        "report": "success",
    }
    assert summary["errors"] == []
    assert summary["severity_counts"]["total"] > 0
    assert summary["severity_counts"]["high"] > 0

    scan_dir = Path(summary["scan_directory"])
    assert scan_dir.is_relative_to(storage_root)
    assert (scan_dir / "metadata.json").is_file()
    assert (scan_dir / "target.json").is_file()

    # Passive stage artifacts
    assert (scan_dir / "passive" / "headers.json").is_file()
    assert (scan_dir / "passive" / "robots.json").is_file()
    assert (scan_dir / "passive" / "whois.json").is_file()
    assert (scan_dir / "passive" / "wayback.json").is_file()
    assert (scan_dir / "passive" / "subfinder.json").is_file()

    # Fingerprint stage artifacts
    assert (scan_dir / "fingerprint" / "wappalyzer.json").is_file()
    assert (scan_dir / "fingerprint" / "nmap.json").is_file()

    # Dynamic routing artifacts
    assert (scan_dir / "routing.json").is_file()
    routing_data = json.loads((scan_dir / "routing.json").read_text(encoding="utf-8"))
    assert isinstance(routing_data, list)
    enabled_scanners = [d["scanner"] for d in routing_data if d.get("enabled")]
    assert "nuclei" in enabled_scanners
    assert "wpscan" in enabled_scanners
    assert "sqlmap" in enabled_scanners

    # Discovery stage artifacts
    assert (scan_dir / "discovery" / "gobuster.json").is_file()
    assert (scan_dir / "discovery" / "dirsearch.json").is_file()

    # Vulnerability stage artifacts
    assert (scan_dir / "vulnerability" / "nuclei.jsonl").is_file()
    assert (scan_dir / "vulnerability" / "sqlmap.json").is_file()
    assert (scan_dir / "vulnerability" / "wpscan.json").is_file()

    # Report stage artifacts
    findings_path = scan_dir / "reports" / "findings.json"
    markdown_path = scan_dir / "reports" / "report.md"
    html_path = scan_dir / "reports" / "report.html"

    assert findings_path.is_file()
    assert markdown_path.is_file()
    assert html_path.is_file()

    findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
    assert findings_data["schema_version"] == "1.0"
    assert len(findings_data["findings"]) > 0

    markdown_content = markdown_path.read_text(encoding="utf-8")
    assert "Web Vulnerability Assessment Report" in markdown_content
    assert "Findings" in markdown_content

    html_content = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "WebVulnScanner" in html_content

    # Latest scan pointer update
    latest_pointer = storage_root / "localhost" / "latest.json"
    assert latest_pointer.is_file()
    latest_data = json.loads(latest_pointer.read_text(encoding="utf-8"))
    assert latest_data["scan_id"] == summary["scan_id"]
    assert latest_data["status"] == "completed"


@pytest.mark.integration
def test_end_to_end_pipeline_partial_failure(
    tmp_path: Path,
    http_server: FixtureServer,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify failure isolation when external tools encounter nonzero exits."""
    storage_root = tmp_path / "scan_storage"
    monkeypatch.setenv("FAKE_TOOL_PORT", str(http_server.port))
    monkeypatch.setenv("FAKE_TOOLS_FAIL", "wappalyzer,nmap")
    monkeypatch.delenv("FAKE_TOOLS_TIMEOUT", raising=False)

    config_path = create_pipeline_config(tmp_path, http_server, storage_root=storage_root)
    target_url = f"http://localhost:{http_server.port}"

    exit_code = main(
        [
            "scan",
            target_url,
            "--confirm-authorized",
            "--config",
            str(config_path),
            "--storage-root",
            str(storage_root),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code in (EXIT_PARTIAL_COMPLETION, EXIT_FINDINGS_FOUND)

    summary = json.loads(captured.out)
    assert summary["status"] == "partial"
    assert len(summary["errors"]) > 0

    scan_dir = Path(summary["scan_directory"])
    # Peer passive tools still generated artifacts
    assert (scan_dir / "passive" / "headers.json").is_file()
    assert (scan_dir / "passive" / "robots.json").is_file()
    assert (scan_dir / "passive" / "wayback.json").is_file()
    assert (scan_dir / "passive" / "subfinder.json").is_file()

    # Reports still generated
    assert (scan_dir / "reports" / "findings.json").is_file()
    assert (scan_dir / "reports" / "report.md").is_file()
    assert (scan_dir / "reports" / "report.html").is_file()

    # Latest pointer is only created for completed scans
    latest_pointer = storage_root / "localhost" / "latest.json"
    assert not latest_pointer.exists()


@pytest.mark.integration
def test_end_to_end_pipeline_partial_discovery_failure(
    tmp_path: Path,
    http_server: FixtureServer,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify tool failures in discovery isolate cleanly and yield partial scan results."""
    storage_root = tmp_path / "scan_storage"
    monkeypatch.setenv("FAKE_TOOL_PORT", str(http_server.port))
    monkeypatch.setenv("FAKE_TOOLS_FAIL", "gobuster,dirsearch")
    monkeypatch.delenv("FAKE_TOOLS_TIMEOUT", raising=False)

    config_path = create_pipeline_config(tmp_path, http_server, storage_root=storage_root)
    target_url = f"http://localhost:{http_server.port}"

    exit_code = main(
        [
            "scan",
            target_url,
            "--confirm-authorized",
            "--config",
            str(config_path),
            "--storage-root",
            str(storage_root),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code in (EXIT_PARTIAL_COMPLETION, EXIT_FINDINGS_FOUND)

    summary = json.loads(captured.out)
    assert summary["status"] == "partial"
    assert summary["stages"]["discovery"] == "failed"
    assert len(summary["errors"]) > 0


@pytest.mark.integration
@pytest.mark.anyio
async def test_end_to_end_direct_orchestrator(
    tmp_path: Path,
    http_server: FixtureServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify direct programmatic Orchestrator execution with all stages."""
    storage_root = tmp_path / "scan_storage"
    monkeypatch.setenv("FAKE_TOOL_PORT", str(http_server.port))
    monkeypatch.delenv("FAKE_TOOLS_FAIL", raising=False)
    monkeypatch.delenv("FAKE_TOOLS_TIMEOUT", raising=False)

    config_path = create_pipeline_config(tmp_path, http_server, storage_root=storage_root)
    config = load_config(user_config=config_path)

    runner = AsyncSubprocessRunner(
        max_concurrency=config.concurrency.max_scanners,
        default_timeout=config.timeouts.default,
        max_output_bytes=config.http.max_response_bytes,
    )
    pipeline = _build_pipeline(config, runner)
    orchestrator = Orchestrator(
        configuration=config,
        context_factory=ScanContextFactory(storage_root),
        pipeline=pipeline,
    )

    target = Target(f"http://localhost:{http_server.port}")
    result = await orchestrator.run(target)

    assert result.status is ScanStatus.COMPLETED
    assert result.pipeline is not None
    assert len(result.pipeline.outcomes) == 6
    for outcome in result.pipeline.outcomes:
        assert outcome.status.value in ("success", "skipped")
