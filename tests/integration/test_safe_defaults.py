"""Integration test validating production readiness, safety constraints, and default profile invariants."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContext
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.fingerprint.nmap import NmapScanner
from webvulnscanner.scanners.vulnerability.nuclei import NucleiScanner
from webvulnscanner.scanners.vulnerability.sqlmap import SQLmapScanner
from webvulnscanner.scanners.vulnerability.wpscan import WPScanScanner


@pytest.mark.integration
def test_safe_profile_defaults_and_safety_envelope() -> None:
    """The default profile must strictly enforce safety ceilings and disallow dangerous operations."""
    config = load_config()

    # 1. Profile must be safe
    assert config.profile.name == "safe"
    safety = config.profile.safety

    # 2. Non-negotiable safety flags must be unconditionally False
    assert safety.allow_destructive is False
    assert safety.allow_auth_bypass is False
    assert safety.allow_waf_bypass is False
    assert safety.allow_rate_limit_bypass is False

    # 3. Rate and concurrency limits must be bounded
    assert safety.max_requests_per_second <= 5.0
    assert safety.max_scanners <= 3
    assert config.concurrency.max_scanners <= 3
    assert config.concurrency.max_targets <= 2

    # 4. Fingerprint timing and discovery depth must be conservative
    assert config.fingerprint.timing_template <= 2
    assert config.fingerprint.host_timeout_seconds <= 300
    assert config.discovery.max_recursion_depth == 0  # no deep recursive crawlers by default

    # 5. HTTP timeouts and boundaries
    assert config.http.max_redirects <= 5
    assert config.http.max_response_bytes <= 2_000_000
    assert "WebVulnScanner" in config.http.user_agent


@pytest.mark.integration
def test_scanner_command_generation_uses_non_destructive_options() -> None:
    """Every scanner's command generator must strictly avoid destructive or intrusive flags."""
    config = load_config()
    target = Target("https://example.com/item?id=1")
    context = ScanContext(
        scan_id="20261001-defaults-audit",
        target=target,
        storage_root=Path("runs"),
        profile_name="safe",
        started_at=None,
    )
    mock_runner = AsyncMock()

    # 1. SQLmap
    sqlmap = SQLmapScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_url=target.url,
    )
    sqlmap_cmd = " ".join(sqlmap.build_command().argv)
    assert "--batch" in sqlmap_cmd
    assert "--risk=1" in sqlmap_cmd
    assert "--level=1" in sqlmap_cmd
    for prohibited in SQLmapScanner.PROHIBITED_OPTIONS:
        assert prohibited not in sqlmap_cmd

    # 2. Nmap
    nmap = NmapScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
    )
    nmap_cmd = " ".join(nmap.build_command().argv)
    assert "-sV" in nmap_cmd
    assert "--version-light" in nmap_cmd
    assert "-Pn" in nmap_cmd
    assert "--script" not in nmap_cmd

    # 3. WPScan
    wpscan = WPScanScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_url=target.url,
    )
    wpscan_cmd = " ".join(wpscan.build_command().argv)
    assert "--no-update" in wpscan_cmd
    assert "--batch" in wpscan_cmd
    assert "--passwords" not in wpscan_cmd

    # 4. Nuclei
    nuclei = NucleiScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target=target,
    )
    nuclei_cmd = " ".join(nuclei.build_command().argv)
    assert "-jsonl" in nuclei_cmd
    assert "-silent" in nuclei_cmd
