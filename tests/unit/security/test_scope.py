"""Unit tests for scope boundaries, subdomain policy, and target revalidation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.models.scan_result import RoutingDecision
from webvulnscanner.models.target import Target
from webvulnscanner.parsers.subfinder import (
    _in_scope as subfinder_in_scope,
)
from webvulnscanner.scanners.passive.wayback import _in_scope as wayback_in_scope
from webvulnscanner.scanners.vulnerability.nuclei import NucleiScanner
from webvulnscanner.scanners.vulnerability.sqlmap import SQLmapScanner
from webvulnscanner.scanners.vulnerability.wpscan import WPScanScanner


def test_in_scope_subdomain_policy() -> None:
    """Subdomain scope check must allow legitimate subdomains and deny suffix lookalikes."""
    domain = "example.com"

    # In scope
    assert subfinder_in_scope("example.com", domain) is True
    assert subfinder_in_scope("sub.example.com", domain) is True
    assert subfinder_in_scope("deep.nested.sub.example.com", domain) is True

    # Suffix collisions and cross-domains must be strictly rejected
    assert subfinder_in_scope("notexample.com", domain) is False
    assert subfinder_in_scope("evilexample.com", domain) is False
    assert subfinder_in_scope("example.com.attacker.com", domain) is False
    assert subfinder_in_scope("attacker.com", domain) is False
    assert subfinder_in_scope("sub.example.org", domain) is False


def test_wayback_in_scope_policy() -> None:
    """Wayback scope check must reject out-of-domain and suffix collisions."""
    domain = "target.test"

    assert wayback_in_scope("target.test", domain) is True
    assert wayback_in_scope("api.target.test", domain) is True

    assert wayback_in_scope("faketarget.test", domain) is False
    assert wayback_in_scope("target.test.evil.com", domain) is False
    assert wayback_in_scope("google.com", domain) is False


@pytest.mark.asyncio
async def test_sqlmap_revalidates_target_within_scope() -> None:
    """SQLmapScanner.validate() must reject target URLs outside authorized context target."""
    config = load_config()
    context_target = Target("https://authorized.example.com")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=context_target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()

    # Out-of-scope target
    out_of_scope_target = "https://unauthorized.evil.com/item?id=1"
    scanner = SQLmapScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_url=out_of_scope_target,
    )

    with pytest.raises(ScannerValidationError, match=r"outside authorized scope"):
        await scanner.validate()


@pytest.mark.asyncio
async def test_wpscan_revalidates_target_within_scope() -> None:
    """WPScanScanner.validate() must reject targets outside authorized host scope."""
    config = load_config()
    context_target = Target("https://authorized.example.com")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=context_target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()
    routing = RoutingDecision(
        scanner="wpscan",
        enabled=True,
        reason="WordPress detected",
        source="wappalyzer",
        rule_id="wp_rule",
    )

    out_of_scope_target = "https://other.domain.com"
    scanner = WPScanScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_url=out_of_scope_target,
        routing_decision=routing,
    )

    with pytest.raises(ScannerValidationError, match=r"outside authorized scope"):
        await scanner.validate()


@pytest.mark.asyncio
async def test_nuclei_revalidates_target_within_scope() -> None:
    """NucleiScanner.validate() must reject targets outside authorized host scope."""
    config = load_config()
    context_target = Target("https://authorized.example.com")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=context_target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()

    out_of_scope_target = "https://other.domain.com"
    scanner = NucleiScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_urls=out_of_scope_target,
    )

    with pytest.raises(ScannerValidationError, match=r"outside authorized scope"):
        await scanner.validate()


def test_idn_and_unicode_lookalike_handling() -> None:
    """IDN characters are converted to ASCII Punycode to prevent homograph attacks."""
    # Cyrillic 'а' in "exаmple.com" vs ASCII 'a'
    # "\u0430" is Cyrillic small letter a
    cyrillic_target = Target("https://ex\u0430mple.com")
    assert cyrillic_target.host.startswith("xn--")
    assert cyrillic_target.host != "example.com"
    assert cyrillic_target.normalized_domain.startswith("xn--")


def test_alternate_port_scope_isolation() -> None:
    """Target URLs with alternate ports are distinct and validated."""
    target_8080 = Target("http://example.com:8080")
    target_80 = Target("http://example.com:80")
    assert target_8080.port == 8080
    assert target_80.port == 80
    assert ":8080" in target_8080.url
    assert ":80" in target_80.url
