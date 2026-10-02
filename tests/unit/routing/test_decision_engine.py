"""Unit tests for the routing decision engine."""

import pytest

from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology
from webvulnscanner.routing.decision_engine import RoutingDecisionEngine
from webvulnscanner.routing.rules import RoutingContext


def test_engine_default_initialization() -> None:
    engine = RoutingDecisionEngine()
    ctx = RoutingContext(target_url="https://example.com")
    decisions = engine.evaluate(ctx)

    assert len(decisions) == 3
    scanners = [d.scanner for d in decisions]
    assert scanners == ["nuclei", "sqlmap", "wpscan"]

    # nuclei should be enabled due to target_url https fallback
    nuclei_d = next(d for d in decisions if d.scanner == "nuclei")
    assert nuclei_d.enabled is True

    # sqlmap and wpscan should be disabled due to lack of evidence
    sqlmap_d = next(d for d in decisions if d.scanner == "sqlmap")
    assert sqlmap_d.enabled is False

    wpscan_d = next(d for d in decisions if d.scanner == "wpscan")
    assert wpscan_d.enabled is False


def test_engine_config_override_disables_with_evidence() -> None:
    engine = RoutingDecisionEngine()
    tech = Technology(name="WordPress", source="wappalyzer", confidence=1.0)
    ctx = RoutingContext(
        target_url="https://example.com",
        technologies=(tech,),
        scanner_configs={"wpscan": {"enabled": False}},
    )
    decisions = engine.evaluate(ctx)
    wpscan_d = next(d for d in decisions if d.scanner == "wpscan")

    assert wpscan_d.enabled is False
    assert wpscan_d.source == "configuration"
    assert "explicitly disabled" in wpscan_d.reason


def test_engine_wpscan_enabled_with_wordpress() -> None:
    engine = RoutingDecisionEngine()
    tech = Technology(name="WordPress", source="wappalyzer", confidence=0.9)
    ctx = RoutingContext(
        target_url="https://example.com",
        technologies=(tech,),
    )
    decisions = engine.evaluate(ctx)
    wpscan_d = next(d for d in decisions if d.scanner == "wpscan")

    assert wpscan_d.enabled is True
    assert wpscan_d.source == "technology"


def test_engine_sqlmap_enabled_with_query_urls() -> None:
    engine = RoutingDecisionEngine()
    ctx = RoutingContext(
        target_url="https://example.com/item?id=42",
        urls=("https://example.com/search?q=test",),
    )
    decisions = engine.evaluate(ctx)
    sqlmap_d = next(d for d in decisions if d.scanner == "sqlmap")

    assert sqlmap_d.enabled is True
    assert sqlmap_d.source == "query_urls"


def test_engine_nuclei_disabled_for_non_http() -> None:
    engine = RoutingDecisionEngine()
    ctx = RoutingContext(target_url="ftp://example.com")
    decisions = engine.evaluate(ctx)
    nuclei_d = next(d for d in decisions if d.scanner == "nuclei")

    assert nuclei_d.enabled is False
    assert nuclei_d.source == "web_service"


def test_engine_nuclei_enabled_with_service() -> None:
    engine = RoutingDecisionEngine()
    svc = WebService(
        host="example.com",
        port=8080,
        protocol="tcp",
        service="http",
        product=None,
        version=None,
        tunnel=None,
        web_url="http://example.com:8080/",
    )
    ctx = RoutingContext(
        target_url="ftp://example.com",
        services=(svc,),
    )
    decisions = engine.evaluate(ctx)
    nuclei_d = next(d for d in decisions if d.scanner == "nuclei")

    assert nuclei_d.enabled is True
    assert nuclei_d.source == "web_service"


def test_engine_deterministic_output() -> None:
    engine = RoutingDecisionEngine()
    tech = Technology(name="WordPress", source="wappalyzer", confidence=0.9)
    ctx = RoutingContext(
        target_url="https://example.com/page?id=1",
        technologies=(tech,),
    )

    d1 = engine.evaluate(ctx)
    d2 = engine.evaluate(ctx)

    assert d1 == d2
    enabled = engine.get_enabled_scanners(d1)
    assert enabled == ("nuclei", "sqlmap", "wpscan")


def test_engine_invalid_inputs() -> None:
    with pytest.raises(TypeError, match="context must be a RoutingContext"):
        RoutingDecisionEngine().evaluate("invalid")  # type: ignore[arg-type]

    with pytest.raises(
        ValueError, match="target_scanners must contain only non-empty strings"
    ):
        RoutingDecisionEngine(target_scanners=[""])
