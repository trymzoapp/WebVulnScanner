"""Unit tests for routing decisions and routing rules."""

import pytest

from webvulnscanner.models.scan_result import RoutingDecision
from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology
from webvulnscanner.routing.rules import (
    ConfigurationOverrideRule,
    HttpServiceRule,
    QueryUrlRule,
    RoutingContext,
    WordPressTechnologyRule,
)


def test_routing_decision_valid() -> None:
    decision = RoutingDecision(
        scanner="wpscan",
        enabled=True,
        reason="WordPress detected",
        source="technology",
        rule_id="rule_wordpress_technology",
        matched_evidence=("WordPress 6.2",),
    )
    assert decision.scanner == "wpscan"
    assert decision.enabled is True
    assert decision.reason == "WordPress detected"
    assert decision.source == "technology"
    assert decision.rule_id == "rule_wordpress_technology"
    assert decision.matched_evidence == ("WordPress 6.2",)


def test_routing_decision_validation_errors() -> None:
    with pytest.raises(ValueError, match="scanner must be a non-empty string"):
        RoutingDecision(
            scanner="",
            enabled=True,
            reason="reason",
            source="source",
            rule_id="rule_id",
        )

    with pytest.raises(TypeError, match="enabled must be a boolean"):
        RoutingDecision(
            scanner="wpscan",
            enabled="true",  # type: ignore[arg-type]
            reason="reason",
            source="source",
            rule_id="rule_id",
        )

    with pytest.raises(ValueError, match="reason must be a non-empty string"):
        RoutingDecision(
            scanner="wpscan",
            enabled=True,
            reason="  ",
            source="source",
            rule_id="rule_id",
        )


def test_routing_decision_serialization_roundtrip() -> None:
    decision = RoutingDecision(
        scanner="sqlmap",
        enabled=True,
        reason="Query URLs found",
        source="query_urls",
        rule_id="rule_query_urls_sqlmap",
        matched_evidence=("https://example.com/item?id=1",),
    )
    serialized = decision.to_dict()
    assert serialized == {
        "scanner": "sqlmap",
        "enabled": True,
        "reason": "Query URLs found",
        "source": "query_urls",
        "rule_id": "rule_query_urls_sqlmap",
        "matched_evidence": ["https://example.com/item?id=1"],
    }
    deserialized = RoutingDecision.from_dict(serialized)
    assert deserialized == decision


def test_routing_decision_from_dict_invalid() -> None:
    with pytest.raises(ValueError, match="fields do not match"):
        RoutingDecision.from_dict({"scanner": "sqlmap"})

    with pytest.raises(TypeError, match="enabled must be a boolean"):
        RoutingDecision.from_dict(
            {
                "scanner": "sqlmap",
                "enabled": 1,
                "reason": "reason",
                "source": "source",
                "rule_id": "rule_id",
                "matched_evidence": [],
            }
        )


def test_routing_context_validation() -> None:
    with pytest.raises(ValueError, match="target_url must be a non-empty string"):
        RoutingContext(target_url="")

    ctx = RoutingContext(target_url="https://example.com")
    assert ctx.target_url == "https://example.com"
    assert ctx.technologies == ()
    assert ctx.services == ()
    assert ctx.urls == ()


def test_configuration_override_rule() -> None:
    rule = ConfigurationOverrideRule("wpscan")
    assert rule.rule_id == "rule_config_override_wpscan"

    # Enabled or default in config -> returns None
    ctx_enabled = RoutingContext(
        target_url="https://example.com",
        scanner_configs={"wpscan": {"enabled": True}},
    )
    assert rule.evaluate(ctx_enabled) is None

    # Disabled in config -> returns RoutingDecision(enabled=False)
    ctx_disabled = RoutingContext(
        target_url="https://example.com",
        scanner_configs={"wpscan": {"enabled": False}},
    )
    decision = rule.evaluate(ctx_disabled)
    assert decision is not None
    assert decision.scanner == "wpscan"
    assert decision.enabled is False
    assert decision.source == "configuration"


def test_wordpress_technology_rule_matched() -> None:
    rule = WordPressTechnologyRule(default_threshold=0.5)
    tech = Technology(
        name="WordPress",
        source="wappalyzer",
        confidence=0.9,
        categories=("CMS",),
    )
    ctx = RoutingContext(
        target_url="https://example.com",
        technologies=(tech,),
    )
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.scanner == "wpscan"
    assert decision.enabled is True
    assert decision.source == "technology"
    assert "meets threshold" in decision.reason


def test_wordpress_technology_rule_low_confidence() -> None:
    rule = WordPressTechnologyRule(default_threshold=0.8)
    tech = Technology(
        name="WordPress",
        source="wappalyzer",
        confidence=0.4,
    )
    ctx = RoutingContext(
        target_url="https://example.com",
        technologies=(tech,),
    )
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.scanner == "wpscan"
    assert decision.enabled is False
    assert "below threshold" in decision.reason


def test_wordpress_technology_rule_no_wordpress() -> None:
    rule = WordPressTechnologyRule()
    tech = Technology(
        name="Nginx",
        source="headers",
        confidence=1.0,
    )
    ctx = RoutingContext(
        target_url="https://example.com",
        technologies=(tech,),
    )
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.scanner == "wpscan"
    assert decision.enabled is False
    assert decision.matched_evidence == ()


def test_http_service_rule() -> None:
    rule = HttpServiceRule("nuclei")
    svc = WebService(
        host="example.com",
        port=443,
        protocol="tcp",
        service="https",
        product=None,
        version=None,
        tunnel=None,
        web_url="https://example.com:443",
    )
    ctx = RoutingContext(
        target_url="https://example.com",
        services=(svc,),
    )
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.scanner == "nuclei"
    assert decision.enabled is True
    assert decision.source == "web_service"
    assert any("https://example.com:443" in ev for ev in decision.matched_evidence)


def test_query_url_rule() -> None:
    rule = QueryUrlRule("sqlmap")
    ctx = RoutingContext(
        target_url="https://example.com/search?q=test&page=1",
        urls=("https://example.com/profile?id=123", "https://example.com/about"),
    )
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.scanner == "sqlmap"
    assert decision.enabled is True
    assert decision.source == "query_urls"
    assert len(decision.matched_evidence) == 2
    assert "https://example.com/search?q=test&page=1" in decision.matched_evidence
    assert "https://example.com/profile?id=123" in decision.matched_evidence


def test_query_url_rule_no_queries() -> None:
    rule = QueryUrlRule("sqlmap")
    ctx = RoutingContext(
        target_url="https://example.com/about",
        urls=("https://example.com/contact",),
    )
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.scanner == "sqlmap"
    assert decision.enabled is False
    assert decision.matched_evidence == ()
