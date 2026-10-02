"""Explainable, deterministic dynamic routing rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from urllib.parse import parse_qs, urlparse

from webvulnscanner.models.scan_result import RoutingDecision
from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology


@dataclass(frozen=True, slots=True)
class RoutingContext:
    """Input evidence and configuration for dynamic routing rules."""

    target_url: str
    technologies: tuple[Technology, ...] = ()
    services: tuple[WebService, ...] = ()
    urls: tuple[str, ...] = ()
    scanner_configs: Mapping[str, Mapping[str, Any]] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if not isinstance(self.target_url, str) or not self.target_url.strip():
            raise ValueError("target_url must be a non-empty string")
        if not isinstance(self.technologies, tuple) or any(
            not isinstance(item, Technology) for item in self.technologies
        ):
            raise TypeError("technologies must be a tuple of Technology models")
        if not isinstance(self.services, tuple) or any(
            not isinstance(item, WebService) for item in self.services
        ):
            raise TypeError("services must be a tuple of WebService models")
        if not isinstance(self.urls, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.urls
        ):
            raise TypeError("urls must be a tuple of non-empty strings")
        if not isinstance(self.scanner_configs, Mapping):
            raise TypeError("scanner_configs must be a mapping")


class RoutingRule(ABC):
    """Abstract base class for deterministic scanner selection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Return unique identifier for this rule."""
        ...

    @abstractmethod
    def evaluate(self, context: RoutingContext) -> RoutingDecision | None:
        """Evaluate rule against context evidence."""
        ...


class ConfigurationOverrideRule(RoutingRule):
    """Rule that explicitly disables a scanner if configuration disables it."""

    def __init__(self, scanner: str) -> None:
        if not isinstance(scanner, str) or not scanner.strip():
            raise ValueError("scanner must be a non-empty string")
        self._scanner = scanner.strip()

    @property
    def rule_id(self) -> str:
        return f"rule_config_override_{self._scanner}"

    def evaluate(self, context: RoutingContext) -> RoutingDecision | None:
        scanner_cfg = context.scanner_configs.get(self._scanner, {})
        if isinstance(scanner_cfg, Mapping) and scanner_cfg.get("enabled") is False:
            return RoutingDecision(
                scanner=self._scanner,
                enabled=False,
                reason=f"Scanner '{self._scanner}' is explicitly disabled in configuration",
                source="configuration",
                rule_id=self.rule_id,
                matched_evidence=(),
            )
        return None


class WordPressTechnologyRule(RoutingRule):
    """Rule that enables WPScan when WordPress evidence meets a confidence threshold."""

    def __init__(self, default_threshold: float = 0.5) -> None:
        if (
            isinstance(default_threshold, bool)
            or not isinstance(default_threshold, (int, float))
            or not 0.0 <= default_threshold <= 1.0
        ):
            raise ValueError("threshold must be a number between 0.0 and 1.0")
        self._default_threshold = float(default_threshold)

    @property
    def rule_id(self) -> str:
        return "rule_wordpress_technology"

    def evaluate(self, context: RoutingContext) -> RoutingDecision | None:
        wpscan_cfg = context.scanner_configs.get("wpscan", {})
        threshold = self._default_threshold
        if isinstance(wpscan_cfg, Mapping) and "confidence_threshold" in wpscan_cfg:
            cfg_thresh = wpscan_cfg["confidence_threshold"]
            if (
                isinstance(cfg_thresh, (int, float))
                and not isinstance(cfg_thresh, bool)
                and 0.0 <= cfg_thresh <= 1.0
            ):
                threshold = float(cfg_thresh)

        wp_techs = [
            tech
            for tech in context.technologies
            if tech.name.lower() == "wordpress"
            or any("wordpress" in cat.lower() for cat in tech.categories)
        ]

        if not wp_techs:
            return RoutingDecision(
                scanner="wpscan",
                enabled=False,
                reason="No WordPress technology evidence detected",
                source="technology",
                rule_id=self.rule_id,
                matched_evidence=(),
            )

        matched_techs = [t for t in wp_techs if t.confidence >= threshold]
        evidence = tuple(
            sorted({f"{t.name} (confidence={t.confidence:.2f})" for t in wp_techs})
        )

        if matched_techs:
            return RoutingDecision(
                scanner="wpscan",
                enabled=True,
                reason=f"WordPress technology evidence meets threshold ({threshold:.2f})",
                source="technology",
                rule_id=self.rule_id,
                matched_evidence=evidence,
            )

        return RoutingDecision(
            scanner="wpscan",
            enabled=False,
            reason=f"WordPress technology evidence confidence is below threshold ({threshold:.2f})",
            source="technology",
            rule_id=self.rule_id,
            matched_evidence=evidence,
        )


class HttpServiceRule(RoutingRule):
    """Rule that enables HTTP(S) vulnerability scanners for confirmed HTTP services."""

    def __init__(self, scanner: str = "nuclei") -> None:
        if not isinstance(scanner, str) or not scanner.strip():
            raise ValueError("scanner must be a non-empty string")
        self._scanner = scanner.strip()

    @property
    def rule_id(self) -> str:
        return f"rule_http_services_{self._scanner}"

    def evaluate(self, context: RoutingContext) -> RoutingDecision | None:
        http_services: list[str] = []
        for svc in context.services:
            if (svc.service and "http" in svc.service.lower()) or (
                svc.web_url is not None
            ):
                url_str = svc.web_url or f"{svc.host}:{svc.port}"
                http_services.append(url_str)

        if not http_services and (
            context.target_url.startswith("http://")
            or context.target_url.startswith("https://")
        ):
            http_services.append(context.target_url)

        evidence = tuple(sorted(set(http_services)))
        if evidence:
            return RoutingDecision(
                scanner=self._scanner,
                enabled=True,
                reason=f"Confirmed HTTP(S) service available for target ({len(evidence)} service(s))",
                source="web_service",
                rule_id=self.rule_id,
                matched_evidence=evidence,
            )

        return RoutingDecision(
            scanner=self._scanner,
            enabled=False,
            reason="No confirmed HTTP(S) web services detected for target",
            source="web_service",
            rule_id=self.rule_id,
            matched_evidence=(),
        )


class QueryUrlRule(RoutingRule):
    """Rule that enables SQLmap when in-scope URLs with query parameters are available."""

    def __init__(self, scanner: str = "sqlmap") -> None:
        if not isinstance(scanner, str) or not scanner.strip():
            raise ValueError("scanner must be a non-empty string")
        self._scanner = scanner.strip()

    @property
    def rule_id(self) -> str:
        return f"rule_query_urls_{self._scanner}"

    def evaluate(self, context: RoutingContext) -> RoutingDecision | None:
        query_urls: list[str] = []
        candidate_urls = list(context.urls)
        if context.target_url not in candidate_urls:
            candidate_urls.append(context.target_url)

        for url in candidate_urls:
            parsed = urlparse(url)
            if parsed.query and bool(parse_qs(parsed.query)):
                query_urls.append(url)

        evidence = tuple(sorted(set(query_urls)))
        if evidence:
            return RoutingDecision(
                scanner=self._scanner,
                enabled=True,
                reason=f"Detected {len(evidence)} query-bearing URL(s) suitable for parameter assessment",
                source="query_urls",
                rule_id=self.rule_id,
                matched_evidence=evidence,
            )

        return RoutingDecision(
            scanner=self._scanner,
            enabled=False,
            reason="No in-scope URLs with query parameters found",
            source="query_urls",
            rule_id=self.rule_id,
            matched_evidence=(),
        )
