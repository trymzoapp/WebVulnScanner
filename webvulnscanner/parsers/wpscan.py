"""Structured WPScan output parser."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


class WPScanParser(BaseParser[Finding]):
    """Normalize WPScan JSON output into Finding models."""

    def __init__(self, target_url: str | None = None) -> None:
        super().__init__("wpscan")
        self.target_url = target_url

    def parse(self, parser_input: ParserInput) -> ParseResult[Finding]:
        content = parser_input.content.strip()
        if not content:
            return ParseResult(items=(), warnings=())

        try:
            data = json.loads(content)
        except json.JSONDecodeError as error:
            raise self.parsing_error(
                "WPScan output is not valid JSON", cause=error
            ) from error

        if not isinstance(data, Mapping):
            raise self.parsing_error("WPScan output must be a JSON object")

        findings: list[Finding] = []
        warnings: list[str] = []

        target = data.get("target_url") or self.target_url or "unknown-target"

        # 1. Core vulnerabilities
        wp_version_data = data.get("version")
        if isinstance(wp_version_data, Mapping):
            vuls = wp_version_data.get("vulnerabilities", [])
            if isinstance(vuls, list):
                for vul in vuls:
                    if isinstance(vul, Mapping):
                        findings.append(
                            _vul_to_finding("WordPress Core", vul, str(target))
                        )

        # 2. Plugin vulnerabilities
        plugins_data = data.get("plugins")
        if isinstance(plugins_data, Mapping):
            for plugin_slug, plugin_info in plugins_data.items():
                if isinstance(plugin_info, Mapping):
                    vuls = plugin_info.get("vulnerabilities", [])
                    if isinstance(vuls, list):
                        for vul in vuls:
                            if isinstance(vul, Mapping):
                                findings.append(
                                    _vul_to_finding(
                                        f"Plugin: {plugin_slug}", vul, str(target)
                                    )
                                )

        # 3. Theme vulnerabilities
        theme_data = data.get("main_theme")
        if isinstance(theme_data, Mapping):
            theme_slug = theme_data.get("name", "main_theme")
            vuls = theme_data.get("vulnerabilities", [])
            if isinstance(vuls, list):
                for vul in vuls:
                    if isinstance(vul, Mapping):
                        findings.append(
                            _vul_to_finding(f"Theme: {theme_slug}", vul, str(target))
                        )

        # 4. Interesting findings (informational)
        interesting = data.get("interesting_findings", [])
        if isinstance(interesting, list):
            for item in interesting:
                if isinstance(item, Mapping):
                    to_finding = _interesting_to_finding(item, str(target))
                    if to_finding:
                        findings.append(to_finding)

        return ParseResult(
            items=tuple(findings),
            warnings=tuple(warnings),
        )


def _vul_to_finding(component: str, vul: Mapping[str, Any], target: str) -> Finding:
    title = vul.get("title") or f"Vulnerability in {component}"
    vul_type = vul.get("vuln_type") or "vulnerability"
    references: list[str] = []
    refs = vul.get("references")
    if isinstance(refs, Mapping):
        for _ref_type, ref_urls in refs.items():
            if isinstance(ref_urls, list):
                for u in ref_urls:
                    if isinstance(u, str) and u.strip():
                        references.append(u.strip())

    return Finding(
        title=f"[{component}] {title}",
        severity=Severity.HIGH,
        source_scanner="wpscan",
        affected_resource=target,
        rule_id=str(vul_type).casefold().replace(" ", "-"),
        description=f"Vulnerability identified in {component}: {title}",
        evidence=(f"Component: {component}", f"Type: {vul_type}"),
        references=tuple(references),
    )


def _interesting_to_finding(item: Mapping[str, Any], target: str) -> Finding | None:
    to_check = item.get("to_s") or item.get("url") or item.get("type")
    if not to_check:
        return None
    url = item.get("url") or target
    evidence: list[str] = []
    if "to_s" in item and isinstance(item["to_s"], str):
        evidence.append(item["to_s"])

    return Finding(
        title=f"WordPress Observation: {item.get('type', 'Interesting Finding')}",
        severity=Severity.INFO,
        source_scanner="wpscan",
        affected_resource=str(url),
        rule_id="wpscan-observation",
        description=str(item.get("to_s", "Informational WPScan observation.")),
        evidence=tuple(evidence),
        references=(),
    )


__all__ = ["WPScanParser"]
