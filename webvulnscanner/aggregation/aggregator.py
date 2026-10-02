"""Result aggregator combining stage outcomes into an AggregateScanReport."""

from __future__ import annotations

import contextlib
from collections.abc import Mapping, Sequence
from typing import Any

from webvulnscanner.aggregation.deduplicator import FindingDeduplicator
from webvulnscanner.aggregation.severity import normalize_severity
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.pipeline import StageName, StageOutcome
from webvulnscanner.models.discovery import DiscoveredResource
from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.report import AggregateScanReport, SeveritySummary
from webvulnscanner.models.scan_result import RoutingDecision, ScanResult
from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}


class ResultAggregator:
    """Aggregate findings, technologies, services, routing decisions, and status."""

    def __init__(self, deduplicator: FindingDeduplicator | None = None) -> None:
        self.deduplicator = deduplicator or FindingDeduplicator()

    def aggregate(
        self,
        context: ScanContext,
        stage_outcomes: Mapping[StageName, StageOutcome],
    ) -> AggregateScanReport:
        """Combine stage outcomes into one report-ready AggregateScanReport."""
        raw_findings: list[Finding] = []
        technologies: list[Technology] = []
        services: list[WebService] = []
        discovered_resources: list[DiscoveredResource] = []
        routing_decisions: list[RoutingDecision] = []
        tool_statuses: dict[str, str] = {}
        all_errors: list[str] = list(context.metadata.errors)

        for _stage_name, outcome in stage_outcomes.items():
            all_errors.extend(outcome.errors)
            if not outcome.artifacts:
                continue

            # Process findings from vulnerability parsers or scanner results
            self._extract_findings(outcome.artifacts, raw_findings)
            self._extract_technologies(outcome.artifacts, technologies)
            self._extract_services(outcome.artifacts, services)
            self._extract_resources(outcome.artifacts, discovered_resources)
            self._extract_routing(outcome.artifacts, routing_decisions)
            self._extract_tool_statuses(outcome.artifacts, tool_statuses)

        # Normalize severities
        normalized_findings: list[Finding] = []
        for finding in raw_findings:
            norm_sev = normalize_severity(finding.severity)
            if norm_sev is not finding.severity:
                normalized_findings.append(
                    Finding(
                        title=finding.title,
                        severity=norm_sev,
                        source_scanner=finding.source_scanner,
                        affected_resource=finding.affected_resource,
                        rule_id=finding.rule_id,
                        parameter=finding.parameter,
                        description=finding.description,
                        evidence=finding.evidence,
                        references=finding.references,
                    )
                )
            else:
                normalized_findings.append(finding)

        # Deduplicate findings
        deduped = self.deduplicator.deduplicate(normalized_findings)

        # Sort findings deterministically
        sorted_findings = tuple(
            sorted(
                deduped,
                key=lambda f: (
                    _SEVERITY_ORDER.get(f.severity, 99),
                    f.title.casefold(),
                    f.affected_resource.casefold(),
                    f.finding_id,
                ),
            )
        )

        # Compute severity summary
        severity_summary = _build_severity_summary(sorted_findings)

        return AggregateScanReport(
            metadata=context.metadata,
            findings=sorted_findings,
            technologies=tuple(
                sorted(set(technologies), key=lambda t: (t.name.casefold(), t.source))
            ),
            services=tuple(sorted(set(services), key=lambda s: (s.host, s.port))),
            discovered_resources=tuple(
                sorted(set(discovered_resources), key=lambda r: r.url)
            ),
            routing_decisions=tuple(
                sorted(set(routing_decisions), key=lambda d: d.scanner)
            ),
            tool_statuses=tool_statuses,
            severity_summary=severity_summary,
            errors=tuple(dict.fromkeys(all_errors)),
        )

    def _extract_findings(
        self, artifacts: Mapping[str, Any], output: list[Finding]
    ) -> None:
        for key in ("findings", "vulnerability"):
            val = artifacts.get(key)
            if isinstance(val, (list, tuple)):
                for f in val:
                    if isinstance(f, Finding):
                        output.append(f)
                    elif isinstance(f, Mapping):
                        with contextlib.suppress(Exception):
                            output.append(Finding.from_dict(f))
            elif (findings_attr := getattr(val, "findings", None)) and isinstance(
                findings_attr, tuple
            ):
                for f in findings_attr:
                    if isinstance(f, Finding):
                        output.append(f)
            elif (sr_attr := getattr(val, "scanner_results", None)) and isinstance(
                sr_attr, tuple
            ):
                for sr in sr_attr:
                    if isinstance(sr, ScanResult):
                        for f in sr.findings:
                            output.append(f)

    def _extract_technologies(
        self, artifacts: Mapping[str, Any], output: list[Technology]
    ) -> None:
        for key in ("technologies", "fingerprint"):
            val = artifacts.get(key)
            if isinstance(val, (list, tuple)):
                for t in val:
                    if isinstance(t, Technology):
                        output.append(t)
                    elif isinstance(t, Mapping):
                        with contextlib.suppress(Exception):
                            output.append(Technology.from_dict(t))
            elif (tech_attr := getattr(val, "technologies", None)) and isinstance(
                tech_attr, tuple
            ):
                for t in tech_attr:
                    if isinstance(t, Technology):
                        output.append(t)

    def _extract_services(
        self, artifacts: Mapping[str, Any], output: list[WebService]
    ) -> None:
        for key in ("services", "fingerprint"):
            val = artifacts.get(key)
            if isinstance(val, (list, tuple)):
                for s in val:
                    if isinstance(s, WebService):
                        output.append(s)
                    elif isinstance(s, Mapping):
                        with contextlib.suppress(Exception):
                            output.append(WebService.from_dict(s))
            elif (serv_attr := getattr(val, "services", None)) and isinstance(
                serv_attr, tuple
            ):
                for s in serv_attr:
                    if isinstance(s, WebService):
                        output.append(s)

    def _extract_resources(
        self, artifacts: Mapping[str, Any], output: list[DiscoveredResource]
    ) -> None:
        for key in ("resources", "discovery"):
            val = artifacts.get(key)
            if isinstance(val, (list, tuple)):
                for r in val:
                    if isinstance(r, DiscoveredResource):
                        output.append(r)
                    elif isinstance(r, Mapping):
                        with contextlib.suppress(Exception):
                            output.append(DiscoveredResource.from_dict(r))
            elif (res_attr := getattr(val, "resources", None)) and isinstance(
                res_attr, tuple
            ):
                for r in res_attr:
                    if isinstance(r, DiscoveredResource):
                        output.append(r)

    def _extract_routing(
        self, artifacts: Mapping[str, Any], output: list[RoutingDecision]
    ) -> None:
        raw = artifacts.get("decisions")
        if isinstance(raw, (list, tuple)):
            for d in raw:
                if isinstance(d, RoutingDecision):
                    output.append(d)
                elif isinstance(d, Mapping):
                    with contextlib.suppress(TypeError, ValueError):
                        output.append(RoutingDecision.from_dict(d))

    def _extract_tool_statuses(
        self, artifacts: Mapping[str, Any], output: dict[str, str]
    ) -> None:
        for key in (
            "scanner_results",
            "vulnerability",
            "discovery",
            "fingerprint",
            "passive",
        ):
            val = artifacts.get(key)
            if (sr_attr := getattr(val, "scanner_results", None)) and isinstance(
                sr_attr, tuple
            ):
                for sr in sr_attr:
                    if isinstance(sr, ScanResult):
                        output[sr.scanner] = sr.status.value


def _build_severity_summary(findings: Sequence[Finding]) -> SeveritySummary:
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
        Severity.UNKNOWN: 0,
    }
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return SeveritySummary(
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        unknown=counts[Severity.UNKNOWN],
        total=len(findings),
    )


__all__ = ["ResultAggregator"]
