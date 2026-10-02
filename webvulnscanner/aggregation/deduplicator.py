"""Deterministic finding deduplication and provenance-preserving merging."""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlparse

from webvulnscanner.models.finding import Finding, Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}


def canonicalize_resource(resource: str) -> str:
    """Canonicalize affected resource URL for stable deduplication."""
    if not isinstance(resource, str) or not resource.strip():
        return resource
    parsed = urlparse(resource.strip())
    if not parsed.scheme or not parsed.netloc:
        return resource.strip()
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    port_part = (
        f":{parsed.port}"
        if parsed.port
        and (
            (parsed.scheme == "http" and parsed.port != 80)
            or (parsed.scheme == "https" and parsed.port != 443)
        )
        else ""
    )
    hostname = (parsed.hostname or "").lower()
    return f"{parsed.scheme}://{hostname}{port_part}{path}"


class FindingDeduplicator:
    """Deduplicate findings deterministically while combining evidence and provenance."""

    def deduplicate(self, findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """Merge duplicate findings sharing identity, resource, and parameter."""
        if not findings:
            return ()

        grouped: dict[tuple[str, str, str], list[Finding]] = {}

        for finding in findings:
            identity_part = (finding.rule_id or finding.title).casefold().strip()
            resource_part = canonicalize_resource(finding.affected_resource).casefold()
            param_part = (finding.parameter or "").casefold().strip()
            key = (identity_part, resource_part, param_part)

            grouped.setdefault(key, []).append(finding)

        merged_findings: list[Finding] = []
        for key in sorted(grouped, key=lambda k: (k[0], k[1], k[2])):
            group = grouped[key]
            merged_findings.append(self._merge_group(group))

        return tuple(merged_findings)

    def _merge_group(self, group: list[Finding]) -> Finding:
        if len(group) == 1:
            return group[0]

        # Highest severity wins
        highest_severity = max(
            group, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)
        ).severity

        # Combine source scanners deterministically
        scanners = sorted({f.source_scanner for f in group})
        combined_source = ", ".join(scanners)

        # Merge evidence & references
        evidence_set: set[str] = set()
        for f in group:
            evidence_set.update(f.evidence)
        merged_evidence = tuple(sorted(evidence_set))

        refs_set: set[str] = set()
        for f in group:
            refs_set.update(f.references)
        merged_refs = tuple(sorted(refs_set))

        primary = group[0]

        return Finding(
            title=primary.title,
            severity=highest_severity,
            source_scanner=combined_source,
            affected_resource=primary.affected_resource,
            rule_id=primary.rule_id,
            parameter=primary.parameter,
            description=primary.description,
            evidence=merged_evidence,
            references=merged_refs,
        )


__all__ = ["FindingDeduplicator", "canonicalize_resource"]
