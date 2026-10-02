"""Unit tests for finding deduplication."""

from webvulnscanner.aggregation.deduplicator import (
    FindingDeduplicator,
    canonicalize_resource,
)
from webvulnscanner.models.finding import Finding, Severity


def test_canonicalize_resource() -> None:
    assert (
        canonicalize_resource("https://example.com/page/") == "https://example.com/page"
    )
    assert (
        canonicalize_resource("https://EXAMPLE.COM:443/test")
        == "https://example.com/test"
    )
    assert (
        canonicalize_resource("http://example.com:8080/api/")
        == "http://example.com:8080/api"
    )


def test_deduplicator_merges_exact_duplicates() -> None:
    f1 = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        source_scanner="sqlmap",
        affected_resource="https://example.com/search?q=1",
        rule_id="sql-injection",
        parameter="q",
        evidence=("evidence 1",),
    )
    f2 = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        source_scanner="sqlmap",
        affected_resource="https://example.com/search?q=1",
        rule_id="sql-injection",
        parameter="q",
        evidence=("evidence 2",),
    )

    dedup = FindingDeduplicator()
    result = dedup.deduplicate([f1, f2])

    assert len(result) == 1
    merged = result[0]
    assert merged.title == "SQL Injection"
    assert set(merged.evidence) == {"evidence 1", "evidence 2"}


def test_deduplicator_cross_scanner() -> None:
    f1 = Finding(
        title="XSS Vulnerability",
        severity=Severity.MEDIUM,
        source_scanner="nuclei",
        affected_resource="https://example.com/page",
        rule_id="xss-vuln",
        evidence=("matcher: xss",),
    )
    f2 = Finding(
        title="XSS Vulnerability",
        severity=Severity.HIGH,
        source_scanner="custom_scanner",
        affected_resource="https://example.com/page",
        rule_id="xss-vuln",
        evidence=("payload reflected",),
    )

    dedup = FindingDeduplicator()
    result = dedup.deduplicate([f1, f2])

    assert len(result) == 1
    merged = result[0]
    assert merged.severity is Severity.HIGH
    assert "custom_scanner" in merged.source_scanner
    assert "nuclei" in merged.source_scanner
    assert len(merged.evidence) == 2


def test_deduplicator_distinct_parameters_stay_separate() -> None:
    f1 = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        source_scanner="sqlmap",
        affected_resource="https://example.com/search",
        rule_id="sql-injection",
        parameter="id",
    )
    f2 = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        source_scanner="sqlmap",
        affected_resource="https://example.com/search",
        rule_id="sql-injection",
        parameter="name",
    )

    dedup = FindingDeduplicator()
    result = dedup.deduplicate([f1, f2])

    assert len(result) == 2
