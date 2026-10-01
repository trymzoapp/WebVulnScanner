"""Unit tests for the result aggregator."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from webvulnscanner.aggregation.aggregator import ResultAggregator
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.core.pipeline import StageName, StageOutcome, StageStatus
from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.target import Target
from webvulnscanner.utils.time import utc_now


def test_aggregator_empty_scan() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={},
        )

        aggregator = ResultAggregator()
        report = aggregator.aggregate(ctx, {})

        assert report.metadata.scan_id == ctx.scan_id
        assert report.findings == ()
        assert report.severity_summary.total == 0
        assert report.errors == ()


def test_aggregator_combines_findings_and_severities() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={},
        )

        f1 = Finding(
            title="Medium Vuln",
            severity=Severity.MEDIUM,
            source_scanner="scanner1",
            affected_resource="https://example.com/a",
            rule_id="rule1",
        )
        f2 = Finding(
            title="Critical Vuln",
            severity=Severity.CRITICAL,
            source_scanner="scanner2",
            affected_resource="https://example.com/b",
            rule_id="rule2",
        )

        now = utc_now()
        outcomes = {
            StageName.VULNERABILITY: StageOutcome(
                name=StageName.VULNERABILITY,
                status=StageStatus.SUCCESS,
                started_at=now,
                completed_at=now,
                artifacts={"findings": (f1, f2)},
            )
        }

        aggregator = ResultAggregator()
        report = aggregator.aggregate(ctx, outcomes)

        assert len(report.findings) == 2
        # Critical should be ordered first
        assert report.findings[0].severity is Severity.CRITICAL
        assert report.findings[1].severity is Severity.MEDIUM

        assert report.severity_summary.critical == 1
        assert report.severity_summary.medium == 1
        assert report.severity_summary.total == 2
