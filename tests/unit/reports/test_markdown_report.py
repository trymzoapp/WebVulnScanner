"""Unit tests for the Markdown report generator."""

from pathlib import Path
from tempfile import TemporaryDirectory

from webvulnscanner.aggregation.aggregator import ResultAggregator
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.target import Target
from webvulnscanner.reports.markdown_report import MarkdownReportGenerator


def test_markdown_report_generation() -> None:
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
            title="SQL Injection | Hostile Pipe",
            severity=Severity.HIGH,
            source_scanner="sqlmap",
            affected_resource="https://example.com/search?id=1",
            description="High vulnerability description.",
            evidence=("evidence line 1",),
        )

        aggregator = ResultAggregator()
        aggregator.aggregate(ctx, {})

        # Re-aggregate with findings
        outcomes = {
            "vuln": type(
                "DummyOutcome",
                (),
                {
                    "errors": (),
                    "artifacts": {"findings": (f1,)},
                },
            )()
        }
        report_with_findings = aggregator.aggregate(ctx, outcomes)

        generator = MarkdownReportGenerator()
        file_path = generator.generate(ctx, report_with_findings)

        assert file_path.exists()
        assert file_path == ctx.stage_directory("reports") / "report.md"

        content = file_path.read_text(encoding="utf-8")
        assert "# Authorized Web Vulnerability Assessment Report" in content
        assert "## Scan Overview" in content
        assert "SQL Injection \\| Hostile Pipe" in content
