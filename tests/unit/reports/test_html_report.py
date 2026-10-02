"""Unit tests for the HTML report generator."""

from pathlib import Path
from tempfile import TemporaryDirectory

from webvulnscanner.aggregation.aggregator import ResultAggregator
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.target import Target
from webvulnscanner.reports.html_report import HtmlReportGenerator


def test_html_report_generation_and_escaping() -> None:
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
            title="<script>alert(1)</script>",
            severity=Severity.HIGH,
            source_scanner="nuclei",
            affected_resource="https://example.com/xss",
            evidence=("<img src=x onerror=alert('xss')>",),
        )

        aggregator = ResultAggregator()
        outcomes = {
            "vuln": type(
                "DummyOutcome",
                (),
                {
                    "errors": ("<script>error</script>",),
                    "artifacts": {"findings": (f1,)},
                },
            )()
        }
        report = aggregator.aggregate(ctx, outcomes)

        generator = HtmlReportGenerator()
        file_path = generator.generate(ctx, report)

        assert file_path.exists()
        assert file_path == ctx.stage_directory("reports") / "report.html"

        content = file_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
        assert "&lt;script&gt;error&lt;/script&gt;" in content
