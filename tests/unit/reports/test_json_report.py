"""Unit tests for the JSON report generator."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from webvulnscanner.aggregation.aggregator import ResultAggregator
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.target import Target
from webvulnscanner.reports.json_report import SCHEMA_VERSION, JsonReportGenerator


def test_json_report_generation() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={},
        )

        Finding(
            title="XSS Test",
            severity=Severity.HIGH,
            source_scanner="nuclei",
            affected_resource="https://example.com/search",
        )

        aggregator = ResultAggregator()
        report = aggregator.aggregate(ctx, {})

        generator = JsonReportGenerator()
        file_path = generator.generate(ctx, report)

        assert file_path.exists()
        assert file_path == ctx.stage_directory("reports") / "findings.json"

        data = json.loads(file_path.read_text(encoding="utf-8"))
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["scan_id"] == ctx.scan_id
        assert data["target_url"] == "https://example.com/"
        assert "summary" in data
        assert "findings" in data
