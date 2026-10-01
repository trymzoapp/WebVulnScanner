"""Canonical JSON report generator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from webvulnscanner.core.context import ScanContext
from webvulnscanner.models.report import AggregateScanReport
from webvulnscanner.utils.filesystem import atomic_write_json


SCHEMA_VERSION = "1.0"


class JsonReportGenerator:
    """Generate canonical reports/findings.json machine-readable report."""

    def generate(
        self,
        context: ScanContext,
        report: AggregateScanReport,
        *,
        output_filename: str = "findings.json",
    ) -> Path:
        """Write reports/findings.json atomically and return its path."""
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "scan_id": context.scan_id,
            "target_url": context.target.url,
            "normalized_domain": context.target.normalized_domain,
            "metadata": report.metadata.to_dict(),
            "summary": report.severity_summary.to_dict(),
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else f for f in report.findings
            ],
            "technologies": [
                t.to_dict() if hasattr(t, "to_dict") else t for t in report.technologies
            ],
            "services": [
                s.to_dict() if hasattr(s, "to_dict") else s for s in report.services
            ],
            "discovered_resources": [
                r.to_dict() if hasattr(r, "to_dict") else r
                for r in report.discovered_resources
            ],
            "routing_decisions": [
                d.to_dict() if hasattr(d, "to_dict") else d
                for d in report.routing_decisions
            ],
            "tool_statuses": dict(report.tool_statuses),
            "errors": list(report.errors),
        }

        output_dir = context.stage_directory("reports")
        output_path = output_dir / output_filename
        return atomic_write_json(
            output_path,
            payload,
            storage_root=context.storage_root,
            overwrite=True,
        )


__all__ = ["SCHEMA_VERSION", "JsonReportGenerator"]
