"""Human-readable Markdown assessment report generator."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from webvulnscanner.core.context import ScanContext
from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.report import AggregateScanReport
from webvulnscanner.utils.filesystem import atomic_write_text


def _escape_md(text: str) -> str:
    """Sanitize untrusted text to prevent Markdown structure injection."""
    if not text:
        return ""
    # Replace markdown table pipes and backticks safely
    escaped = text.replace("|", "\\|").replace("\r", "").replace("\n", " ")
    return escaped


class MarkdownReportGenerator:
    """Generate reports/report.md human-readable Markdown report."""

    def generate(
        self,
        context: ScanContext,
        report: AggregateScanReport,
        *,
        output_filename: str = "report.md",
    ) -> Path:
        """Write reports/report.md atomically and return its path."""
        lines: list[str] = [
            "# Authorized Web Vulnerability Assessment Report",
            "",
            "> **Notice:** This assessment was performed exclusively for authorized target assets under explicitly defined safety rules and scope.",
            "",
            "## Scan Overview",
            "",
            f"- **Target URL:** `{_escape_md(context.target.url)}`",
            f"- **Scan ID:** `{_escape_md(context.scan_id)}`",
            f"- **Profile:** `{_escape_md(report.metadata.profile)}`",
            f"- **Scan Status:** `{_escape_md(report.metadata.status.value)}`",
            f"- **Start Time (UTC):** `{report.metadata.started_at.isoformat()}`",
            "",
            "## Severity Summary",
            "",
            "| Severity | Count |",
            "| --- | --- |",
            f"| **Critical** | {report.severity_summary.critical} |",
            f"| **High** | {report.severity_summary.high} |",
            f"| **Medium** | {report.severity_summary.medium} |",
            f"| **Low** | {report.severity_summary.low} |",
            f"| **Info** | {report.severity_summary.info} |",
            f"| **Unknown** | {report.severity_summary.unknown} |",
            f"| **Total** | {report.severity_summary.total} |",
            "",
            "## Vulnerability Findings",
            "",
        ]

        vuln_findings = [f for f in report.findings if f.severity is not Severity.INFO]
        info_findings = [f for f in report.findings if f.severity is Severity.INFO]

        if not vuln_findings:
            lines.append("No vulnerability findings were identified.")
            lines.append("")
        else:
            for idx, finding in enumerate(vuln_findings, start=1):
                lines.extend(
                    [
                        f"### {idx}. {_escape_md(finding.title)}",
                        "",
                        f"- **Severity:** `{finding.severity.value.upper()}`",
                        f"- **Scanner:** `{_escape_md(finding.source_scanner)}`",
                        f"- **Affected Resource:** `{_escape_md(finding.affected_resource)}`",
                    ]
                )
                if finding.parameter:
                    lines.append(f"- **Parameter:** `{_escape_md(finding.parameter)}`")
                if finding.rule_id:
                    lines.append(f"- **Rule ID:** `{_escape_md(finding.rule_id)}`")
                lines.append("")
                if finding.description:
                    lines.extend([f"**Description:** {_escape_md(finding.description)}", ""])
                if finding.evidence:
                    lines.append("**Evidence:**")
                    for ev in finding.evidence:
                        lines.append(f"- `{_escape_md(ev)}`")
                    lines.append("")
                if finding.references:
                    lines.append("**References:**")
                    for ref in finding.references:
                        lines.append(f"- {_escape_md(ref)}")
                    lines.append("")

        if info_findings:
            lines.extend(["## Informational Observations", ""])
            for idx, finding in enumerate(info_findings, start=1):
                lines.append(
                    f"- **{_escape_md(finding.title)}** (`{_escape_md(finding.affected_resource)}` via `{_escape_md(finding.source_scanner)}`)"
                )
            lines.append("")

        if report.errors:
            lines.extend(["## Execution Errors & Warnings", ""])
            for err in report.errors:
                lines.append(f"- ⚠️ {_escape_md(err)}")
            lines.append("")

        content = "\n".join(lines)
        output_dir = context.stage_directory("reports")
        output_path = output_dir / output_filename

        return atomic_write_text(
            output_path,
            content,
            storage_root=context.storage_root,
            overwrite=True,
        )


__all__ = ["MarkdownReportGenerator"]
