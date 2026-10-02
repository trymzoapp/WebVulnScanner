"""Self-contained, autoescaped HTML assessment report generator."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from webvulnscanner.core.context import ScanContext
from webvulnscanner.models.report import AggregateScanReport
from webvulnscanner.utils.filesystem import atomic_write_text


class HtmlReportGenerator:
    """Generate self-contained reports/report.html report with autoescaping."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self.template_dir = (
            Path(__file__).resolve().parent / "templates"
            if template_dir is None
            else Path(template_dir)
        )
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml", "j2"]),
        )

    def generate(
        self,
        context: ScanContext,
        report: AggregateScanReport,
        *,
        output_filename: str = "report.html",
    ) -> Path:
        """Write reports/report.html atomically and return its path."""
        template = self.env.get_template("report.html.j2")

        rendered = template.render(
            target_url=context.target.url,
            scan_id=context.scan_id,
            profile=report.metadata.profile,
            summary=report.severity_summary,
            findings=report.findings,
            errors=report.errors,
            metadata=report.metadata,
        )

        output_dir = context.stage_directory("reports")
        output_path = output_dir / output_filename

        return atomic_write_text(
            output_path,
            rendered,
            storage_root=context.storage_root,
            overwrite=True,
        )


__all__ = ["HtmlReportGenerator"]
