"""Report generation stage integrating JSON, Markdown, and HTML reports."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from webvulnscanner.aggregation.aggregator import ResultAggregator
from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext, update_latest_pointer
from webvulnscanner.core.pipeline import (
    FailurePolicy,
    PipelineStage,
    StageName,
    StageOutcome,
    StageStatus,
)

from webvulnscanner.models.report import ScanMetadata, ScanStatus
from webvulnscanner.reports.html_report import HtmlReportGenerator
from webvulnscanner.reports.json_report import JsonReportGenerator
from webvulnscanner.reports.markdown_report import MarkdownReportGenerator
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import utc_now


class ReportStage(PipelineStage):
    """Pipeline stage executing enabled report generators."""

    name = StageName.REPORT
    dependencies: tuple[StageName, ...] = ()
    failure_policy = FailurePolicy.CONTINUE

    def __init__(
        self,
        *,
        configuration: AppConfig,
        aggregator: ResultAggregator | None = None,
        json_generator: JsonReportGenerator | None = None,
        markdown_generator: MarkdownReportGenerator | None = None,
        html_generator: HtmlReportGenerator | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.configuration = configuration
        self.aggregator = aggregator or ResultAggregator()
        self.json_generator = json_generator or JsonReportGenerator()
        self.markdown_generator = markdown_generator or MarkdownReportGenerator()
        self.html_generator = html_generator or HtmlReportGenerator()
        self._time_provider = time_provider

    async def run(
        self,
        context: ScanContext,
        previous: Mapping[StageName, StageOutcome],
    ) -> StageOutcome:
        started_at = utc_now()
        report = self.aggregator.aggregate(context, previous)

        report_config = self.configuration.reports
        generated_paths: dict[str, str] = {}
        errors: list[str] = []

        if report_config.json:
            try:
                p = self.json_generator.generate(context, report)
                generated_paths["json"] = str(p)
            except Exception as e:
                errors.append(f"JSON report generation failed: {e}")

        if report_config.markdown:
            try:
                p = self.markdown_generator.generate(context, report)
                generated_paths["markdown"] = str(p)
            except Exception as e:
                errors.append(f"Markdown report generation failed: {e}")

        if report_config.html:
            try:
                p = self.html_generator.generate(context, report)
                generated_paths["html"] = str(p)
            except Exception as e:
                errors.append(f"HTML report generation failed: {e}")

        # Finalize metadata status and update latest.json
        completed_metadata = ScanMetadata(
            scan_id=report.metadata.scan_id,
            target_url=report.metadata.target_url,
            normalized_domain=report.metadata.normalized_domain,
            started_at=report.metadata.started_at,
            completed_at=utc_now(),
            profile=report.metadata.profile,
            scanner_configuration=report.metadata.scanner_configuration,
            status=ScanStatus.COMPLETED if not report.errors else ScanStatus.PARTIAL,
            tool_versions=report.metadata.tool_versions,
            errors=report.errors,
        )

        atomic_write_json(
            context.scan_directory / "metadata.json",
            completed_metadata.to_dict(),
            storage_root=context.storage_root,
            overwrite=True,
        )

        update_latest_pointer(context, completed_metadata)

        status = StageStatus.SUCCESS if generated_paths else StageStatus.FAILED
        return StageOutcome(
            name=self.name,
            status=status,
            started_at=started_at,
            completed_at=utc_now(),
            errors=tuple(errors),
            artifacts={
                "report_paths": generated_paths,
                "report": report,
                "final_metadata": completed_metadata,
            },
        )
