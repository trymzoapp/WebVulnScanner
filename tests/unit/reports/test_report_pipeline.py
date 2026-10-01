"""Unit tests for report stage integration and latest-scan pointer updates."""

import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import create_scan_context, update_latest_pointer
from webvulnscanner.core.pipeline import StageStatus
from webvulnscanner.models.report import ScanMetadata, ScanStatus
from webvulnscanner.models.target import Target
from webvulnscanner.reports.stage import ReportStage


@pytest.mark.anyio
async def test_report_stage_execution_and_latest_pointer() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={},
        )
        config = load_config(profile_name="safe")

        stage = ReportStage(configuration=config)
        outcome = await stage.run(ctx, {})

        assert outcome.status is StageStatus.SUCCESS
        assert "report_paths" in outcome.artifacts
        paths = outcome.artifacts["report_paths"]

        assert "json" in paths
        assert "markdown" in paths
        assert "html" in paths

        latest_path = storage_root / target.normalized_domain / "latest.json"
        assert latest_path.exists()

        latest_data = json.loads(latest_path.read_text(encoding="utf-8"))
        assert latest_data["scan_id"] == ctx.scan_id


def test_update_latest_pointer_concurrency_protection() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={},
        )

        t_newer = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
        t_older = datetime(2026, 10, 1, 11, 0, 0, tzinfo=timezone.utc)

        meta_newer = ScanMetadata(
            scan_id="scan-newer",
            target_url=target.url,
            normalized_domain=target.normalized_domain,
            started_at=t_newer,
            completed_at=t_newer,
            profile="safe",
            scanner_configuration={},
            status=ScanStatus.COMPLETED,
        )

        meta_older = ScanMetadata(
            scan_id="scan-older",
            target_url=target.url,
            normalized_domain=target.normalized_domain,
            started_at=t_older,
            completed_at=t_newer,
            profile="safe",
            scanner_configuration={},
            status=ScanStatus.COMPLETED,
        )

        # Update with newer scan first
        res1 = update_latest_pointer(ctx, meta_newer)
        assert res1 is not None
        assert res1.exists()

        data1 = json.loads(res1.read_text(encoding="utf-8"))
        assert data1["scan_id"] == "scan-newer"

        # Attempt to update with older scan -> rejected (returns None)
        res2 = update_latest_pointer(ctx, meta_older)
        assert res2 is None

        # Data remains from newer scan
        data2 = json.loads(res1.read_text(encoding="utf-8"))
        assert data2["scan_id"] == "scan-newer"
