"""Unit tests for routing decision persistence, logging, and stage execution."""

import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from webvulnscanner.core.context import create_scan_context, write_routing_decisions
from webvulnscanner.core.pipeline import StageName, StageOutcome, StageStatus
from webvulnscanner.models.scan_result import RoutingDecision
from webvulnscanner.models.technology import Technology
from webvulnscanner.models.target import Target
from webvulnscanner.routing.stage import RoutingStage
from webvulnscanner.utils.time import utc_now


def test_write_routing_decisions_persistence() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={},
        )

        decisions = (
            RoutingDecision(
                scanner="wpscan",
                enabled=True,
                reason="WordPress found",
                source="technology",
                rule_id="rule_wordpress_technology",
                matched_evidence=("WordPress 6.2",),
            ),
            RoutingDecision(
                scanner="sqlmap",
                enabled=False,
                reason="No query params",
                source="query_urls",
                rule_id="rule_query_urls_sqlmap",
            ),
        )

        file_path = write_routing_decisions(ctx, decisions)
        assert file_path.exists()
        assert file_path == ctx.scan_directory / "routing.json"

        content = json.loads(file_path.read_text(encoding="utf-8"))
        assert len(content) == 2
        assert content[0]["scanner"] == "wpscan"
        assert content[0]["enabled"] is True
        assert content[1]["scanner"] == "sqlmap"
        assert content[1]["enabled"] is False


@pytest.mark.anyio
async def test_routing_stage_run() -> None:
    with TemporaryDirectory() as tmpdir:
        storage_root = Path(tmpdir)
        target = Target("https://example.com")
        ctx = create_scan_context(
            storage_root=storage_root,
            target=target,
            profile_name="safe",
            scanner_configuration={"scanners": {"wpscan": {"enabled": True}}},
        )

        now = utc_now()
        wp_tech = Technology(name="WordPress", source="wappalyzer", confidence=1.0)
        previous_outcomes = {
            StageName.PASSIVE: StageOutcome(
                name=StageName.PASSIVE,
                status=StageStatus.SUCCESS,
                started_at=now,
                completed_at=now,
                artifacts={"urls": ["https://example.com/item?id=5"]},
            ),
            StageName.FINGERPRINT: StageOutcome(
                name=StageName.FINGERPRINT,
                status=StageStatus.SUCCESS,
                started_at=now,
                completed_at=now,
                artifacts={"technologies": [wp_tech.to_dict()]},
            ),
        }

        stage = RoutingStage()
        outcome = await stage.run(ctx, previous_outcomes)

        assert outcome.status is StageStatus.SUCCESS
        assert "decisions" in outcome.artifacts
        assert "enabled_scanners" in outcome.artifacts

        enabled = outcome.artifacts["enabled_scanners"]
        assert "wpscan" in enabled
        assert "sqlmap" in enabled
        assert "nuclei" in enabled

        routing_file = Path(outcome.artifacts["routing_file"])
        assert routing_file.exists()
