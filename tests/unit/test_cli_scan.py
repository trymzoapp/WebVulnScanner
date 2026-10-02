"""Unit tests for complete CLI scan execution, authorization, summary, and exit codes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from webvulnscanner.cli import (
    EXIT_FATAL_FAILURE,
    EXIT_FINDINGS_FOUND,
    EXIT_INTERRUPTED,
    EXIT_INVALID_INPUT,
    EXIT_PARTIAL_COMPLETION,
    EXIT_SUCCESS,
    _build_pipeline,
    main,
)
from webvulnscanner.config.loader import load_config
from webvulnscanner.core.orchestrator import OrchestrationResult
from webvulnscanner.core.pipeline import (
    Pipeline,
    PipelineResult,
    PipelineStatus,
    StageName,
    StageOutcome,
    StageStatus,
)
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.report import (
    AggregateScanReport,
    ScanMetadata,
    ScanStatus,
    SeveritySummary,
)
from webvulnscanner.utils.time import utc_now


def test_build_pipeline_assembles_all_six_stages() -> None:
    config = load_config(profile_name="safe")
    runner = AsyncSubprocessRunner(
        max_concurrency=config.concurrency.max_scanners,
        default_timeout=config.timeouts.default,
    )
    pipeline = _build_pipeline(config, runner)

    stage_names = [stage.name for stage in pipeline._stages]
    assert stage_names == [
        StageName.PASSIVE,
        StageName.FINGERPRINT,
        StageName.ROUTING,
        StageName.DISCOVERY,
        StageName.VULNERABILITY,
        StageName.REPORT,
    ]


def test_scan_fails_without_authorized_confirmation_in_non_interactive_mode(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    exit_code = main(["scan", "https://example.com"])

    assert exit_code == EXIT_INVALID_INPUT
    captured = capsys.readouterr()
    assert "error: Authorized-use confirmation required." in captured.err


def test_scan_succeeds_with_confirm_authorized_flag(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "scan",
            "https://example.com",
            "--confirm-authorized",
            "--storage-root",
            str(tmp_path / "runs"),
        ],
        pipeline_factory=lambda config, runner: Pipeline(()),
    )

    assert exit_code == EXIT_SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert payload["authorized_use_confirmed"] is True
    assert payload["severity_counts"]["total"] == 0
    assert payload["report_paths"] == {}


def test_scan_succeeds_with_yes_short_flag(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "scan",
            "https://example.com",
            "-y",
            "--storage-root",
            str(tmp_path / "runs"),
        ],
        pipeline_factory=lambda config, runner: Pipeline(()),
    )

    assert exit_code == EXIT_SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert payload["authorized_use_confirmed"] is True


def test_interactive_authorization_confirmation_yes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    exit_code = main(
        ["scan", "https://example.com", "--storage-root", str(tmp_path / "runs")],
        pipeline_factory=lambda config, runner: Pipeline(()),
    )

    assert exit_code == EXIT_SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert payload["authorized_use_confirmed"] is True


def test_interactive_authorization_confirmation_no(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    exit_code = main(
        ["scan", "https://example.com", "--storage-root", str(tmp_path / "runs")],
        pipeline_factory=lambda config, runner: Pipeline(()),
    )

    assert exit_code == EXIT_INVALID_INPUT
    captured = capsys.readouterr()
    assert "error: Authorized-use confirmation required." in captured.err


def test_exit_findings_found_when_vulnerabilities_exist(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = utc_now()
    metadata = ScanMetadata(
        scan_id="test-scan-1",
        target_url="https://example.com/",
        normalized_domain="example.com",
        started_at=now,
        completed_at=now,
        profile="safe",
        scanner_configuration={},
        status=ScanStatus.COMPLETED,
    )
    report = AggregateScanReport(
        metadata=metadata,
        severity_summary=SeveritySummary(high=2, total=2),
    )

    report_outcome = StageOutcome(
        name=StageName.REPORT,
        status=StageStatus.SUCCESS,
        started_at=now,
        completed_at=now,
        artifacts={
            "report": report,
            "report_paths": {"json": "reports/findings.json"},
        },
    )

    def pipeline_with_findings(config: object, runner: object) -> Pipeline:
        p = Pipeline(())
        return p

    def mock_execute(*args: object, **kwargs: object) -> OrchestrationResult:
        return OrchestrationResult(
            status=ScanStatus.COMPLETED,
            context=None,
            pipeline=PipelineResult(
                status=PipelineStatus.COMPLETED,
                outcomes=(report_outcome,),
            ),
            metadata=metadata,
        )

    monkeypatch.setattr("webvulnscanner.cli._execute_scan", mock_execute)

    exit_code = main(["scan", "https://example.com", "--confirm-authorized"])

    assert exit_code == EXIT_FINDINGS_FOUND
    payload = json.loads(capsys.readouterr().out)
    assert payload["severity_counts"]["high"] == 2
    assert payload["severity_counts"]["total"] == 2
    assert payload["report_paths"] == {"json": "reports/findings.json"}


def test_exit_partial_completion_on_partial_scan_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = utc_now()
    metadata = ScanMetadata(
        scan_id="test-scan-2",
        target_url="https://example.com/",
        normalized_domain="example.com",
        started_at=now,
        completed_at=now,
        profile="safe",
        scanner_configuration={},
        status=ScanStatus.PARTIAL,
        errors=("subfinder failed",),
    )

    def mock_execute(*args: object, **kwargs: object) -> OrchestrationResult:
        return OrchestrationResult(
            status=ScanStatus.PARTIAL,
            context=None,
            pipeline=PipelineResult(
                status=PipelineStatus.PARTIAL,
                outcomes=(),
            ),
            metadata=metadata,
            errors=("subfinder failed",),
        )

    monkeypatch.setattr("webvulnscanner.cli._execute_scan", mock_execute)

    exit_code = main(["scan", "https://example.com", "-y"])

    assert exit_code == EXIT_PARTIAL_COMPLETION
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "partial"
    assert payload["errors"] == ["subfinder failed"]


def test_exit_fatal_failure_on_failed_scan_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def mock_execute(*args: object, **kwargs: object) -> OrchestrationResult:
        return OrchestrationResult(
            status=ScanStatus.FAILED,
            context=None,
            pipeline=None,
            metadata=None,
            errors=("fatal context error",),
        )

    monkeypatch.setattr("webvulnscanner.cli._execute_scan", mock_execute)

    exit_code = main(["scan", "https://example.com", "-y"])

    assert exit_code == EXIT_FATAL_FAILURE
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"


def test_keyboard_interrupt_returns_interrupted_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def mock_interrupt(*args: object, **kwargs: object) -> OrchestrationResult:
        raise KeyboardInterrupt

    monkeypatch.setattr("webvulnscanner.cli._execute_scan", mock_interrupt)

    exit_code = main(["scan", "https://example.com", "-y"])

    assert exit_code == EXIT_INTERRUPTED
    captured = capsys.readouterr()
    assert "error: Scan interrupted by user." in captured.err
