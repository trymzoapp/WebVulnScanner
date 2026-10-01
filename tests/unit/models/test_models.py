"""Tests for finding, technology, and scanner-result contracts."""

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.models.scan_result import (
    ScanError,
    ScanResult,
    ScannerStatus,
    SubprocessDetails,
)
from webvulnscanner.models.technology import Technology


STARTED = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
COMPLETED = STARTED + timedelta(seconds=2.5)


def make_finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "Missing Content-Security-Policy",
        "severity": Severity.LOW,
        "source_scanner": "headers",
        "affected_resource": "https://example.com/",
        "rule_id": "missing-csp",
        "description": "The response does not define a CSP.",
        "evidence": ("Content-Security-Policy header absent",),
        "references": ("https://developer.mozilla.org/docs/Web/HTTP/CSP",),
    }
    values.update(overrides)
    return Finding(**values)


def make_technology(**overrides: Any) -> Technology:
    values: dict[str, Any] = {
        "name": "WordPress",
        "source": "wappalyzer",
        "confidence": 0.95,
        "version": "6.6",
        "categories": ("CMS",),
        "evidence": ("generator meta tag",),
    }
    values.update(overrides)
    return Technology(**values)


def test_severity_and_status_are_string_enums() -> None:
    assert Severity.HIGH.value == "high"
    assert ScannerStatus.TIMED_OUT.value == "timed_out"


def test_finding_id_is_stable_for_the_same_identity() -> None:
    first = make_finding(description="first observation")
    second = make_finding(
        description="updated observation",
        evidence=("different safe evidence",),
    )

    assert first.finding_id == second.finding_id
    assert len(first.finding_id) == 64


def test_finding_id_changes_for_distinct_parameters() -> None:
    first = make_finding(parameter="id")
    second = make_finding(parameter="page")

    assert first.finding_id != second.finding_id


def test_finding_serialization_round_trip_is_json_compatible() -> None:
    finding = make_finding()

    payload = json.loads(json.dumps(finding.to_dict()))

    assert Finding.from_dict(payload) == finding
    assert isinstance(payload["evidence"], list)
    assert isinstance(payload["severity"], str)


def test_finding_rejects_tampered_stable_id() -> None:
    payload = make_finding().to_dict()
    payload["finding_id"] = "0" * 64

    with pytest.raises(ValueError, match="finding_id"):
        Finding.from_dict(payload)


@pytest.mark.parametrize(
    "overrides",
    [
        {"title": ""},
        {"severity": "low"},
        {"source_scanner": " "},
        {"affected_resource": ""},
        {"evidence": ["not", "a", "tuple"]},
        {"references": ("",)},
    ],
)
def test_finding_rejects_invalid_required_fields(overrides: dict[str, Any]) -> None:
    with pytest.raises((TypeError, ValueError)):
        make_finding(**overrides)


def test_technology_serialization_round_trip_and_defaults() -> None:
    technology = Technology(name="nginx", source="headers", confidence=1)

    payload = json.loads(json.dumps(technology.to_dict()))

    assert technology.confidence == 1.0
    assert technology.version is None
    assert technology.categories == ()
    assert technology.evidence == ()
    assert Technology.from_dict(payload) == technology


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("nan"), float("inf"), True])
def test_technology_rejects_invalid_confidence(confidence: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        make_technology(confidence=confidence)


def test_successful_scan_result_round_trip_is_json_compatible() -> None:
    result = ScanResult(
        scanner="wappalyzer",
        status=ScannerStatus.SUCCESS,
        started_at=STARTED.astimezone(timezone(timedelta(hours=5, minutes=30))),
        completed_at=COMPLETED,
        output_paths=("fingerprint/wappalyzer.json",),
        findings=(make_finding(),),
        technologies=(make_technology(),),
        subprocess_details=SubprocessDetails(
            duration_seconds=2.0,
            exit_code=0,
            stdout='{"technologies": []}',
        ),
    )

    payload = json.loads(json.dumps(result.to_dict()))
    restored = ScanResult.from_dict(payload)

    assert restored == result
    assert result.started_at.tzinfo is timezone.utc
    assert result.duration_seconds == 2.5
    assert payload["started_at"].endswith("Z")
    assert isinstance(payload["findings"], list)


def test_failed_scanner_result_is_representable() -> None:
    result = ScanResult(
        scanner="nuclei",
        status=ScannerStatus.FAILED,
        started_at=STARTED,
        completed_at=COMPLETED,
        errors=(
            ScanError(
                code="nonzero_exit",
                message="Nuclei exited unsuccessfully",
            ),
        ),
        subprocess_details=SubprocessDetails(
            duration_seconds=2.4,
            exit_code=2,
            stderr="bounded and redacted diagnostic",
        ),
    )

    assert result.status is ScannerStatus.FAILED
    assert result.findings == ()
    assert ScanResult.from_dict(result.to_dict()) == result


def test_skipped_scanner_result_requires_no_process() -> None:
    result = ScanResult(
        scanner="wpscan",
        status=ScannerStatus.SKIPPED,
        started_at=STARTED,
        completed_at=STARTED,
        skip_reason="WordPress was not detected",
    )

    assert result.duration_seconds == 0.0
    assert result.subprocess_details is None
    assert result.errors == ()


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "success"},
        {"started_at": datetime(2026, 9, 29, 12, 0)},
        {"completed_at": STARTED - timedelta(seconds=1)},
        {
            "status": ScannerStatus.SUCCESS,
            "errors": (ScanError(code="unexpected", message="failure"),),
        },
        {"status": ScannerStatus.SKIPPED},
        {
            "status": ScannerStatus.SKIPPED,
            "skip_reason": "not applicable",
            "subprocess_details": SubprocessDetails(duration_seconds=0),
        },
        {"status": ScannerStatus.FAILED},
        {
            "status": ScannerStatus.TIMED_OUT,
            "errors": (ScanError(code="timeout", message="timed out"),),
            "subprocess_details": SubprocessDetails(
                duration_seconds=2,
                timed_out=False,
            ),
        },
        {"output_paths": ["reports/output.json"]},
    ],
)
def test_scan_result_rejects_inconsistent_states(overrides: dict[str, Any]) -> None:
    values: dict[str, Any] = {
        "scanner": "test-scanner",
        "status": ScannerStatus.SUCCESS,
        "started_at": STARTED,
        "completed_at": COMPLETED,
    }
    values.update(overrides)

    with pytest.raises((TypeError, ValueError)):
        ScanResult(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"duration_seconds": -1},
        {"duration_seconds": float("nan")},
        {"duration_seconds": True},
        {"exit_code": False},
        {"timed_out": "yes"},
        {"stdout": object()},
    ],
)
def test_subprocess_details_reject_invalid_values(
    overrides: dict[str, Any],
) -> None:
    values: dict[str, Any] = {"duration_seconds": 1.0}
    values.update(overrides)

    with pytest.raises((TypeError, ValueError)):
        SubprocessDetails(**values)


def test_serialized_duration_must_match_timestamps() -> None:
    result = ScanResult(
        scanner="headers",
        status=ScannerStatus.SUCCESS,
        started_at=STARTED,
        completed_at=COMPLETED,
    )
    payload = result.to_dict()
    payload["duration_seconds"] = 100

    with pytest.raises(ValueError, match="duration_seconds"):
        ScanResult.from_dict(payload)


def test_models_are_immutable() -> None:
    finding = make_finding()

    with pytest.raises(FrozenInstanceError):
        finding.title = "changed"  # type: ignore[misc]
