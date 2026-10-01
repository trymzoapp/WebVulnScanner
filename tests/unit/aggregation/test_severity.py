"""Unit tests for severity normalization."""

import pytest

from webvulnscanner.aggregation.severity import normalize_severity
from webvulnscanner.models.finding import Severity


@pytest.mark.parametrize(
    "input_val, expected",
    [
        ("info", Severity.INFO),
        ("INFO", Severity.INFO),
        ("Informational", Severity.INFO),
        ("low", Severity.LOW),
        ("LOW", Severity.LOW),
        ("medium", Severity.MEDIUM),
        ("Medium", Severity.MEDIUM),
        ("moderate", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("unknown", Severity.UNKNOWN),
        (Severity.HIGH, Severity.HIGH),
        # Numeric boundaries (CVSS v3/v4)
        (0.0, Severity.INFO),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
        ("7.5", Severity.HIGH),
        # Invalid / missing / unknown cases
        (None, Severity.UNKNOWN),
        ("", Severity.UNKNOWN),
        ("  ", Severity.UNKNOWN),
        ("weird_severity", Severity.UNKNOWN),
        (11.5, Severity.UNKNOWN),
        (-1.0, Severity.UNKNOWN),
    ],
)
def test_normalize_severity(input_val, expected) -> None:
    assert normalize_severity(input_val) is expected
