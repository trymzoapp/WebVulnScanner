"""Scanner-agnostic severity normalization."""

from __future__ import annotations

import math
from typing import Any

from webvulnscanner.models.finding import Severity


_LABEL_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "high": Severity.HIGH,
    "major": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
    "unknown": Severity.UNKNOWN,
}


def normalize_severity(
    value: Any,
    *,
    default: Severity = Severity.UNKNOWN,
) -> Severity:
    """Normalize string labels, CVSS scores, or enums into canonical Severity."""
    if isinstance(value, Severity):
        return value

    if value is None:
        return default

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        score = float(value)
        if not math.isfinite(score) or score < 0.0 or score > 10.0:
            return default
        if score == 0.0:
            return Severity.INFO
        if score < 4.0:
            return Severity.LOW
        if score < 7.0:
            return Severity.MEDIUM
        if score < 9.0:
            return Severity.HIGH
        return Severity.CRITICAL

    if isinstance(value, str):
        clean = value.strip().casefold()
        if not clean:
            return default
        if clean in _LABEL_MAP:
            return _LABEL_MAP[clean]
        try:
            numeric = float(clean)
            return normalize_severity(numeric, default=default)
        except ValueError:
            return default

    return default


__all__ = ["normalize_severity"]
