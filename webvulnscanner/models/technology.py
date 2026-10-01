"""Typed detected-technology model."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class Technology:
    """A technology observation with confidence and scanner provenance."""

    name: str
    source: str
    confidence: float
    version: str | None = None
    categories: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("name", self.name)
        _require_text("source", self.source)
        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise TypeError("confidence must be a number")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        object.__setattr__(self, "confidence", confidence)
        if self.version is not None:
            _require_text("version", self.version)
        _require_text_tuple("categories", self.categories)
        _require_text_tuple("evidence", self.evidence)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "name": self.name,
            "source": self.source,
            "confidence": self.confidence,
            "version": self.version,
            "categories": list(self.categories),
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Technology:
        """Build a technology observation from serialized JSON data."""
        expected = {
            "name",
            "source",
            "confidence",
            "version",
            "categories",
            "evidence",
        }
        if not isinstance(data, Mapping):
            raise TypeError("serialized technology must be a mapping")
        if set(data) != expected:
            raise ValueError("serialized technology fields do not match the expected schema")
        return cls(
            name=data["name"],
            source=data["source"],
            confidence=data["confidence"],
            version=data["version"],
            categories=_json_text_list("categories", data["categories"]),
            evidence=_json_text_list("evidence", data["evidence"]),
        )


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_text_tuple(name: str, values: object) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be a tuple of strings")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{name} must contain only non-empty strings")


def _json_text_list(name: str, values: object) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise TypeError(f"{name} must be a JSON array of strings")
    result = tuple(values)
    _require_text_tuple(name, result)
    return result


__all__ = ["Technology"]
