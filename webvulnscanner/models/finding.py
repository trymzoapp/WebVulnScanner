"""Typed vulnerability finding model."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class Severity(str, Enum):
    """Canonical finding severities."""

    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Finding:
    """A scanner finding with a deterministic identity and JSON-safe evidence."""

    title: str
    severity: Severity
    source_scanner: str
    affected_resource: str
    rule_id: str | None = None
    parameter: str | None = None
    description: str = ""
    evidence: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    finding_id: str = field(init=False)

    def __post_init__(self) -> None:
        _require_text("title", self.title)
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        _require_text("source_scanner", self.source_scanner)
        _require_text("affected_resource", self.affected_resource)
        _require_optional_text("rule_id", self.rule_id)
        _require_optional_text("parameter", self.parameter)
        if not isinstance(self.description, str):
            raise TypeError("description must be a string")
        _require_text_tuple("evidence", self.evidence)
        _require_text_tuple("references", self.references)
        object.__setattr__(self, "finding_id", self._stable_id())

    def _stable_id(self) -> str:
        identity = {
            "identity": self.rule_id or self.title,
            "parameter": self.parameter,
            "resource": self.affected_resource,
            "scanner": self.source_scanner,
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "source_scanner": self.source_scanner,
            "affected_resource": self.affected_resource,
            "rule_id": self.rule_id,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": list(self.evidence),
            "references": list(self.references),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        """Build a finding from its JSON-compatible representation."""
        _require_mapping_keys(
            data,
            {
                "finding_id",
                "title",
                "severity",
                "source_scanner",
                "affected_resource",
                "rule_id",
                "parameter",
                "description",
                "evidence",
                "references",
            },
        )
        finding = cls(
            title=data["title"],
            severity=Severity(data["severity"]),
            source_scanner=data["source_scanner"],
            affected_resource=data["affected_resource"],
            rule_id=data["rule_id"],
            parameter=data["parameter"],
            description=data["description"],
            evidence=_json_text_list("evidence", data["evidence"]),
            references=_json_text_list("references", data["references"]),
        )
        if data["finding_id"] != finding.finding_id:
            raise ValueError("finding_id does not match the finding identity")
        return finding


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_optional_text(name: str, value: object) -> None:
    if value is not None:
        _require_text(name, value)


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


def _require_mapping_keys(data: Mapping[str, Any], expected: set[str]) -> None:
    if not isinstance(data, Mapping):
        raise TypeError("serialized finding must be a mapping")
    if set(data) != expected:
        raise ValueError("serialized finding fields do not match the expected schema")


__all__ = ["Finding", "Severity"]
