"""Scan metadata models shared by storage and future reports."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from webvulnscanner.utils.time import as_utc, format_utc


class ScanStatus(StrEnum):
    """Lifecycle state persisted in scan metadata."""

    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ScanMetadata:
    """Immutable, JSON-safe metadata for one scan execution."""

    scan_id: str
    target_url: str
    normalized_domain: str
    started_at: datetime
    profile: str
    scanner_configuration: Mapping[str, object]
    status: ScanStatus = ScanStatus.RUNNING
    completed_at: datetime | None = None
    tool_versions: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("scan_id", self.scan_id)
        _require_text("target_url", self.target_url)
        _require_text("normalized_domain", self.normalized_domain)
        if (
            "/" in self.normalized_domain
            or "\\" in self.normalized_domain
            or ".." in self.normalized_domain
        ):
            raise ValueError("normalized_domain is not filesystem-safe")
        _require_text("profile", self.profile)
        if not isinstance(self.status, ScanStatus):
            raise TypeError("status must be a ScanStatus")

        started_at = as_utc(self.started_at, field_name="started_at")
        object.__setattr__(self, "started_at", started_at)
        if self.completed_at is not None:
            completed_at = as_utc(self.completed_at, field_name="completed_at")
            if completed_at < started_at:
                raise ValueError("completed_at must not precede started_at")
            object.__setattr__(self, "completed_at", completed_at)

        if self.status is ScanStatus.RUNNING and self.completed_at is not None:
            raise ValueError("running scan metadata cannot have completed_at")
        if self.status is not ScanStatus.RUNNING and self.completed_at is None:
            raise ValueError("terminal scan metadata requires completed_at")

        frozen_configuration = _freeze_mapping(
            "scanner_configuration",
            self.scanner_configuration,
        )
        object.__setattr__(
            self,
            "scanner_configuration",
            frozen_configuration,
        )
        object.__setattr__(
            self,
            "tool_versions",
            _freeze_tool_versions(self.tool_versions),
        )
        if not isinstance(self.errors, tuple):
            raise TypeError("errors must be a tuple of strings")
        if any(
            not isinstance(error, str) or not error.strip() for error in self.errors
        ):
            raise ValueError("errors must contain only non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible metadata representation."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "normalized_domain": self.normalized_domain,
            "started_at": format_utc(self.started_at),
            "completed_at": (
                None if self.completed_at is None else format_utc(self.completed_at)
            ),
            "profile": self.profile,
            "scanner_configuration": _thaw_json(self.scanner_configuration),
            "tool_versions": dict(self.tool_versions),
            "status": self.status.value,
            "errors": list(self.errors),
        }


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _freeze_mapping(name: str, value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError(f"{name} must be a string-keyed mapping")
    return MappingProxyType(
        {str(key): _freeze_json(item, f"{name}.{key}") for key, item in value.items()}
    )


def _freeze_json(value: object, name: str) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{name} must contain only finite numbers")
        return value
    if isinstance(value, Mapping):
        return _freeze_mapping(name, value)
    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json(item, f"{name}[{index}]") for index, item in enumerate(value)
        )
    raise TypeError(f"{name} contains a non-JSON-compatible value")


def _freeze_tool_versions(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError("tool_versions must be a mapping")
    result: dict[str, str] = {}
    for tool, version in value.items():
        _require_text("tool name", tool)
        _require_text("tool version", version)
        result[tool] = version
    return MappingProxyType(result)


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class SeveritySummary:
    """Summary counts by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0
    total: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "unknown": self.unknown,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SeveritySummary:
        return cls(
            critical=int(data.get("critical", 0)),
            high=int(data.get("high", 0)),
            medium=int(data.get("medium", 0)),
            low=int(data.get("low", 0)),
            info=int(data.get("info", 0)),
            unknown=int(data.get("unknown", 0)),
            total=int(data.get("total", 0)),
        )


@dataclass(frozen=True, slots=True)
class AggregateScanReport:
    """The aggregate, report-ready scan assessment model."""

    metadata: ScanMetadata
    findings: tuple[Any, ...] = ()
    technologies: tuple[Any, ...] = ()
    services: tuple[Any, ...] = ()
    discovered_resources: tuple[Any, ...] = ()
    routing_decisions: tuple[Any, ...] = ()
    tool_statuses: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    severity_summary: SeveritySummary = field(default_factory=SeveritySummary)
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings
            ],
            "technologies": [
                t.to_dict() if hasattr(t, "to_dict") else t for t in self.technologies
            ],
            "services": [
                s.to_dict() if hasattr(s, "to_dict") else s for s in self.services
            ],
            "discovered_resources": [
                r.to_dict() if hasattr(r, "to_dict") else r
                for r in self.discovered_resources
            ],
            "routing_decisions": [
                d.to_dict() if hasattr(d, "to_dict") else d
                for d in self.routing_decisions
            ],
            "tool_statuses": dict(self.tool_statuses),
            "severity_summary": self.severity_summary.to_dict(),
            "errors": list(self.errors),
        }


__all__ = [
    "AggregateScanReport",
    "ScanMetadata",
    "ScanStatus",
    "SeveritySummary",
]
