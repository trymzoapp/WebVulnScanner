"""Typed scanner execution result models."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from webvulnscanner.models.finding import Finding
from webvulnscanner.models.technology import Technology


class ScannerStatus(str, Enum):
    """Terminal state of one scanner execution."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class ScanError:
    """A safe, structured scanner error suitable for reports and metadata."""

    code: str
    message: str
    recoverable: bool = True

    def __post_init__(self) -> None:
        _require_text("error code", self.code)
        _require_text("error message", self.message)
        if not isinstance(self.recoverable, bool):
            raise TypeError("recoverable must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "recoverable": self.recoverable,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanError:
        _require_exact_keys(data, {"code", "message", "recoverable"}, "scan error")
        return cls(
            code=data["code"],
            message=data["message"],
            recoverable=data["recoverable"],
        )


@dataclass(frozen=True, slots=True)
class SubprocessDetails:
    """Bounded, pre-redacted details from an external-tool execution."""

    duration_seconds: float
    exit_code: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ):
            raise TypeError("duration_seconds must be a number")
        duration = float(self.duration_seconds)
        if not math.isfinite(duration) or duration < 0:
            raise ValueError("duration_seconds must be finite and non-negative")
        object.__setattr__(self, "duration_seconds", duration)
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise TypeError("exit_code must be an integer or None")
        if not isinstance(self.timed_out, bool):
            raise TypeError("timed_out must be a boolean")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SubprocessDetails:
        _require_exact_keys(
            data,
            {"duration_seconds", "exit_code", "timed_out", "stdout", "stderr"},
            "subprocess details",
        )
        return cls(
            duration_seconds=data["duration_seconds"],
            exit_code=data["exit_code"],
            timed_out=data["timed_out"],
            stdout=data["stdout"],
            stderr=data["stderr"],
        )


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The complete, JSON-serializable outcome of one scanner execution."""

    scanner: str
    status: ScannerStatus
    started_at: datetime
    completed_at: datetime
    output_paths: tuple[str, ...] = ()
    findings: tuple[Finding, ...] = ()
    technologies: tuple[Technology, ...] = ()
    errors: tuple[ScanError, ...] = ()
    subprocess_details: SubprocessDetails | None = None
    skip_reason: str | None = None
    artifacts: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        _require_text("scanner", self.scanner)
        if not isinstance(self.status, ScannerStatus):
            raise TypeError("status must be a ScannerStatus")
        started_at = _as_utc("started_at", self.started_at)
        completed_at = _as_utc("completed_at", self.completed_at)
        if completed_at < started_at:
            raise ValueError("completed_at must not precede started_at")
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "completed_at", completed_at)

        _require_text_tuple("output_paths", self.output_paths)
        _require_model_tuple("findings", self.findings, Finding)
        _require_model_tuple("technologies", self.technologies, Technology)
        _require_model_tuple("errors", self.errors, ScanError)
        if self.subprocess_details is not None and not isinstance(
            self.subprocess_details, SubprocessDetails
        ):
            raise TypeError("subprocess_details must be SubprocessDetails or None")
        if self.skip_reason is not None:
            _require_text("skip_reason", self.skip_reason)
        object.__setattr__(
            self,
            "artifacts",
            _freeze_artifact_mapping(self.artifacts),
        )

        if self.status is ScannerStatus.SUCCESS:
            if self.errors:
                raise ValueError("successful scan results cannot contain errors")
            if self.skip_reason is not None:
                raise ValueError("successful scan results cannot have a skip reason")
        elif self.status is ScannerStatus.SKIPPED:
            if self.skip_reason is None:
                raise ValueError("skipped scan results require a skip reason")
            if self.errors or self.findings or self.technologies:
                raise ValueError("skipped scan results cannot contain results or errors")
            if self.subprocess_details is not None:
                raise ValueError("skipped scan results cannot contain subprocess details")
        else:
            if not self.errors:
                raise ValueError("failed, timed-out, or cancelled results require an error")
            if self.skip_reason is not None:
                raise ValueError("non-skipped scan results cannot have a skip reason")

        if (
            self.status is ScannerStatus.TIMED_OUT
            and self.subprocess_details is not None
            and not self.subprocess_details.timed_out
        ):
            raise ValueError("timed-out result has inconsistent subprocess details")

    @property
    def duration_seconds(self) -> float:
        """Return total scanner duration."""
        return (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "scanner": self.scanner,
            "status": self.status.value,
            "started_at": _format_datetime(self.started_at),
            "completed_at": _format_datetime(self.completed_at),
            "duration_seconds": self.duration_seconds,
            "output_paths": list(self.output_paths),
            "findings": [finding.to_dict() for finding in self.findings],
            "technologies": [
                technology.to_dict() for technology in self.technologies
            ],
            "errors": [error.to_dict() for error in self.errors],
            "subprocess_details": (
                None
                if self.subprocess_details is None
                else self.subprocess_details.to_dict()
            ),
            "skip_reason": self.skip_reason,
            "artifacts": _thaw_artifact(self.artifacts),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanResult:
        """Build a scan result from its JSON-compatible representation."""
        _require_exact_keys(
            data,
            {
                "scanner",
                "status",
                "started_at",
                "completed_at",
                "duration_seconds",
                "output_paths",
                "findings",
                "technologies",
                "errors",
                "subprocess_details",
                "skip_reason",
                "artifacts",
            },
            "scan result",
        )
        subprocess_data = data["subprocess_details"]
        subprocess_details = (
            None
            if subprocess_data is None
            else SubprocessDetails.from_dict(_require_mapping(subprocess_data))
        )
        result = cls(
            scanner=data["scanner"],
            status=ScannerStatus(data["status"]),
            started_at=_parse_datetime("started_at", data["started_at"]),
            completed_at=_parse_datetime("completed_at", data["completed_at"]),
            output_paths=_json_text_list("output_paths", data["output_paths"]),
            findings=tuple(
                Finding.from_dict(_require_mapping(item))
                for item in _require_json_list("findings", data["findings"])
            ),
            technologies=tuple(
                Technology.from_dict(_require_mapping(item))
                for item in _require_json_list("technologies", data["technologies"])
            ),
            errors=tuple(
                ScanError.from_dict(_require_mapping(item))
                for item in _require_json_list("errors", data["errors"])
            ),
            subprocess_details=subprocess_details,
            skip_reason=data["skip_reason"],
            artifacts=_require_mapping(data["artifacts"]),
        )
        serialized_duration = data["duration_seconds"]
        if isinstance(serialized_duration, bool) or not isinstance(
            serialized_duration, (int, float)
        ):
            raise TypeError("duration_seconds must be a JSON number")
        if not math.isclose(
            float(serialized_duration),
            result.duration_seconds,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            raise ValueError("duration_seconds does not match scan timestamps")
        return result


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_text_tuple(name: str, values: object) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be a tuple of strings")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{name} must contain only non-empty strings")


def _require_model_tuple(
    name: str,
    values: object,
    model_type: type[object],
) -> None:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be a tuple")
    if any(not isinstance(value, model_type) for value in values):
        raise TypeError(f"{name} contains an invalid model")


def _as_utc(name: str, value: object) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be an ISO-8601 string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be a valid ISO-8601 timestamp") from error


def _require_exact_keys(
    data: Mapping[str, Any],
    expected: set[str],
    model_name: str,
) -> None:
    if not isinstance(data, Mapping):
        raise TypeError(f"serialized {model_name} must be a mapping")
    if set(data) != expected:
        raise ValueError(
            f"serialized {model_name} fields do not match the expected schema"
        )


def _require_mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("nested model must be a JSON object")
    return value


def _require_json_list(name: str, value: object) -> list[Any]:
    if not isinstance(value, list):
        raise TypeError(f"{name} must be a JSON array")
    return value


def _json_text_list(name: str, value: object) -> tuple[str, ...]:
    values = tuple(_require_json_list(name, value))
    _require_text_tuple(name, values)
    return values


def _freeze_artifact_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise TypeError("artifacts must be a string-keyed mapping")
    return MappingProxyType(
        {str(key): _freeze_artifact(item) for key, item in value.items()}
    )


def _freeze_artifact(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("artifacts must contain finite numbers")
        return value
    if isinstance(value, Mapping):
        return _freeze_artifact_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_artifact(item) for item in value)
    raise TypeError("artifacts contain a non-JSON-compatible value")


def _thaw_artifact(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_artifact(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_artifact(item) for item in value]
    return value


__all__ = [
    "RoutingDecision",
    "ScanError",
    "ScanResult",
    "ScannerStatus",
    "SubprocessDetails",
]


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """An explainable, typed dynamic routing decision for a scanner."""

    scanner: str
    enabled: bool
    reason: str
    source: str
    rule_id: str
    matched_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("scanner", self.scanner)
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")
        _require_text("reason", self.reason)
        _require_text("source", self.source)
        _require_text("rule_id", self.rule_id)
        _require_text_tuple("matched_evidence", self.matched_evidence)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "scanner": self.scanner,
            "enabled": self.enabled,
            "reason": self.reason,
            "source": self.source,
            "rule_id": self.rule_id,
            "matched_evidence": list(self.matched_evidence),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RoutingDecision:
        """Build a routing decision from its JSON-compatible representation."""
        expected = {
            "scanner",
            "enabled",
            "reason",
            "source",
            "rule_id",
            "matched_evidence",
        }
        _require_exact_keys(data, expected, "routing decision")
        enabled = data["enabled"]
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")
        return cls(
            scanner=data["scanner"],
            enabled=enabled,
            reason=data["reason"],
            source=data["source"],
            rule_id=data["rule_id"],
            matched_evidence=_json_text_list(
                "matched_evidence", data["matched_evidence"]
            ),
        )

