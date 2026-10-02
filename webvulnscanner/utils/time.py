"""UTC time helpers used by persisted scan metadata."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(UTC)


def as_utc(value: datetime, *, field_name: str = "timestamp") -> datetime:
    """Validate a timezone-aware datetime and normalize it to UTC."""
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def format_utc(value: datetime) -> str:
    """Serialize a timezone-aware datetime as an ISO-8601 UTC string."""
    return as_utc(value).isoformat().replace("+00:00", "Z")


__all__ = ["as_utc", "format_utc", "utc_now"]
