"""Typed content-discovery resource observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from webvulnscanner.models.target import Target


@dataclass(frozen=True, slots=True)
class DiscoveredResource:
    """One normalized in-scope web resource with scanner provenance."""

    url: str
    status_code: int
    source: str
    content_length: int | None = None

    def __post_init__(self) -> None:
        target = Target(self.url)
        object.__setattr__(self, "url", target.url)
        if isinstance(self.status_code, bool) or not isinstance(
            self.status_code, int
        ):
            raise TypeError("status_code must be an integer")
        if not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be between 100 and 599")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("source must be a non-empty string")
        if self.content_length is not None and (
            isinstance(self.content_length, bool)
            or not isinstance(self.content_length, int)
            or self.content_length < 0
        ):
            raise ValueError("content_length must be a non-negative integer or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "source": self.source,
            "content_length": self.content_length,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> DiscoveredResource:
        expected = {"url", "status_code", "source", "content_length"}
        if set(data) != expected:
            raise ValueError("serialized discovered resource fields do not match")
        return cls(
            url=data["url"],  # type: ignore[arg-type]
            status_code=data["status_code"],  # type: ignore[arg-type]
            source=data["source"],  # type: ignore[arg-type]
            content_length=data["content_length"],  # type: ignore[arg-type]
        )


__all__ = ["DiscoveredResource"]
