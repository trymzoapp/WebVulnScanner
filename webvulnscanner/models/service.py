"""Typed network service observations used by routing and discovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from webvulnscanner.models.target import Target


@dataclass(frozen=True, slots=True)
class WebService:
    """One open service associated with an explicitly requested target."""

    host: str
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    tunnel: str | None
    web_url: str | None

    def __post_init__(self) -> None:
        canonical_host = Target(self.host).host
        object.__setattr__(self, "host", canonical_host)
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65_535
        ):
            raise ValueError("service port must be between 1 and 65535")
        if self.protocol != "tcp":
            raise ValueError("only TCP service observations are supported")
        for name in ("service", "product", "version", "tunnel"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or not value.strip()
            ):
                raise ValueError(f"{name} must be a non-empty string or None")
        if self.web_url is not None:
            web_target = Target(self.web_url)
            if web_target.host != canonical_host:
                raise ValueError("web service URL must use the observed host")
            object.__setattr__(self, "web_url", web_target.url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "tunnel": self.tunnel,
            "web_url": self.web_url,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> WebService:
        expected = {
            "host",
            "port",
            "protocol",
            "service",
            "product",
            "version",
            "tunnel",
            "web_url",
        }
        if set(data) != expected:
            raise ValueError("serialized web service fields do not match")
        return cls(
            host=data["host"],  # type: ignore[arg-type]
            port=data["port"],  # type: ignore[arg-type]
            protocol=data["protocol"],  # type: ignore[arg-type]
            service=data["service"],  # type: ignore[arg-type]
            product=data["product"],  # type: ignore[arg-type]
            version=data["version"],  # type: ignore[arg-type]
            tunnel=data["tunnel"],  # type: ignore[arg-type]
            web_url=data["web_url"],  # type: ignore[arg-type]
        )


__all__ = ["WebService"]
