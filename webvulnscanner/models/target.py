"""Typed representation of a validated WebVulnScanner target."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from webvulnscanner.utils.validators import validate_target


class TargetKind(str, Enum):
    """Supported target address categories."""

    HOSTNAME = "hostname"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True, init=False)
class Target:
    """A canonical target safe to use as pipeline input.

    Construction always validates the supplied value. Target-derived filesystem paths
    must use ``normalized_domain`` rather than ``original`` or ``url``.
    """

    original: str
    url: str
    scheme: Literal["http", "https"]
    host: str
    port: int | None
    normalized_domain: str
    kind: TargetKind

    def __init__(self, value: str, *, default_scheme: str = "https") -> None:
        """Validate ``value`` and initialize immutable canonical target fields."""
        validated = validate_target(value, default_scheme=default_scheme)
        object.__setattr__(self, "original", validated.original)
        object.__setattr__(self, "url", validated.url)
        object.__setattr__(self, "scheme", validated.scheme)
        object.__setattr__(self, "host", validated.host)
        object.__setattr__(self, "port", validated.port)
        object.__setattr__(self, "normalized_domain", validated.normalized_domain)
        object.__setattr__(self, "kind", TargetKind(validated.kind))

    @property
    def is_ip(self) -> bool:
        """Return whether this target is an IPv4 or IPv6 address."""
        return self.kind in {TargetKind.IPV4, TargetKind.IPV6}


__all__ = ["Target", "TargetKind"]
