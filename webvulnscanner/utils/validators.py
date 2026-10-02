"""Validation and normalization helpers for explicit scan targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

from webvulnscanner.core.exceptions import TargetValidationError

TargetKindValue = Literal["hostname", "ipv4", "ipv6"]

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SUPPORTED_SCHEMES = frozenset({"http", "https"})
_UNSAFE_INPUT = re.compile(r"[\x00-\x20\x7f\\;\|`$<>]")


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """Validated target components used to construct the public target model."""

    original: str
    url: str
    scheme: Literal["http", "https"]
    host: str
    port: int | None
    normalized_domain: str
    kind: TargetKindValue


def validate_target(
    value: str,
    *,
    default_scheme: str = "https",
) -> ValidatedTarget:
    """Validate and canonicalize one HTTP(S), hostname, IPv4, or IPv6 target."""
    if not isinstance(value, str) or not value:
        raise _invalid("target must be a non-empty string")
    if value.strip().startswith("-"):
        raise _invalid("target must not start with a hyphen or CLI flag")
    if _UNSAFE_INPUT.search(value):
        raise _invalid("target contains whitespace, control characters, or backslashes")

    scheme = default_scheme.casefold()
    if scheme not in _SUPPORTED_SCHEMES:
        raise _invalid("default scheme must be either http or https")

    raw_ip = _parse_ip(value)
    if raw_ip is not None:
        return _build_ip_target(value, raw_ip, scheme)

    candidate = value if "://" in value else f"{scheme}://{value}"
    parsed = _split_url(candidate)
    parsed_scheme_value = parsed.scheme.casefold()
    if parsed_scheme_value not in _SUPPORTED_SCHEMES:
        raise _invalid("only http and https targets are supported")
    parsed_scheme = cast(Literal["http", "https"], parsed_scheme_value)
    if not parsed.netloc or parsed.hostname is None:
        raise _invalid("target must include a valid hostname or IP address")
    if parsed.username is not None or parsed.password is not None:
        raise _invalid("credentials must not be embedded in a target URL")

    port = _validated_port(parsed)
    canonical_host, kind = _canonicalize_host(parsed.hostname)
    netloc = _format_netloc(canonical_host, kind, port)
    path = parsed.path or "/"
    canonical_url = urlunsplit((parsed_scheme, netloc, path, parsed.query, ""))

    return ValidatedTarget(
        original=value,
        url=canonical_url,
        scheme=parsed_scheme,
        host=canonical_host,
        port=port,
        normalized_domain=_filesystem_name(canonical_host, kind),
        kind=kind,
    )


def _split_url(value: str) -> SplitResult:
    try:
        return urlsplit(value)
    except ValueError as error:
        raise _invalid("target URL is malformed", cause=error) from error


def _validated_port(parsed: SplitResult) -> int | None:
    try:
        port = parsed.port
    except ValueError as error:
        raise _invalid(
            "target port is malformed or outside 1-65535", cause=error
        ) from error
    if port is not None and not 1 <= port <= 65535:
        raise _invalid("target port must be between 1 and 65535")
    return port


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and "%" in value:
        raise _invalid("scoped IPv6 addresses are not supported")
    return address


def _canonicalize_host(host: str) -> tuple[str, TargetKindValue]:
    if "%" in host:
        raise _invalid("scoped IPv6 addresses are not supported")

    address = _parse_ip(host)
    if isinstance(address, ipaddress.IPv4Address):
        return str(address), "ipv4"
    if isinstance(address, ipaddress.IPv6Address):
        return address.compressed.casefold(), "ipv6"

    return _canonicalize_hostname(host), "hostname"


def _canonicalize_hostname(host: str) -> str:
    hostname = host.removesuffix(".")
    if not hostname:
        raise _invalid("hostname must not be empty")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError as error:
        raise _invalid(
            "hostname contains invalid internationalized characters", cause=error
        ) from error

    if len(ascii_hostname) > 253:
        raise _invalid("hostname exceeds 253 characters")
    labels = ascii_hostname.split(".")
    if any(not label for label in labels):
        raise _invalid("hostname contains an empty label")
    if all(label.isdigit() for label in labels) and len(labels) == 4:
        raise _invalid("numeric dotted target is not a valid IPv4 address")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise _invalid("hostname contains an invalid DNS label")
    return ascii_hostname


def _build_ip_target(
    original: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    scheme: str,
) -> ValidatedTarget:
    host = str(address).casefold()
    kind: TargetKindValue = (
        "ipv4" if isinstance(address, ipaddress.IPv4Address) else "ipv6"
    )
    netloc = _format_netloc(host, kind, None)
    supported_scheme = cast(Literal["http", "https"], scheme)
    return ValidatedTarget(
        original=original,
        url=urlunsplit((supported_scheme, netloc, "/", "", "")),
        scheme=supported_scheme,
        host=host,
        port=None,
        normalized_domain=_filesystem_name(host, kind),
        kind=kind,
    )


def _format_netloc(host: str, kind: TargetKindValue, port: int | None) -> str:
    rendered_host = f"[{host}]" if kind == "ipv6" else host
    return rendered_host if port is None else f"{rendered_host}:{port}"


def _filesystem_name(host: str, kind: TargetKindValue) -> str:
    if kind == "ipv6":
        # Underscores cannot occur in a validated hostname, keeping this namespace
        # distinct while replacing Windows-invalid colons.
        return f"ipv6__{host.replace(':', '-')}"
    return host


def _invalid(
    message: str,
    *,
    cause: BaseException | None = None,
) -> TargetValidationError:
    return TargetValidationError(
        message,
        component="target",
        operation="validate",
        cause=cause,
    )


__all__ = ["ValidatedTarget", "validate_target"]
