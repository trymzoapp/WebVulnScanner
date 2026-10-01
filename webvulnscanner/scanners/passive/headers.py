"""Safe passive collection of HTTP response and security headers."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urljoin

import httpx

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import (
    ScannerValidationError,
    TargetValidationError,
)
from webvulnscanner.models.scan_result import ScanError, ScanResult, ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import as_utc, utc_now


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SELECTED_HEADERS = frozenset(
    {
        "cache-control",
        "content-length",
        "content-security-policy",
        "content-type",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "location",
        "permissions-policy",
        "referrer-policy",
        "server",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "x-permitted-cross-domain-policies",
        "x-powered-by",
    }
)
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
    }
)


@dataclass(frozen=True, slots=True)
class HttpRequestSpec:
    """One immutable non-mutating HTTP request."""

    method: str
    url: str
    headers: Mapping[str, str]
    timeout_seconds: float
    max_response_bytes: int

    def __post_init__(self) -> None:
        if self.method != "GET":
            raise ValueError("headers scanner only supports GET requests")
        if not self.url:
            raise ValueError("request URL must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("request timeout must be positive")
        if self.max_response_bytes < 1:
            raise ValueError("response size cap must be positive")
        if not isinstance(self.headers, Mapping) or any(
            not isinstance(name, str)
            or not isinstance(value, str)
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in f"{name}{value}"
            )
            for name, value in self.headers.items()
        ):
            raise ValueError("request headers must be safe strings")
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True, slots=True)
class HttpResponseData:
    """Bounded response metadata returned by an injected HTTP client."""

    url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body_bytes: int
    body: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url:
            raise ValueError("response URL must be a non-empty string")
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise ValueError("response status must be an HTTP status code")
        if not isinstance(self.headers, tuple) or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(value, str) for value in item)
            for item in self.headers
        ):
            raise TypeError("response headers must be string pairs")
        if (
            isinstance(self.body_bytes, bool)
            or not isinstance(self.body_bytes, int)
            or self.body_bytes < 0
        ):
            raise ValueError("response body size must be a non-negative integer")
        if not isinstance(self.body, bytes):
            raise TypeError("response body must be bytes")


class HttpClientProtocol(Protocol):
    """Narrow asynchronous HTTP dependency used by the scanner."""

    async def get(self, request: HttpRequestSpec) -> HttpResponseData:
        """Perform one GET without automatically following redirects."""


class HttpRequestFailure(Exception):
    """Safe HTTP failure carrying a stable result code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class HttpxHeadersClient:
    """Production HTTP client with TLS verification and bounded streaming."""

    async def get(self, request: HttpRequestSpec) -> HttpResponseData:
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                verify=True,
            ) as client:
                async with client.stream(
                    request.method,
                    request.url,
                    headers=dict(request.headers),
                    timeout=request.timeout_seconds,
                ) as response:
                    body_bytes = 0
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body_bytes += len(chunk)
                        if body_bytes > request.max_response_bytes:
                            raise HttpRequestFailure(
                                "response_too_large",
                                "response exceeded the configured size limit",
                            )
                        body.extend(chunk)
                    return HttpResponseData(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=tuple(response.headers.multi_items()),
                        body_bytes=body_bytes,
                        body=bytes(body),
                    )
        except HttpRequestFailure:
            raise
        except httpx.TimeoutException as error:
            raise HttpRequestFailure(
                "timeout",
                "HTTP request exceeded its configured timeout",
            ) from error
        except httpx.TransportError as error:
            if _has_tls_cause(error):
                raise HttpRequestFailure(
                    "tls_error",
                    "TLS verification or negotiation failed",
                ) from error
            raise HttpRequestFailure(
                "network_error",
                "HTTP request failed",
            ) from error


@dataclass(frozen=True, slots=True)
class HeaderObservation:
    """Collected final response and redirect metadata."""

    initial_url: str
    final_response: HttpResponseData
    redirects: tuple[Mapping[str, object], ...]


class HeadersScanner:
    """Collect selected response headers using GET-only bounded requests."""

    name = "headers"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        context: ScanContext,
        client: HttpClientProtocol | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.configuration = configuration
        self.context = context
        self.client = client or HttpxHeadersClient()
        self._time_provider = time_provider

    async def validate(self) -> None:
        """Validate eligibility and required request limits."""
        scanner = self.configuration.scanner(self.name)
        if scanner.concurrency < 1:
            raise ScannerValidationError("headers concurrency must be positive")
        if self.context.target.scheme not in {"http", "https"}:
            raise ScannerValidationError("headers scanner requires an HTTP(S) target")

    def build_command(self, url: str | None = None) -> HttpRequestSpec:
        """Build one safe GET request specification."""
        return HttpRequestSpec(
            method="GET",
            url=self.context.target.url if url is None else url,
            headers={
                "User-Agent": self.configuration.http.user_agent,
                "Accept": "*/*",
            },
            timeout_seconds=float(
                self.configuration.timeouts.for_scanner(self.name)
            ),
            max_response_bytes=self.configuration.http.max_response_bytes,
        )

    def parse(self, observation: HeaderObservation) -> dict[str, object]:
        """Normalize selected headers and omit sensitive cookie values."""
        selected: dict[str, list[str]] = {}
        set_cookie_count = 0
        for raw_name, value in observation.final_response.headers:
            name = raw_name.casefold()
            if name == "set-cookie":
                set_cookie_count += 1
                continue
            if name in _SENSITIVE_HEADERS or name not in _SELECTED_HEADERS:
                continue
            selected.setdefault(name, []).append(value)

        return {
            "scanner": self.name,
            "target_url": observation.initial_url,
            "final_url": observation.final_response.url,
            "status_code": observation.final_response.status_code,
            "redirect_chain": [dict(item) for item in observation.redirects],
            "headers": {
                name: ", ".join(values) for name, values in sorted(selected.items())
            },
            "cookies": {
                "set_cookie_present": set_cookie_count > 0,
                "set_cookie_count": set_cookie_count,
            },
            "body_bytes": observation.final_response.body_bytes,
        }

    async def run(self) -> ScanResult:
        """Run the bounded GET/redirect lifecycle and persist structured JSON."""
        started_at = self._now()
        if not self.configuration.scanner(self.name).enabled:
            return ScanResult(
                scanner=self.name,
                status=ScannerStatus.SKIPPED,
                started_at=started_at,
                completed_at=self._now(),
                skip_reason="scanner is disabled by configuration",
            )
        try:
            await self.validate()
            observation = await self._collect()
            parsed = self.parse(observation)
            output_path = atomic_write_json(
                self.context.stage_directory("passive") / "headers.json",
                parsed,
                storage_root=self.context.storage_root,
                overwrite=False,
            )
            relative_path = output_path.relative_to(
                self.context.scan_directory
            ).as_posix()
            return ScanResult(
                scanner=self.name,
                status=ScannerStatus.SUCCESS,
                started_at=started_at,
                completed_at=self._now(),
                output_paths=(relative_path,),
            )
        except asyncio.CancelledError:
            raise
        except HttpRequestFailure as error:
            status = (
                ScannerStatus.TIMED_OUT
                if error.code == "timeout"
                else ScannerStatus.FAILED
            )
            return self._failed(started_at, status, error.code, str(error))
        except ScannerValidationError as error:
            return self._failed(
                started_at,
                ScannerStatus.FAILED,
                "validation_failed",
                str(error),
            )

    async def _collect(self) -> HeaderObservation:
        current_url = self.context.target.url
        redirects: list[Mapping[str, object]] = []
        while True:
            response = await self.client.get(self.build_command(current_url))
            location = _header_value(response.headers, "location")
            if response.status_code not in _REDIRECT_STATUSES or location is None:
                return HeaderObservation(
                    initial_url=self.context.target.url,
                    final_response=response,
                    redirects=tuple(redirects),
                )
            if len(redirects) >= self.configuration.http.max_redirects:
                raise HttpRequestFailure(
                    "redirect_limit",
                    "response exceeded the configured redirect limit",
                )
            next_url = urljoin(response.url, location)
            try:
                next_target = Target(next_url)
            except TargetValidationError as error:
                raise HttpRequestFailure(
                    "invalid_redirect",
                    "response contained an invalid redirect target",
                ) from error
            if next_target.host != self.context.target.host:
                raise HttpRequestFailure(
                    "out_of_scope_redirect",
                    "redirect target is outside the authorized host scope",
                )
            redirects.append(
                {
                    "url": response.url,
                    "status_code": response.status_code,
                    "location": next_target.url,
                }
            )
            current_url = next_target.url

    def _failed(
        self,
        started_at: datetime,
        status: ScannerStatus,
        code: str,
        message: str,
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            status=status,
            started_at=started_at,
            completed_at=self._now(),
            errors=(ScanError(code=code, message=message),),
        )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="headers scanner timestamp")


def _header_value(
    headers: tuple[tuple[str, str], ...],
    requested_name: str,
) -> str | None:
    for name, value in headers:
        if name.casefold() == requested_name:
            return value
    return None


def _has_tls_cause(error: BaseException) -> bool:
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        if isinstance(current, ssl.SSLError):
            return True
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return False


__all__ = [
    "HeaderObservation",
    "HeadersScanner",
    "HttpClientProtocol",
    "HttpRequestFailure",
    "HttpRequestSpec",
    "HttpResponseData",
    "HttpxHeadersClient",
]
