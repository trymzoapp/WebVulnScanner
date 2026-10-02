"""Bounded passive Wayback CDX URL collection."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import TargetValidationError
from webvulnscanner.models.scan_result import ScanError, ScannerStatus, ScanResult
from webvulnscanner.models.target import Target, TargetKind
from webvulnscanner.parsers.subfinder import registrable_domain
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import as_utc, utc_now


class WaybackFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WaybackClientProtocol(Protocol):
    async def fetch_page(
        self,
        *,
        endpoint: str,
        domain: str,
        page: int,
        page_size: int,
        timeout: float,
        max_response_bytes: int,
    ) -> tuple[str, ...]:
        """Return one structured archive page."""


class HttpxWaybackClient:
    """HTTPS CDX client with bounded structured response parsing."""

    async def fetch_page(
        self,
        *,
        endpoint: str,
        domain: str,
        page: int,
        page_size: int,
        timeout: float,
        max_response_bytes: int,
    ) -> tuple[str, ...]:
        try:
            async with (
                httpx.AsyncClient(
                    follow_redirects=False,
                    verify=True,
                ) as client,
                client.stream(
                    "GET",
                    endpoint,
                    params={
                        "url": f"{domain}/*",
                        "output": "json",
                        "fl": "original",
                        "collapse": "urlkey",
                        "filter": "statuscode:200",
                        "page": page,
                        "limit": page_size,
                    },
                    timeout=timeout,
                ) as response,
            ):
                if response.status_code != 200:
                    raise WaybackFailure(
                        "archive_error",
                        "Wayback endpoint returned an unsuccessful status",
                    )
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > max_response_bytes:
                        raise WaybackFailure(
                            "response_too_large",
                            "Wayback response exceeded the configured size limit",
                        )
        except WaybackFailure:
            raise
        except httpx.TimeoutException as error:
            raise WaybackFailure("timeout", "Wayback request timed out") from error
        except httpx.TransportError as error:
            raise WaybackFailure("network_error", "Wayback request failed") from error
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WaybackFailure(
                "malformed_response",
                "Wayback response was not valid JSON",
            ) from error
        if not isinstance(payload, list):
            raise WaybackFailure(
                "malformed_response",
                "Wayback response schema was invalid",
            )
        rows = payload[1:] if payload and payload[0] == ["original"] else payload
        urls: list[str] = []
        for row in rows:
            if not isinstance(row, list) or not row or not isinstance(row[0], str):
                raise WaybackFailure(
                    "malformed_response",
                    "Wayback response row was invalid",
                )
            urls.append(row[0])
        return tuple(urls)


class WaybackScanner:
    """Collect archived URLs without requesting any archived resource."""

    name = "wayback"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        context: ScanContext,
        client: WaybackClientProtocol | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.configuration = configuration
        self.context = context
        self.client = client or HttpxWaybackClient()
        self._sleep = sleep
        self._time_provider = time_provider
        self.scope_domain = registrable_domain(context.target.host)

    async def validate(self) -> None:
        self.configuration.scanner(self.name)

    def build_command(self, page: int) -> dict[str, object]:
        """Build structured endpoint parameters without an archived-path request."""
        return {
            "endpoint": self.configuration.wayback.endpoint,
            "domain": self.scope_domain,
            "page": page,
            "page_size": self.configuration.wayback.page_size,
        }

    def parse(
        self,
        raw_urls: list[str],
    ) -> dict[str, object]:
        accepted: set[str] = set()
        malformed_count = 0
        out_of_scope_count = 0
        duplicate_count = 0
        for raw_url in raw_urls:
            parsed = urlsplit(raw_url)
            if parsed.scheme.casefold() not in {"http", "https"}:
                malformed_count += 1
                continue
            try:
                target = Target(raw_url)
            except TargetValidationError:
                malformed_count += 1
                continue
            if target.kind is not TargetKind.HOSTNAME or not _in_scope(
                target.host,
                self.scope_domain,
            ):
                out_of_scope_count += 1
                continue
            if target.url in accepted:
                duplicate_count += 1
                continue
            accepted.add(target.url)

        urls = sorted(accepted)[: self.configuration.wayback.max_records]
        return {
            "scanner": self.name,
            "domain": self.scope_domain,
            "urls": urls,
            "query_urls": [url for url in urls if urlsplit(url).query],
            "count": len(urls),
            "malformed_count": malformed_count,
            "out_of_scope_count": out_of_scope_count,
            "duplicate_count": duplicate_count,
        }

    async def run(self) -> ScanResult:
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
            raw_urls = await self._collect_pages()
            payload = self.parse(raw_urls)
            output = atomic_write_json(
                self.context.stage_directory("passive") / "wayback.json",
                payload,
                storage_root=self.context.storage_root,
                overwrite=False,
            )
            return ScanResult(
                scanner=self.name,
                status=ScannerStatus.SUCCESS,
                started_at=started_at,
                completed_at=self._now(),
                output_paths=(
                    output.relative_to(self.context.scan_directory).as_posix(),
                ),
                artifacts={
                    "urls": payload["urls"],
                    "query_urls": payload["query_urls"],
                },
            )
        except asyncio.CancelledError:
            raise
        except WaybackFailure as error:
            status = (
                ScannerStatus.TIMED_OUT
                if error.code == "timeout"
                else ScannerStatus.FAILED
            )
            return ScanResult(
                scanner=self.name,
                status=status,
                started_at=started_at,
                completed_at=self._now(),
                errors=(ScanError(code=error.code, message=str(error)),),
            )

    async def _collect_pages(self) -> list[str]:
        collected: list[str] = []
        page_size = self.configuration.wayback.page_size
        max_pages = math.ceil(self.configuration.wayback.max_records / page_size) + 1
        rate = self.configuration.scanner(self.name).rate_limit_per_second
        for page in range(max_pages):
            page_urls = await self.client.fetch_page(
                endpoint=self.configuration.wayback.endpoint,
                domain=self.scope_domain,
                page=page,
                page_size=page_size,
                timeout=float(self.configuration.timeouts.for_scanner(self.name)),
                max_response_bytes=self.configuration.http.max_response_bytes,
            )
            collected.extend(page_urls)
            if len(collected) >= self.configuration.wayback.max_records:
                break
            if len(page_urls) < page_size:
                break
            await self._sleep(1.0 / rate)
        return collected[: self.configuration.wayback.max_records]

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="Wayback scanner timestamp")


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


__all__ = [
    "HttpxWaybackClient",
    "WaybackClientProtocol",
    "WaybackFailure",
    "WaybackScanner",
]
