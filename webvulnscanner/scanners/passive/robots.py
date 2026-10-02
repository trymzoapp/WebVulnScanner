"""Safe retrieval and parsing of a target origin's robots.txt."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.models.scan_result import ScanError, ScannerStatus, ScanResult
from webvulnscanner.scanners.passive.headers import (
    HttpClientProtocol,
    HttpRequestFailure,
    HttpRequestSpec,
    HttpResponseData,
    HttpxHeadersClient,
)
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import as_utc, utc_now


class RobotsScanner:
    """Retrieve one bounded robots.txt without requesting discovered paths."""

    name = "robots"

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
        """Validate the configured scanner before network access."""
        self.configuration.scanner(self.name)

    def build_command(self) -> HttpRequestSpec:
        """Build the single allowed robots.txt GET request."""
        target = urlsplit(self.context.target.url)
        robots_url = urlunsplit((target.scheme, target.netloc, "/robots.txt", "", ""))
        return HttpRequestSpec(
            method="GET",
            url=robots_url,
            headers={
                "User-Agent": self.configuration.http.user_agent,
                "Accept": "text/plain,*/*;q=0.1",
            },
            timeout_seconds=float(self.configuration.timeouts.for_scanner(self.name)),
            max_response_bytes=self.configuration.http.max_response_bytes,
        )

    def parse(self, response: HttpResponseData) -> dict[str, object]:
        """Parse user-agent groups and sitemap directives."""
        if response.status_code in {404, 410}:
            return _empty_result(response, exists=False)

        groups: list[dict[str, list[str]]] = []
        sitemaps: list[str] = []
        warnings: list[str] = []
        current: dict[str, list[str]] | None = None
        for line_number, raw_line in enumerate(
            response.body.decode("utf-8", errors="replace").splitlines(),
            start=1,
        ):
            line = raw_line.split("#", maxsplit=1)[0].strip()
            if not line:
                continue
            if ":" not in line:
                warnings.append(f"line {line_number}: missing directive separator")
                continue
            key, value = (part.strip() for part in line.split(":", maxsplit=1))
            directive = key.casefold()
            if directive == "user-agent":
                if current is None or current["allow"] or current["disallow"]:
                    current = {
                        "user_agents": [],
                        "allow": [],
                        "disallow": [],
                    }
                    groups.append(current)
                if value:
                    current["user_agents"].append(value)
                else:
                    warnings.append(f"line {line_number}: empty user-agent")
            elif directive in {"allow", "disallow"}:
                if current is None:
                    warnings.append(
                        f"line {line_number}: {directive} without user-agent"
                    )
                else:
                    current[directive].append(value)
            elif directive == "sitemap":
                if value:
                    sitemaps.append(value)
                else:
                    warnings.append(f"line {line_number}: empty sitemap")

        return {
            "scanner": "robots",
            "url": response.url,
            "status_code": response.status_code,
            "exists": True,
            "groups": groups,
            "sitemaps": list(dict.fromkeys(sitemaps)),
            "warnings": warnings,
            "body_bytes": response.body_bytes,
        }

    async def run(self) -> ScanResult:
        """Retrieve, parse, and atomically persist robots.txt metadata."""
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
            response = await self.client.get(self.build_command())
            if 300 <= response.status_code < 400:
                raise HttpRequestFailure(
                    "redirect_not_followed",
                    "robots.txt redirect was not followed",
                )
            payload = self.parse(response)
            output = atomic_write_json(
                self.context.stage_directory("passive") / "robots.json",
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
            )
        except asyncio.CancelledError:
            raise
        except HttpRequestFailure as error:
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

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="robots scanner timestamp")


def _empty_result(
    response: HttpResponseData,
    *,
    exists: bool,
) -> dict[str, object]:
    return {
        "scanner": "robots",
        "url": response.url,
        "status_code": response.status_code,
        "exists": exists,
        "groups": [],
        "sitemaps": [],
        "warnings": [],
        "body_bytes": response.body_bytes,
    }


__all__ = ["RobotsScanner"]
