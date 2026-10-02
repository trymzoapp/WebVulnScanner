"""Passive, bounded WHOIS registration-data collection."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import WebVulnScannerError
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.scan_result import ScanError, ScannerStatus, ScanResult
from webvulnscanner.utils.command import Command
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import as_utc, format_utc, utc_now


@dataclass(frozen=True, slots=True)
class WhoisRecord:
    """Tool-independent WHOIS fields before scanner normalization."""

    registrar: str | None = None
    created_at: datetime | str | None = None
    updated_at: datetime | str | None = None
    expires_at: datetime | str | None = None
    statuses: tuple[str, ...] = ()
    nameservers: tuple[str, ...] = ()


class WhoisClientProtocol(Protocol):
    async def lookup(self, domain: str, *, timeout: float) -> WhoisRecord:
        """Return bounded registration data for one domain."""


class WhoisFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CommandWhoisClient:
    """WHOIS executable adapter using the common subprocess runner."""

    def __init__(
        self,
        runner: AsyncSubprocessRunner,
        executable: str,
    ) -> None:
        self.runner = runner
        self.executable = executable

    async def lookup(self, domain: str, *, timeout: float) -> WhoisRecord:
        try:
            result = await self.runner.run(
                Command(self.executable, (domain,)),
                timeout=timeout,
            )
        except WebVulnScannerError as error:
            raise WhoisFailure("tool_unavailable", str(error)) from error
        if result.timed_out:
            raise WhoisFailure("timeout", "WHOIS lookup timed out")
        if result.return_code != 0:
            raise WhoisFailure("lookup_failed", "WHOIS lookup failed")
        return _parse_common_whois(result.stdout)


class WhoisScanner:
    """Collect normalized registration data without querying IP targets."""

    name = "whois"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        context: ScanContext,
        client: WhoisClientProtocol | None = None,
        runner: AsyncSubprocessRunner | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.configuration = configuration
        self.context = context
        scanner_config = configuration.scanner(self.name)
        if client is None:
            if runner is None or scanner_config.executable is None:
                raise ValueError(
                    "WHOIS requires an injected client or configured runner"
                )
            client = CommandWhoisClient(runner, scanner_config.executable)
        self.client = client
        self._time_provider = time_provider

    async def validate(self) -> None:
        self.configuration.scanner(self.name)

    def build_command(self) -> Command | None:
        executable = self.configuration.scanner(self.name).executable
        return (
            None
            if executable is None
            else Command(executable, (self.context.target.host,))
        )

    def parse(self, record: WhoisRecord) -> dict[str, object]:
        if not isinstance(record, WhoisRecord):
            raise WhoisFailure("malformed_response", "WHOIS response was malformed")
        return {
            "scanner": self.name,
            "domain": self.context.target.host,
            "registrar": _optional_text(record.registrar),
            "created_at": _normalized_date(record.created_at),
            "updated_at": _normalized_date(record.updated_at),
            "expires_at": _normalized_date(record.expires_at),
            "statuses": _normalized_values(record.statuses, lowercase=False),
            "nameservers": _normalized_values(record.nameservers, lowercase=True),
        }

    async def run(self) -> ScanResult:
        started_at = self._now()
        if not self.configuration.scanner(self.name).enabled:
            return self._skipped(started_at, "scanner is disabled by configuration")
        if self.context.target.is_ip:
            return self._skipped(
                started_at,
                "WHOIS domain registration lookup is not applicable to IP targets",
            )
        try:
            await self.validate()
            record = await self.client.lookup(
                self.context.target.host,
                timeout=float(self.configuration.timeouts.for_scanner(self.name)),
            )
            payload = self.parse(record)
            output = atomic_write_json(
                self.context.stage_directory("passive") / "whois.json",
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
        except WhoisFailure as error:
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

    def _skipped(self, started_at: datetime, reason: str) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            status=ScannerStatus.SKIPPED,
            started_at=started_at,
            completed_at=self._now(),
            skip_reason=reason,
        )

    def _now(self) -> datetime:
        return as_utc(self._time_provider(), field_name="WHOIS scanner timestamp")


def _normalized_date(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return format_utc(value)
    if not isinstance(value, str) or not value.strip():
        raise WhoisFailure("malformed_response", "WHOIS date was malformed")
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise WhoisFailure("malformed_response", "WHOIS date was malformed") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return format_utc(parsed)


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise WhoisFailure("malformed_response", "WHOIS text field was malformed")
    return value.strip()


def _normalized_values(
    values: tuple[str, ...],
    *,
    lowercase: bool,
) -> list[str]:
    if not isinstance(values, tuple) or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise WhoisFailure("malformed_response", "WHOIS list field was malformed")
    normalized = [
        value.strip().removesuffix(".").casefold() if lowercase else value.strip()
        for value in values
    ]
    return list(dict.fromkeys(normalized))


def _parse_common_whois(raw: str) -> WhoisRecord:
    fields: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        fields.setdefault(key.strip().casefold(), []).append(value.strip())
    return WhoisRecord(
        registrar=_first(fields, "registrar"),
        created_at=_first(fields, "creation date", "created on", "created"),
        updated_at=_first(fields, "updated date", "last updated on", "updated"),
        expires_at=_first(
            fields,
            "registry expiry date",
            "expiration date",
            "expires on",
        ),
        statuses=tuple(fields.get("domain status", ())),
        nameservers=tuple(fields.get("name server", fields.get("nserver", ()))),
    )


def _first(fields: dict[str, list[str]], *names: str) -> str | None:
    for name in names:
        values = fields.get(name)
        if values:
            return values[0]
    return None


__all__ = [
    "CommandWhoisClient",
    "WhoisClientProtocol",
    "WhoisFailure",
    "WhoisRecord",
    "WhoisScanner",
]
