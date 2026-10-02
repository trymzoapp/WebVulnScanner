"""Tests for passive WHOIS registration collection."""

import asyncio
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive.whois import (
    WhoisFailure,
    WhoisRecord,
    WhoisScanner,
)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


class FakeWhoisClient:
    def __init__(self, outcome: WhoisRecord | Exception) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, float]] = []

    async def lookup(self, domain: str, *, timeout: float) -> WhoisRecord:
        self.calls.append((domain, timeout))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def scanner(
    tmp_path: Path,
    client: FakeWhoisClient,
    target: str = "example.com",
) -> WhoisScanner:
    configuration = load_config()
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target(target),
        profile_name="safe",
        scanner_configuration={},
    )
    return WhoisScanner(
        configuration=configuration,
        context=context,
        client=client,
        time_provider=lambda: NOW,
    )


def test_success_normalizes_registration_fields(tmp_path: Path) -> None:
    client = FakeWhoisClient(
        WhoisRecord(
            registrar=" Example Registrar ",
            created_at=datetime(
                2020,
                1,
                1,
                5,
                30,
                tzinfo=timezone(timedelta(hours=5, minutes=30)),
            ),
            updated_at="2026-01-02T03:04:05Z",
            expires_at="2030-01-01",
            statuses=("clientTransferProhibited", "clientTransferProhibited"),
            nameservers=("NS1.EXAMPLE.COM.", "ns2.example.com"),
        )
    )
    instance = scanner(tmp_path, client)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert client.calls == [("example.com", 60.0)]
    payload = json.loads(
        (instance.context.scan_directory / "passive" / "whois.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["registrar"] == "Example Registrar"
    assert payload["created_at"] == "2020-01-01T00:00:00Z"
    assert payload["updated_at"] == "2026-01-02T03:04:05Z"
    assert payload["expires_at"] == "2030-01-01T00:00:00Z"
    assert payload["statuses"] == ["clientTransferProhibited"]
    assert payload["nameservers"] == ["ns1.example.com", "ns2.example.com"]


def test_missing_fields_are_serialized_explicitly(tmp_path: Path) -> None:
    instance = scanner(tmp_path, FakeWhoisClient(WhoisRecord()))

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    payload = json.loads(
        (instance.context.scan_directory / "passive" / "whois.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["registrar"] is None
    assert payload["created_at"] is None
    assert payload["statuses"] == []
    assert payload["nameservers"] == []


@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_code"),
    [
        (
            WhoisFailure("timeout", "WHOIS lookup timed out"),
            ScannerStatus.TIMED_OUT,
            "timeout",
        ),
        (
            WhoisFailure("lookup_failed", "WHOIS lookup failed"),
            ScannerStatus.FAILED,
            "lookup_failed",
        ),
    ],
)
def test_raw_lookup_failures_are_controlled(
    tmp_path: Path,
    failure: Exception,
    expected_status: ScannerStatus,
    expected_code: str,
) -> None:
    instance = scanner(tmp_path, FakeWhoisClient(failure))

    result = asyncio.run(instance.run())

    assert result.status is expected_status
    assert result.errors[0].code == expected_code
    assert not (instance.context.scan_directory / "passive" / "whois.json").exists()


def test_malformed_record_returns_controlled_failure(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        FakeWhoisClient(WhoisRecord(created_at="not-a-date")),
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "malformed_response"


@pytest.mark.parametrize("target", ["192.0.2.1", "2001:db8::1"])
def test_ip_targets_are_skipped_without_lookup(
    tmp_path: Path,
    target: str,
) -> None:
    client = FakeWhoisClient(WhoisRecord())
    instance = scanner(tmp_path, client, target)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SKIPPED
    assert "not applicable" in (result.skip_reason or "")
    assert client.calls == []


def test_configured_command_contains_only_executable_and_domain(tmp_path: Path) -> None:
    instance = scanner(tmp_path, FakeWhoisClient(WhoisRecord()))

    command = instance.build_command()

    assert command is not None
    assert command.argv == ("whois", "example.com")
