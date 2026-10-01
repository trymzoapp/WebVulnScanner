"""Tests for bounded passive Wayback URL collection."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive.wayback import (
    WaybackFailure,
    WaybackScanner,
)


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class FakeWaybackClient:
    def __init__(self, *pages: tuple[str, ...] | Exception) -> None:
        self.pages = list(pages)
        self.calls: list[dict[str, Any]] = []

    async def fetch_page(self, **kwargs: Any) -> tuple[str, ...]:
        self.calls.append(kwargs)
        outcome = self.pages.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def scanner(
    tmp_path: Path,
    client: FakeWaybackClient,
    *,
    overrides: dict[str, Any] | None = None,
) -> tuple[WaybackScanner, list[float]]:
    configuration = load_config(overrides=overrides)
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("www.example.com"),
        profile_name="safe",
        scanner_configuration={},
    )
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    return (
        WaybackScanner(
            configuration=configuration,
            context=context,
            client=client,
            sleep=fake_sleep,
            time_provider=lambda: NOW,
        ),
        delays,
    )


def test_pagination_rate_limit_canonicalization_and_query_collection(
    tmp_path: Path,
) -> None:
    client = FakeWaybackClient(
        (
            "HTTP://Example.COM/path#fragment",
            "https://api.example.com/search?q=one",
        ),
        ("https://example.com/final",),
    )
    instance, delays = scanner(
        tmp_path,
        client,
        overrides={
            "wayback": {"page_size": 2, "max_records": 10},
            "scanners": {"wayback": {"rate_limit_per_second": 2.0}},
        },
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert len(client.calls) == 2
    assert delays == [0.5]
    assert all(
        call["endpoint"] == "https://web.archive.org/cdx/search/cdx"
        for call in client.calls
    )
    payload = json.loads(
        (
            instance.context.scan_directory / "passive" / "wayback.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["urls"] == [
        "http://example.com/path",
        "https://api.example.com/search?q=one",
        "https://example.com/final",
    ]
    assert payload["query_urls"] == [
        "https://api.example.com/search?q=one"
    ]


def test_malformed_duplicates_and_out_of_scope_urls_are_counted(
    tmp_path: Path,
) -> None:
    client = FakeWaybackClient(
        (
            "https://example.com/a",
            "https://example.com/a#duplicate",
            "ftp://example.com/file",
            "not a URL",
            "https://outside.example.net/a",
        )
    )
    instance, _ = scanner(
        tmp_path,
        client,
        overrides={"wayback": {"page_size": 10}},
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    payload = json.loads(
        (
            instance.context.scan_directory / "passive" / "wayback.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["urls"] == ["https://example.com/a"]
    assert payload["duplicate_count"] == 1
    assert payload["malformed_count"] == 2
    assert payload["out_of_scope_count"] == 1


def test_record_cap_bounds_collection_and_pagination(tmp_path: Path) -> None:
    client = FakeWaybackClient(
        (
            "https://example.com/1",
            "https://example.com/2",
            "https://example.com/3",
        ),
        ("https://example.com/never-requested",),
    )
    instance, delays = scanner(
        tmp_path,
        client,
        overrides={"wayback": {"page_size": 3, "max_records": 2}},
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert len(client.calls) == 1
    assert delays == []
    payload = json.loads(
        (
            instance.context.scan_directory / "passive" / "wayback.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["count"] == 2


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (
            WaybackFailure("timeout", "Wayback request timed out"),
            ScannerStatus.TIMED_OUT,
        ),
        (
            WaybackFailure("malformed_response", "invalid archive response"),
            ScannerStatus.FAILED,
        ),
        (
            WaybackFailure("network_error", "archive unavailable"),
            ScannerStatus.FAILED,
        ),
    ],
)
def test_archive_failures_are_controlled(
    tmp_path: Path,
    failure: Exception,
    expected_status: ScannerStatus,
) -> None:
    instance, _ = scanner(tmp_path, FakeWaybackClient(failure))

    result = asyncio.run(instance.run())

    assert result.status is expected_status
    assert result.output_paths == ()
    assert not (
        instance.context.scan_directory / "passive" / "wayback.json"
    ).exists()


def test_build_command_contains_only_archive_endpoint_parameters(
    tmp_path: Path,
) -> None:
    instance, _ = scanner(tmp_path, FakeWaybackClient(()))

    command = instance.build_command(3)

    assert command == {
        "endpoint": "https://web.archive.org/cdx/search/cdx",
        "domain": "example.com",
        "page": 3,
        "page_size": 500,
    }
