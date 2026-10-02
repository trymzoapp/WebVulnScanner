"""Tests for bounded robots.txt collection."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive.headers import (
    HttpRequestFailure,
    HttpRequestSpec,
    HttpResponseData,
)
from webvulnscanner.scanners.passive.robots import RobotsScanner

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


class FakeClient:
    def __init__(self, outcome: HttpResponseData | Exception) -> None:
        self.outcome = outcome
        self.requests: list[HttpRequestSpec] = []

    async def get(self, request: HttpRequestSpec) -> HttpResponseData:
        self.requests.append(request)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def make_scanner(
    tmp_path: Path,
    client: FakeClient,
    *,
    target: str = "https://example.com/path?query=1",
) -> RobotsScanner:
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
    return RobotsScanner(
        configuration=configuration,
        context=context,
        client=client,
        time_provider=lambda: NOW,
    )


def response(status: int, body: str = "", **headers: str) -> HttpResponseData:
    encoded = body.encode()
    return HttpResponseData(
        url="https://example.com/robots.txt",
        status_code=status,
        headers=tuple(headers.items()),
        body_bytes=len(encoded),
        body=encoded,
    )


def test_valid_robots_is_parsed_without_requesting_discovered_paths(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        response(
            200,
            """
            User-agent: *
            Disallow: /private
            Allow: /public
            Sitemap: https://example.com/sitemap.xml
            """,
        )
    )
    scanner = make_scanner(tmp_path, client)

    result = asyncio.run(scanner.run())

    assert result.status is ScannerStatus.SUCCESS
    assert len(client.requests) == 1
    assert client.requests[0].method == "GET"
    assert client.requests[0].url == "https://example.com/robots.txt"
    payload = json.loads(
        (scanner.context.scan_directory / "passive" / "robots.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["groups"] == [
        {
            "user_agents": ["*"],
            "allow": ["/public"],
            "disallow": ["/private"],
        }
    ]
    assert payload["sitemaps"] == ["https://example.com/sitemap.xml"]
    assert all(
        request.url != "https://example.com/private" for request in client.requests
    )


def test_malformed_lines_become_warnings_without_losing_valid_data(
    tmp_path: Path,
) -> None:
    client = FakeClient(
        response(
            200,
            "Disallow: /orphan\nbad line\nUser-agent: bot\nDisallow: /tmp\n",
        )
    )
    scanner = make_scanner(tmp_path, client)

    result = asyncio.run(scanner.run())

    assert result.status is ScannerStatus.SUCCESS
    payload = json.loads(
        (scanner.context.scan_directory / "passive" / "robots.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(payload["warnings"]) == 2
    assert payload["groups"][0]["disallow"] == ["/tmp"]


@pytest.mark.parametrize("status", [404, 410])
def test_missing_robots_is_successful_empty_result(
    tmp_path: Path,
    status: int,
) -> None:
    scanner = make_scanner(tmp_path, FakeClient(response(status)))

    result = asyncio.run(scanner.run())

    assert result.status is ScannerStatus.SUCCESS
    payload = json.loads(
        (scanner.context.scan_directory / "passive" / "robots.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["exists"] is False
    assert payload["groups"] == []
    assert payload["sitemaps"] == []


def test_redirect_is_not_followed(tmp_path: Path) -> None:
    client = FakeClient(response(302, "", Location="/other-robots.txt"))
    scanner = make_scanner(tmp_path, client)

    result = asyncio.run(scanner.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "redirect_not_followed"
    assert len(client.requests) == 1


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (
            HttpRequestFailure("timeout", "request timed out"),
            ScannerStatus.TIMED_OUT,
        ),
        (
            HttpRequestFailure("response_too_large", "response too large"),
            ScannerStatus.FAILED,
        ),
    ],
)
def test_bounded_request_failures_are_controlled(
    tmp_path: Path,
    failure: Exception,
    expected_status: ScannerStatus,
) -> None:
    scanner = make_scanner(tmp_path, FakeClient(failure))

    result = asyncio.run(scanner.run())

    assert result.status is expected_status
    assert not (scanner.context.scan_directory / "passive" / "robots.json").exists()
