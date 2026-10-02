"""Tests for safe passive HTTP header collection."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive.headers import (
    HeadersScanner,
    HttpRequestFailure,
    HttpRequestSpec,
    HttpResponseData,
)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


class FakeHttpClient:
    def __init__(self, *outcomes: HttpResponseData | Exception) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[HttpRequestSpec] = []

    async def get(self, request: HttpRequestSpec) -> HttpResponseData:
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def response(
    *,
    url: str = "https://example.com/",
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body_bytes: int = 128,
) -> HttpResponseData:
    return HttpResponseData(
        url=url,
        status_code=status,
        headers=headers,
        body_bytes=body_bytes,
    )


def scanner(
    tmp_path: Path,
    client: FakeHttpClient,
    *,
    target: str = "https://example.com/",
    config_overrides: dict[str, Any] | None = None,
) -> HeadersScanner:
    configuration = load_config(overrides=config_overrides)
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target(target),
        profile_name=configuration.profile.name,
        scanner_configuration={},
    )
    return HeadersScanner(
        configuration=configuration,
        context=context,
        client=client,
        time_provider=lambda: NOW,
    )


def test_success_uses_get_and_writes_selected_structured_headers(
    tmp_path: Path,
) -> None:
    client = FakeHttpClient(
        response(
            headers=(
                ("Content-Security-Policy", "default-src 'self'"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Server", "example"),
                ("X-Unselected", "not persisted"),
            )
        )
    )
    instance = scanner(
        tmp_path,
        client,
        config_overrides={
            "http": {
                "user_agent": "AuthorizedScanner/1.0",
                "max_response_bytes": 4096,
            },
            "timeouts": {"headers": 12},
        },
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert result.output_paths == ("passive/headers.json",)
    assert len(client.requests) == 1
    request = client.requests[0]
    assert request.method == "GET"
    assert request.headers["User-Agent"] == "AuthorizedScanner/1.0"
    assert request.timeout_seconds == 12
    assert request.max_response_bytes == 4096

    output_path = instance.context.scan_directory / result.output_paths[0]
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status_code"] == 200
    assert payload["headers"] == {
        "content-security-policy": "default-src 'self'",
        "server": "example",
        "strict-transport-security": "max-age=31536000",
    }
    assert payload["redirect_chain"] == []
    assert payload["body_bytes"] == 128


def test_redirect_chain_is_bounded_recorded_and_get_only(tmp_path: Path) -> None:
    client = FakeHttpClient(
        response(
            status=302,
            headers=(("Location", "/login"),),
        ),
        response(
            url="https://example.com/login",
            headers=(("X-Frame-Options", "DENY"),),
        ),
    )
    instance = scanner(tmp_path, client)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert [request.method for request in client.requests] == ["GET", "GET"]
    assert client.requests[1].url == "https://example.com/login"
    payload = json.loads(
        (instance.context.scan_directory / "passive" / "headers.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["final_url"] == "https://example.com/login"
    assert payload["redirect_chain"] == [
        {
            "location": "https://example.com/login",
            "status_code": 302,
            "url": "https://example.com/",
        }
    ]


def test_cookie_and_authorization_values_are_never_persisted(
    tmp_path: Path,
) -> None:
    secrets = ("session=private-cookie", "Bearer private-token")
    client = FakeHttpClient(
        response(
            headers=(
                ("Set-Cookie", secrets[0]),
                ("Set-Cookie", "other=second-cookie"),
                ("Authorization", secrets[1]),
                ("Content-Type", "text/html"),
            )
        )
    )
    instance = scanner(tmp_path, client)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    output = (instance.context.scan_directory / "passive" / "headers.json").read_text(
        encoding="utf-8"
    )
    payload = json.loads(output)
    assert payload["cookies"] == {
        "set_cookie_count": 2,
        "set_cookie_present": True,
    }
    assert "set-cookie" not in payload["headers"]
    assert "authorization" not in payload["headers"]
    for secret in (*secrets, "second-cookie"):
        assert secret not in output


@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_code"),
    [
        (
            HttpRequestFailure("timeout", "HTTP request timed out"),
            ScannerStatus.TIMED_OUT,
            "timeout",
        ),
        (
            HttpRequestFailure("response_too_large", "response too large"),
            ScannerStatus.FAILED,
            "response_too_large",
        ),
        (
            HttpRequestFailure("tls_error", "TLS verification failed"),
            ScannerStatus.FAILED,
            "tls_error",
        ),
        (
            HttpRequestFailure("network_error", "HTTP request failed"),
            ScannerStatus.FAILED,
            "network_error",
        ),
    ],
)
def test_network_failures_return_controlled_results_without_artifacts(
    tmp_path: Path,
    failure: HttpRequestFailure,
    expected_status: ScannerStatus,
    expected_code: str,
) -> None:
    client = FakeHttpClient(failure)
    instance = scanner(tmp_path, client)

    result = asyncio.run(instance.run())

    assert result.status is expected_status
    assert result.errors[0].code == expected_code
    assert result.output_paths == ()
    assert not (instance.context.scan_directory / "passive" / "headers.json").exists()


def test_redirect_limit_returns_controlled_failure(tmp_path: Path) -> None:
    client = FakeHttpClient(
        response(status=302, headers=(("Location", "/one"),)),
    )
    instance = scanner(
        tmp_path,
        client,
        config_overrides={"http": {"max_redirects": 0}},
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "redirect_limit"
    assert len(client.requests) == 1


def test_cross_host_redirect_is_not_requested(tmp_path: Path) -> None:
    client = FakeHttpClient(
        response(
            status=302,
            headers=(("Location", "https://outside.example.net/"),),
        )
    )
    instance = scanner(tmp_path, client)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "out_of_scope_redirect"
    assert len(client.requests) == 1


def test_disabled_scanner_skips_without_http_request(tmp_path: Path) -> None:
    client = FakeHttpClient()
    instance = scanner(
        tmp_path,
        client,
        config_overrides={"scanners": {"headers": {"enabled": False}}},
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SKIPPED
    assert client.requests == []
