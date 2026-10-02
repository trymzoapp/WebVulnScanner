"""Integration tests verifying network boundaries, scope enforcement, and redirect containment."""

from __future__ import annotations

import json
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive.headers import HeadersScanner


class RedirectBoundaryHandler(BaseHTTPRequestHandler):
    """Serve specific HTTP redirect scenarios to test network scope boundaries."""

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/in-scope-redirect":
            self.send_response(302)
            self.send_header("Location", "/final-destination")
            self.end_headers()
            return

        if path == "/final-destination":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<h1>Landed safely</h1>")
            return

        if path == "/cross-domain-redirect":
            self.send_response(302)
            # Malicious redirect attempting to take scanner out of scope
            self.send_header(
                "Location", "https://unauthorized-evil-domain.com/token-leak"
            )
            self.end_headers()
            return

        if path == "/infinite-loop":
            self.send_response(302)
            self.send_header("Location", "/infinite-loop")
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


class BoundaryServer:
    """Threaded local server for boundary testing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), RedirectBoundaryHandler)
        self.host, self.port = self._server.server_address[:2]
        self.base_url = f"http://{self.host}:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)

    def __enter__(self) -> BoundaryServer:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()


@pytest.fixture
def boundary_server() -> Generator[BoundaryServer, None, None]:
    with BoundaryServer() as server:
        yield server


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cross_domain_redirect_is_blocked(
    boundary_server: BoundaryServer,
    tmp_path: Path,
) -> None:
    """Scanner must halt on cross-domain redirect and not access out-of-scope targets."""
    config = load_config()
    target_url = f"{boundary_server.base_url}/cross-domain-redirect"
    target = Target(target_url)

    context = create_scan_context(
        tmp_path / "runs",
        target,
        profile_name="safe",
        scanner_configuration={},
    )

    scanner = HeadersScanner(
        configuration=config,
        context=context,
    )

    result = await scanner.run()

    # The scanner should register a controlled failure/warning for out-of-scope redirect
    assert result.status == ScannerStatus.FAILED
    error_codes = [err.code for err in result.errors]
    assert "out_of_scope_redirect" in error_codes


@pytest.mark.integration
@pytest.mark.asyncio
async def test_in_scope_redirect_is_followed(
    boundary_server: BoundaryServer,
    tmp_path: Path,
) -> None:
    """Scanner should follow in-scope redirects on the authorized host."""
    config = load_config()
    target_url = f"{boundary_server.base_url}/in-scope-redirect"
    target = Target(target_url)

    context = create_scan_context(
        tmp_path / "runs",
        target,
        profile_name="safe",
        scanner_configuration={},
    )

    scanner = HeadersScanner(
        configuration=config,
        context=context,
    )

    result = await scanner.run()
    assert result.status == ScannerStatus.SUCCESS
    assert result.output_paths
    output_path = context.scan_directory / result.output_paths[0]
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload.get("status_code") == 200


@pytest.mark.integration
@pytest.mark.asyncio
async def test_redirect_limit_enforced(
    boundary_server: BoundaryServer,
    tmp_path: Path,
) -> None:
    """Redirect loops must be cleanly terminated according to max_redirects config."""
    config = load_config()
    target_url = f"{boundary_server.base_url}/infinite-loop"
    target = Target(target_url)

    context = create_scan_context(
        tmp_path / "runs",
        target,
        profile_name="safe",
        scanner_configuration={},
    )

    scanner = HeadersScanner(
        configuration=config,
        context=context,
    )

    result = await scanner.run()
    assert result.status == ScannerStatus.FAILED
    error_codes = [err.code for err in result.errors]
    assert "redirect_limit" in error_codes
