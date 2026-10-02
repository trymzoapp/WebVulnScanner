"""Local HTTP fixture server for end-to-end integration tests."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class FixtureHandler(BaseHTTPRequestHandler):
    """Serve deterministic mock responses for passive recon and discovery."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress standard HTTP server logging during tests."""
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        host, port = self.server.server_address[:2]
        base_url = f"http://{host}:{port}"

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/8.2.0")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "max-age=3600")
            self.end_headers()
            self.wfile.write(
                b"<!DOCTYPE html><html><head><title>Test App</title></head><body><h1>Welcome</h1></body></html>"
            )
            return

        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            content = f"""User-agent: *
Disallow: /admin
Disallow: /secret
Allow: /public
Sitemap: {base_url}/sitemap.xml
"""
            self.wfile.write(content.encode("utf-8"))
            return

        if path == "/cdx":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            records = [
                ["original"],
                [f"{base_url}/search?q=test"],
                [f"{base_url}/items?category=books&id=42"],
            ]
            self.wfile.write(json.dumps(records).encode("utf-8"))
            return

        if path in {"/admin", "/login", "/dashboard", "/public"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<h1>{path.lstrip('/').title()} Page</h1>".encode())
            return

        if path in {"/search", "/items"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>Dynamic Resource</h1>")
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Not Found")


class FixtureServer:
    """Threaded local HTTP server lifecycle helper."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), FixtureHandler)
        self.host, self.port = self._server.server_address[:2]
        self.base_url = f"http://{self.host}:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)

    def __enter__(self) -> FixtureServer:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.stop()
