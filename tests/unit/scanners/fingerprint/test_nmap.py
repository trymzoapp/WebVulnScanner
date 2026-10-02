"""Tests for constrained Nmap scanner behavior."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.fingerprint.nmap import NmapScanner
from webvulnscanner.utils.command import Command

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "nmap" / "web-services.xml"


def process(
    stdout: str = "",
    *,
    return_code: int | None = 0,
    timed_out: bool = False,
) -> SubprocessResult:
    return SubprocessResult(
        command=("nmap",),
        stdout=stdout,
        stderr="",
        return_code=return_code,
        duration_seconds=0.1,
        timed_out=timed_out,
    )


class FakeRunner:
    def __init__(self, *results: SubprocessResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[Command, float | None]] = []

    async def run(
        self, command: Command, *, timeout: float | None = None
    ) -> SubprocessResult:
        self.calls.append((command, timeout))
        return self.results.pop(0)


def scanner(tmp_path: Path, runner: FakeRunner) -> NmapScanner:
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("https://example.com"),
        profile_name="safe",
        scanner_configuration={},
    )
    return NmapScanner(
        configuration=load_config(),
        runner=runner,
        context=context,
        time_provider=lambda: NOW,
    )


def test_safe_command_and_xml_output_persistence(tmp_path: Path) -> None:
    runner = FakeRunner(
        process("Nmap 7.95"),
        process(FIXTURE.read_text(encoding="utf-8")),
    )
    instance = scanner(tmp_path, runner)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    command = runner.calls[1][0].argv
    assert command == (
        "nmap",
        "-n",
        "-Pn",
        "-sV",
        "--version-light",
        "-T2",
        "--host-timeout",
        "120s",
        "-p",
        "80,443,8080,8443",
        "-oX",
        "-",
        "example.com",
    )
    for prohibited in ("--script", "-O", "-sU", "-p-"):
        assert prohibited not in command
    assert result.artifacts["urls"] == (
        "http://example.com/",
        "https://example.com/",
    )
    payload = json.loads(
        (instance.context.scan_directory / "fingerprint" / "nmap.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(payload["web_services"]) == 2
    assert result.technologies[0].source == "nmap"


def test_timeout_and_nonzero_exit_are_controlled(tmp_path: Path) -> None:
    timed_out = scanner(
        tmp_path,
        FakeRunner(process("version"), process(return_code=None, timed_out=True)),
    )
    timeout_result = asyncio.run(timed_out.run())
    assert timeout_result.status is ScannerStatus.TIMED_OUT

    failed = scanner(
        tmp_path / "other",
        FakeRunner(process("version"), process(return_code=2)),
    )
    failed_result = asyncio.run(failed.run())
    assert failed_result.status is ScannerStatus.FAILED
    assert failed_result.errors[0].code == "nonzero_exit"


def test_malformed_xml_is_controlled(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        FakeRunner(process("version"), process("<broken")),
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "parse_failed"
