"""Tests for bounded Wappalyzer scanner execution."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.fingerprint.wappalyzer import WappalyzerScanner
from webvulnscanner.utils.command import Command


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def process(
    stdout: str = "",
    *,
    return_code: int | None = 0,
    timed_out: bool = False,
) -> SubprocessResult:
    return SubprocessResult(
        command=("wappalyzer",),
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


def scanner(tmp_path: Path, runner: FakeRunner) -> WappalyzerScanner:
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("https://example.com/path"),
        profile_name="safe",
        scanner_configuration={},
    )
    return WappalyzerScanner(
        configuration=load_config(),
        runner=runner,
        context=context,
        time_provider=lambda: NOW,
    )


def test_success_uses_literal_target_and_writes_json(tmp_path: Path) -> None:
    runner = FakeRunner(
        process("1.0"),
        process('{"technologies":[{"name":"nginx","confidence":100}]}'),
    )
    instance = scanner(tmp_path, runner)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert runner.calls[0][0].argv == ("wappalyzer", "--version")
    assert runner.calls[1][0].argv == (
        "wappalyzer",
        "https://example.com/path",
    )
    assert result.technologies[0].name == "nginx"
    payload = json.loads(
        (
            instance.context.scan_directory
            / "fingerprint"
            / "wappalyzer.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["count"] == 1


def test_empty_output_is_persisted_as_empty_result(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        FakeRunner(process("1.0"), process('{"technologies":[]}')),
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    assert result.technologies == ()


def test_malformed_output_is_controlled(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        FakeRunner(process("1.0"), process("not-json")),
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "parse_failed"


def test_timeout_is_controlled(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        FakeRunner(process("1.0"), process(timed_out=True, return_code=None)),
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.TIMED_OUT
