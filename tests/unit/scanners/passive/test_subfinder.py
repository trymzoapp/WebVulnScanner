"""Tests for the structured Subfinder scanner."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.passive.subfinder import SubfinderScanner
from webvulnscanner.utils.command import Command

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "subfinder" / "mixed.jsonl"


def result(
    stdout: str = "",
    *,
    return_code: int | None = 0,
    timed_out: bool = False,
) -> SubprocessResult:
    return SubprocessResult(
        command=("subfinder",),
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
        self,
        command: Command,
        *,
        timeout: float | None = None,
    ) -> SubprocessResult:
        self.calls.append((command, timeout))
        return self.results.pop(0)


def scanner(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    executable: str | None = "subfinder",
) -> SubfinderScanner:
    configuration = load_config(
        overrides={"scanners": {"subfinder": {"executable": executable}}}
    )
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("www.example.com"),
        profile_name="safe",
        scanner_configuration={},
    )
    return SubfinderScanner(
        configuration=configuration,
        runner=runner,
        context=context,
        time_provider=lambda: NOW,
    )


def test_success_checks_version_requests_jsonl_and_writes_scoped_output(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(
        result("subfinder v2.6.0"),
        result(FIXTURE.read_text(encoding="utf-8")),
    )
    instance = scanner(tmp_path, runner)

    scan_result = asyncio.run(instance.run())

    assert scan_result.status is ScannerStatus.SUCCESS
    assert runner.calls[0][0].argv == ("subfinder", "-version")
    command = runner.calls[1][0]
    assert command.argv == (
        "subfinder",
        "-d",
        "example.com",
        "-json",
        "-silent",
        "-rl",
        "5",
        "-t",
        "2",
    )
    payload = json.loads(
        (instance.context.scan_directory / "passive" / "subfinder.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["subdomains"] == ["api.example.com", "mobile.example.com"]
    assert payload["count"] == 2
    assert payload["excluded_count"] == 1
    assert len(payload["warnings"]) == 2


def test_executable_with_spaces_remains_one_literal_argument(tmp_path: Path) -> None:
    runner = FakeRunner(result("version"), result(""))
    instance = scanner(tmp_path, runner, executable=r"C:\Tools Safe\subfinder.exe")

    scan_result = asyncio.run(instance.run())

    assert scan_result.status is ScannerStatus.SUCCESS
    assert runner.calls[0][0].argv[0] == r"C:\Tools Safe\subfinder.exe"
    assert runner.calls[1][0].argv[0] == r"C:\Tools Safe\subfinder.exe"


def test_version_failure_is_controlled_and_prevents_scan_command(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(result(return_code=1))
    instance = scanner(tmp_path, runner)

    scan_result = asyncio.run(instance.run())

    assert scan_result.status is ScannerStatus.FAILED
    assert scan_result.errors[0].code == "validation_failed"
    assert len(runner.calls) == 1


def test_scan_timeout_is_controlled(tmp_path: Path) -> None:
    runner = FakeRunner(
        result("version"),
        result(return_code=1, timed_out=True),
    )
    instance = scanner(tmp_path, runner)

    scan_result = asyncio.run(instance.run())

    assert scan_result.status is ScannerStatus.TIMED_OUT
    assert scan_result.errors[0].code == "timeout"


def test_missing_executable_is_controlled_without_runner_call(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    instance = scanner(tmp_path, runner, executable=None)

    scan_result = asyncio.run(instance.run())

    assert scan_result.status is ScannerStatus.FAILED
    assert scan_result.errors[0].code == "validation_failed"
    assert runner.calls == []
