"""Tests for bounded Gobuster discovery."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.discovery.gobuster import GobusterScanner
from webvulnscanner.utils.command import Command


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def process(
    stdout: str = "",
    *,
    return_code: int | None = 0,
    timed_out: bool = False,
) -> SubprocessResult:
    return SubprocessResult(
        command=("gobuster",),
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


def scanner(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    target_url: str = "https://example.com/",
    create_wordlist: bool = True,
) -> GobusterScanner:
    wordlist = tmp_path / "words.txt"
    if create_wordlist:
        wordlist.parent.mkdir(parents=True, exist_ok=True)
        wordlist.write_text("admin\n", encoding="utf-8")
    configuration = load_config(
        overrides={
            "scanners": {
                "gobuster": {
                    "enabled": True,
                    "wordlist": str(wordlist),
                }
            }
        }
    )
    context = ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("example.com"),
        profile_name="safe",
        scanner_configuration={},
    )
    return GobusterScanner(
        configuration=configuration,
        runner=runner,
        context=context,
        target_url=target_url,
        time_provider=lambda: NOW,
    )


def test_safe_command_parses_and_persists_resources(tmp_path: Path) -> None:
    runner = FakeRunner(
        process("3.6"),
        process(
            "/admin (Status: 200) [Size: 42]\n"
            "/login (Status: 403) [Size: 0]\n"
        ),
    )
    instance = scanner(tmp_path, runner)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    command = runner.calls[1][0].argv
    assert command[:4] == (
        "gobuster",
        "dir",
        "--url",
        "https://example.com/",
    )
    assert "--recursive" not in command
    assert command[command.index("--threads") + 1] == "2"
    assert command[command.index("--delay") + 1] == "200ms"
    assert result.artifacts["urls"] == (
        "https://example.com/admin",
        "https://example.com/login",
    )
    payload = json.loads(
        (
            instance.context.scan_directory / "discovery" / "gobuster.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["count"] == 2


def test_missing_wordlist_and_out_of_scope_target_are_controlled(
    tmp_path: Path,
) -> None:
    missing = scanner(
        tmp_path,
        FakeRunner(),
        create_wordlist=False,
    )
    assert asyncio.run(missing.run()).errors[0].code == "validation_failed"

    outside = scanner(
        tmp_path / "outside",
        FakeRunner(),
        target_url="https://other.example/",
    )
    outside_result = asyncio.run(outside.run())
    assert outside_result.status is ScannerStatus.FAILED
    assert outside_result.errors[0].code == "validation_failed"


def test_malformed_output_and_timeout_are_controlled(tmp_path: Path) -> None:
    malformed = scanner(
        tmp_path,
        FakeRunner(process("3.6"), process("terminal banner only")),
    )
    malformed_result = asyncio.run(malformed.run())
    assert malformed_result.status is ScannerStatus.FAILED
    assert malformed_result.errors[0].code == "parse_failed"

    timed_out = scanner(
        tmp_path / "timeout",
        FakeRunner(process("3.6"), process(return_code=None, timed_out=True)),
    )
    assert asyncio.run(timed_out.run()).status is ScannerStatus.TIMED_OUT
