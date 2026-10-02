"""Tests for bounded JSON-producing Dirsearch discovery."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.discovery.dirsearch import DirsearchScanner
from webvulnscanner.utils.command import Command

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def process(
    stdout: str = "",
    *,
    return_code: int | None = 0,
    timed_out: bool = False,
) -> SubprocessResult:
    return SubprocessResult(
        command=("dirsearch",),
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
    recursion_depth: int = 0,
    target_url: str = "https://example.com/",
) -> DirsearchScanner:
    wordlist = tmp_path / "words.txt"
    wordlist.parent.mkdir(parents=True, exist_ok=True)
    wordlist.write_text("admin\n", encoding="utf-8")
    configuration = load_config(
        overrides={
            "discovery": {"max_recursion_depth": recursion_depth},
            "scanners": {
                "dirsearch": {
                    "enabled": True,
                    "wordlist": str(wordlist),
                }
            },
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
    return DirsearchScanner(
        configuration=configuration,
        runner=runner,
        context=context,
        target_url=target_url,
        time_provider=lambda: NOW,
    )


def test_json_output_command_and_common_resource_persistence(
    tmp_path: Path,
) -> None:
    output = json.dumps(
        {
            "results": [
                {
                    "url": "https://example.com/admin",
                    "status": 200,
                    "content-length": 42,
                },
                {
                    "url": "https://outside.example/admin",
                    "status": 200,
                },
            ]
        }
    )
    runner = FakeRunner(process("0.4"), process(output))
    instance = scanner(tmp_path, runner)

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SUCCESS
    command = runner.calls[1][0].argv
    assert command[command.index("--format") + 1] == "json"
    assert command[command.index("--output") + 1] == "-"
    assert "--recursive" not in command
    assert result.artifacts["urls"] == ("https://example.com/admin",)
    payload = json.loads(
        (instance.context.scan_directory / "discovery" / "dirsearch.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["resources"][0]["source"] == "dirsearch"
    assert len(payload["warnings"]) == 1


def test_bounded_recursion_flags_are_explicit(tmp_path: Path) -> None:
    runner = FakeRunner(process("0.4"), process('{"results":[]}'))
    instance = scanner(tmp_path, runner, recursion_depth=2)

    assert asyncio.run(instance.run()).status is ScannerStatus.SUCCESS
    command = runner.calls[1][0].argv
    assert command[command.index("--max-recursion-depth") + 1] == "2"


def test_invalid_configuration_malformed_json_failure_and_timeout(
    tmp_path: Path,
) -> None:
    try:
        scanner(tmp_path, FakeRunner(), recursion_depth=3)
    except Exception as error:
        assert "max_recursion_depth" in str(error)
    else:
        raise AssertionError("unsafe recursion depth must be rejected")

    malformed = scanner(
        tmp_path / "malformed",
        FakeRunner(process("0.4"), process("not-json")),
    )
    result = asyncio.run(malformed.run())
    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "parse_failed"

    timed_out = scanner(
        tmp_path / "timeout",
        FakeRunner(process("0.4"), process(return_code=None, timed_out=True)),
    )
    assert asyncio.run(timed_out.run()).status is ScannerStatus.TIMED_OUT
