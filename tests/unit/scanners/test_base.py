"""Tests for the common scanner lifecycle contract."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import ScanContext, ScanContextFactory
from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.scan_result import ScannerStatus
from webvulnscanner.models.target import Target
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput
from webvulnscanner.scanners.base import BaseScanner, ScannerOutput
from webvulnscanner.utils.command import Command


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class JsonListParser(BaseParser[int]):
    def __init__(self) -> None:
        super().__init__("json-list")

    def parse(self, parser_input: ParserInput) -> ParseResult[int]:
        try:
            value = json.loads(parser_input.content)
        except json.JSONDecodeError as error:
            raise self.parsing_error("invalid scanner JSON", cause=error) from error
        if not isinstance(value, list):
            raise self.parsing_error("expected a JSON array")
        return ParseResult(items=tuple(value))


class FakeRunner:
    def __init__(self, result: SubprocessResult) -> None:
        self.result = result
        self.calls: list[tuple[Command, float | None]] = []

    async def run(
        self,
        command: Command,
        *,
        timeout: float | None = None,
    ) -> SubprocessResult:
        self.calls.append((command, timeout))
        return self.result


class FakeScanner(BaseScanner):
    name = "headers"

    def __init__(
        self,
        *,
        validation_failure: bool = False,
        **dependencies: Any,
    ) -> None:
        super().__init__(**dependencies)
        self.validation_failure = validation_failure
        self.lifecycle: list[str] = []

    async def validate(self) -> None:
        self.lifecycle.append("validate")
        if self.validation_failure:
            raise ScannerValidationError("fake scanner validation failed")

    def build_command(self) -> Command:
        self.lifecycle.append("build_command")
        return Command("fake-tool", ("--json",))

    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        self.lifecycle.append("parse")
        self.parser.parse(ParserInput(process_result.stdout))
        return ScannerOutput(output_paths=("passive/headers.json",))


def process_result(
    *,
    stdout: str = "[]",
    stderr: str = "",
    return_code: int | None = 0,
    timed_out: bool = False,
) -> SubprocessResult:
    return SubprocessResult(
        command=("fake-tool", "--json"),
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
        duration_seconds=1.25,
        timed_out=timed_out,
    )


def context(tmp_path: Path) -> ScanContext:
    return ScanContextFactory(
        tmp_path / "runs",
        time_provider=lambda: NOW,
        id_provider=lambda: "scan-00000001",
    ).create(
        Target("example.com"),
        profile_name="safe",
        scanner_configuration={},
    )


def scanner(
    tmp_path: Path,
    *,
    runner: FakeRunner,
    configuration: Any = None,
    validation_failure: bool = False,
) -> FakeScanner:
    return FakeScanner(
        configuration=load_config() if configuration is None else configuration,
        runner=runner,
        context=context(tmp_path),
        parser=JsonListParser(),
        time_provider=lambda: NOW,
        validation_failure=validation_failure,
    )


def test_dependencies_are_injected_and_lifecycle_order_is_deterministic(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(process_result())
    instance = scanner(tmp_path, runner=runner)

    result = asyncio.run(instance.run())

    assert instance.runner is runner
    assert isinstance(instance.parser, JsonListParser)
    assert instance.context.target.host == "example.com"
    assert instance.lifecycle == ["validate", "build_command", "parse"]
    assert result.status is ScannerStatus.SUCCESS
    assert result.output_paths == ("passive/headers.json",)
    assert result.subprocess_details is not None
    assert result.subprocess_details.exit_code == 0
    assert runner.calls[0][1] == 30


def test_disabled_scanner_returns_skipped_without_execution(tmp_path: Path) -> None:
    runner = FakeRunner(process_result())
    configuration = load_config(
        overrides={"scanners": {"headers": {"enabled": False}}}
    )
    instance = scanner(
        tmp_path,
        runner=runner,
        configuration=configuration,
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.SKIPPED
    assert result.skip_reason == "scanner is disabled by configuration"
    assert runner.calls == []
    assert instance.lifecycle == []


def test_validation_failure_returns_controlled_failed_result(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        runner=FakeRunner(process_result()),
        validation_failure=True,
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "validation_failed"
    assert instance.lifecycle == ["validate"]


@pytest.mark.parametrize(
    ("process", "expected_status", "expected_code"),
    [
        (
            process_result(return_code=2, stderr="bounded diagnostic"),
            ScannerStatus.FAILED,
            "nonzero_exit",
        ),
        (
            process_result(return_code=1, timed_out=True),
            ScannerStatus.TIMED_OUT,
            "timeout",
        ),
    ],
)
def test_process_failures_become_controlled_scan_results(
    tmp_path: Path,
    process: SubprocessResult,
    expected_status: ScannerStatus,
    expected_code: str,
) -> None:
    instance = scanner(tmp_path, runner=FakeRunner(process))

    result = asyncio.run(instance.run())

    assert result.status is expected_status
    assert result.errors[0].code == expected_code
    assert result.subprocess_details is not None
    assert instance.lifecycle == ["validate", "build_command"]


def test_parse_failure_returns_controlled_failed_result(tmp_path: Path) -> None:
    instance = scanner(
        tmp_path,
        runner=FakeRunner(process_result(stdout="{invalid")),
    )

    result = asyncio.run(instance.run())

    assert result.status is ScannerStatus.FAILED
    assert result.errors[0].code == "parse_failed"
    assert instance.lifecycle == ["validate", "build_command", "parse"]


def test_scanner_contract_is_abstract() -> None:
    class IncompleteScanner(BaseScanner):
        name = "incomplete"

    with pytest.raises(TypeError):
        IncompleteScanner(  # type: ignore[abstract]
            configuration=load_config(),
            runner=FakeRunner(process_result()),
            context=object(),  # type: ignore[arg-type]
            parser=JsonListParser(),
        )


def test_contract_has_no_report_generation_api() -> None:
    assert not hasattr(BaseScanner, "generate_report")
    assert not hasattr(BaseScanner, "route_scanners")
