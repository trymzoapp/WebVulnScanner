"""Structured Wappalyzer technology fingerprinting."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.wappalyzer import WappalyzerParser
from webvulnscanner.scanners.base import (
    BaseScanner,
    ScannerOutput,
    SubprocessRunnerProtocol,
)
from webvulnscanner.utils.command import Command
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import utc_now


class WappalyzerScanner(BaseScanner):
    """Run Wappalyzer's JSON-producing CLI and persist normalized observations."""

    name = "wappalyzer"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        runner: SubprocessRunnerProtocol,
        context: ScanContext,
        parser: WappalyzerParser | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        super().__init__(
            configuration=configuration,
            runner=runner,
            context=context,
            parser=parser or WappalyzerParser(),
            time_provider=time_provider,
        )

    async def validate(self) -> None:
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Wappalyzer executable is not configured")
        version = await self.runner.run(
            Command(executable, ("--version",)),
            timeout=min(
                15.0,
                float(self.configuration.timeouts.for_scanner(self.name)),
            ),
        )
        if version.timed_out:
            raise ScannerValidationError("Wappalyzer version check timed out")
        if version.return_code != 0:
            raise ScannerValidationError("Wappalyzer version check failed")

    def build_command(self) -> Command:
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Wappalyzer executable is not configured")
        # The Wappalyzer CLI emits JSON by default. Avoid presentation flags so the
        # parser never has to consume terminal-formatted output.
        return Command(executable, (self.context.target.url,))

    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        if not isinstance(self.parser, WappalyzerParser):
            raise TypeError("Wappalyzer scanner requires WappalyzerParser")
        parsed = self.parser.parse(ParserInput(process_result.stdout))
        payload = {
            "scanner": self.name,
            "target": self.context.target.url,
            "technologies": [item.to_dict() for item in parsed.items],
            "count": len(parsed.items),
            "warnings": list(parsed.warnings),
        }
        output = atomic_write_json(
            self.context.stage_directory("fingerprint") / "wappalyzer.json",
            payload,
            storage_root=self.context.storage_root,
            overwrite=False,
        )
        return ScannerOutput(
            technologies=parsed.items,
            output_paths=(output.relative_to(self.context.scan_directory).as_posix(),),
            artifacts={
                "technologies": tuple(item.to_dict() for item in parsed.items),
            },
        )


__all__ = ["WappalyzerScanner"]
