"""Structured, scope-filtered Subfinder scanner."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.subfinder import (
    SubfinderParser,
    registrable_domain,
)
from webvulnscanner.scanners.base import (
    BaseScanner,
    ScannerOutput,
    SubprocessRunnerProtocol,
)
from webvulnscanner.utils.command import Command
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import utc_now


class SubfinderScanner(BaseScanner):
    """Run Subfinder in JSONL mode and persist only in-scope hosts."""

    name = "subfinder"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        runner: SubprocessRunnerProtocol,
        context: ScanContext,
        parser: SubfinderParser | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.scope_domain = registrable_domain(context.target.host)
        super().__init__(
            configuration=configuration,
            runner=runner,
            context=context,
            parser=parser or SubfinderParser(self.scope_domain),
            time_provider=time_provider,
        )

    async def validate(self) -> None:
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Subfinder executable is not configured")
        version = await self.runner.run(
            Command(executable, ("-version",)),
            timeout=min(
                15.0,
                float(self.configuration.timeouts.for_scanner(self.name)),
            ),
        )
        if version.timed_out:
            raise ScannerValidationError("Subfinder version check timed out")
        if version.return_code != 0:
            raise ScannerValidationError("Subfinder version check failed")

    def build_command(self) -> Command:
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Subfinder executable is not configured")
        rate_limit = max(1, int(self.scanner_config.rate_limit_per_second))
        return Command(
            executable,
            (
                "-d",
                self.scope_domain,
                "-json",
                "-silent",
                "-rl",
                str(rate_limit),
                "-t",
                str(self.scanner_config.concurrency),
            ),
        )

    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        if not isinstance(self.parser, SubfinderParser):
            raise TypeError("Subfinder scanner requires SubfinderParser")
        parsed = self.parser.parse(ParserInput(process_result.stdout))
        payload = {
            "scanner": self.name,
            "domain": self.scope_domain,
            "subdomains": list(parsed.items),
            "count": len(parsed.items),
            "excluded_count": parsed.excluded_count,
            "warnings": list(parsed.warnings),
        }
        output = atomic_write_json(
            self.context.stage_directory("passive") / "subfinder.json",
            payload,
            storage_root=self.context.storage_root,
            overwrite=False,
        )
        return ScannerOutput(
            output_paths=(output.relative_to(self.context.scan_directory).as_posix(),),
            artifacts={"hosts": parsed.items},
        )


__all__ = ["SubfinderScanner"]
