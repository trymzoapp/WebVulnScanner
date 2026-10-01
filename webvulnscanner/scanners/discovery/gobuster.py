"""Bounded Gobuster directory discovery."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urljoin

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import ParsingError, ScannerValidationError
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.discovery import DiscoveredResource
from webvulnscanner.models.target import Target
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput
from webvulnscanner.scanners.base import (
    BaseScanner,
    ScannerOutput,
    SubprocessRunnerProtocol,
)
from webvulnscanner.utils.command import Command
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import utc_now


_OUTPUT = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?\s*$"
)


class GobusterParser(BaseParser[DiscoveredResource]):
    """Isolate parsing of Gobuster's stable output-file line format."""

    def __init__(self, base_url: str) -> None:
        super().__init__("gobuster")
        self.base = Target(base_url)

    def parse(self, parser_input: ParserInput) -> ParseResult[DiscoveredResource]:
        resources: dict[str, DiscoveredResource] = {}
        warnings: list[str] = []
        meaningful = 0
        for line_number, raw in enumerate(parser_input.content.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            meaningful += 1
            match = _OUTPUT.fullmatch(line)
            if match is None:
                warnings.append(f"line {line_number}: unrecognized Gobuster record")
                continue
            url = urljoin(self.base.url, match.group("path"))
            try:
                target = Target(url)
            except Exception:
                warnings.append(f"line {line_number}: invalid discovered URL")
                continue
            if target.host != self.base.host or target.scheme != self.base.scheme:
                warnings.append(f"line {line_number}: out-of-scope discovered URL")
                continue
            resource = DiscoveredResource(
                url=target.url,
                status_code=int(match.group("status")),
                source="gobuster",
                content_length=(
                    None
                    if match.group("size") is None
                    else int(match.group("size"))
                ),
            )
            resources[resource.url] = resource
        if meaningful and not resources:
            raise ParsingError(
                "Gobuster output contained no valid records",
                component="gobuster",
                operation="parse",
            )
        return ParseResult(
            items=tuple(resources[key] for key in sorted(resources)),
            warnings=tuple(warnings),
        )


class GobusterScanner(BaseScanner):
    """Run one non-recursive Gobuster scan against a confirmed web service."""

    name = "gobuster"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        runner: SubprocessRunnerProtocol,
        context: ScanContext,
        target_url: str,
        output_filename: str = "gobuster.json",
        parser: GobusterParser | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.target = Target(target_url)
        if re.fullmatch(r"gobuster(?:-[a-f0-9]{12})?\.json", output_filename) is None:
            raise ValueError("invalid Gobuster output filename")
        self.output_filename = output_filename
        super().__init__(
            configuration=configuration,
            runner=runner,
            context=context,
            parser=parser or GobusterParser(self.target.url),
            time_provider=time_provider,
        )

    async def validate(self) -> None:
        if self.target.host != self.context.target.host:
            raise ScannerValidationError(
                "Gobuster target is outside the explicit target host"
            )
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Gobuster executable is not configured")
        wordlist = self.scanner_config.wordlist
        if wordlist is None:
            raise ScannerValidationError("Gobuster wordlist is not configured")
        if not wordlist.is_file():
            raise ScannerValidationError("Gobuster wordlist does not exist")
        version = await self.runner.run(
            Command(executable, ("version",)),
            timeout=min(
                15.0,
                float(self.configuration.timeouts.for_scanner(self.name)),
            ),
        )
        if version.timed_out or version.return_code != 0:
            raise ScannerValidationError("Gobuster version check failed")

    def build_command(self) -> Command:
        executable = self.scanner_config.executable
        wordlist = self.scanner_config.wordlist
        if executable is None or wordlist is None:
            raise ScannerValidationError("Gobuster prerequisites are not configured")
        delay_ms = max(
            1,
            math.ceil(1000.0 / self.scanner_config.rate_limit_per_second),
        )
        return Command(
            executable,
            (
                "dir",
                "--url",
                self.target.url,
                "--wordlist",
                str(wordlist),
                "--threads",
                str(self.scanner_config.concurrency),
                "--delay",
                f"{delay_ms}ms",
                "--status-codes",
                ",".join(
                    str(code) for code in self.configuration.discovery.status_codes
                ),
                "--no-error",
                "--no-color",
                "--quiet",
            ),
        )

    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        if not isinstance(self.parser, GobusterParser):
            raise TypeError("Gobuster scanner requires GobusterParser")
        parsed = self.parser.parse(ParserInput(process_result.stdout))
        payload = {
            "scanner": self.name,
            "target": self.target.url,
            "resources": [item.to_dict() for item in parsed.items],
            "count": len(parsed.items),
            "warnings": list(parsed.warnings),
        }
        output = atomic_write_json(
            self.context.stage_directory("discovery") / self.output_filename,
            payload,
            storage_root=self.context.storage_root,
            overwrite=False,
        )
        return ScannerOutput(
            output_paths=(
                output.relative_to(self.context.scan_directory).as_posix(),
            ),
            artifacts={
                "resources": tuple(item.to_dict() for item in parsed.items),
                "urls": tuple(item.url for item in parsed.items),
            },
        )


__all__ = ["GobusterParser", "GobusterScanner"]
