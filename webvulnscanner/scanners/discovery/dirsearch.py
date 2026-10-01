"""Bounded Dirsearch directory discovery using JSON output."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import ScannerValidationError
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


class DirsearchParser(BaseParser[DiscoveredResource]):
    """Normalize Dirsearch's documented JSON result records."""

    def __init__(self, base_url: str) -> None:
        super().__init__("dirsearch")
        self.base = Target(base_url)

    def parse(self, parser_input: ParserInput) -> ParseResult[DiscoveredResource]:
        try:
            payload = json.loads(parser_input.content)
        except json.JSONDecodeError as error:
            raise self.parsing_error("Dirsearch output is not valid JSON", cause=error)
        records = payload.get("results") if isinstance(payload, Mapping) else payload
        if not isinstance(records, list):
            raise self.parsing_error("Dirsearch JSON must contain a results array")

        resources: dict[str, DiscoveredResource] = {}
        warnings: list[str] = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                warnings.append(f"result {index}: expected an object")
                continue
            try:
                resource = _resource(record)
                target = Target(resource.url)
            except (TypeError, ValueError):
                warnings.append(f"result {index}: invalid structured record")
                continue
            if target.host != self.base.host or target.scheme != self.base.scheme:
                warnings.append(f"result {index}: out-of-scope URL")
                continue
            resources[target.url] = resource
        return ParseResult(
            items=tuple(resources[key] for key in sorted(resources)),
            warnings=tuple(warnings),
        )


class DirsearchScanner(BaseScanner):
    """Run Dirsearch with bounded recursion, concurrency, and request rate."""

    name = "dirsearch"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        runner: SubprocessRunnerProtocol,
        context: ScanContext,
        target_url: str,
        output_filename: str = "dirsearch.json",
        parser: DirsearchParser | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        self.target = Target(target_url)
        if re.fullmatch(r"dirsearch(?:-[a-f0-9]{12})?\.json", output_filename) is None:
            raise ValueError("invalid Dirsearch output filename")
        self.output_filename = output_filename
        super().__init__(
            configuration=configuration,
            runner=runner,
            context=context,
            parser=parser or DirsearchParser(self.target.url),
            time_provider=time_provider,
        )

    async def validate(self) -> None:
        if self.target.host != self.context.target.host:
            raise ScannerValidationError(
                "Dirsearch target is outside the explicit target host"
            )
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Dirsearch executable is not configured")
        wordlist = self.scanner_config.wordlist
        if wordlist is None:
            raise ScannerValidationError("Dirsearch wordlist is not configured")
        if not wordlist.is_file():
            raise ScannerValidationError("Dirsearch wordlist does not exist")
        version = await self.runner.run(
            Command(executable, ("--version",)),
            timeout=min(
                15.0,
                float(self.configuration.timeouts.for_scanner(self.name)),
            ),
        )
        if version.timed_out or version.return_code != 0:
            raise ScannerValidationError("Dirsearch version check failed")

    def build_command(self) -> Command:
        executable = self.scanner_config.executable
        wordlist = self.scanner_config.wordlist
        if executable is None or wordlist is None:
            raise ScannerValidationError("Dirsearch prerequisites are not configured")
        discovery = self.configuration.discovery
        arguments = [
            "--url",
            self.target.url,
            "--wordlist",
            str(wordlist),
            "--threads",
            str(self.scanner_config.concurrency),
            "--max-rate",
            str(max(1, int(self.scanner_config.rate_limit_per_second))),
            "--timeout",
            str(self.configuration.timeouts.for_scanner(self.name)),
            "--extensions",
            ",".join(discovery.dirsearch_extensions),
            "--format",
            "json",
            "--output",
            "-",
            "--quiet-mode",
        ]
        if discovery.max_recursion_depth > 0:
            arguments.extend(
                (
                    "--recursive",
                    "--max-recursion-depth",
                    str(discovery.max_recursion_depth),
                )
            )
        return Command(executable, tuple(arguments))

    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        if not isinstance(self.parser, DirsearchParser):
            raise TypeError("Dirsearch scanner requires DirsearchParser")
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


def _resource(record: Mapping[str, object]) -> DiscoveredResource:
    url = record.get("url")
    status = record.get("status")
    if status is None:
        status = record.get("status_code")
    length = record.get("content-length")
    if length is None:
        length = record.get("content_length")
    if not isinstance(url, str):
        raise TypeError("result URL must be a string")
    if isinstance(status, str) and status.isdigit():
        status = int(status)
    if isinstance(length, str) and length.isdigit():
        length = int(length)
    return DiscoveredResource(
        url=url,
        status_code=status,  # type: ignore[arg-type]
        source="dirsearch",
        content_length=length,  # type: ignore[arg-type]
    )


__all__ = ["DirsearchParser", "DirsearchScanner"]
