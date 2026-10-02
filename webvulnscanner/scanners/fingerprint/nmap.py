"""Constrained Nmap web-service fingerprinting."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from webvulnscanner.config.loader import AppConfig
from webvulnscanner.core.context import ScanContext
from webvulnscanner.core.exceptions import ScannerValidationError
from webvulnscanner.core.subprocess_runner import SubprocessResult
from webvulnscanner.models.service import WebService
from webvulnscanner.models.technology import Technology
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.nmap import NmapParser
from webvulnscanner.scanners.base import (
    BaseScanner,
    ScannerOutput,
    SubprocessRunnerProtocol,
)
from webvulnscanner.utils.command import Command
from webvulnscanner.utils.filesystem import atomic_write_json
from webvulnscanner.utils.time import utc_now


class NmapScanner(BaseScanner):
    """Identify services only on the configured bounded TCP port allowlist."""

    name = "nmap"

    def __init__(
        self,
        *,
        configuration: AppConfig,
        runner: SubprocessRunnerProtocol,
        context: ScanContext,
        parser: NmapParser | None = None,
        time_provider: Callable[[], datetime] = utc_now,
    ) -> None:
        super().__init__(
            configuration=configuration,
            runner=runner,
            context=context,
            parser=parser
            or NmapParser(context.target.host, configuration.fingerprint.ports),
            time_provider=time_provider,
        )

    async def validate(self) -> None:
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Nmap executable is not configured")
        version = await self.runner.run(
            Command(executable, ("--version",)),
            timeout=min(
                15.0,
                float(self.configuration.timeouts.for_scanner(self.name)),
            ),
        )
        if version.timed_out:
            raise ScannerValidationError("Nmap version check timed out")
        if version.return_code != 0:
            raise ScannerValidationError("Nmap version check failed")

    def build_command(self) -> Command:
        executable = self.scanner_config.executable
        if executable is None:
            raise ScannerValidationError("Nmap executable is not configured")
        settings = self.configuration.fingerprint
        return Command(
            executable,
            (
                "-n",
                "-Pn",
                "-sV",
                "--version-light",
                f"-T{settings.timing_template}",
                "--host-timeout",
                f"{settings.host_timeout_seconds}s",
                "-p",
                ",".join(str(port) for port in settings.ports),
                "-oX",
                "-",
                self.context.target.host,
            ),
        )

    def parse(self, process_result: SubprocessResult) -> ScannerOutput:
        if not isinstance(self.parser, NmapParser):
            raise TypeError("Nmap scanner requires NmapParser")
        parsed = self.parser.parse(ParserInput(process_result.stdout))
        services = tuple(item.to_dict() for item in parsed.items)
        web_services = tuple(
            item.to_dict() for item in parsed.items if item.web_url is not None
        )
        technologies = _technologies(parsed.items)
        payload = {
            "scanner": self.name,
            "target": self.context.target.host,
            "services": list(services),
            "web_services": list(web_services),
            "warnings": list(parsed.warnings),
        }
        output = atomic_write_json(
            self.context.stage_directory("fingerprint") / "nmap.json",
            payload,
            storage_root=self.context.storage_root,
            overwrite=False,
        )
        return ScannerOutput(
            technologies=technologies,
            output_paths=(output.relative_to(self.context.scan_directory).as_posix(),),
            artifacts={
                "services": services,
                "web_services": web_services,
                "urls": tuple(
                    item.web_url for item in parsed.items if item.web_url is not None
                ),
            },
        )


def _technologies(
    services: tuple[WebService, ...],
) -> tuple[Technology, ...]:
    observations: dict[tuple[str, str | None], Technology] = {}
    for item in services:
        product = item.product
        web_url = item.web_url
        if product is None or web_url is None:
            continue
        technology = Technology(
            name=product,
            source="nmap",
            confidence=0.7,
            version=item.version,
            categories=("Web server",),
            evidence=(web_url,),
        )
        observations[(technology.name.casefold(), technology.version)] = technology
    return tuple(
        sorted(
            observations.values(),
            key=lambda item: (item.name.casefold(), item.version or ""),
        )
    )


__all__ = ["NmapScanner"]
