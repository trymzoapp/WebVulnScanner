"""Safe command-line execution for complete web vulnerability scanning pipeline."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from webvulnscanner import __version__
from webvulnscanner.config.loader import AppConfig, load_config
from webvulnscanner.core.context import ScanContextFactory
from webvulnscanner.core.exceptions import ConfigurationError, TargetValidationError
from webvulnscanner.core.orchestrator import OrchestrationResult, Orchestrator
from webvulnscanner.core.pipeline import Pipeline, StageName
from webvulnscanner.core.subprocess_runner import AsyncSubprocessRunner
from webvulnscanner.models.report import ScanStatus
from webvulnscanner.models.target import Target
from webvulnscanner.reports.stage import ReportStage
from webvulnscanner.routing.stage import RoutingStage
from webvulnscanner.scanners.discovery import create_discovery_stage
from webvulnscanner.scanners.fingerprint import create_fingerprint_stage
from webvulnscanner.scanners.passive import create_passive_stage
from webvulnscanner.scanners.vulnerability import create_vulnerability_stage


EXIT_SUCCESS = 0
EXIT_FINDINGS_FOUND = 1
EXIT_INVALID_INPUT = 2
EXIT_PARTIAL_COMPLETION = 3
EXIT_FATAL_FAILURE = 4
EXIT_SCAN_FAILED = 4
EXIT_INTERRUPTED = 130

PipelineFactory = Callable[[AppConfig, AsyncSubprocessRunner], Pipeline]


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without performing filesystem or process work."""
    parser = argparse.ArgumentParser(
        prog="webvulnscanner",
        description=(
            "Run authorized, non-destructive web vulnerability assessments."
        ),
        epilog=(
            "Use only against assets you own or have explicit permission to assess."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="run authorized web vulnerability assessment pipeline",
    )
    scan_parser.add_argument(
        "target",
        help="HTTP(S) URL, hostname, IPv4 address, or IPv6 address",
    )
    scan_parser.add_argument(
        "--confirm-authorized",
        "-y",
        "--yes",
        action="store_true",
        dest="confirm_authorized",
        help="confirm affirmative authorization to assess the target asset",
    )
    _add_configuration_options(scan_parser)

    config_parser = subparsers.add_parser(
        "config",
        help="print the validated effective configuration",
    )
    _add_configuration_options(config_parser)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    pipeline_factory: PipelineFactory | None = None,
) -> int:
    """Run configuration inspection or full authorized scan execution."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        configuration = _load_configuration(arguments)
        if arguments.command == "config":
            _print_json(_configuration_data(configuration))
            return EXIT_SUCCESS
        target = Target(arguments.target)
    except (ConfigurationError, TargetValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    if not _confirm_authorization(
        bool(getattr(arguments, "confirm_authorized", False)),
        target_str=arguments.target,
    ):
        print(
            "error: Authorized-use confirmation required. "
            "Pass --confirm-authorized (or -y) or confirm interactively.",
            file=sys.stderr,
        )
        return EXIT_INVALID_INPUT

    try:
        result = _execute_scan(
            configuration,
            target,
            pipeline_factory=pipeline_factory or _build_pipeline,
        )
    except KeyboardInterrupt:
        print("error: Scan interrupted by user.", file=sys.stderr)
        return EXIT_INTERRUPTED

    _print_json(_execution_summary(result, target))
    return _determine_exit_code(result)


def _confirm_authorization(confirmed_flag: bool, target_str: str) -> bool:
    if confirmed_flag:
        return True
    if sys.stdin.isatty():
        try:
            response = input(
                f"Confirm explicit authorization to assess target '{target_str}' [y/N]: "
            )
            return response.strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False
    return False


def _execute_scan(
    configuration: AppConfig,
    target: Target,
    *,
    pipeline_factory: PipelineFactory,
) -> OrchestrationResult:
    """Construct bounded runtime dependencies and execute one target."""
    runner = AsyncSubprocessRunner(
        max_concurrency=configuration.concurrency.max_scanners,
        default_timeout=configuration.timeouts.default,
        max_output_bytes=configuration.http.max_response_bytes,
    )
    pipeline = pipeline_factory(configuration, runner)
    orchestrator = Orchestrator(
        configuration=configuration,
        context_factory=ScanContextFactory(configuration.storage.root),
        pipeline=pipeline,
    )
    return asyncio.run(orchestrator.run(target))


def _build_pipeline(
    configuration: AppConfig,
    runner: AsyncSubprocessRunner,
) -> Pipeline:
    """Assemble all pipeline stages (passive, fingerprint, routing, discovery, vulnerability, report)."""
    return Pipeline(
        (
            create_passive_stage(
                configuration=configuration,
                subprocess_runner=runner,
            ),
            create_fingerprint_stage(
                configuration=configuration,
                subprocess_runner=runner,
            ),
            RoutingStage(),
            create_discovery_stage(
                configuration=configuration,
                subprocess_runner=runner,
            ),
            create_vulnerability_stage(
                configuration=configuration,
                subprocess_runner=runner,
            ),
            ReportStage(
                configuration=configuration,
            ),
        )
    )


def _determine_exit_code(result: OrchestrationResult) -> int:
    """Determine a stable CLI exit code from orchestration and report outcomes."""
    if result.status is ScanStatus.FAILED:
        return EXIT_FATAL_FAILURE
    if result.status is ScanStatus.CANCELLED:
        return EXIT_INTERRUPTED

    total_findings = 0
    if result.pipeline is not None:
        report_outcome = next(
            (o for o in result.pipeline.outcomes if o.name is StageName.REPORT),
            None,
        )
        if report_outcome and report_outcome.artifacts:
            report_obj = report_outcome.artifacts.get("report")
            if report_obj is not None and hasattr(report_obj, "severity_summary"):
                total_findings = report_obj.severity_summary.total

    if total_findings > 0:
        return EXIT_FINDINGS_FOUND

    if result.status is ScanStatus.PARTIAL or result.errors:
        return EXIT_PARTIAL_COMPLETION

    return EXIT_SUCCESS


def _execution_summary(
    result: OrchestrationResult,
    target: Target,
) -> dict[str, object]:
    context = result.context
    stages = (
        {}
        if result.pipeline is None
        else {
            outcome.name.value: outcome.status.value
            for outcome in result.pipeline.outcomes
        }
    )
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "total": 0,
    }
    report_paths: dict[str, str] = {}

    if result.pipeline is not None:
        report_outcome = next(
            (o for o in result.pipeline.outcomes if o.name is StageName.REPORT),
            None,
        )
        if report_outcome and report_outcome.artifacts:
            paths = report_outcome.artifacts.get("report_paths")
            if isinstance(paths, Mapping):
                report_paths = {str(k): str(v) for k, v in paths.items()}
            report_obj = report_outcome.artifacts.get("report")
            if report_obj is not None and hasattr(report_obj, "severity_summary"):
                severity_counts = report_obj.severity_summary.to_dict()

    return {
        "status": result.status.value,
        "authorized_use_required": True,
        "authorized_use_confirmed": True,
        "target_url": target.url,
        "normalized_domain": target.normalized_domain,
        "scan_id": None if context is None else context.scan_id,
        "scan_directory": (
            None if context is None else str(context.scan_directory)
        ),
        "stages": stages,
        "severity_counts": severity_counts,
        "report_paths": report_paths,
        "errors": list(result.errors),
    }


def _add_configuration_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        help="configuration profile name (default: safe)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="optional user YAML configuration file",
    )
    parser.add_argument(
        "--storage-root",
        type=Path,
        help="override the scan result storage root",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="override the default scanner timeout in seconds",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        help="override maximum concurrently running scanners",
    )


def _load_configuration(arguments: argparse.Namespace) -> AppConfig:
    overrides: dict[str, Any] = {}
    if arguments.storage_root is not None:
        overrides["storage"] = {"root": str(arguments.storage_root)}
    if arguments.timeout is not None:
        overrides["timeouts"] = {"default": arguments.timeout}
    if arguments.concurrency is not None:
        overrides["concurrency"] = {"max_scanners": arguments.concurrency}
    return load_config(
        profile_name=arguments.profile,
        user_config=arguments.config,
        overrides=overrides or None,
    )


def _configuration_data(configuration: AppConfig) -> dict[str, object]:
    return {
        "profile": {
            "name": configuration.profile.name,
            "safety": {
                "allow_destructive": (
                    configuration.profile.safety.allow_destructive
                ),
                "allow_auth_bypass": (
                    configuration.profile.safety.allow_auth_bypass
                ),
                "allow_waf_bypass": configuration.profile.safety.allow_waf_bypass,
                "allow_rate_limit_bypass": (
                    configuration.profile.safety.allow_rate_limit_bypass
                ),
                "max_requests_per_second": (
                    configuration.profile.safety.max_requests_per_second
                ),
                "max_scanners": configuration.profile.safety.max_scanners,
            },
        },
        "timeouts": {
            "default": configuration.timeouts.default,
            **dict(configuration.timeouts.per_scanner),
        },
        "concurrency": {
            "max_scanners": configuration.concurrency.max_scanners,
            "max_targets": configuration.concurrency.max_targets,
        },
        "http": {
            "user_agent": configuration.http.user_agent,
            "max_redirects": configuration.http.max_redirects,
            "max_response_bytes": configuration.http.max_response_bytes,
        },
        "wayback": {
            "endpoint": configuration.wayback.endpoint,
            "max_records": configuration.wayback.max_records,
            "page_size": configuration.wayback.page_size,
        },
        "fingerprint": {
            "ports": list(configuration.fingerprint.ports),
            "timing_template": configuration.fingerprint.timing_template,
            "host_timeout_seconds": (
                configuration.fingerprint.host_timeout_seconds
            ),
        },
        "discovery": {
            "status_codes": list(configuration.discovery.status_codes),
            "dirsearch_extensions": list(
                configuration.discovery.dirsearch_extensions
            ),
            "max_recursion_depth": (
                configuration.discovery.max_recursion_depth
            ),
        },
        "reports": {
            "json": configuration.reports.json,
            "markdown": configuration.reports.markdown,
            "html": configuration.reports.html,
        },
        "storage": {"root": str(configuration.storage.root)},
        "scanners": {
            name: {
                "enabled": scanner.enabled,
                "executable": scanner.executable,
                "wordlist": (
                    None if scanner.wordlist is None else str(scanner.wordlist)
                ),
                "concurrency": scanner.concurrency,
                "rate_limit_per_second": scanner.rate_limit_per_second,
            }
            for name, scanner in sorted(configuration.scanners.items())
        },
    }


def _print_json(value: Mapping[str, object]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


__all__ = [
    "EXIT_FATAL_FAILURE",
    "EXIT_FINDINGS_FOUND",
    "EXIT_INTERRUPTED",
    "EXIT_INVALID_INPUT",
    "EXIT_PARTIAL_COMPLETION",
    "EXIT_SCAN_FAILED",
    "EXIT_SUCCESS",
    "build_parser",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())

