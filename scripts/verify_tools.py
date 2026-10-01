#!/usr/bin/env python3
"""Safe dependency verification script for WebVulnScanner external tools."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class ToolStatus(str, Enum):
    """External tool availability and version status."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Specification and check parameters for one external tool."""

    name: str
    executable: str
    version_args: tuple[str, ...]
    version_regex: str
    min_version: str | None
    install_hint: str


@dataclass(frozen=True, slots=True)
class ToolCheckResult:
    """Verification outcome for one tool."""

    name: str
    executable: str
    status: ToolStatus
    path: str | None
    detected_version: str | None
    min_version: str | None
    install_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "executable": self.executable,
            "status": self.status.value,
            "path": self.path,
            "detected_version": self.detected_version,
            "min_version": self.min_version,
            "install_hint": self.install_hint,
        }


DEFAULT_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="nmap",
        executable="nmap",
        version_args=("--version",),
        version_regex=r"Nmap version ([0-9]+\.[0-9]+)",
        min_version="7.80",
        install_hint="apt install nmap / brew install nmap",
    ),
    ToolSpec(
        name="nuclei",
        executable="nuclei",
        version_args=("-version",),
        version_regex=r"Nuclei Engine Version: v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="3.0.0",
        install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    ToolSpec(
        name="subfinder",
        executable="subfinder",
        version_args=("-version",),
        version_regex=r"Subfinder Engine Version: v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="2.5.0",
        install_hint="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    ToolSpec(
        name="wappalyzer",
        executable="wappalyzer",
        version_args=("--version",),
        version_regex=r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version=None,
        install_hint="npm install -g wappalyzer-cli",
    ),
    ToolSpec(
        name="dirsearch",
        executable="dirsearch",
        version_args=("--version",),
        version_regex=r"dirsearch v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="0.4.0",
        install_hint="pip install dirsearch",
    ),
    ToolSpec(
        name="gobuster",
        executable="gobuster",
        version_args=("version",),
        version_regex=r"Gobuster v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="3.0.0",
        install_hint="go install github.com/OJ/gobuster/v3@latest",
    ),
    ToolSpec(
        name="sqlmap",
        executable="sqlmap",
        version_args=("--version",),
        version_regex=r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="1.5.0",
        install_hint="apt install sqlmap / pip install sqlmap",
    ),
    ToolSpec(
        name="wpscan",
        executable="wpscan",
        version_args=("--version",),
        version_regex=r"WPScan v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="3.8.0",
        install_hint="gem install wpscan / brew install wpscan",
    ),
    ToolSpec(
        name="whois",
        executable="whois",
        version_args=("--version",),
        version_regex=r"whois ([0-9]+\.[0-9]+)",
        min_version=None,
        install_hint="apt install whois / brew install whois",
    ),
)


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    parts: list[int] = []
    for part in version_str.split("."):
        clean = re.sub(r"[^0-9]", "", part)
        if clean:
            parts.append(int(clean))
    return tuple(parts)


def check_tool(spec: ToolSpec, executable_override: str | None = None) -> ToolCheckResult:
    """Safely check an external executable's existence and version without network access."""
    exe_name = executable_override or spec.executable
    resolved_path = shutil.which(exe_name)

    if resolved_path is None:
        return ToolCheckResult(
            name=spec.name,
            executable=exe_name,
            status=ToolStatus.MISSING,
            path=None,
            detected_version=None,
            min_version=spec.min_version,
            install_hint=spec.install_hint,
        )

    try:
        proc = subprocess.run(
            [resolved_path, *spec.version_args],
            capture_output=True,
            text=True,
            timeout=5.0,
            shell=False,
            check=False,
        )
        combined_output = f"{proc.stdout}\n{proc.stderr}"
    except (OSError, subprocess.SubprocessError):
        return ToolCheckResult(
            name=spec.name,
            executable=exe_name,
            status=ToolStatus.UNKNOWN,
            path=resolved_path,
            detected_version=None,
            min_version=spec.min_version,
            install_hint=spec.install_hint,
        )

    match = re.search(spec.version_regex, combined_output, re.IGNORECASE)
    if not match:
        return ToolCheckResult(
            name=spec.name,
            executable=exe_name,
            status=ToolStatus.UNKNOWN,
            path=resolved_path,
            detected_version=None,
            min_version=spec.min_version,
            install_hint=spec.install_hint,
        )

    detected = match.group(1)
    status = ToolStatus.AVAILABLE

    if spec.min_version:
        detected_parts = _parse_version_tuple(detected)
        min_parts = _parse_version_tuple(spec.min_version)
        if detected_parts < min_parts:
            status = ToolStatus.INCOMPATIBLE

    return ToolCheckResult(
        name=spec.name,
        executable=exe_name,
        status=status,
        path=resolved_path,
        detected_version=detected,
        min_version=spec.min_version,
        install_hint=spec.install_hint,
    )


def verify_all_tools(
    tools: tuple[ToolSpec, ...] = DEFAULT_TOOLS,
    custom_executables: Mapping[str, str] | None = None,
) -> list[ToolCheckResult]:
    """Verify all defined tools and return their check outcomes."""
    results: list[ToolCheckResult] = []
    custom = custom_executables or {}
    for spec in tools:
        custom_exe = custom.get(spec.name)
        results.append(check_tool(spec, executable_override=custom_exe))
    return results


def format_table(results: list[ToolCheckResult]) -> str:
    """Format verification results as a clean ASCII status table."""
    headers = ("Tool", "Status", "Version", "Minimum", "Path")
    rows = [
        (
            r.name,
            r.status.value,
            r.detected_version or "-",
            r.min_version or "-",
            r.path or "-",
        )
        for r in results
    ]

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    data_lines = [
        " | ".join(val.ljust(col_widths[i]) for i, val in enumerate(row))
        for row in rows
    ]

    missing = [r for r in results if r.status in (ToolStatus.MISSING, ToolStatus.INCOMPATIBLE)]
    hints = ""
    if missing:
        hints = "\n\nInstallation Guidance:\n" + "\n".join(
            f"  - {r.name}: {r.install_hint}" for r in missing
        )

    return f"{header_line}\n{sep_line}\n" + "\n".join(data_lines) + hints


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify availability and versions of WebVulnScanner external security tools."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON.",
    )
    args = parser.parse_args()

    results = verify_all_tools()

    if args.json_output:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print("WebVulnScanner External Tool Verification:\n")
        print(format_table(results))

    any_missing = any(r.status == ToolStatus.MISSING for r in results)
    return 1 if any_missing else 0


if __name__ == "__main__":
    sys.exit(main())
