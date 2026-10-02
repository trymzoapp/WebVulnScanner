"""Helpers and executable wrappers for fake external tools."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent

ALL_TOOLS = (
    "subfinder",
    "whois",
    "wappalyzer",
    "nmap",
    "gobuster",
    "dirsearch",
    "nuclei",
    "sqlmap",
    "wpscan",
)


def ensure_tool_wrappers() -> None:
    """Generate .cmd and POSIX wrapper scripts in tests/fixtures/tools/."""
    TOOLS_DIR / "fake_tool.py"
    for tool in ALL_TOOLS:
        cmd_path = TOOLS_DIR / f"{tool}.cmd"
        cmd_content = f"""@echo off
if defined PYTHON (
    "%PYTHON%" "%~dp0fake_tool.py" {tool} %*
) else (
    python "%~dp0fake_tool.py" {tool} %*
)
"""
        cmd_path.write_text(cmd_content, encoding="utf-8")

        sh_path = TOOLS_DIR / tool
        sh_content = f"""#!/bin/sh
PYTHON="${{PYTHON:-python3}}"
exec "$PYTHON" "$(dirname "$0")/fake_tool.py" {tool} "$@"
"""
        sh_path.write_text(sh_content, encoding="utf-8")
        try:
            current_mode = sh_path.stat().st_mode
            sh_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass


def get_fake_tool_path(tool_name: str) -> str:
    """Return the platform-appropriate executable path for the fake tool."""
    ensure_tool_wrappers()
    ext = ".cmd" if sys.platform == "win32" else ""
    path = TOOLS_DIR / f"{tool_name}{ext}"
    return str(path)


ensure_tool_wrappers()
