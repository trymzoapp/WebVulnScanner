"""Unit tests for the external tool dependency verification script."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from scripts.verify_tools import (
    DEFAULT_TOOLS,
    ToolCheckResult,
    ToolSpec,
    ToolStatus,
    check_tool,
    format_table,
    verify_all_tools,
)


@pytest.fixture
def sample_spec() -> ToolSpec:
    return ToolSpec(
        name="testtool",
        executable="testtool",
        version_args=("--version",),
        version_regex=r"testtool v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        min_version="2.0.0",
        install_hint="apt install testtool",
    )


def test_check_tool_missing(sample_spec: ToolSpec) -> None:
    """When executable is not on PATH, check_tool returns MISSING."""
    with patch("shutil.which", return_value=None):
        res = check_tool(sample_spec)
        assert res.status == ToolStatus.MISSING
        assert res.path is None
        assert res.detected_version is None
        assert res.install_hint == sample_spec.install_hint


def test_check_tool_available_compatible(sample_spec: ToolSpec) -> None:
    """When executable is found and version meets minimum, status is AVAILABLE."""
    mock_proc = MagicMock()
    mock_proc.stdout = "testtool v2.4.1 (linux-amd64)\n"
    mock_proc.stderr = ""

    with patch("shutil.which", return_value="/usr/local/bin/testtool"), \
         patch("subprocess.run", return_value=mock_proc):
        res = check_tool(sample_spec)
        assert res.status == ToolStatus.AVAILABLE
        assert res.detected_version == "2.4.1"
        assert res.path == "/usr/local/bin/testtool"


def test_check_tool_incompatible_version(sample_spec: ToolSpec) -> None:
    """When detected version is below min_version, status is INCOMPATIBLE."""
    mock_proc = MagicMock()
    mock_proc.stdout = "testtool v1.8.0\n"
    mock_proc.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/testtool"), \
         patch("subprocess.run", return_value=mock_proc):
        res = check_tool(sample_spec)
        assert res.status == ToolStatus.INCOMPATIBLE
        assert res.detected_version == "1.8.0"


def test_check_tool_unknown_version(sample_spec: ToolSpec) -> None:
    """When version cannot be parsed from output, status is UNKNOWN."""
    mock_proc = MagicMock()
    mock_proc.stdout = "unrecognized output format\n"
    mock_proc.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/testtool"), \
         patch("subprocess.run", return_value=mock_proc):
        res = check_tool(sample_spec)
        assert res.status == ToolStatus.UNKNOWN
        assert res.detected_version is None


def test_check_tool_subprocess_error(sample_spec: ToolSpec) -> None:
    """When running tool raises an error, status is UNKNOWN without crashing."""
    with patch("shutil.which", return_value="/usr/bin/testtool"), \
         patch("subprocess.run", side_effect=subprocess.SubprocessError("Failed")):
        res = check_tool(sample_spec)
        assert res.status == ToolStatus.UNKNOWN


def test_verify_all_tools() -> None:
    """verify_all_tools returns a result for each tool spec."""
    with patch("shutil.which", return_value=None):
        results = verify_all_tools()
        assert len(results) == len(DEFAULT_TOOLS)
        assert all(r.status == ToolStatus.MISSING for r in results)


def test_format_table() -> None:
    """format_table creates an ASCII table with headers and guidance."""
    results = [
        ToolCheckResult(
            name="nmap",
            executable="nmap",
            status=ToolStatus.AVAILABLE,
            path="/usr/bin/nmap",
            detected_version="7.94",
            min_version="7.80",
            install_hint="apt install nmap",
        ),
        ToolCheckResult(
            name="nuclei",
            executable="nuclei",
            status=ToolStatus.MISSING,
            path=None,
            detected_version=None,
            min_version="3.0.0",
            install_hint="go install nuclei",
        ),
    ]

    table = format_table(results)
    assert "Tool" in table
    assert "Status" in table
    assert "nmap" in table
    assert "AVAILABLE" in table
    assert "nuclei" in table
    assert "MISSING" in table
    assert "Installation Guidance:" in table
    assert "go install nuclei" in table
