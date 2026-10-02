"""Unit tests verifying command injection prevention, argument isolation, and option safety."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from webvulnscanner.config.loader import load_config
from webvulnscanner.core.context import create_scan_context
from webvulnscanner.core.exceptions import TargetValidationError
from webvulnscanner.core.subprocess_runner import (
    AsyncSubprocessRunner,
)
from webvulnscanner.models.target import Target
from webvulnscanner.scanners.fingerprint.nmap import NmapScanner
from webvulnscanner.scanners.vulnerability.sqlmap import SQLmapScanner
from webvulnscanner.scanners.vulnerability.wpscan import WPScanScanner
from webvulnscanner.utils.command import Command


def test_command_rejects_null_bytes_and_invalid_types() -> None:
    """Command must strictly reject null bytes and non-string arguments."""
    with pytest.raises(ValueError, match=r"must not contain a null byte"):
        Command("nmap\x00extra", ())

    with pytest.raises(ValueError, match=r"must not contain a null byte"):
        Command("nmap", ("-p", "80\x00--script=evil"))

    with pytest.raises(ValueError, match=r"must not be empty"):
        Command("", ())

    with pytest.raises(TypeError, match=r"executable must be a string"):
        Command(123, ())  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"arguments must be a tuple of strings"):
        Command("nmap", ["-sV"])  # type: ignore[arg-type]


def test_command_rejects_malformed_environment() -> None:
    """Environment variables in Command cannot have null bytes or '=' in key."""
    with pytest.raises(ValueError, match=r"environment keys cannot contain '='"):
        Command("nmap", (), environment={"BAD=KEY": "value"})

    with pytest.raises(ValueError, match=r"must not contain a null byte"):
        Command("nmap", (), environment={"KEY": "val\x00ue"})


@pytest.mark.asyncio
async def test_subprocess_runner_passes_metacharacters_literally() -> None:
    """Subprocess runner executes without shell, passing metacharacters literally."""
    runner = AsyncSubprocessRunner(max_concurrency=2, default_timeout=5.0)

    # We use python itself as the executable to echo back arguments exactly
    shell_payload = "echo $(id); calc.exe | dir & whoami && rm -rf / > /tmp/pwn"
    cmd = Command(
        executable=sys.executable,
        arguments=("-c", "import sys; print(sys.argv[1])", shell_payload),
    )

    result = await runner.run(cmd)
    assert result.succeeded
    # The output should match the exact literal string, uninterpreted by any shell
    assert result.stdout.strip() == shell_payload


def test_target_validation_prevents_flag_injection() -> None:
    """Target strings cannot start with hyphen or inject CLI options."""
    flag_injections = [
        "-h",
        "--help",
        "-oX /tmp/evil",
        "--script=all",
        "-u http://evil.com",
        "--os-shell",
        "; calc.exe",
        "| whoami",
        "http://example.com/`id`",
    ]
    for bad_target in flag_injections:
        with pytest.raises(TargetValidationError):
            Target(bad_target)


def test_sqlmap_scanner_prohibits_destructive_and_privilege_escalation_options() -> (
    None
):
    """SQLmapScanner must strictly omit dangerous, intrusive, and dumping options."""
    config = load_config()
    target = Target("https://example.com/items?id=1")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()

    scanner = SQLmapScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_url=target.url,
    )

    cmd = scanner.build_command()
    cmd_args = " ".join(cmd.argv)

    for prohibited in SQLmapScanner.PROHIBITED_OPTIONS:
        assert prohibited not in cmd_args, (
            f"Prohibited option {prohibited} found in SQLmap command"
        )

    assert "--batch" in cmd.arguments
    assert "--risk=1" in cmd.arguments
    assert "--level=1" in cmd.arguments
    assert "-u" in cmd.arguments
    assert target.url in cmd.arguments


def test_sqlmap_scanner_rejects_invalid_output_filename() -> None:
    """SQLmapScanner output filename must follow a safe pattern, preventing path traversal."""
    config = load_config()
    target = Target("https://example.com/items?id=1")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()

    bad_filenames = [
        "../sqlmap.json",
        "../../etc/passwd",
        "sqlmap.json.exe",
        "custom_tool.sh",
        "sqlmap-invalidchars!.json",
    ]
    for bad_name in bad_filenames:
        with pytest.raises(ValueError, match=r"invalid SQLmap output filename"):
            SQLmapScanner(
                configuration=config,
                runner=mock_runner,
                context=context,
                target_url=target.url,
                output_filename=bad_name,
            )


def test_nmap_command_strictly_bounded() -> None:
    """Nmap command must use constrained flags and explicit target host."""
    config = load_config()
    target = Target("https://example.com")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()

    scanner = NmapScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
    )

    cmd = scanner.build_command()
    assert cmd.executable == "nmap"
    assert "-Pn" in cmd.arguments
    assert "-sV" in cmd.arguments
    assert "--version-light" in cmd.arguments
    assert "-oX" in cmd.arguments
    assert "-" in cmd.arguments
    assert target.host in cmd.arguments
    # Verify no arbitrary script execution or intrusive flags
    assert "--script" not in cmd.arguments
    assert "-sS" not in cmd.arguments
    assert "-A" not in cmd.arguments


def test_wpscan_command_safe_and_batch() -> None:
    """WPScan command must be non-interactive and use --no-update."""
    config = load_config()
    target = Target("https://example.com")
    context = create_scan_context(
        storage_root=Path("runs"),
        target=target,
        profile_name="safe",
        scanner_configuration={},
    )
    mock_runner = AsyncMock()

    scanner = WPScanScanner(
        configuration=config,
        runner=mock_runner,
        context=context,
        target_url=target.url,
    )

    cmd = scanner.build_command()
    assert "--format" in cmd.arguments
    assert "json" in cmd.arguments
    assert "--detection-mode" in cmd.arguments
    assert "passive" in cmd.arguments
    # Ensure no brute-forcing options
    for prohibited in WPScanScanner.PROHIBITED_OPTIONS:
        assert prohibited not in cmd.arguments
