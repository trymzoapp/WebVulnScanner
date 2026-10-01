"""Tests for the initial safe command-line interface."""

import asyncio
import json
from pathlib import Path

import pytest

from webvulnscanner import __version__
from webvulnscanner.cli import EXIT_INVALID_INPUT, EXIT_SUCCESS, main
from webvulnscanner.core.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_help_describes_authorized_use(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as captured:
        main(["--help"])

    assert captured.value.code == 0
    output = capsys.readouterr().out
    assert "authorized" in output.casefold()
    assert "scan" in output
    assert "config" in output


def test_version_is_available_without_a_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        main(["--version"])

    assert captured.value.code == 0
    assert capsys.readouterr().out.strip() == f"webvulnscanner {__version__}"


def test_scan_requires_an_explicit_target(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        main(["scan"])

    assert captured.value.code == 2
    assert "target" in capsys.readouterr().err


@pytest.mark.parametrize(
    "target",
    [
        "../escape",
        "ftp://example.com",
        "https://user:password@example.com",
        "https://example.com:not-a-port",
    ],
)
def test_invalid_target_creates_no_storage_or_subprocess(
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    async def forbidden_subprocess(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid input must not launch a subprocess")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_subprocess)

    exit_code = main(["scan", target])

    assert exit_code == EXIT_INVALID_INPUT
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_valid_scan_input_and_overrides_execute_with_injected_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    storage = tmp_path / "custom-runs"

    async def forbidden_subprocess(*args: object, **kwargs: object) -> None:
        raise AssertionError("injected empty pipeline must not launch subprocesses")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_subprocess)

    exit_code = main(
        [
            "scan",
            "HTTPS://Example.COM:8443/path",
            "--confirm-authorized",
            "--profile",
            "safe",
            "--storage-root",
            str(storage),
            "--timeout",
            "45",
            "--concurrency",
            "2",
        ],
        pipeline_factory=lambda configuration, runner: Pipeline(()),
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_SUCCESS
    assert payload["status"] == "completed"
    assert payload["authorized_use_required"] is True
    assert payload["target_url"] == "https://example.com:8443/path"
    assert payload["normalized_domain"] == "example.com"
    assert Path(payload["scan_directory"]).is_relative_to(storage)
    assert payload["scan_id"]
    assert payload["stages"] == {}
    assert storage.exists()


def test_config_command_prints_validated_effective_configuration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["config", "--profile", "standard"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_SUCCESS
    assert payload["profile"]["name"] == "standard"
    assert payload["profile"]["safety"]["allow_destructive"] is False
    assert payload["concurrency"]["max_scanners"] == 5
    assert payload["scanners"]["gobuster"]["enabled"] is True


def test_user_config_is_applied(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    user_config = tmp_path / "config.yaml"
    user_config.write_text(
        'profile:\n  name: "safe"\nreports:\n  html: false\n',
        encoding="utf-8",
    )

    exit_code = main(["config", "--config", str(user_config)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == EXIT_SUCCESS
    assert payload["reports"]["html"] is False


@pytest.mark.parametrize(
    "arguments",
    [
        ["config", "--timeout", "0"],
        ["config", "--concurrency", "0"],
        ["config", "--profile", "missing"],
        ["config", "--config", "missing.yaml"],
    ],
)
def test_invalid_configuration_returns_concise_exit_code(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(arguments)

    captured = capsys.readouterr()
    assert exit_code == EXIT_INVALID_INPUT
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert "Traceback" not in captured.err


def test_console_entry_point_is_declared() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '[project.scripts]' in pyproject
    assert 'webvulnscanner = "webvulnscanner.cli:main"' in pyproject


def test_no_bypass_or_destructive_options_are_exposed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(["scan", "--help"])

    help_text = capsys.readouterr().out.casefold()
    for prohibited in ("bypass", "destructive", "tamper", "evasion"):
        assert prohibited not in help_text
