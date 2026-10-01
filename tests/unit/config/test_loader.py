"""Tests for layered configuration loading and safety validation."""

from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.config.loader import ConfigLoader, load_config
from webvulnscanner.core.exceptions import ConfigurationError


PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "config"


def write_user_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "user.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_safe_profile_is_default_and_fully_typed() -> None:
    config = load_config()

    assert config.profile.name == "safe"
    assert config.profile.safety.allow_destructive is False
    assert config.concurrency.max_scanners == 3
    assert config.concurrency.max_targets == 2
    assert config.http.max_redirects == 5
    assert config.http.max_response_bytes == 1_048_576
    assert "WebVulnScanner" in config.http.user_agent
    assert config.wayback.endpoint.startswith("https://")
    assert config.wayback.max_records == 5_000
    assert config.wayback.page_size == 500
    assert config.fingerprint.ports == (80, 443, 8080, 8443)
    assert config.fingerprint.timing_template == 2
    assert config.fingerprint.host_timeout_seconds == 120
    assert config.discovery.max_recursion_depth == 0
    assert config.discovery.dirsearch_extensions == ("html", "php", "js", "txt")
    assert config.reports.json is True
    assert config.storage.root == Path("runs")
    assert config.timeouts.for_scanner("nuclei") == 600
    assert config.timeouts.for_scanner("unknown") == 300
    assert config.scanner("nuclei").executable == "nuclei"
    assert config.scanner("gobuster").enabled is False


def test_standard_profile_applies_bounded_profile_overrides() -> None:
    config = load_config(profile_name="standard")

    assert config.profile.name == "standard"
    assert config.concurrency.max_scanners == 5
    assert config.scanner("gobuster").enabled is True
    assert config.scanner("nuclei").rate_limit_per_second == 10.0
    assert config.profile.safety.allow_waf_bypass is False


def test_user_file_can_select_profile(tmp_path: Path) -> None:
    user_config = write_user_config(
        tmp_path,
        'profile:\n  name: "standard"\nreports:\n  html: false\n',
    )

    config = load_config(user_config=user_config)

    assert config.profile.name == "standard"
    assert config.reports.html is False
    assert config.scanner("gobuster").enabled is True


def test_precedence_is_defaults_then_scanners_profile_user_and_runtime() -> None:
    overrides: dict[str, Any] = {
        "timeouts": {"headers": 10},
        "reports": {"html": True},
    }

    config = load_config(
        user_config=FIXTURES / "custom.yaml",
        overrides=overrides,
    )

    assert config.timeouts.for_scanner("headers") == 10
    assert config.reports.html is True
    assert config.storage.root == Path("custom-runs")
    assert config.scanner("nuclei").executable == "/opt/tools/nuclei"
    assert config.scanner("nuclei").rate_limit_per_second == 3.0
    assert overrides == {
        "timeouts": {"headers": 10},
        "reports": {"html": True},
    }


def test_configuration_mappings_are_immutable() -> None:
    config = load_config()

    with pytest.raises(TypeError):
        config.scanners["nuclei"] = config.scanner("nuclei")  # type: ignore[index]
    with pytest.raises(TypeError):
        config.timeouts.per_scanner["nuclei"] = 1  # type: ignore[index]


def test_unknown_scanner_lookup_raises_typed_error() -> None:
    config = load_config()

    with pytest.raises(ConfigurationError, match="not configured"):
        config.scanner("not-a-scanner")


def test_malformed_yaml_raises_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="unable to load"):
        load_config(user_config=FIXTURES / "malformed.yaml")


def test_missing_user_file_raises_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_config(user_config=tmp_path / "missing.yaml")


@pytest.mark.parametrize("profile_name", ["missing", "../safe", "Safe", "safe/other"])
def test_missing_or_unsafe_profile_names_are_rejected(profile_name: str) -> None:
    with pytest.raises(ConfigurationError):
        load_config(profile_name=profile_name)


@pytest.mark.parametrize(
    "overrides",
    [
        {"unexpected": True},
        {"reports": {"pdf": True}},
        {"concurrency": {"worker_count": 2}},
        {"timeouts": {"typo-scanner": 10}},
        {"scanners": {"typo-scanner": {"enabled": True}}},
        {"scanners": {"nuclei": {"unknown_setting": True}}},
        {"profile": {"safety": {"unknown_limit": 1}}},
    ],
)
def test_unknown_critical_keys_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigurationError, match="unknown"):
        load_config(overrides=overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"timeouts": {"default": 0}},
        {"timeouts": {"nuclei": 86_401}},
        {"timeouts": {"nuclei": True}},
        {"concurrency": {"max_scanners": 0}},
        {"concurrency": {"max_targets": 21}},
        {"concurrency": {"max_targets": 1.5}},
        {"reports": {"json": "yes"}},
        {"http": {"user_agent": "unsafe\r\nInjected: true"}},
        {"http": {"max_redirects": 21}},
        {"http": {"max_response_bytes": 0}},
        {"wayback": {"endpoint": "http://archive.example/api"}},
        {"wayback": {"max_records": 0}},
        {"wayback": {"page_size": 5001}},
        {"fingerprint": {"ports": []}},
        {"fingerprint": {"ports": [0]}},
        {"fingerprint": {"timing_template": 4}},
        {"fingerprint": {"host_timeout_seconds": 3601}},
        {"discovery": {"status_codes": [99]}},
        {"discovery": {"dirsearch_extensions": ["../php"]}},
        {"discovery": {"max_recursion_depth": 3}},
        {"storage": {"root": ""}},
        {"scanners": {"nuclei": {"concurrency": 0}}},
        {"scanners": {"nuclei": {"rate_limit_per_second": float("inf")}}},
    ],
)
def test_invalid_limits_and_types_are_rejected(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ConfigurationError):
        load_config(overrides=overrides)


@pytest.mark.parametrize(
    "flag",
    [
        "allow_destructive",
        "allow_auth_bypass",
        "allow_waf_bypass",
        "allow_rate_limit_bypass",
    ],
)
def test_unsafe_profile_flags_are_always_rejected(flag: str) -> None:
    with pytest.raises(ConfigurationError, match="unsafe profile flags"):
        load_config(overrides={"profile": {"safety": {flag: True}}})


def test_unsafe_fixture_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="allow_destructive"):
        load_config(user_config=FIXTURES / "unsafe.yaml")


def test_runtime_limits_cannot_exceed_profile_safety_envelope() -> None:
    with pytest.raises(ConfigurationError, match="safety limit"):
        load_config(overrides={"concurrency": {"max_scanners": 4}})

    with pytest.raises(ConfigurationError):
        load_config(
            overrides={"scanners": {"nuclei": {"rate_limit_per_second": 6.0}}}
        )


def test_explicit_profile_cannot_be_renamed_by_user_file(tmp_path: Path) -> None:
    user_config = write_user_config(tmp_path, 'profile:\n  name: "standard"\n')

    with pytest.raises(ConfigurationError, match="cannot change"):
        load_config(profile_name="safe", user_config=user_config)


def test_missing_packaged_configuration_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="defaults.yaml"):
        ConfigLoader(tmp_path).load()
