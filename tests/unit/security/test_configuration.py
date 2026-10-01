"""Unit tests verifying configuration trust boundaries, limits, and safety invariants."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from webvulnscanner.config.loader import ConfigLoader, load_config
from webvulnscanner.core.exceptions import ConfigurationError


def test_cannot_enable_destructive_or_bypass_flags() -> None:
    """Prohibited safety flags must raise ConfigurationError even if configured."""
    forbidden_flags = [
        "allow_destructive",
        "allow_auth_bypass",
        "allow_waf_bypass",
        "allow_rate_limit_bypass",
    ]
    for flag in forbidden_flags:
        with pytest.raises(ConfigurationError, match=r"unsafe profile flags are prohibited"):
            load_config(overrides={"profile": {"safety": {flag: True}}})


def test_concurrency_max_scanners_exceeding_profile_safety_rejected() -> None:
    """concurrency.max_scanners cannot exceed the profile's safety limit."""
    # In safe profile, safety.max_scanners is 3
    with pytest.raises(ConfigurationError, match=r"max_scanners exceeds the selected profile safety limit"):
        load_config(overrides={"concurrency": {"max_scanners": 4}})


def test_excessive_timeouts_rejected() -> None:
    """Timeouts above 86400 or below 1 must be rejected."""
    with pytest.raises(ConfigurationError, match=r"timeouts\.default must be between 1 and 86400"):
        load_config(overrides={"timeouts": {"default": 86401}})

    with pytest.raises(ConfigurationError, match=r"timeouts\.default must be between 1 and 86400"):
        load_config(overrides={"timeouts": {"default": 0}})

    with pytest.raises(ConfigurationError, match=r"timeouts\.nuclei must be between 1 and 86400"):
        load_config(overrides={"timeouts": {"nuclei": 100_000}})


def test_excessive_concurrency_limits_rejected() -> None:
    """Global concurrency bounds must not exceed hard limits (max 20)."""
    with pytest.raises(ConfigurationError, match=r"concurrency\.max_targets must be between 1 and 20"):
        load_config(overrides={"concurrency": {"max_targets": 21}})

    with pytest.raises(ConfigurationError, match=r"concurrency\.max_targets must be between 1 and 20"):
        load_config(overrides={"concurrency": {"max_targets": 0}})


def test_excessive_scanner_rate_limits_rejected() -> None:
    """Scanner rate limits cannot exceed profile safety max requests per second."""
    # safe profile max_requests_per_second is 5.0
    with pytest.raises(ConfigurationError, match=r"rate_limit_per_second must be between"):
        load_config(overrides={"scanners": {"nuclei": {"rate_limit_per_second": 10.0}}})

    with pytest.raises(ConfigurationError, match=r"rate_limit_per_second must be between"):
        load_config(overrides={"scanners": {"nuclei": {"rate_limit_per_second": 0.0}}})


def test_excessive_fingerprint_settings_rejected() -> None:
    """Nmap timing template > 3 or timeout > 3600 must be rejected."""
    with pytest.raises(ConfigurationError, match=r"fingerprint\.timing_template must be between 0 and 3"):
        load_config(overrides={"fingerprint": {"timing_template": 4}})

    with pytest.raises(ConfigurationError, match=r"fingerprint\.host_timeout_seconds must be between 1 and 3600"):
        load_config(overrides={"fingerprint": {"host_timeout_seconds": 7200}})

    with pytest.raises(ConfigurationError, match=r"fingerprint\.ports"):
        load_config(overrides={"fingerprint": {"ports": [0]}})

    with pytest.raises(ConfigurationError, match=r"fingerprint\.ports"):
        load_config(overrides={"fingerprint": {"ports": [70000]}})

    with pytest.raises(ConfigurationError, match=r"fingerprint\.ports"):
        load_config(overrides={"fingerprint": {"ports": list(range(1, 66))}})


def test_unsafe_http_settings_rejected() -> None:
    """HTTP user-agent and limits must be strictly validated."""
    with pytest.raises(ConfigurationError, match=r"http\.user_agent must be a non-empty string"):
        load_config(overrides={"http": {"user_agent": ""}})

    with pytest.raises(ConfigurationError, match=r"http\.user_agent must be a non-empty string"):
        load_config(overrides={"http": {"user_agent": "   "}})

    # User-agent with CRLF or control characters
    with pytest.raises(ConfigurationError, match=r"http\.user_agent must be a non-empty string"):
        load_config(overrides={"http": {"user_agent": "BadAgent\r\nInjected-Header: evil"}})

    with pytest.raises(ConfigurationError, match=r"http\.max_redirects must be between 0 and 20"):
        load_config(overrides={"http": {"max_redirects": 25}})

    with pytest.raises(ConfigurationError, match=r"http\.max_response_bytes must be between 1 and 10485760"):
        load_config(overrides={"http": {"max_response_bytes": 20_000_000}})


def test_wayback_endpoint_security() -> None:
    """Wayback endpoint must strictly be an HTTPS URL without embedded credentials."""
    with pytest.raises(ConfigurationError, match=r"wayback\.endpoint must be an HTTPS URL"):
        load_config(overrides={"wayback": {"endpoint": "http://web.archive.org/cdx/search/cdx"}})

    with pytest.raises(ConfigurationError, match=r"wayback\.endpoint must be an HTTPS URL"):
        load_config(overrides={"wayback": {"endpoint": "ftp://archive.org"}})

    with pytest.raises(ConfigurationError, match=r"wayback\.endpoint must be an HTTPS URL"):
        load_config(overrides={"wayback": {"endpoint": "https://user:pass@web.archive.org/cdx"}})


def test_discovery_extension_and_depth_safety() -> None:
    """Discovery extensions and depth must prevent abuse and excessive recursion."""
    with pytest.raises(ConfigurationError, match=r"discovery\.max_recursion_depth must be between 0 and 2"):
        load_config(overrides={"discovery": {"max_recursion_depth": 5}})

    # Extension with path traversal or invalid characters
    with pytest.raises(ConfigurationError, match=r"discovery\.dirsearch_extensions contains an invalid extension"):
        load_config(overrides={"discovery": {"dirsearch_extensions": ["../evil"]}})

    with pytest.raises(ConfigurationError, match=r"discovery\.dirsearch_extensions contains an invalid extension"):
        load_config(overrides={"discovery": {"dirsearch_extensions": [".php"]}})

    # Too many extensions
    with pytest.raises(ConfigurationError, match=r"discovery\.dirsearch_extensions must be an array of at most 20 items"):
        load_config(overrides={"discovery": {"dirsearch_extensions": [f"ext{i}" for i in range(25)]}})


def test_profile_name_traversal_and_injection() -> None:
    """Profile name must be strictly alphanumeric with hyphens/underscores."""
    invalid_profiles = [
        "../traversal",
        "../../etc/passwd",
        "profile;rm -rf /",
        "profile|calc",
        "standard\x00extra",
        "UPPERCASE",
        "profile with spaces",
    ]
    for bad_name in invalid_profiles:
        with pytest.raises(ConfigurationError):
            load_config(profile_name=bad_name)


def test_storage_root_safety() -> None:
    """Storage root cannot be empty or contain null bytes."""
    with pytest.raises(ConfigurationError, match=r"storage\.root must be a non-empty path string"):
        load_config(overrides={"storage": {"root": ""}})

    with pytest.raises(ConfigurationError, match=r"storage\.root must be a non-empty path string"):
        load_config(overrides={"storage": {"root": "runs\x00injected"}})


def test_unknown_and_missing_keys_rejected() -> None:
    """Unknown root keys, unknown scanners, or missing required keys must fail."""
    with pytest.raises(ConfigurationError, match=r"root configuration contains unknown keys"):
        load_config(overrides={"injected_root_key": True})

    with pytest.raises(ConfigurationError, match=r"unknown scanner configuration"):
        load_config(overrides={"scanners": {"malicious_scanner": {"enabled": True}}})


def test_malformed_yaml_handling(tmp_path: Path) -> None:
    """Malformed YAML, non-dict root, or non-string keys must raise ConfigurationError."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(":\n  - invalid: yaml [", encoding="utf-8")
    loader = ConfigLoader()
    with pytest.raises(ConfigurationError, match=r"unable to load configuration file"):
        loader.load(user_config=bad_yaml)

    list_yaml = tmp_path / "list.yaml"
    list_yaml.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match=r"must contain a string-keyed mapping"):
        loader.load(user_config=list_yaml)
