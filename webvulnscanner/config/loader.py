"""Layered, typed YAML configuration loading."""

from __future__ import annotations

import copy
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import yaml

from webvulnscanner.core.exceptions import ConfigurationError

_ROOT_KEYS = {
    "timeouts",
    "concurrency",
    "http",
    "wayback",
    "fingerprint",
    "discovery",
    "reports",
    "storage",
    "profile",
    "scanners",
}
_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_MAX_TIMEOUT_SECONDS = 86_400
_MAX_SCANNERS = 20
_MAX_TARGETS = 20
_MAX_REQUESTS_PER_SECOND = 50.0


@dataclass(frozen=True, slots=True)
class TimeoutConfig:
    """Default and scanner-specific timeout values in seconds."""

    default: int
    per_scanner: Mapping[str, int]

    def for_scanner(self, scanner: str) -> int:
        """Return a scanner timeout, falling back to the configured default."""
        return self.per_scanner.get(scanner, self.default)


@dataclass(frozen=True, slots=True)
class ConcurrencyConfig:
    """Global scanner and target concurrency bounds."""

    max_scanners: int
    max_targets: int


@dataclass(frozen=True, slots=True)
class HttpConfig:
    """Shared safe HTTP request limits for passive web collectors."""

    user_agent: str
    max_redirects: int
    max_response_bytes: int


@dataclass(frozen=True, slots=True)
class WaybackConfig:
    """Bounded passive archive API settings."""

    endpoint: str
    max_records: int
    page_size: int


@dataclass(frozen=True, slots=True)
class FingerprintConfig:
    """Safe Nmap service-fingerprinting limits."""

    ports: tuple[int, ...]
    timing_template: int
    host_timeout_seconds: int


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Shared bounded content-discovery settings."""

    status_codes: tuple[int, ...]
    dirsearch_extensions: tuple[str, ...]
    max_recursion_depth: int


@dataclass(frozen=True, slots=True)
class ReportConfig:
    """Enabled report output formats."""

    json: bool
    markdown: bool
    html: bool


@dataclass(frozen=True, slots=True)
class StorageConfig:
    """Scan-result storage settings."""

    root: Path


@dataclass(frozen=True, slots=True)
class SafetyConfig:
    """Non-negotiable behavior flags and profile-specific resource ceilings."""

    allow_destructive: bool
    allow_auth_bypass: bool
    allow_waf_bypass: bool
    allow_rate_limit_bypass: bool
    max_requests_per_second: float
    max_scanners: int


@dataclass(frozen=True, slots=True)
class ProfileConfig:
    """Selected profile and its safety envelope."""

    name: str
    safety: SafetyConfig


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    """Externalized generic settings for one scanner or passive collector."""

    enabled: bool
    executable: str | None
    wordlist: Path | None
    concurrency: int
    rate_limit_per_second: float


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Complete immutable application configuration."""

    timeouts: TimeoutConfig
    concurrency: ConcurrencyConfig
    http: HttpConfig
    wayback: WaybackConfig
    fingerprint: FingerprintConfig
    discovery: DiscoveryConfig
    reports: ReportConfig
    storage: StorageConfig
    profile: ProfileConfig
    scanners: Mapping[str, ScannerConfig]

    def scanner(self, name: str) -> ScannerConfig:
        """Return a named scanner configuration with an actionable error."""
        try:
            return self.scanners[name]
        except KeyError as error:
            raise ConfigurationError(
                f"scanner is not configured: {name}",
                component="configuration",
                operation="lookup",
                cause=error,
            ) from error


class ConfigLoader:
    """Load defaults, scanner definitions, a profile, and optional overrides."""

    def __init__(self, config_directory: Path | None = None) -> None:
        self._config_directory = (
            Path(__file__).resolve().parent
            if config_directory is None
            else Path(config_directory)
        )

    def load(
        self,
        *,
        profile_name: str | None = None,
        user_config: Path | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> AppConfig:
        """Load configuration using documented low-to-high precedence."""
        defaults = self._load_yaml(self._config_directory / "defaults.yaml")
        scanner_definitions = self._load_yaml(self._config_directory / "scanners.yaml")
        user_values = {} if user_config is None else self._load_yaml(Path(user_config))

        default_profile = _read_profile_name(defaults)
        user_profile = _read_profile_name(user_values, required=False)
        selected_profile = profile_name or user_profile or default_profile
        if not selected_profile:
            raise _configuration_error("configuration profile name must not be empty")
        _validate_profile_name(selected_profile)

        profile_path = self._config_directory / "profiles" / f"{selected_profile}.yaml"
        if not profile_path.is_file():
            raise _configuration_error(
                f"configuration profile does not exist: {selected_profile}"
            )
        profile_values = self._load_yaml(profile_path)
        if _read_profile_name(profile_values) != selected_profile:
            raise _configuration_error(
                "profile filename and declared profile name do not match"
            )

        merged = _deep_merge(defaults, scanner_definitions)
        merged = _deep_merge(merged, profile_values)
        merged = _deep_merge(merged, user_values)
        if overrides is not None:
            if not isinstance(overrides, Mapping):
                raise _configuration_error("runtime overrides must be a mapping")
            merged = _deep_merge(merged, overrides)

        final_profile = _read_profile_name(merged)
        if final_profile != selected_profile:
            raise _configuration_error(
                "user configuration cannot change the selected profile name"
            )

        scanner_root = _required_mapping(
            scanner_definitions, "scanners", "scanner definitions"
        )
        known_scanners = frozenset(scanner_root)
        return _parse_config(merged, known_scanners)

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise _configuration_error(f"configuration file does not exist: {path}")
        try:
            with path.open("r", encoding="utf-8") as stream:
                loaded = yaml.safe_load(stream)
        except (OSError, yaml.YAMLError) as error:
            raise _configuration_error(
                f"unable to load configuration file: {path.name}",
                cause=error,
            ) from error
        if loaded is None:
            return {}
        if not isinstance(loaded, dict) or any(
            not isinstance(key, str) for key in loaded
        ):
            raise _configuration_error(
                f"configuration file must contain a string-keyed mapping: {path.name}"
            )
        return loaded


def load_config(
    *,
    profile_name: str | None = None,
    user_config: Path | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> AppConfig:
    """Load application configuration from the packaged configuration directory."""
    return ConfigLoader().load(
        profile_name=profile_name,
        user_config=user_config,
        overrides=overrides,
    )


def _parse_config(
    data: Mapping[str, Any],
    known_scanners: frozenset[str],
) -> AppConfig:
    _require_keys(data, _ROOT_KEYS, "root configuration")

    profile = _parse_profile(_required_mapping(data, "profile", "configuration"))
    concurrency = _parse_concurrency(
        _required_mapping(data, "concurrency", "configuration")
    )
    if concurrency.max_scanners > profile.safety.max_scanners:
        raise _configuration_error(
            "max_scanners exceeds the selected profile safety limit"
        )

    scanners = _parse_scanners(
        _required_mapping(data, "scanners", "configuration"),
        known_scanners,
        profile.safety,
    )
    timeouts = _parse_timeouts(
        _required_mapping(data, "timeouts", "configuration"),
        known_scanners,
    )
    reports = _parse_reports(_required_mapping(data, "reports", "configuration"))
    http = _parse_http(_required_mapping(data, "http", "configuration"))
    wayback = _parse_wayback(_required_mapping(data, "wayback", "configuration"))
    fingerprint = _parse_fingerprint(
        _required_mapping(data, "fingerprint", "configuration")
    )
    discovery = _parse_discovery(_required_mapping(data, "discovery", "configuration"))
    storage = _parse_storage(_required_mapping(data, "storage", "configuration"))

    return AppConfig(
        timeouts=timeouts,
        concurrency=concurrency,
        http=http,
        wayback=wayback,
        fingerprint=fingerprint,
        discovery=discovery,
        reports=reports,
        storage=storage,
        profile=profile,
        scanners=MappingProxyType(scanners),
    )


def _parse_timeouts(
    data: Mapping[str, Any],
    known_scanners: frozenset[str],
) -> TimeoutConfig:
    unknown = set(data) - (set(known_scanners) | {"default"})
    if unknown:
        raise _configuration_error(
            f"unknown timeout configuration: {', '.join(sorted(unknown))}"
        )
    if "default" not in data:
        raise _configuration_error("timeouts.default is required")
    default = _bounded_int(
        "timeouts.default",
        data["default"],
        minimum=1,
        maximum=_MAX_TIMEOUT_SECONDS,
    )
    per_scanner = {
        name: _bounded_int(
            f"timeouts.{name}",
            value,
            minimum=1,
            maximum=_MAX_TIMEOUT_SECONDS,
        )
        for name, value in data.items()
        if name != "default"
    }
    return TimeoutConfig(default=default, per_scanner=MappingProxyType(per_scanner))


def _parse_concurrency(data: Mapping[str, Any]) -> ConcurrencyConfig:
    _require_keys(data, {"max_scanners", "max_targets"}, "concurrency")
    return ConcurrencyConfig(
        max_scanners=_bounded_int(
            "concurrency.max_scanners",
            data["max_scanners"],
            minimum=1,
            maximum=_MAX_SCANNERS,
        ),
        max_targets=_bounded_int(
            "concurrency.max_targets",
            data["max_targets"],
            minimum=1,
            maximum=_MAX_TARGETS,
        ),
    )


def _parse_reports(data: Mapping[str, Any]) -> ReportConfig:
    _require_keys(data, {"json", "markdown", "html"}, "reports")
    return ReportConfig(
        json=_boolean("reports.json", data["json"]),
        markdown=_boolean("reports.markdown", data["markdown"]),
        html=_boolean("reports.html", data["html"]),
    )


def _parse_http(data: Mapping[str, Any]) -> HttpConfig:
    _require_keys(
        data,
        {"user_agent", "max_redirects", "max_response_bytes"},
        "http",
    )
    user_agent = data["user_agent"]
    if (
        not isinstance(user_agent, str)
        or not user_agent.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in user_agent)
    ):
        raise _configuration_error("http.user_agent must be a non-empty string")
    return HttpConfig(
        user_agent=user_agent,
        max_redirects=_bounded_int(
            "http.max_redirects",
            data["max_redirects"],
            minimum=0,
            maximum=20,
        ),
        max_response_bytes=_bounded_int(
            "http.max_response_bytes",
            data["max_response_bytes"],
            minimum=1,
            maximum=10_485_760,
        ),
    )


def _parse_wayback(data: Mapping[str, Any]) -> WaybackConfig:
    _require_keys(data, {"endpoint", "max_records", "page_size"}, "wayback")
    endpoint = data["endpoint"]
    if not isinstance(endpoint, str):
        raise _configuration_error("wayback.endpoint must be an HTTPS URL")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None:
        raise _configuration_error("wayback.endpoint must be an HTTPS URL")
    return WaybackConfig(
        endpoint=endpoint,
        max_records=_bounded_int(
            "wayback.max_records",
            data["max_records"],
            minimum=1,
            maximum=100_000,
        ),
        page_size=_bounded_int(
            "wayback.page_size",
            data["page_size"],
            minimum=1,
            maximum=5_000,
        ),
    )


def _parse_fingerprint(data: Mapping[str, Any]) -> FingerprintConfig:
    _require_keys(
        data,
        {"ports", "timing_template", "host_timeout_seconds"},
        "fingerprint",
    )
    ports = _bounded_int_sequence(
        "fingerprint.ports",
        data["ports"],
        minimum=1,
        maximum=65_535,
        max_items=64,
    )
    return FingerprintConfig(
        ports=ports,
        timing_template=_bounded_int(
            "fingerprint.timing_template",
            data["timing_template"],
            minimum=0,
            maximum=3,
        ),
        host_timeout_seconds=_bounded_int(
            "fingerprint.host_timeout_seconds",
            data["host_timeout_seconds"],
            minimum=1,
            maximum=3_600,
        ),
    )


def _parse_discovery(data: Mapping[str, Any]) -> DiscoveryConfig:
    _require_keys(
        data,
        {"status_codes", "dirsearch_extensions", "max_recursion_depth"},
        "discovery",
    )
    status_codes = _bounded_int_sequence(
        "discovery.status_codes",
        data["status_codes"],
        minimum=100,
        maximum=599,
        max_items=50,
    )
    raw_extensions = data["dirsearch_extensions"]
    if not isinstance(raw_extensions, list) or len(raw_extensions) > 20:
        raise _configuration_error(
            "discovery.dirsearch_extensions must be an array of at most 20 items"
        )
    extensions: list[str] = []
    for value in raw_extensions:
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9]{1,16}", value) is None
        ):
            raise _configuration_error(
                "discovery.dirsearch_extensions contains an invalid extension"
            )
        extensions.append(value.casefold())
    return DiscoveryConfig(
        status_codes=status_codes,
        dirsearch_extensions=tuple(dict.fromkeys(extensions)),
        max_recursion_depth=_bounded_int(
            "discovery.max_recursion_depth",
            data["max_recursion_depth"],
            minimum=0,
            maximum=2,
        ),
    )


def _parse_storage(data: Mapping[str, Any]) -> StorageConfig:
    _require_keys(data, {"root"}, "storage")
    root = data["root"]
    if not isinstance(root, str) or not root.strip() or "\x00" in root:
        raise _configuration_error("storage.root must be a non-empty path string")
    return StorageConfig(root=Path(root))


def _parse_profile(data: Mapping[str, Any]) -> ProfileConfig:
    _require_keys(data, {"name", "safety"}, "profile")
    name = data["name"]
    if not isinstance(name, str):
        raise _configuration_error("profile.name must be a string")
    _validate_profile_name(name)
    safety_data = _required_mapping(data, "safety", "profile")
    _require_keys(
        safety_data,
        {
            "allow_destructive",
            "allow_auth_bypass",
            "allow_waf_bypass",
            "allow_rate_limit_bypass",
            "max_requests_per_second",
            "max_scanners",
        },
        "profile.safety",
    )
    forbidden_flags = {
        name: _boolean(f"profile.safety.{name}", safety_data[name])
        for name in (
            "allow_destructive",
            "allow_auth_bypass",
            "allow_waf_bypass",
            "allow_rate_limit_bypass",
        )
    }
    enabled_unsafe = sorted(
        name for name, enabled in forbidden_flags.items() if enabled
    )
    if enabled_unsafe:
        raise _configuration_error(
            "unsafe profile flags are prohibited: " + ", ".join(enabled_unsafe)
        )
    return ProfileConfig(
        name=name,
        safety=SafetyConfig(
            **forbidden_flags,
            max_requests_per_second=_bounded_float(
                "profile.safety.max_requests_per_second",
                safety_data["max_requests_per_second"],
                minimum=0.1,
                maximum=_MAX_REQUESTS_PER_SECOND,
            ),
            max_scanners=_bounded_int(
                "profile.safety.max_scanners",
                safety_data["max_scanners"],
                minimum=1,
                maximum=_MAX_SCANNERS,
            ),
        ),
    )


def _parse_scanners(
    data: Mapping[str, Any],
    known_scanners: frozenset[str],
    safety: SafetyConfig,
) -> dict[str, ScannerConfig]:
    unknown = set(data) - set(known_scanners)
    missing = set(known_scanners) - set(data)
    if unknown:
        raise _configuration_error(
            f"unknown scanner configuration: {', '.join(sorted(unknown))}"
        )
    if missing:
        raise _configuration_error(
            f"missing scanner configuration: {', '.join(sorted(missing))}"
        )

    scanners: dict[str, ScannerConfig] = {}
    expected = {
        "enabled",
        "executable",
        "wordlist",
        "concurrency",
        "rate_limit_per_second",
    }
    for name in sorted(known_scanners):
        scanner_data = _mapping_value(f"scanners.{name}", data[name])
        _require_keys(scanner_data, expected, f"scanners.{name}")
        concurrency = _bounded_int(
            f"scanners.{name}.concurrency",
            scanner_data["concurrency"],
            minimum=1,
            maximum=safety.max_scanners,
        )
        rate_limit = _bounded_float(
            f"scanners.{name}.rate_limit_per_second",
            scanner_data["rate_limit_per_second"],
            minimum=0.1,
            maximum=safety.max_requests_per_second,
        )
        scanners[name] = ScannerConfig(
            enabled=_boolean(
                f"scanners.{name}.enabled",
                scanner_data["enabled"],
            ),
            executable=_optional_text(
                f"scanners.{name}.executable",
                scanner_data["executable"],
            ),
            wordlist=_optional_path(
                f"scanners.{name}.wordlist",
                scanner_data["wordlist"],
            ),
            concurrency=concurrency,
            rate_limit_per_second=rate_limit,
        )
    return scanners


def _read_profile_name(
    data: Mapping[str, Any],
    *,
    required: bool = True,
) -> str | None:
    profile = data.get("profile")
    if profile is None and not required:
        return None
    if not isinstance(profile, Mapping):
        raise _configuration_error("profile must be a mapping")
    name = profile.get("name")
    if name is None and not required:
        return None
    if not isinstance(name, str):
        raise _configuration_error("profile.name must be a string")
    return name


def _validate_profile_name(name: str) -> None:
    if _PROFILE_NAME.fullmatch(name) is None:
        raise _configuration_error(
            "profile name may contain only lowercase letters, numbers, hyphens, and underscores"
        )


def _deep_merge(
    lower: Mapping[str, Any],
    higher: Mapping[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(dict(lower))
    for key, value in higher.items():
        current = result.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            result[key] = _deep_merge(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _required_mapping(
    data: Mapping[str, Any],
    key: str,
    parent: str,
) -> Mapping[str, Any]:
    if key not in data:
        raise _configuration_error(f"{parent}.{key} is required")
    return _mapping_value(f"{parent}.{key}", data[key])


def _mapping_value(name: str, value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _configuration_error(f"{name} must be a string-keyed mapping")
    return value


def _require_keys(
    data: Mapping[str, Any],
    expected: set[str],
    section: str,
) -> None:
    actual = set(data)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise _configuration_error(
            f"{section} is missing required keys: {', '.join(missing)}"
        )
    if unknown:
        raise _configuration_error(
            f"{section} contains unknown keys: {', '.join(unknown)}"
        )


def _bounded_int(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _configuration_error(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise _configuration_error(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_float(
    name: str,
    value: object,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _configuration_error(f"{name} must be a number")
    numeric = float(value)
    if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
        raise _configuration_error(f"{name} must be between {minimum} and {maximum}")
    return numeric


def _bounded_int_sequence(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
    max_items: int,
) -> tuple[int, ...]:
    if not isinstance(value, list) or not value or len(value) > max_items:
        raise _configuration_error(
            f"{name} must be a non-empty array of at most {max_items} integers"
        )
    result: list[int] = []
    for item in value:
        result.append(_bounded_int(name, item, minimum=minimum, maximum=maximum))
    return tuple(dict.fromkeys(result))


def _boolean(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise _configuration_error(f"{name} must be a boolean")
    return value


def _optional_text(name: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise _configuration_error(f"{name} must be a non-empty string or null")
    return value


def _optional_path(name: str, value: object) -> Path | None:
    text = _optional_text(name, value)
    return None if text is None else Path(text)


def _configuration_error(
    message: str,
    *,
    cause: BaseException | None = None,
) -> ConfigurationError:
    return ConfigurationError(
        message,
        component="configuration",
        operation="load",
        cause=cause,
    )


__all__ = [
    "AppConfig",
    "ConcurrencyConfig",
    "ConfigLoader",
    "DiscoveryConfig",
    "FingerprintConfig",
    "HttpConfig",
    "ProfileConfig",
    "ReportConfig",
    "SafetyConfig",
    "ScannerConfig",
    "StorageConfig",
    "TimeoutConfig",
    "WaybackConfig",
    "load_config",
]
