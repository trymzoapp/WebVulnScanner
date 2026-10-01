"""Tests for target validation trust boundaries."""

from pathlib import Path

import pytest

from webvulnscanner.core.exceptions import TargetValidationError
from webvulnscanner.utils.validators import validate_target


@pytest.mark.parametrize(
    "value",
    [
        "",
        " example.com",
        "example.com ",
        "example com",
        "example.com\n",
        r"example.com\..\escape",
        "../etc/passwd",
        "ftp://example.com",
        "file:///etc/passwd",
        "https://user:password@example.com",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:not-a-port",
        "https://2001:db8::1",
        "https://bad_label.example",
        "https://-bad.example",
        "https://bad-.example",
        "https://example..com",
        "999.999.999.999",
        "fe80::1%eth0",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_invalid_or_ambiguous_targets_are_rejected(value: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(value)


@pytest.mark.parametrize("default_scheme", ["ftp", "file", "", "HTTPS "])
def test_unsupported_default_scheme_is_rejected(default_scheme: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target("example.com", default_scheme=default_scheme)


def test_malformed_url_preserves_safe_cause_context() -> None:
    with pytest.raises(TargetValidationError) as captured:
        validate_target("https://example.com:invalid")

    error = captured.value
    assert error.component == "target"
    assert error.operation == "validate"
    assert error.cause_type == "ValueError"
    assert "invalid" not in str(error).casefold()


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "EXAMPLE.COM.",
        "https://example.com/path/../../resource",
        "192.0.2.1",
        "2001:db8::1",
    ],
)
def test_normalized_domain_cannot_escape_storage_root(
    value: str,
    tmp_path: Path,
) -> None:
    target = validate_target(value)
    candidate = (tmp_path / target.normalized_domain).resolve()

    assert candidate.is_relative_to(tmp_path.resolve())
    assert "/" not in target.normalized_domain
    assert "\\" not in target.normalized_domain
    assert ".." not in target.normalized_domain


def test_ipv6_namespace_cannot_be_used_by_a_hostname() -> None:
    ipv6_name = validate_target("2001:db8::1").normalized_domain

    assert ipv6_name.startswith("ipv6__")
    with pytest.raises(TargetValidationError):
        validate_target(ipv6_name)


def test_validated_target_contains_only_canonical_components() -> None:
    target = validate_target("HTTPS://Example.COM.:443/a?b=1#fragment")

    assert target.url == "https://example.com:443/a?b=1"
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 443
    assert target.normalized_domain == "example.com"
    assert target.kind == "hostname"
