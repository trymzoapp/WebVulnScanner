"""Tests for the public target model."""

from dataclasses import FrozenInstanceError

import pytest

from webvulnscanner.models.target import Target, TargetKind


def test_hostname_target_uses_safe_canonical_defaults() -> None:
    target = Target("Example.COM.")

    assert target.original == "Example.COM."
    assert target.url == "https://example.com/"
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port is None
    assert target.normalized_domain == "example.com"
    assert target.kind is TargetKind.HOSTNAME
    assert target.is_ip is False


def test_url_target_preserves_path_query_and_explicit_port() -> None:
    target = Target("HTTP://Example.com:8080/a/path?item=1#ignored")

    assert target.url == "http://example.com:8080/a/path?item=1"
    assert target.scheme == "http"
    assert target.host == "example.com"
    assert target.port == 8080


def test_default_scheme_can_be_selected_explicitly() -> None:
    target = Target("example.com/login", default_scheme="http")

    assert target.url == "http://example.com/login"
    assert target.scheme == "http"


def test_internationalized_hostname_is_normalized_to_idna() -> None:
    target = Target("https://münich.example/")

    assert target.host == "xn--mnich-kva.example"
    assert target.normalized_domain == "xn--mnich-kva.example"
    assert target.url == "https://xn--mnich-kva.example/"


def test_ipv4_target_is_canonical() -> None:
    target = Target("192.0.2.10")

    assert target.url == "https://192.0.2.10/"
    assert target.host == "192.0.2.10"
    assert target.normalized_domain == "192.0.2.10"
    assert target.kind is TargetKind.IPV4
    assert target.is_ip is True


@pytest.mark.parametrize(
    ("value", "expected_url", "expected_port"),
    [
        ("2001:0db8:0:0:0:0:0:1", "https://[2001:db8::1]/", None),
        ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443/", 8443),
        ("[2001:db8::1]", "https://[2001:db8::1]/", None),
    ],
)
def test_ipv6_target_is_canonical_and_filesystem_safe(
    value: str,
    expected_url: str,
    expected_port: int | None,
) -> None:
    target = Target(value)

    assert target.url == expected_url
    assert target.host == "2001:db8::1"
    assert target.port == expected_port
    assert target.normalized_domain == "ipv6__2001-db8--1"
    assert ":" not in target.normalized_domain
    assert "/" not in target.normalized_domain
    assert "\\" not in target.normalized_domain
    assert target.kind is TargetKind.IPV6
    assert target.is_ip is True


def test_equivalent_hosts_share_one_normalized_domain() -> None:
    first = Target("https://Example.COM:443/path")
    second = Target("example.com.")

    assert first.normalized_domain == second.normalized_domain == "example.com"


def test_distinct_ipv6_addresses_do_not_collide() -> None:
    first = Target("2001:db8::1")
    second = Target("2001:db8::2")

    assert first.normalized_domain != second.normalized_domain


def test_target_is_immutable_after_validation() -> None:
    target = Target("example.com")

    with pytest.raises(FrozenInstanceError):
        target.host = "other.example"  # type: ignore[misc]
