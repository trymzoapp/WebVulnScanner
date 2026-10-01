"""Tests for secure Nmap XML parsing."""

from pathlib import Path

import pytest

from webvulnscanner.core.exceptions import ParsingError
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.nmap import NmapParser


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "nmap"
    / "web-services.xml"
)


def test_parses_only_open_configured_services_and_web_urls() -> None:
    parsed = NmapParser("example.com", (80, 443, 8080)).parse(
        ParserInput(FIXTURE.read_text(encoding="utf-8"))
    )

    assert [(item.port, item.service) for item in parsed.items] == [
        (80, "http"),
        (443, "http"),
    ]
    assert [item.web_url for item in parsed.items] == [
        "http://example.com/",
        "https://example.com/",
    ]
    assert len(parsed.warnings) == 2


def test_missing_or_down_hosts_return_empty_result() -> None:
    content = '<nmaprun><host><status state="down"/></host></nmaprun>'

    assert NmapParser("example.com", (80,)).parse(
        ParserInput(content)
    ).items == ()


@pytest.mark.parametrize(
    "content",
    [
        "not xml",
        "<other/>",
        '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun/>',
    ],
)
def test_malformed_and_hostile_xml_is_rejected(content: str) -> None:
    with pytest.raises(ParsingError):
        NmapParser("example.com", (80,)).parse(ParserInput(content))
