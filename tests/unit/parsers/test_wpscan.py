"""Unit tests for the WPScan parser."""

from pathlib import Path

from webvulnscanner.models.finding import Severity
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.wpscan import WPScanParser


def test_wpscan_parser_fixture() -> None:
    fixture_path = Path(__file__).parents[2] / "fixtures" / "wpscan" / "sample.json"
    content = fixture_path.read_text(encoding="utf-8")

    parser = WPScanParser()
    result = parser.parse(ParserInput(content=content, source=fixture_path))

    assert len(result.items) == 2

    vul = result.items[0]
    assert vul.severity is Severity.HIGH
    assert vul.source_scanner == "wpscan"
    assert "Unauthenticated XSS" in vul.title
    assert "CVE-2022-31812" in vul.references

    obs = result.items[1]
    assert obs.severity is Severity.INFO
    assert obs.source_scanner == "wpscan"


def test_wpscan_parser_empty() -> None:
    parser = WPScanParser()
    result = parser.parse(ParserInput(content=""))
    assert result.items == ()
    assert result.warnings == ()
