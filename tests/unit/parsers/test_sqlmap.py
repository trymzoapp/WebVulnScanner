"""Unit tests for the SQLmap parser."""

from pathlib import Path

from webvulnscanner.models.finding import Severity
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.sqlmap import SQLmapParser


def test_sqlmap_parser_fixture() -> None:
    fixture_path = Path(__file__).parents[2] / "fixtures" / "sqlmap" / "sample.json"
    content = fixture_path.read_text(encoding="utf-8")

    parser = SQLmapParser()
    result = parser.parse(ParserInput(content=content, source=fixture_path))

    assert len(result.items) == 1
    finding = result.items[0]
    assert finding.source_scanner == "sqlmap"
    assert finding.severity is Severity.HIGH
    assert finding.parameter == "id"
    assert finding.affected_resource == "https://example.com/item?id=1"
    assert "boolean-based blind" in finding.description


def test_sqlmap_parser_empty() -> None:
    parser = SQLmapParser()
    result = parser.parse(ParserInput(content=""))
    assert result.items == ()
    assert result.warnings == ()
