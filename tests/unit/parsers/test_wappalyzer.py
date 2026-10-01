"""Tests for structured Wappalyzer parsing."""

from pathlib import Path

import pytest

from webvulnscanner.core.exceptions import ParsingError
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.wappalyzer import WappalyzerParser


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "wappalyzer"
    / "technologies.json"
)


def test_parses_normalizes_and_warns_for_partial_output() -> None:
    parsed = WappalyzerParser().parse(
        ParserInput(FIXTURE.read_text(encoding="utf-8"))
    )

    assert [item.name for item in parsed.items] == ["PHP", "WordPress"]
    assert parsed.items[0].confidence == 0.8
    assert parsed.items[1].categories == ("CMS",)
    assert parsed.items[1].evidence == ("https://wordpress.org",)
    assert parsed.warnings == ("technology 2: invalid structured record",)


def test_empty_structured_output_is_successful() -> None:
    parsed = WappalyzerParser().parse(ParserInput('{"technologies": []}'))

    assert parsed.items == ()
    assert parsed.warnings == ()


@pytest.mark.parametrize("content", ["not-json", "{}", '{"other": []}'])
def test_malformed_or_unrecognized_output_is_controlled(content: str) -> None:
    with pytest.raises(ParsingError):
        WappalyzerParser().parse(ParserInput(content))
