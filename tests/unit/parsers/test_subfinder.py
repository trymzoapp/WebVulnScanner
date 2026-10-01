"""Tests for strict Subfinder JSONL parsing and scope filtering."""

from pathlib import Path

from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.subfinder import (
    SubfinderParser,
    registrable_domain,
)


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "subfinder"
    / "mixed.jsonl"
)


def test_structured_fixture_is_normalized_deduplicated_and_scoped() -> None:
    parser = SubfinderParser("www.example.com")

    result = parser.parse(
        ParserInput(FIXTURE.read_text(encoding="utf-8"), source=FIXTURE)
    )

    assert parser.scope_domain == "example.com"
    assert result.items == ("api.example.com", "mobile.example.com")
    assert result.excluded_count == 1
    assert len(result.warnings) == 2


def test_terminal_formatted_text_is_not_treated_as_a_hostname() -> None:
    result = SubfinderParser("example.com").parse(
        ParserInput("[INF] Found subdomain: unsafe.example.com\n")
    )

    assert result.items == ()
    assert result.excluded_count == 0
    assert result.warnings == ("line 1: malformed JSON record",)


def test_malformed_and_invalid_records_do_not_drop_valid_records() -> None:
    content = "\n".join(
        [
            '{"host":"valid.example.com"}',
            '{"host":123}',
            '{"host":"bad_label.example.com"}',
            '{"host":"192.0.2.1"}',
            "{broken",
        ]
    )

    result = SubfinderParser("example.com").parse(ParserInput(content))

    assert result.items == ("valid.example.com",)
    assert len(result.warnings) == 4


def test_registrable_domain_uses_offline_public_suffix_data() -> None:
    assert registrable_domain("www.shop.example.co.uk") == "example.co.uk"
    assert registrable_domain("API.EXAMPLE.COM.") == "example.com"
