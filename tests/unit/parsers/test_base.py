"""Tests for generic parser contracts."""

import json
from pathlib import Path

import pytest

from webvulnscanner.core.exceptions import ParsingError
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


class IntegerListParser(BaseParser[int]):
    def __init__(self) -> None:
        super().__init__("integer-list")

    def parse(self, parser_input: ParserInput) -> ParseResult[int]:
        try:
            value = json.loads(parser_input.content)
        except json.JSONDecodeError as error:
            raise self.parsing_error("invalid JSON", cause=error) from error
        if not isinstance(value, list) or any(
            isinstance(item, bool) or not isinstance(item, int) for item in value
        ):
            raise self.parsing_error("expected an integer array")
        return ParseResult(items=tuple(value))


def test_parser_input_and_output_are_typed_and_immutable(tmp_path: Path) -> None:
    parser_input = ParserInput("[1, 2, 3]", source=tmp_path / "output.json")
    result = IntegerListParser().parse(parser_input)

    assert result.items == (1, 2, 3)
    assert result.warnings == ()
    assert parser_input.source == tmp_path / "output.json"


def test_parser_failure_has_typed_context_and_preserved_cause() -> None:
    parser = IntegerListParser()

    with pytest.raises(ParsingError) as captured:
        parser.parse(ParserInput("{not-json"))

    assert captured.value.component == "integer-list"
    assert captured.value.operation == "parse"
    assert captured.value.cause_type == "JSONDecodeError"


def test_semantically_invalid_output_raises_parsing_error() -> None:
    with pytest.raises(ParsingError, match="integer array"):
        IntegerListParser().parse(ParserInput('["not-an-integer"]'))


def test_parser_contract_is_abstract() -> None:
    class IncompleteParser(BaseParser[int]):
        pass

    with pytest.raises(TypeError):
        IncompleteParser("incomplete")  # type: ignore[abstract]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"content": 123},
        {"content": "{}", "source": "output.json"},
    ],
)
def test_parser_input_rejects_invalid_types(kwargs: dict[str, object]) -> None:
    with pytest.raises(TypeError):
        ParserInput(**kwargs)  # type: ignore[arg-type]


def test_parse_result_rejects_invalid_warning_contract() -> None:
    with pytest.raises(TypeError):
        ParseResult(items=(), warnings=["warning"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ParseResult(items=(), warnings=("",))
