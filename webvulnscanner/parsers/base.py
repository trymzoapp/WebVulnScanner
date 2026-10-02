"""Generic contracts for structured external-tool parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar

from webvulnscanner.core.exceptions import ParsingError

ParsedT = TypeVar("ParsedT")


@dataclass(frozen=True, slots=True)
class ParserInput:
    """Bounded structured content and optional source metadata."""

    content: str
    source: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise TypeError("parser content must be a string")
        if self.source is not None and not isinstance(self.source, Path):
            raise TypeError("parser source must be a pathlib.Path or None")


@dataclass(frozen=True, slots=True)
class ParseResult(Generic[ParsedT]):
    """Parsed items plus non-fatal warnings."""

    items: tuple[ParsedT, ...] = ()
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            raise TypeError("parsed items must be a tuple")
        if not isinstance(self.warnings, tuple):
            raise TypeError("parse warnings must be a tuple")
        if any(
            not isinstance(warning, str) or not warning.strip()
            for warning in self.warnings
        ):
            raise ValueError("parse warnings must contain non-empty strings")


class BaseParser(ABC, Generic[ParsedT]):
    """Abstract parser with a typed controlled-failure helper."""

    name: str

    def __init__(self, name: str) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("parser name must be a non-empty string")
        self.name = name

    @abstractmethod
    def parse(self, parser_input: ParserInput) -> ParseResult[ParsedT]:
        """Parse structured input or raise a typed ``ParsingError``."""

    def parsing_error(
        self,
        message: str,
        *,
        cause: BaseException | None = None,
    ) -> ParsingError:
        """Create a parser-attributed controlled failure."""
        return ParsingError(
            message,
            component=self.name,
            operation="parse",
            cause=cause,
        )


__all__ = ["BaseParser", "ParseResult", "ParsedT", "ParserInput"]
