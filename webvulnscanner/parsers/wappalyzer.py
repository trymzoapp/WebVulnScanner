"""Parser for structured Wappalyzer JSON output."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from webvulnscanner.models.technology import Technology
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


class WappalyzerParser(BaseParser[Technology]):
    """Normalize Wappalyzer technology observations without parsing terminal text."""

    def __init__(self) -> None:
        super().__init__("wappalyzer")

    def parse(self, parser_input: ParserInput) -> ParseResult[Technology]:
        if not parser_input.content.strip():
            return ParseResult()
        try:
            payload = json.loads(parser_input.content)
        except json.JSONDecodeError as error:
            raise self.parsing_error(
                "Wappalyzer output is not valid JSON", cause=error
            ) from error

        records = _technology_records(payload)
        technologies: dict[tuple[str, str | None], Technology] = {}
        warnings: list[str] = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                warnings.append(f"technology {index}: expected an object")
                continue
            try:
                technology = _technology(record)
            except (TypeError, ValueError):
                warnings.append(f"technology {index}: invalid structured record")
                continue
            key = (technology.name.casefold(), technology.version)
            existing = technologies.get(key)
            if existing is None or technology.confidence > existing.confidence:
                technologies[key] = technology

        return ParseResult(
            items=tuple(
                sorted(
                    technologies.values(),
                    key=lambda item: (item.name.casefold(), item.version or ""),
                )
            ),
            warnings=tuple(warnings),
        )


def _technology_records(payload: object) -> list[object]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, Mapping):
        raise WappalyzerParser().parsing_error(
            "Wappalyzer JSON root must be an object or array"
        )
    direct = payload.get("technologies")
    if isinstance(direct, list):
        return direct

    records: list[object] = []
    found_container = False
    for value in payload.values():
        if not isinstance(value, Mapping):
            continue
        nested = value.get("technologies")
        if isinstance(nested, list):
            found_container = True
            records.extend(nested)
    if not found_container:
        raise WappalyzerParser().parsing_error(
            "Wappalyzer JSON does not contain a technologies array"
        )
    return records


def _technology(record: Mapping[str, Any]) -> Technology:
    name = record.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("technology name is required")

    raw_confidence = record.get("confidence", 1.0)
    if isinstance(raw_confidence, str):
        raw_confidence = float(raw_confidence)
    if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, (int, float)):
        raise TypeError("technology confidence must be numeric")
    confidence = float(raw_confidence)
    if confidence > 1.0:
        confidence /= 100.0

    raw_version = record.get("version")
    version = raw_version.strip() if isinstance(raw_version, str) else None
    if version == "":
        version = None

    categories = _categories(record.get("categories"))
    evidence: list[str] = []
    for key in ("website", "source", "evidence"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            evidence.append(value.strip())

    return Technology(
        name=name.strip(),
        source="wappalyzer",
        confidence=confidence,
        version=version,
        categories=categories,
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _categories(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise TypeError("categories must be an array")
    categories: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            categories.append(item.strip())
        elif isinstance(item, Mapping):
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                categories.append(name.strip())
            else:
                raise ValueError("category name is required")
        else:
            raise TypeError("category must be a string or object")
    return tuple(dict.fromkeys(categories))


__all__ = ["WappalyzerParser"]
