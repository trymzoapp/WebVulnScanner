"""Parser for Subfinder JSONL output."""

from __future__ import annotations

import json
from dataclasses import dataclass

import tldextract

from webvulnscanner.core.exceptions import TargetValidationError
from webvulnscanner.models.target import Target, TargetKind
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


@dataclass(frozen=True, slots=True)
class SubfinderParseResult(ParseResult[str]):
    """In-scope subdomains plus count of excluded structured records."""

    excluded_count: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.excluded_count < 0:
            raise ValueError("excluded_count must be non-negative")


class SubfinderParser(BaseParser[str]):
    """Parse JSONL records without accepting terminal-formatted fallback text."""

    def __init__(self, scope_domain: str) -> None:
        super().__init__("subfinder")
        self.scope_domain = registrable_domain(scope_domain)

    def parse(self, parser_input: ParserInput) -> SubfinderParseResult:
        subdomains: set[str] = set()
        warnings: list[str] = []
        excluded_count = 0
        for line_number, raw_line in enumerate(
            parser_input.content.splitlines(),
            start=1,
        ):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                warnings.append(f"line {line_number}: malformed JSON record")
                continue
            if not isinstance(record, dict) or not isinstance(
                record.get("host"), str
            ):
                warnings.append(f"line {line_number}: missing string host")
                continue
            try:
                target = Target(record["host"])
            except TargetValidationError:
                warnings.append(f"line {line_number}: invalid hostname")
                continue
            if target.kind is not TargetKind.HOSTNAME:
                warnings.append(f"line {line_number}: non-hostname result")
                continue
            host = target.host
            if not _in_scope(host, self.scope_domain):
                excluded_count += 1
                continue
            subdomains.add(host)
        return SubfinderParseResult(
            items=tuple(sorted(subdomains)),
            warnings=tuple(warnings),
            excluded_count=excluded_count,
        )


def registrable_domain(host: str) -> str:
    """Return an offline public-suffix-derived registrable domain."""
    canonical = Target(host).host
    extracted = tldextract.TLDExtract(suffix_list_urls=())(canonical)
    if extracted.suffix and extracted.domain:
        return f"{extracted.domain}.{extracted.suffix}".casefold()
    return canonical


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


__all__ = [
    "SubfinderParseResult",
    "SubfinderParser",
    "registrable_domain",
]
