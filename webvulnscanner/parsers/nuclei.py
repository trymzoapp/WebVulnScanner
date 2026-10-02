"""Structured Nuclei JSONL output parser."""

from __future__ import annotations

import json
from collections.abc import Mapping
from io import StringIO
from typing import Any

from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


class NucleiParser(BaseParser[Finding]):
    """Stream and convert Nuclei JSONL records into normalized findings."""

    def __init__(self) -> None:
        super().__init__("nuclei")

    def parse(self, parser_input: ParserInput) -> ParseResult[Finding]:
        if not parser_input.content.strip():
            return ParseResult(items=(), warnings=())

        findings: list[Finding] = []
        warnings: list[str] = []

        stream = StringIO(parser_input.content)
        for line_number, line in enumerate(stream, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                record = json.loads(line_str)
            except json.JSONDecodeError:
                warnings.append(f"line {line_number}: invalid JSON line")
                continue

            if not isinstance(record, Mapping):
                warnings.append(f"line {line_number}: record is not a JSON object")
                continue

            try:
                finding = _record_to_finding(record)
                findings.append(finding)
            except (ValueError, TypeError) as error:
                warnings.append(f"line {line_number}: {error}")
                continue

        return ParseResult(
            items=tuple(findings),
            warnings=tuple(warnings),
        )


def _record_to_finding(record: Mapping[str, Any]) -> Finding:
    template_id = (
        record.get("template-id") or record.get("template_id") or "nuclei-finding"
    )
    info = record.get("info")
    if not isinstance(info, Mapping):
        info = {}

    name = info.get("name") or template_id
    raw_severity = str(info.get("severity", "info")).lower()

    severity_map = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    severity = severity_map.get(raw_severity, Severity.UNKNOWN)

    affected = (
        record.get("matched-at")
        or record.get("matched_at")
        or record.get("host")
        or record.get("url")
    )
    if not isinstance(affected, str) or not affected.strip():
        raise ValueError("record missing affected resource URL")

    evidence_items: list[str] = []
    matcher = record.get("matcher-name") or record.get("matcher_name")
    if matcher:
        evidence_items.append(f"matcher: {matcher}")
    extracted = record.get("extracted-results") or record.get("extracted_results")
    if isinstance(extracted, list):
        for item in extracted:
            if isinstance(item, str) and item.strip():
                evidence_items.append(item.strip())
    elif isinstance(extracted, str) and extracted.strip():
        evidence_items.append(extracted.strip())

    references: list[str] = []
    raw_refs = info.get("reference")
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if isinstance(ref, str) and ref.strip():
                references.append(ref.strip())
    elif isinstance(raw_refs, str) and raw_refs.strip():
        references.append(raw_refs.strip())

    description = info.get("description") or ""
    if not isinstance(description, str):
        description = str(description)

    return Finding(
        title=str(name),
        severity=severity,
        source_scanner="nuclei",
        affected_resource=str(affected).strip(),
        rule_id=str(template_id),
        description=description,
        evidence=tuple(evidence_items),
        references=tuple(references),
    )


__all__ = ["NucleiParser"]
