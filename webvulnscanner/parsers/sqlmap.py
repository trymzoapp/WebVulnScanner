"""Structured SQLmap output parser."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from webvulnscanner.models.finding import Finding, Severity
from webvulnscanner.parsers.base import BaseParser, ParseResult, ParserInput


class SQLmapParser(BaseParser[Finding]):
    """Normalize SQLmap execution results and findings into Finding models."""

    def __init__(self, target_url: str | None = None) -> None:
        super().__init__("sqlmap")
        self.target_url = target_url

    def parse(self, parser_input: ParserInput) -> ParseResult[Finding]:
        content = parser_input.content.strip()
        if not content:
            return ParseResult(items=(), warnings=())

        findings: list[Finding] = []
        warnings: list[str] = []

        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            payload = {"stdout": content}

        if isinstance(payload, Mapping):
            target = payload.get("target") or self.target_url or "unknown-target"
            stdout = payload.get("stdout") or ""
            if not isinstance(stdout, str):
                stdout = str(stdout)

            # Parse parameter vulnerability indicators from stdout/text
            param_matches = re.findall(
                r"Parameter:\s*([^\n]+)\s*\(([^)]+)\)\s*\n\s*Type:\s*([^\n]+)",
                stdout,
            )
            if param_matches:
                for param, place, inj_type in param_matches:
                    param_clean = param.strip()
                    place_clean = place.strip()
                    type_clean = inj_type.strip()
                    finding = Finding(
                        title=f"SQL Injection in parameter '{param_clean}'",
                        severity=Severity.HIGH,
                        source_scanner="sqlmap",
                        affected_resource=str(target),
                        rule_id="sql-injection",
                        parameter=param_clean,
                        description=f"Confirmed {type_clean} SQL injection vulnerability in {place_clean} parameter '{param_clean}'.",
                        evidence=(f"Parameter: {param_clean}", f"Type: {type_clean}", f"Place: {place_clean}"),
                        references=("https://owasp.org/www-community/attacks/SQL_Injection",),
                    )
                    findings.append(finding)
            elif "is vulnerable" in stdout or "dbms:" in stdout.lower():
                finding = Finding(
                    title="SQL Injection Detected",
                    severity=Severity.HIGH,
                    source_scanner="sqlmap",
                    affected_resource=str(target),
                    rule_id="sql-injection",
                    description="SQLmap identified dynamic SQL injection vulnerability.",
                    evidence=("SQL injection confirmed by SQLmap execution",),
                    references=("https://owasp.org/www-community/attacks/SQL_Injection",),
                )
                findings.append(finding)
        else:
            warnings.append("expected JSON object or text output payload")

        return ParseResult(
            items=tuple(findings),
            warnings=tuple(warnings),
        )


__all__ = ["SQLmapParser"]
