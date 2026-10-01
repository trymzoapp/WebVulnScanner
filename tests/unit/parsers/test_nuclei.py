"""Unit tests for the Nuclei JSONL parser."""

from pathlib import Path

import pytest

from webvulnscanner.models.finding import Severity
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.nuclei import NucleiParser


def test_nuclei_parser_fixture() -> None:
    fixture_path = Path(__file__).parents[2] / "fixtures" / "nuclei" / "sample.jsonl"
    content = fixture_path.read_text(encoding="utf-8")

    parser = NucleiParser()
    result = parser.parse(ParserInput(content=content, source=fixture_path))

    assert len(result.items) == 2
    f1 = result.items[0]
    assert f1.title == "Git Config Exposure"
    assert f1.severity is Severity.MEDIUM
    assert f1.source_scanner == "nuclei"
    assert f1.affected_resource == "https://example.com/.git/config"
    assert f1.rule_id == "git-config"
    assert f1.references == ("https://git-scm.com",)
    assert f1.evidence == ("matcher: http-git-config",)
    assert len(f1.finding_id) == 64

    f2 = result.items[1]
    assert f2.title == "WAF Detection"
    assert f2.severity is Severity.INFO

    # 2 warnings for line 3 (invalid JSON) and line 4 (missing URL)
    assert len(result.warnings) == 2


def test_nuclei_parser_empty() -> None:
    parser = NucleiParser()
    result = parser.parse(ParserInput(content=""))
    assert result.items == ()
    assert result.warnings == ()
