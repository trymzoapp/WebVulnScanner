"""Regression and schema compatibility tests across all structured tool parsers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webvulnscanner.core.exceptions import ParsingError
from webvulnscanner.models.finding import Severity
from webvulnscanner.parsers.base import ParserInput
from webvulnscanner.parsers.nmap import NmapParser
from webvulnscanner.parsers.nuclei import NucleiParser
from webvulnscanner.parsers.sqlmap import SQLmapParser
from webvulnscanner.parsers.subfinder import SubfinderParser
from webvulnscanner.parsers.wappalyzer import WappalyzerParser
from webvulnscanner.parsers.wpscan import WPScanParser

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


def test_nuclei_parser_regression_and_compatibility() -> None:
    """Nuclei parser handles fixtures, unknown fields, malformed lines, and empty inputs."""
    parser = NucleiParser()

    # 1. Official fixture with valid and invalid lines
    fixture_path = FIXTURES_DIR / "nuclei" / "sample.jsonl"
    content = fixture_path.read_text(encoding="utf-8")
    result = parser.parse(ParserInput(content))

    assert len(result.items) == 2
    assert any(w.startswith("line 3") for w in result.warnings)  # invalid json
    assert any(w.startswith("line 4") for w in result.warnings)  # missing url

    # 2. Unknown fields tolerance
    unknown_fields_record = json.dumps(
        {
            "template-id": "custom-vuln",
            "matched-at": "https://example.com/test",
            "info": {
                "name": "Test Vuln",
                "severity": "high",
                "new_unrecognized_field": 12345,
            },
            "extra_top_level_field": "future_version_data",
        }
    )
    res_unknown = parser.parse(ParserInput(unknown_fields_record))
    assert len(res_unknown.items) == 1
    assert res_unknown.items[0].severity == Severity.HIGH
    assert res_unknown.items[0].title == "Test Vuln"

    # 3. Empty input
    assert parser.parse(ParserInput("")).items == ()
    assert parser.parse(ParserInput("   \n  \n")).items == ()


def test_nmap_parser_regression_and_compatibility() -> None:
    """Nmap parser handles XML fixtures, XXE defenses, truncated XML, and empty inputs."""
    parser = NmapParser(requested_host="example.com", allowed_ports=(80, 443, 8080))

    # 1. XML fixture
    fixture_path = FIXTURES_DIR / "nmap" / "web-services.xml"
    content = fixture_path.read_text(encoding="utf-8")
    result = parser.parse(ParserInput(content))

    assert (
        len(result.items) == 2
    )  # 80 and 443 open; 8080 is closed, 22 is not in allowed_ports
    ports = [s.port for s in result.items]
    assert 80 in ports
    assert 443 in ports
    assert len(result.warnings) > 0  # for port 8080 and 22

    # 2. XXE rejection
    xxe_payload = (
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun></nmaprun>'
    )
    with pytest.raises(ParsingError, match=r"prohibited declarations"):
        parser.parse(ParserInput(xxe_payload))

    # 3. Malformed / truncated XML
    with pytest.raises(ParsingError, match=r"not valid XML"):
        parser.parse(ParserInput("<nmaprun><host><ports>"))

    # 4. Unexpected root element
    with pytest.raises(ParsingError, match=r"unexpected root element"):
        parser.parse(ParserInput("<wrongroot></wrongroot>"))


def test_subfinder_parser_regression_and_compatibility() -> None:
    """Subfinder parser extracts in-scope hosts, drops out-of-scope, and handles malformed lines."""
    parser = SubfinderParser(scope_domain="example.com")

    fixture_path = FIXTURES_DIR / "subfinder" / "mixed.jsonl"
    content = fixture_path.read_text(encoding="utf-8")
    result = parser.parse(ParserInput(content))

    assert "api.example.com" in result.items
    assert "mobile.example.com" in result.items
    # out-of-scope domain outside.example.net excluded
    assert "outside.example.net" not in result.items
    assert result.excluded_count >= 1
    assert len(result.warnings) > 0  # malformed lines

    # Empty input
    empty_res = parser.parse(ParserInput(""))
    assert empty_res.items == ()
    assert empty_res.excluded_count == 0


def test_wappalyzer_parser_regression_and_compatibility() -> None:
    """Wappalyzer parser handles object/array schemas, deduplicates, and rejects malformed inputs."""
    parser = WappalyzerParser()

    fixture_path = FIXTURES_DIR / "wappalyzer" / "technologies.json"
    content = fixture_path.read_text(encoding="utf-8")
    result = parser.parse(ParserInput(content))

    assert len(result.items) == 2  # WordPress and PHP (empty name skipped)
    tech_names = [t.name for t in result.items]
    assert "WordPress" in tech_names
    assert "PHP" in tech_names

    # Direct list schema compatibility
    list_payload = json.dumps(
        [
            {"name": "Nginx", "version": "1.24", "confidence": 100},
            {"name": "React", "version": "18.2", "confidence": 90},
        ]
    )
    list_result = parser.parse(ParserInput(list_payload))
    assert len(list_result.items) == 2

    # Malformed JSON
    with pytest.raises(ParsingError, match=r"not valid JSON"):
        parser.parse(ParserInput("{not a json}"))

    # Empty input
    assert parser.parse(ParserInput("")).items == ()


def test_sqlmap_parser_regression_and_compatibility() -> None:
    """SQLmap parser handles structured JSON, raw stdout parameters, and empty content."""
    parser = SQLmapParser(target_url="https://example.com/item?id=1")

    # 1. JSON fixture
    fixture_path = FIXTURES_DIR / "sqlmap" / "sample.json"
    content = fixture_path.read_text(encoding="utf-8")
    result = parser.parse(ParserInput(content))

    assert len(result.items) == 1
    finding = result.items[0]
    assert finding.source_scanner == "sqlmap"
    assert finding.severity == Severity.HIGH
    assert finding.parameter == "id"
    assert "boolean-based blind" in finding.description

    # 2. Raw text fallback
    raw_text = "Parameter: query (GET)\n    Type: time-based blind"
    text_result = parser.parse(ParserInput(raw_text))
    assert len(text_result.items) == 1
    assert text_result.items[0].parameter == "query"

    # 3. Empty content
    assert parser.parse(ParserInput("")).items == ()


def test_wpscan_parser_regression_and_compatibility() -> None:
    """WPScan parser extracts core, plugin, theme, and interesting observations safely."""
    parser = WPScanParser(target_url="https://example.com/")

    # 1. JSON fixture
    fixture_path = FIXTURES_DIR / "wpscan" / "sample.json"
    content = fixture_path.read_text(encoding="utf-8")
    result = parser.parse(ParserInput(content))

    assert len(result.items) >= 1
    vuln_titles = [f.title for f in result.items]
    assert any("WordPress 6.0 - Unauthenticated XSS" in title for title in vuln_titles)

    # 2. Unknown fields tolerance
    extra_data = json.dumps(
        {
            "target_url": "https://example.com/",
            "version": {"number": "6.1", "vulnerabilities": []},
            "plugins": {
                "woocommerce": {
                    "version": "7.0",
                    "vulnerabilities": [
                        {"title": "WooCommerce SQLi", "vuln_type": "SQLi"}
                    ],
                    "new_unknown_wpscan_field": {"arbitrary": True},
                }
            },
        }
    )
    res_extra = parser.parse(ParserInput(extra_data))
    assert len(res_extra.items) == 1
    assert "WooCommerce SQLi" in res_extra.items[0].title

    # 3. Empty input and malformed JSON
    assert parser.parse(ParserInput("")).items == ()
    with pytest.raises(ParsingError, match=r"not valid JSON"):
        parser.parse(ParserInput("<html>Error 500</html>"))
