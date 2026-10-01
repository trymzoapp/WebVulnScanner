"""Tests for structured and secret-aware project logging."""

import io
import json
import logging
from datetime import datetime
from typing import Any

import pytest

from webvulnscanner.core.logging import (
    REDACTED,
    bind_logger,
    configure_logging,
    log_event,
)


def json_records(stream: io.StringIO) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in stream.getvalue().splitlines()
        if line.strip()
    ]


def test_human_log_contains_available_scan_context_and_event() -> None:
    stream = io.StringIO()
    base_logger = configure_logging(output_format="human", stream=stream)
    logger = bind_logger(
        base_logger,
        scan_id="scan-123",
        target="example.com",
        scanner="nuclei",
    )

    log_event(
        logger,
        logging.INFO,
        "scanner_started",
        "Scanner started\nsafely",
        template_count=12,
    )

    output = stream.getvalue()
    assert "INFO webvulnscanner" in output
    assert 'scan_id="scan-123"' in output
    assert 'target="example.com"' in output
    assert 'scanner="nuclei"' in output
    assert 'event="scanner_started"' in output
    assert "template_count=12" in output
    assert "Scanner started\\nsafely" in output
    assert output.count("\n") == 1
    timestamp = output.split(" ", maxsplit=1)[0]
    assert datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is not None


def test_json_log_contains_structured_context_and_utc_timestamp() -> None:
    stream = io.StringIO()
    base_logger = configure_logging(output_format="json", stream=stream)
    logger = bind_logger(
        base_logger,
        scan_id="scan-456",
        target="api.example.com",
        scanner="headers",
    )

    log_event(
        logger,
        logging.WARNING,
        "scanner_failed",
        "Scanner returned a controlled failure",
        status="failed",
        exit_code=2,
    )

    record = json_records(stream)[0]
    assert record["level"] == "WARNING"
    assert record["logger"] == "webvulnscanner"
    assert record["event"] == "scanner_failed"
    assert record["scan_id"] == "scan-456"
    assert record["target"] == "api.example.com"
    assert record["scanner"] == "headers"
    assert record["status"] == "failed"
    assert record["exit_code"] == 2
    assert record["timestamp"].endswith("Z")
    assert datetime.fromisoformat(
        record["timestamp"].replace("Z", "+00:00")
    ).tzinfo is not None


def test_missing_context_fields_are_omitted() -> None:
    stream = io.StringIO()
    logger = bind_logger(
        configure_logging(output_format="json", stream=stream),
        scan_id="scan-only",
    )

    log_event(logger, logging.INFO, "scan_created", "Scan context created")

    record = json_records(stream)[0]
    assert record["scan_id"] == "scan-only"
    assert "target" not in record
    assert "scanner" not in record


def test_default_and_configured_sensitive_keys_are_redacted_recursively() -> None:
    stream = io.StringIO()
    logger = configure_logging(
        output_format="json",
        stream=stream,
        sensitive_keys={"client_credential"},
    )

    log_event(
        logger,
        logging.INFO,
        "configuration_loaded",
        "Loaded token-value and client-value",
        api_token="token-value",
        metadata={
            "password": "password-value",
            "nested": {"client_credential": "client-value"},
            "safe": "visible",
        },
    )

    output = stream.getvalue()
    record = json_records(stream)[0]
    assert record["api_token"] == REDACTED
    assert record["metadata"]["password"] == REDACTED
    assert record["metadata"]["nested"]["client_credential"] == REDACTED
    assert record["metadata"]["safe"] == "visible"
    assert REDACTED in record["message"]
    assert "token-value" not in output
    assert "password-value" not in output
    assert "client-value" not in output


def test_human_logs_redact_sensitive_fields() -> None:
    stream = io.StringIO()
    logger = configure_logging(output_format="human", stream=stream)

    log_event(
        logger,
        logging.ERROR,
        "scanner_failed",
        "Authentication token was rejected",
        authorization="Bearer private-token",
    )

    output = stream.getvalue()
    assert f'authorization="{REDACTED}"' in output
    assert "private-token" not in output


def test_repeated_configuration_does_not_duplicate_messages() -> None:
    stream = io.StringIO()
    configure_logging(output_format="human", stream=stream)
    logger = configure_logging(output_format="human", stream=stream)

    log_event(logger, logging.INFO, "single_event", "Emitted once")

    assert stream.getvalue().count("Emitted once") == 1
    managed_handlers = [
        handler
        for handler in logger.handlers
        if getattr(handler, "_webvulnscanner_managed", False)
    ]
    assert len(managed_handlers) == 1


def test_routing_and_failure_events_can_share_one_structured_stream() -> None:
    stream = io.StringIO()
    base_logger = configure_logging(output_format="json", stream=stream)
    logger = bind_logger(base_logger, scan_id="scan-789", target="example.com")

    log_event(
        logger,
        logging.INFO,
        "routing_decision",
        "Scanner routing decision",
        scanner="wpscan",
        enabled=True,
        reason="WordPress detected",
        source="wappalyzer",
    )
    log_event(
        logger,
        logging.ERROR,
        "scanner_failed",
        "Scanner timed out",
        scanner="nuclei",
        failure="timeout",
        duration_seconds=600.0,
    )

    records = json_records(stream)
    assert [record["event"] for record in records] == [
        "routing_decision",
        "scanner_failed",
    ]
    assert records[0]["enabled"] is True
    assert records[0]["reason"] == "WordPress detected"
    assert records[1]["failure"] == "timeout"


def test_arbitrary_objects_are_not_rendered_with_potentially_sensitive_repr() -> None:
    class UnsafeObject:
        def __repr__(self) -> str:
            return "secret-from-repr"

    stream = io.StringIO()
    logger = configure_logging(output_format="json", stream=stream)

    log_event(
        logger,
        logging.INFO,
        "safe_serialization",
        "Object was safely represented",
        value=UnsafeObject(),
    )

    output = stream.getvalue()
    assert "secret-from-repr" not in output
    assert json_records(stream)[0]["value"] == "<UnsafeObject>"


@pytest.mark.parametrize("output_format", ["", "xml", "JSON"])
def test_unknown_output_format_is_rejected(output_format: str) -> None:
    with pytest.raises(ValueError):
        configure_logging(output_format=output_format)


def test_empty_event_and_reserved_fields_are_rejected() -> None:
    logger = configure_logging(stream=io.StringIO())

    with pytest.raises(ValueError, match="event"):
        log_event(logger, logging.INFO, "", "message")
    with pytest.raises(ValueError, match="reserved"):
        log_event(
            logger,
            logging.INFO,
            "test",
            "message",
            levelname="forged",
        )
