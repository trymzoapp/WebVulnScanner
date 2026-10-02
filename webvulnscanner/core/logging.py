"""Structured, contextual, and secret-aware project logging."""

from __future__ import annotations

import json
import logging
import math
import sys
from collections.abc import Collection, Mapping, MutableMapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

LOGGER_NAME = "webvulnscanner"
REDACTED = "[REDACTED]"

_DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "api_token",
        "authorization",
        "cookie",
        "credential",
        "password",
        "secret",
        "token",
    }
)
_STANDARD_RECORD_KEYS = frozenset(
    set(logging.makeLogRecord({}).__dict__) | {"asctime", "message"}
)
_CONTEXT_KEYS = ("scan_id", "target", "scanner")


class SecretRedactor:
    """Redact values whose keys are configured as sensitive."""

    def __init__(self, sensitive_keys: Collection[str] = ()) -> None:
        combined = set(_DEFAULT_SENSITIVE_KEYS)
        combined.update(sensitive_keys)
        self._sensitive_keys = frozenset(_normalize_key(key) for key in combined if key)

    def redact_fields(
        self,
        fields: Mapping[str, object],
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        """Return JSON-safe redacted fields and sensitive strings for message cleanup."""
        sensitive_values: list[str] = []
        redacted = {
            str(key): self._redact_value(str(key), value, sensitive_values)
            for key, value in fields.items()
        }
        return redacted, tuple(sensitive_values)

    def redact_message(
        self,
        message: str,
        sensitive_values: Collection[str],
    ) -> str:
        """Remove known sensitive field values from a rendered message."""
        result = message
        for value in sorted(set(sensitive_values), key=len, reverse=True):
            if value:
                result = result.replace(value, REDACTED)
        return result

    def _redact_value(
        self,
        key: str,
        value: object,
        sensitive_values: list[str],
    ) -> object:
        if _normalize_key(key) in self._sensitive_keys:
            _collect_strings(value, sensitive_values)
            return REDACTED
        if isinstance(value, Mapping):
            return {
                str(nested_key): self._redact_value(
                    str(nested_key),
                    nested_value,
                    sensitive_values,
                )
                for nested_key, nested_value in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            return [self._redact_value("", item, sensitive_values) for item in value]
        return _json_safe_scalar(value)


class JsonLogFormatter(logging.Formatter):
    """Render one log record as a compact JSON object."""

    def __init__(self, redactor: SecretRedactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        fields, sensitive_values = self._redactor.redact_fields(_extra_fields(record))
        message = self._redactor.redact_message(
            record.getMessage(),
            sensitive_values,
        )
        payload: dict[str, object] = {
            "timestamp": _utc_timestamp(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": _single_line(message),
        }
        event = fields.pop("event", None)
        if event is not None:
            payload["event"] = event
        for key in sorted(fields):
            payload[key] = fields[key]
        if record.exc_info is not None and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
        )


class HumanLogFormatter(logging.Formatter):
    """Render one concise, single-line console log record."""

    def __init__(self, redactor: SecretRedactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        fields, sensitive_values = self._redactor.redact_fields(_extra_fields(record))
        message = _single_line(
            self._redactor.redact_message(record.getMessage(), sensitive_values)
        )
        context_parts: list[str] = []
        for key in (*_CONTEXT_KEYS, "event"):
            if key in fields:
                context_parts.append(f"{key}={_human_value(fields.pop(key))}")
        for key in sorted(fields):
            context_parts.append(f"{key}={_human_value(fields[key])}")
        if record.exc_info is not None and record.exc_info[0] is not None:
            context_parts.append(f"exception_type={record.exc_info[0].__name__}")
        context = "" if not context_parts else " " + " ".join(context_parts)
        return (
            f"{_utc_timestamp(record.created)} {record.levelname} "
            f"{record.name}{context} - {message}"
        )


class ContextLoggerAdapter(logging.LoggerAdapter[logging.Logger]):
    """Logger adapter that carries scan and scanner context."""

    def process(
        self,
        msg: object,
        kwargs: MutableMapping[str, Any],
    ) -> tuple[object, MutableMapping[str, Any]]:
        call_extra = kwargs.get("extra", {})
        if call_extra is None:
            call_extra = {}
        if not isinstance(call_extra, Mapping):
            raise TypeError("logging extra fields must be a mapping")
        extra_dict = dict(self.extra or {})
        extra_dict.update(call_extra)
        kwargs["extra"] = extra_dict
        return msg, kwargs


def configure_logging(
    *,
    output_format: str = "human",
    level: int | str = logging.INFO,
    stream: TextIO | None = None,
    sensitive_keys: Collection[str] = (),
) -> logging.Logger:
    """Configure one project handler without accumulating duplicate handlers."""
    if output_format not in {"human", "json"}:
        raise ValueError("output_format must be either 'human' or 'json'")

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    for handler in tuple(logger.handlers):
        if getattr(handler, "_webvulnscanner_managed", False):
            logger.removeHandler(handler)
            handler.close()

    redactor = SecretRedactor(sensitive_keys)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(
        JsonLogFormatter(redactor)
        if output_format == "json"
        else HumanLogFormatter(redactor)
    )
    handler._webvulnscanner_managed = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    return logger


def bind_logger(
    logger: logging.Logger | None = None,
    *,
    scan_id: str | None = None,
    target: str | None = None,
    scanner: str | None = None,
) -> ContextLoggerAdapter:
    """Bind available scan context to a project logger."""
    base_logger = logging.getLogger(LOGGER_NAME) if logger is None else logger
    context = {
        key: value
        for key, value in {
            "scan_id": scan_id,
            "target": target,
            "scanner": scanner,
        }.items()
        if value is not None
    }
    return ContextLoggerAdapter(base_logger, context)


def log_event(
    logger: logging.Logger | logging.LoggerAdapter[logging.Logger],
    level: int,
    event: str,
    message: str,
    **fields: object,
) -> None:
    """Emit a structured event suitable for routing and scanner failures."""
    if not isinstance(event, str) or not event.strip():
        raise ValueError("event must be a non-empty string")
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    reserved = set(fields) & _STANDARD_RECORD_KEYS
    if reserved:
        raise ValueError(
            "structured fields use reserved logging names: "
            + ", ".join(sorted(reserved))
        )
    logger.log(level, message, extra={"event": event, **fields})


def _extra_fields(record: logging.LogRecord) -> dict[str, object]:
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _STANDARD_RECORD_KEYS and not key.startswith("_")
    }


def _normalize_key(key: str) -> str:
    return "".join(character for character in key.casefold() if character.isalnum())


def _collect_strings(value: object, output: list[str]) -> None:
    if isinstance(value, str):
        output.append(value)
    elif isinstance(value, Mapping):
        for nested in value.values():
            _collect_strings(nested, output)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            _collect_strings(nested, output)


def _json_safe_scalar(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, (Path, Enum)):
        return str(value.value if isinstance(value, Enum) else value)
    return f"<{type(value).__name__}>"


def _utc_timestamp(created: float) -> str:
    return (
        datetime.fromtimestamp(created, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _single_line(value: str) -> str:
    return value.replace("\r", "\\r").replace("\n", "\\n")


def _human_value(value: object) -> str:
    if isinstance(value, str) and value != REDACTED:
        return json.dumps(_single_line(value), ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


__all__ = [
    "ContextLoggerAdapter",
    "HumanLogFormatter",
    "JsonLogFormatter",
    "LOGGER_NAME",
    "REDACTED",
    "SecretRedactor",
    "bind_logger",
    "configure_logging",
    "log_event",
]
