"""Typed exceptions used across WebVulnScanner.

Exception messages are intended to be safe for user-facing output. The optional
``cause`` preserves the original exception for programmatic inspection, but callers
must not log or render it without applying the project's redaction policy.
"""

from __future__ import annotations


class WebVulnScannerError(Exception):
    """Base class for expected, controlled framework failures."""

    def __init__(
        self,
        message: str,
        *,
        component: str | None = None,
        operation: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        """Initialize an error with bounded, non-sensitive context.

        ``component`` and ``operation`` should be identifiers, not arbitrary tool output.
        The original ``cause`` is deliberately excluded from the rendered message.
        """
        super().__init__(message)
        self.message = message
        self.component = component
        self.operation = operation
        self.cause = cause

    @property
    def cause_type(self) -> str | None:
        """Return the cause's type without rendering potentially sensitive details."""
        if self.cause is None:
            return None
        return type(self.cause).__name__


class ConfigurationError(WebVulnScannerError):
    """Configuration could not be loaded or validated."""


class TargetValidationError(WebVulnScannerError):
    """A target is invalid, unsupported, ambiguous, or outside allowed scope."""


class StorageError(WebVulnScannerError):
    """Scan storage could not be created, validated, read, or written safely."""


class ScannerError(WebVulnScannerError):
    """Base class for controlled scanner-level failures."""


class ScannerValidationError(ScannerError):
    """A scanner cannot run because its prerequisites or inputs are invalid."""


class SubprocessError(WebVulnScannerError):
    """Base class for failures at an external-process boundary."""


class SubprocessExecutionError(SubprocessError):
    """An external process could not start or completed unsuccessfully."""


class SubprocessTimeoutError(SubprocessError):
    """An external process exceeded its configured timeout."""


class ParsingError(WebVulnScannerError):
    """Structured scanner output could not be parsed safely."""


__all__ = [
    "ConfigurationError",
    "ParsingError",
    "ScannerError",
    "ScannerValidationError",
    "StorageError",
    "SubprocessError",
    "SubprocessExecutionError",
    "SubprocessTimeoutError",
    "TargetValidationError",
    "WebVulnScannerError",
]
