"""Tests for the controlled framework exception hierarchy."""

import pytest

from webvulnscanner.core.exceptions import (
    ConfigurationError,
    ParsingError,
    ScannerError,
    ScannerValidationError,
    StorageError,
    SubprocessError,
    SubprocessExecutionError,
    SubprocessTimeoutError,
    TargetValidationError,
    WebVulnScannerError,
)


@pytest.mark.parametrize(
    ("error_type", "expected_parent"),
    [
        (ConfigurationError, WebVulnScannerError),
        (TargetValidationError, WebVulnScannerError),
        (StorageError, WebVulnScannerError),
        (ScannerValidationError, ScannerError),
        (SubprocessExecutionError, SubprocessError),
        (SubprocessTimeoutError, SubprocessError),
        (ParsingError, WebVulnScannerError),
    ],
)
def test_exception_hierarchy_distinguishes_failure_categories(
    error_type: type[WebVulnScannerError],
    expected_parent: type[WebVulnScannerError],
) -> None:
    """Callers can catch categories by type instead of matching messages."""
    error = error_type("controlled failure")

    assert isinstance(error, expected_parent)
    assert isinstance(error, WebVulnScannerError)


def test_error_preserves_message_and_optional_context() -> None:
    """Safe component and operation identifiers remain programmatically available."""
    error = ScannerValidationError(
        "scanner prerequisites are unavailable",
        component="nuclei",
        operation="validate",
    )

    assert str(error) == "scanner prerequisites are unavailable"
    assert error.message == "scanner prerequisites are unavailable"
    assert error.component == "nuclei"
    assert error.operation == "validate"
    assert error.cause is None
    assert error.cause_type is None


def test_error_context_defaults_to_none() -> None:
    """Context is optional for failures that have no safe identifiers."""
    error = StorageError("storage unavailable")

    assert error.component is None
    assert error.operation is None
    assert error.cause is None
    assert error.cause_type is None


def test_underlying_cause_is_preserved_but_not_rendered() -> None:
    """Potentially sensitive cause text is excluded from normal error rendering."""
    secret = "token-that-must-not-be-rendered"
    cause = OSError(f"process failed with {secret}")
    error = SubprocessExecutionError(
        "external tool failed",
        component="nmap",
        operation="execute",
        cause=cause,
    )

    assert error.cause is cause
    assert error.cause_type == "OSError"
    assert str(error) == "external tool failed"
    assert secret not in str(error)
    assert secret not in repr(error)


def test_specific_exceptions_can_be_caught_without_message_matching() -> None:
    """A timeout remains distinct from other subprocess failures."""
    with pytest.raises(SubprocessTimeoutError):
        raise SubprocessTimeoutError(
            "external tool timed out",
            component="nuclei",
            operation="execute",
        )
