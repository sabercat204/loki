"""Tests for the extraction subsystem's exception hierarchy.

Covers task 3 of specs/extraction-pipeline/tasks.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loki.extraction import (
    ExtractionPipelineError,
    InvalidInputError,
    ManifestConstructionError,
    ToolFailedError,
    ToolTimedOutError,
    ToolWrapperError,
)


def test_inheritance_chain() -> None:
    """Every public exception inherits from ``ExtractionPipelineError``."""
    assert issubclass(InvalidInputError, ExtractionPipelineError)
    assert issubclass(ManifestConstructionError, ExtractionPipelineError)
    assert issubclass(ToolWrapperError, ExtractionPipelineError)
    assert issubclass(ToolTimedOutError, ToolWrapperError)
    assert issubclass(ToolFailedError, ToolWrapperError)


def test_invalid_input_error_carries_path_and_message() -> None:
    """``InvalidInputError`` records ``path`` and ``message`` and shows both in str()."""
    err = InvalidInputError("/tmp/missing.rom", "file does not exist")
    assert err.path == Path("/tmp/missing.rom")
    assert err.message == "file does not exist"
    assert str(err) == "file does not exist: /tmp/missing.rom"


def test_invalid_input_error_accepts_path_object() -> None:
    """``InvalidInputError`` normalises ``str`` inputs into ``Path``."""
    err = InvalidInputError(Path("/tmp/empty.rom"), "file is empty")
    assert isinstance(err.path, Path)
    assert err.path == Path("/tmp/empty.rom")


def test_manifest_construction_error_with_field_path() -> None:
    """``field_path`` and ``cause`` flow through to message + ``__cause__``."""
    underlying = ValueError("oops")
    err = ManifestConstructionError(
        "size must be > 0",
        field_path="components[3].size",
        cause=underlying,
    )
    assert err.field_path == "components[3].size"
    assert err.message == "size must be > 0"
    assert err.__cause__ is underlying
    assert str(err) == "components[3].size: size must be > 0"


def test_manifest_construction_error_without_field_path() -> None:
    """Field path is optional; the message format adapts."""
    err = ManifestConstructionError("validation failed")
    assert err.field_path is None
    assert str(err) == "validation failed"


def test_tool_timed_out_error_pins_status_to_timed_out() -> None:
    """Timeout subclass always reports ``status='TIMED_OUT'`` and no exit status."""
    err = ToolTimedOutError(
        tool_name="UEFIExtract",
        stderr_excerpt="(none)",
        timeout_seconds=30.0,
    )
    assert err.tool_name == "UEFIExtract"
    assert err.status == "TIMED_OUT"
    assert err.exit_status is None
    assert err.timeout_seconds == 30.0
    assert "TIMED_OUT" in str(err)


def test_tool_failed_error_pins_status_to_failed() -> None:
    """Failure subclass always reports ``status='FAILED'`` with the captured exit status."""
    err = ToolFailedError(
        tool_name="UEFIExtract",
        exit_status=2,
        stderr_excerpt="bad input",
    )
    assert err.tool_name == "UEFIExtract"
    assert err.status == "FAILED"
    assert err.exit_status == 2
    assert "FAILED" in str(err)
    assert "exit 2" in str(err)


def test_tool_wrapper_error_can_be_raised_directly() -> None:
    """Direct construction is allowed for unusual cases not fitting the two subclasses."""
    err = ToolWrapperError(
        tool_name="custom-tool",
        status="FAILED",
        exit_status=255,
        stderr_excerpt="(redacted)",
    )
    assert err.status == "FAILED"
    with pytest.raises(ToolWrapperError):
        raise err
