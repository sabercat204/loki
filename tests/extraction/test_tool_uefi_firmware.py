"""Tests for the required ``uefi_firmware`` wrapper (task 9)."""

from __future__ import annotations

import builtins
import importlib
import sys
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

from loki.extraction.errors import ExtractionPipelineError
from loki.extraction.tools.base import ToolStatus
from loki.extraction.tools.uefi_firmware import UefiFirmwareWrapper


def test_wrapper_metadata() -> None:
    assert UefiFirmwareWrapper.name == "uefi_firmware"
    assert UefiFirmwareWrapper.required is True


def test_probe_returns_available_when_package_imports() -> None:
    """The package is installed in the dev env, so probe should succeed."""
    wrapper = UefiFirmwareWrapper()
    assert wrapper.probe() is ToolStatus.AVAILABLE


def test_probe_captures_package_version() -> None:
    wrapper = UefiFirmwareWrapper()
    wrapper.probe()
    # The dev env pins uefi_firmware>=1.10; just assert the version
    # property is populated with a non-empty string.
    assert wrapper.version is not None
    assert isinstance(wrapper.version, str)
    assert wrapper.version


@pytest.fixture()
def _without_uefi_firmware() -> Iterator[None]:
    """Force ``import uefi_firmware`` to raise ``ImportError`` for one test.

    Patches ``builtins.__import__`` so a fresh import attempt fails;
    restores after the test.
    """
    real_import = builtins.__import__
    sys.modules.pop("uefi_firmware", None)

    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "uefi_firmware":
            raise ImportError("simulated missing dependency")
        return real_import(name, globals, locals, fromlist, level)

    with patch.object(builtins, "__import__", fake_import):
        yield
    # Re-import for downstream tests in the same session.
    importlib.import_module("uefi_firmware")


def test_probe_raises_pipeline_error_when_import_fails(
    _without_uefi_firmware: None,
) -> None:
    """A missing required tool aborts the pipeline."""
    wrapper = UefiFirmwareWrapper()
    with pytest.raises(ExtractionPipelineError) as excinfo:
        wrapper.probe()
    assert "uefi_firmware" in str(excinfo.value)
    assert wrapper.version is None


def test_shutdown_is_idempotent() -> None:
    """``shutdown()`` is a no-op and can be called repeatedly."""
    wrapper = UefiFirmwareWrapper()
    wrapper.shutdown()
    wrapper.shutdown()  # no exception


# ---------------------------------------------------------------------
# Decompression helpers (R3.1, R5.8)
# ---------------------------------------------------------------------


def test_decompress_tiano_round_trip() -> None:
    """Compressed-then-decompressed bytes match the original payload."""
    import uefi_firmware.efi_compressor as ec

    wrapper = UefiFirmwareWrapper()
    wrapper.probe()

    payload = b"LOKI-TIANO-DECOMP-CANARY-" * 64
    compressed = bytes(ec.TianoCompress(payload, len(payload)))
    decompressed = wrapper.decompress_tiano(compressed)

    assert decompressed == payload


def test_decompress_lzma_round_trip() -> None:
    """LZMA round-trip succeeds via the wrapper."""
    import uefi_firmware.efi_compressor as ec

    wrapper = UefiFirmwareWrapper()
    wrapper.probe()

    payload = b"LOKI-LZMA-DECOMP-CANARY-" * 64
    compressed = bytes(ec.LzmaCompress(payload, len(payload)))
    decompressed = wrapper.decompress_lzma(compressed)

    assert decompressed == payload


def test_decompress_tiano_returns_none_on_garbage() -> None:
    """Library-level failure surfaces as ``None`` (no exception escapes)."""
    wrapper = UefiFirmwareWrapper()
    wrapper.probe()

    result = wrapper.decompress_tiano(b"NOT REAL TIANO COMPRESSED DATA")
    assert result is None


def test_decompress_lzma_returns_none_on_garbage() -> None:
    """Library-level failure surfaces as ``None`` (no exception escapes)."""
    wrapper = UefiFirmwareWrapper()
    wrapper.probe()

    result = wrapper.decompress_lzma(b"NOT REAL LZMA COMPRESSED DATA")
    assert result is None


def test_decompress_tiano_returns_none_on_empty() -> None:
    """An empty buffer is not a valid Tiano stream; surfaces as ``None``."""
    wrapper = UefiFirmwareWrapper()
    wrapper.probe()

    assert wrapper.decompress_tiano(b"") is None


def test_decompress_tiano_logs_warning_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """R10.5 anchor: failures emit a WARNING under ``loki.extraction.tools``."""
    import logging

    wrapper = UefiFirmwareWrapper()
    wrapper.probe()

    caplog.set_level(logging.WARNING, logger="loki.extraction.tools.uefi_firmware")
    wrapper.decompress_tiano(b"NOT REAL TIANO DATA")

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("TianoDecompress failed" in r.getMessage() for r in warnings)


def test_decompress_tiano_raises_when_not_probed() -> None:
    """Calling decompress_tiano before probe is a pipeline ordering bug."""
    wrapper = UefiFirmwareWrapper()
    with pytest.raises(RuntimeError, match="probe"):
        wrapper.decompress_tiano(b"x")


def test_decompress_lzma_raises_when_not_probed() -> None:
    """Calling decompress_lzma before probe is a pipeline ordering bug."""
    wrapper = UefiFirmwareWrapper()
    with pytest.raises(RuntimeError, match="probe"):
        wrapper.decompress_lzma(b"x")
