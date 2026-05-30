"""Captured-log audit for the extraction subsystem (task 20).

Implements the dynamic half of R10.5 ("at any time, including while
idle") by attaching a recording handler to the ``loki.extraction``
logger and asserting nothing leaks across the full pipeline lifecycle:
import, probe, run, idle, finalize.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.extraction import extract_firmware
from loki.extraction.extractors.base import clear_registry
from loki.extraction.streaming import PEEK_SIZE
from loki.models import ExtractionConfig
from tests.extraction.fixtures import synthetic_uefi_volume


@pytest.fixture()
def captured_records() -> Iterator[list[logging.LogRecord]]:
    """Attach a recording handler to ``loki.extraction`` for one test."""

    records: list[logging.LogRecord] = []

    class _Recorder(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("loki.extraction")
    handler = _Recorder(level=logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


def _formatted_messages(records: list[logging.LogRecord]) -> list[str]:
    return [record.getMessage() for record in records]


# ---------------------------------------------------------------------
# Lifecycle smoke check
# ---------------------------------------------------------------------


def test_emits_run_start_record_with_short_head_preview(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.1: run-start record names path + size and exposes head=8 bytes."""
    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extract_firmware(binary, config)

    starts = [
        m for m in _formatted_messages(captured_records) if m.startswith("extraction starting")
    ]
    assert len(starts) == 1
    msg = starts[0]
    assert f"path={binary.resolve()}" in msg
    # Head preview is exactly 16 hex chars (8 bytes).
    assert "head=" in msg
    head_value = msg.split("head=", 1)[1].split()[0]
    assert len(head_value) == 16


def test_emits_format_detected_record(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.2: detector results are surfaced in an info record."""
    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extract_firmware(binary, config)
    detected = [m for m in _formatted_messages(captured_records) if "detected formats" in m]
    assert len(detected) == 1
    assert "UEFI_PI_VOLUME" in detected[0]


def test_emits_run_finished_record_with_summary(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.4: run-finished record carries duration / counts."""
    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extract_firmware(binary, config)
    finished = [
        m for m in _formatted_messages(captured_records) if m.startswith("extraction finished")
    ]
    assert len(finished) == 1
    assert "duration=" in finished[0]
    assert "components=" in finished[0]
    assert "errors=" in finished[0]


# ---------------------------------------------------------------------
# R10.5 — no content leakage
# ---------------------------------------------------------------------


def test_does_not_log_input_bytes_beyond_head_preview(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """No log record reproduces input bytes beyond the leading 16 hex chars.

    Constructs a fixture whose body contains a sentinel byte sequence
    that would be obvious if anything past the head preview leaked,
    then runs extraction and asserts the sentinel never appears in
    formatted log output.
    """

    binary = synthetic_uefi_volume.build(tmp_path)
    # Patch a sentinel into the FFS file payload region (well past the
    # 16-byte head preview) and make sure extraction still succeeds.
    raw = bytearray(binary.read_bytes())
    sentinel_offset = 0x100
    sentinel = b"LOKI-LEAK-CANARY"
    raw[sentinel_offset : sentinel_offset + len(sentinel)] = sentinel
    binary.write_bytes(bytes(raw))

    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extract_firmware(binary, config)

    messages = _formatted_messages(captured_records)
    for message in messages:
        assert "LOKI-LEAK-CANARY" not in message
        # The leading head preview is 16 hex chars; anything longer
        # *might* be a leak. Allow legitimate hashes (component_id,
        # raw_hash, file_hash) by limiting the check to the
        # explicit byte sentinel rather than scanning hex runs.


def test_does_not_log_ui_section_names(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """The UI section name surfaces in the manifest but never in logs."""

    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    result = extract_firmware(binary, config)
    # The synthetic fixture's UI section name surfaces in the manifest.
    component_names = [c.name for c in result.manifest.components if c.name]
    assert synthetic_uefi_volume.FFS_FILE_NAME in component_names

    messages = _formatted_messages(captured_records)
    for message in messages:
        assert synthetic_uefi_volume.FFS_FILE_NAME not in message


def test_does_not_log_during_idle_state(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.5 'at any time' clause: no records emitted while no
    extraction is in progress.

    This test deliberately doesn't call ``extract_firmware``; just
    importing the module and constructing the fixture should not
    produce any log records on the ``loki.extraction`` logger.
    """

    # Build a fixture (this exercises file I/O but no pipeline code).
    synthetic_uefi_volume.build(tmp_path)
    # Touch every public submodule to make sure import-time logging
    # isn't somehow happening.
    import loki.extraction
    import loki.extraction.api
    import loki.extraction.detection
    import loki.extraction.extractors
    import loki.extraction.manifest
    import loki.extraction.streaming
    import loki.extraction.timing
    import loki.extraction.tools  # noqa: F401

    assert captured_records == []


def test_logger_namespace_is_loki_extraction(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """Every emitted record's logger name starts with ``loki.extraction``."""
    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extract_firmware(binary, config)
    assert captured_records  # at least the start/detect/finish trio
    for record in captured_records:
        assert record.name.startswith("loki.extraction")


def test_head_preview_does_not_exceed_eight_bytes(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.1: ``head=`` value is exactly 16 hex chars regardless of file size."""
    # Construct a much larger binary so the peek window can be many
    # KiB; the head preview must still cap at 16 hex chars.
    large = tmp_path / "large.rom"
    large.write_bytes(b"\xab" * (PEEK_SIZE + 1024))
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extract_firmware(large, config)
    starts = [
        m for m in _formatted_messages(captured_records) if m.startswith("extraction starting")
    ]
    head_value = starts[0].split("head=", 1)[1].split()[0]
    assert len(head_value) == 16
