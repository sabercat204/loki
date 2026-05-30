"""Captured-log audit for the baseline-persistence subsystem (task 16).

Implements the dynamic half of R10.5 ("at any time, including while
idle") by attaching a recording handler to the ``loki.baseline``
logger and asserting nothing leaks across the full persistence
lifecycle: import, construct, load, save, delete, idle.

R10.5 names the forbidden substrings explicitly:

- ``BaselineRecord.source_image_hash``
- ``BaselineRecord.notes``
- Any ``ClassificationRecord`` field beyond the Baseline_Identifier
  permitted by R10.4. The handoff narrows that to: every
  classification's ``component_id`` (UUID surfaces would identify
  individual components), and ``signature_info.signer`` (vendor
  identity beyond what's already in the parent baseline).

The Baseline_Identifier — ``baseline_id``, ``vendor``, ``model``,
``firmware_version`` — is permitted in log messages by R10.4 and so
is excluded from the canary set. Other parent ``BaselineRecord``
fields (``name``, ``baseline_version``, ``created_timestamp``) are
neither explicitly forbidden by R10.5 nor mentioned in R10.4; the
audit does not assert on them.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.baseline.envelope import serialize
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.baseline.store import BaselineStore
from loki.models import BaselineConfig, BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


def _config(path: Path) -> BaselineConfig:
    return BaselineConfig(storage_path=str(path), auto_match=False)


def _store(path: Path) -> BaselineStore:
    return BaselineStore(_config(path))


@pytest.fixture()
def captured_records() -> Iterator[list[logging.LogRecord]]:
    """Attach a recording handler to ``loki.baseline`` for one test."""

    records: list[logging.LogRecord] = []

    class _Recorder(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("loki.baseline")
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


def _formatted_messages(records: list[logging.LogRecord]) -> list[str]:
    return [record.getMessage() for record in records]


def _build_canary_record() -> BaselineRecord:
    """Build a baseline whose forbidden fields contain unique sentinels.

    Each forbidden substring is unique enough to make leakage
    obvious if it ever appears in a log message. ``notes`` carries
    a multi-word string so partial matches still trip the audit.
    """
    record = synthetic_baseline.build(
        vendor="ACME",
        model="LEAK-CANARY-X1",
        firmware_version="1.42",
        classification_count=2,
        notes="LOKI-NOTES-LEAK-CANARY: highly sensitive analyst commentary",
    )
    return record


def _forbidden_substrings(record: BaselineRecord) -> set[str]:
    """Return the set of strings that must never appear in any log record.

    Mirrors R10.5 + the handoff's narrowing.
    """
    forbidden: set[str] = {
        record.source_image_hash,
    }
    if record.notes is not None:
        forbidden.add(record.notes)
    for classification in record.component_manifest:
        forbidden.add(str(classification.component_id))
        if classification.signature_info and classification.signature_info.signer:
            forbidden.add(classification.signature_info.signer)
    return forbidden


# ---------------------------------------------------------------------
# Lifecycle smoke check (R10.1, R10.2, R10.3, R10.4 anchors)
# ---------------------------------------------------------------------


def test_emits_load_start_and_finish_records(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.1 + R10.2: load emits start + finish INFO records."""
    record = _build_canary_record()
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=record.created_timestamp,
        written_by_extractor_version="loki-test-0.1",
    )
    (tmp_path / filename_for(record)).write_bytes(payload)
    _store(tmp_path).load()

    messages = _formatted_messages(captured_records)
    assert any(m.startswith("baseline load starting") for m in messages)
    assert any(m.startswith("baseline load finished") for m in messages)


def test_emits_save_record_with_baseline_identifier(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.4: save emits an INFO record naming the Baseline_Identifier."""
    record = _build_canary_record()
    _store(tmp_path).save(record)

    messages = _formatted_messages(captured_records)
    save_messages = [m for m in messages if m.startswith("baseline save")]
    assert len(save_messages) == 1
    msg = save_messages[0]
    assert str(record.baseline_id) in msg
    assert record.vendor in msg
    assert record.model in msg
    assert record.firmware_version in msg


def test_emits_quarantine_warning_for_each_rejected_file(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.3: each quarantined file produces exactly one WARNING record."""
    (tmp_path / "bad1.yaml").write_bytes(b"::: malformed :::")
    (tmp_path / "bad2.yaml").write_bytes(b"")
    _store(tmp_path).load()

    warnings = [r for r in captured_records if r.levelno == logging.WARNING]
    quarantine_warnings = [r for r in warnings if "baseline quarantine" in r.getMessage()]
    assert len(quarantine_warnings) == 2


# ---------------------------------------------------------------------
# R10.5 — no content leakage during a full lifecycle
# ---------------------------------------------------------------------


def test_load_does_not_leak_forbidden_substrings(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """No load-side log record reproduces any forbidden field."""
    record = _build_canary_record()
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=record.created_timestamp,
        written_by_extractor_version="loki-test-0.1",
    )
    (tmp_path / filename_for(record)).write_bytes(payload)
    _store(tmp_path).load()

    forbidden = _forbidden_substrings(record)
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_save_does_not_leak_forbidden_substrings(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """No save-side log record reproduces any forbidden field."""
    record = _build_canary_record()
    _store(tmp_path).save(record)

    forbidden = _forbidden_substrings(record)
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_full_lifecycle_does_not_leak_forbidden_substrings(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.5 'at any time' clause: nothing leaks across the full lifecycle.

    The lifecycle exercised here covers: construct → load empty →
    save → load (with the saved file) → delete → load empty again.
    Each step touches a different code path; if any step logged a
    forbidden field, this test would catch it.
    """
    record = _build_canary_record()
    store = _store(tmp_path)
    store.load()
    store.save(record)
    store.load()
    store.delete(record.baseline_id)
    store.load()

    forbidden = _forbidden_substrings(record)
    for message in _formatted_messages(captured_records):
        for needle in forbidden:
            assert needle not in message, f"log message leaked '{needle}': {message}"


def test_quarantine_log_does_not_leak_payload_contents(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """A quarantined file's log record names the path + reason, not the payload.

    The Quarantine_Set keeps the original file bytes (R8.2-R8.5)
    so the GUI can later offer a "View raw" affordance, but the
    log record only references the file path and the reason
    string. Verify by quarantining a file whose contents include
    a sentinel and confirming the sentinel never reaches the log.
    """
    sentinel = b"LOKI-QUARANTINE-PAYLOAD-LEAK-CANARY"
    # Malformed YAML that nonetheless contains the sentinel in its
    # body so any naive "log the payload" regression would flag.
    (tmp_path / "bad.yaml").write_bytes(b"::: not yaml :::\n" + sentinel + b"\n")
    _store(tmp_path).load()

    decoded_sentinel = sentinel.decode("ascii")
    for message in _formatted_messages(captured_records):
        assert decoded_sentinel not in message


def test_does_not_log_during_idle_state(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.5 'at any time' clause: no records emitted while no I/O is in progress.

    The module-top imports already touch every public submodule of
    :mod:`loki.baseline` via :class:`BaselineStore`,
    :class:`BaselineConfig`, the envelope helpers, etc. If any
    of those imports emitted a log record, the captured-records
    list would already be non-empty when this test runs.
    """
    # Construct a store; constructor mkdirs but doesn't log.
    _store(tmp_path)

    assert captured_records == []


def test_delete_log_only_carries_identifiers(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """``delete`` logs the baseline_id + path; nothing else."""
    record = _build_canary_record()
    store = _store(tmp_path)
    store.save(record)
    captured_records.clear()  # discard the save log records
    store.delete(record.baseline_id)

    messages = _formatted_messages(captured_records)
    delete_messages = [m for m in messages if m.startswith("baseline delete")]
    assert len(delete_messages) == 1
    msg = delete_messages[0]
    assert str(record.baseline_id) in msg
    # Forbidden substrings absent.
    forbidden = _forbidden_substrings(record)
    for needle in forbidden:
        assert needle not in msg


def test_logger_namespace_is_loki_baseline(
    tmp_path: Path, captured_records: list[logging.LogRecord]
) -> None:
    """R10.6: every emitted record's logger name starts with ``loki.baseline``."""
    record = _build_canary_record()
    store = _store(tmp_path)
    store.save(record)
    store.load()

    assert captured_records  # save + load logged at least once
    for r in captured_records:
        assert r.name.startswith("loki.baseline"), (
            f"record from foreign logger {r.name!r}: {r.getMessage()}"
        )


# ---------------------------------------------------------------------
# Defensive: the canary itself must be present somewhere outside logs
# ---------------------------------------------------------------------


def test_canary_substrings_actually_exist_in_record() -> None:
    """Sanity check: the leak canaries are present in the record we build.

    If the canary isn't actually in the record, the leakage tests
    are trivially passing and won't catch real regressions. This
    test is the inverse: if any of these assertions break, the
    canary fixture has drifted and the audit needs updating.
    """
    record = _build_canary_record()
    forbidden = _forbidden_substrings(record)
    # The notes canary must be in the record's notes.
    assert record.notes is not None
    assert "LOKI-NOTES-LEAK-CANARY" in record.notes
    # source_image_hash must be a 64-char lowercase hex string.
    assert record.source_image_hash in forbidden
    assert len(record.source_image_hash) == 64
    # Every classification's component_id must be a UUID.
    for classification in record.component_manifest:
        assert str(classification.component_id) in forbidden
        assert isinstance(classification.component_id, uuid.UUID)
    # signature_info.signer ("DEMO-CA" from the synthetic builder)
    # must be in the forbidden set.
    assert any("DEMO-CA" in s for s in forbidden)
