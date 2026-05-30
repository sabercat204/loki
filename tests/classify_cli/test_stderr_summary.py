"""Tests for ``_format_summary_line`` covering R4.1-R4.7.

Pins the format string for the Stderr_Summary_Line at the helper
level: integer counts for ``<N>``, ``<K>``, and ``<E>``, a
four-decimal-place duration for ``<S>``, no trailing newline (the
caller appends via ``print(..., file=sys.stderr)``), and no
``rules_loaded=<R>`` segment per the G2-B decision (R4.3).

R4.1 (the line is emitted at all) and R4.5 / R4.6 (emission
discipline across success / partial-cancellation / per-component-
error / whole-run-failure paths) are checked at the handler level
in task 11 and the P57 paired test in task 16. This module
verifies the format string only.

The ``needs_review`` field on ``ClassificationRecord`` is
auto-computed: ``needs_review = composite_confidence < 0.60``,
where composite_confidence is the minimum across the four axis
confidences. So a record built with confidence ``0.9`` has
``needs_review = False``; with confidence ``0.5``,
``needs_review = True``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from loki.classification import ClassificationResult
from loki.classification.errors import ClassificationError
from loki.classify_helpers import _format_summary_line
from loki.models.classification import (
    AxisClassification,
    ClassificationRecord,
)
from loki.models.enums import ClassificationMethod


def _build_record(
    *,
    component_id: uuid.UUID | None = None,
    confidence: float = 0.9,
) -> ClassificationRecord:
    """Construct a small ``ClassificationRecord`` with predictable needs_review.

    All four axes share ``confidence``, so the auto-computed
    ``needs_review`` resolves deterministically: ``confidence < 0.6``
    → ``needs_review = True``; otherwise False.
    """
    cid = component_id if component_id is not None else uuid.uuid4()
    sid = uuid.uuid4()
    axis = AxisClassification(
        label="uefi_driver",
        confidence=confidence,
        method=ClassificationMethod.RULE,
    )
    return ClassificationRecord(
        component_id=cid,
        source_image_id=sid,
        extraction_offset="0x1000",
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        type_axis=axis,
        vendor_axis=AxisClassification(
            label="intel",
            confidence=confidence,
            method=ClassificationMethod.RULE,
        ),
        security_axis=AxisClassification(
            label="secure",
            confidence=confidence,
            method=ClassificationMethod.RULE,
        ),
        mutability_axis=AxisClassification(
            label="readonly",
            confidence=confidence,
            method=ClassificationMethod.RULE,
        ),
        classification_version="1.0.0",
    )


def _build_error() -> ClassificationError:
    """Construct a small ``ClassificationError`` for tests."""
    return ClassificationError(
        component_id=uuid.uuid4(),
        error_message="synthetic error",
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
    )


class TestFormatSummaryLineEmpty:
    """Behavior on an empty ``ClassificationResult`` (R4.2 with N=K=E=0)."""

    def test_empty_result_format(self) -> None:
        """Empty input renders the canonical zero-counts form."""
        result = ClassificationResult(records=[], errors=[])
        line = _format_summary_line(result, duration_seconds=0.0001)

        assert line == ("classify: 0 records (0 need_review), 0 errors, duration=0.0001s")
        # No trailing newline (caller adds it).
        assert not line.endswith("\n")


class TestFormatSummaryLinePopulated:
    """Behavior on a populated result with mixed needs_review counts (R4.2)."""

    def test_populated_result_format(self) -> None:
        """Mixed needs_review records render the right N/K split."""
        # Two records below 0.6 → needs_review=True.
        # One record at 0.9 → needs_review=False.
        records = [
            _build_record(confidence=0.5),
            _build_record(confidence=0.5),
            _build_record(confidence=0.9),
        ]
        errors = [_build_error()]
        result = ClassificationResult(records=records, errors=errors)
        line = _format_summary_line(result, duration_seconds=1.2345)

        assert line == ("classify: 3 records (2 need_review), 1 errors, duration=1.2345s")

    def test_k_equals_n(self) -> None:
        """When every record needs review, the format still emits K verbatim (R4.4)."""
        records = [
            _build_record(confidence=0.5),
            _build_record(confidence=0.5),
            _build_record(confidence=0.5),
        ]
        result = ClassificationResult(records=records, errors=[])
        line = _format_summary_line(result, duration_seconds=0.5)

        assert "(3 need_review)" in line
        assert line == ("classify: 3 records (3 need_review), 0 errors, duration=0.5000s")

    def test_k_equals_zero(self) -> None:
        """When no record needs review, K=0 still emits verbatim (R4.4)."""
        records = [
            _build_record(confidence=0.9),
            _build_record(confidence=0.9),
        ]
        result = ClassificationResult(records=records, errors=[])
        line = _format_summary_line(result, duration_seconds=0.5)

        assert "(0 need_review)" in line
        assert line == ("classify: 2 records (0 need_review), 0 errors, duration=0.5000s")


class TestFormatSummaryLineDuration:
    """Behavior across various duration values (R4.2 ``<S>`` rounding)."""

    def test_small_duration(self) -> None:
        """Small durations round to four decimal places."""
        result = ClassificationResult(records=[], errors=[])
        line = _format_summary_line(result, duration_seconds=0.0001)
        assert "duration=0.0001s" in line

    def test_mid_duration(self) -> None:
        """Mid-range durations preserve four decimal places."""
        result = ClassificationResult(records=[], errors=[])
        line = _format_summary_line(result, duration_seconds=1.2345)
        assert "duration=1.2345s" in line

    def test_large_duration(self) -> None:
        """Large durations stay formatted to four decimal places."""
        result = ClassificationResult(records=[], errors=[])
        line = _format_summary_line(result, duration_seconds=999.9999)
        assert "duration=999.9999s" in line

    def test_zero_duration(self) -> None:
        """A zero duration is formatted as ``0.0000s``."""
        result = ClassificationResult(records=[], errors=[])
        line = _format_summary_line(result, duration_seconds=0.0)
        assert "duration=0.0000s" in line


class TestFormatSummaryLineDeterminism:
    """Two calls on the same input produce identical strings (R9.1 helper-level)."""

    def test_two_calls_produce_byte_equal_strings(self) -> None:
        """Determinism at the helper level: identical input → identical output."""
        records = [
            _build_record(confidence=0.5),
            _build_record(confidence=0.9),
        ]
        result = ClassificationResult(records=records, errors=[_build_error()])

        first = _format_summary_line(result, duration_seconds=0.1234)
        second = _format_summary_line(result, duration_seconds=0.1234)
        assert first == second


class TestFormatSummaryLineNoRulesLoaded:
    """R4.3 / G2-B: no ``rules_loaded=<R>`` segment in the v1 output."""

    def test_no_rules_loaded_segment_emitted(self) -> None:
        """The format string MUST NOT include a ``rules_loaded`` segment."""
        result = ClassificationResult(records=[_build_record()], errors=[])
        line = _format_summary_line(result, duration_seconds=0.1)

        assert "rules_loaded" not in line
