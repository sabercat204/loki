"""Tests for ``_serialize_result`` covering R3.1-R3.5, R3.7, R3.8.

Pins the indented JSON shape (R3.1, R3.4), the ``model_dump(mode="json")``
serialization of records and errors (R3.2, R3.3), the
``["records", "errors"]`` top-level key ordering (R3.5), the
deterministic byte-equal round-trip property (R9.1 helper-level
slice), and the R5.6 dual-record passthrough (R3.8) where the
library emits both a ``ClassificationRecord`` and a
``ClassificationError`` for the same ``component_id``.

R3.6 (--summary-only zero-byte stdout) is checked at the
handler-integration level in task 11. R3.7's serialization-error
path is exercised at the handler level in task 11; this helper
itself raises whatever ``json.dumps`` raises (no internal
try/except).

The R5.6 dual-record test constructs the result directly rather
than running the full pipeline, mirroring the design's per-helper
unit-test discipline.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from loki.classification import ClassificationResult
from loki.classification.errors import ClassificationError
from loki.classify_helpers import _serialize_result
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
    """Construct a small valid ``ClassificationRecord`` for tests.

    All four axes share the same ``confidence`` so the
    auto-computed ``composite_confidence`` and ``needs_review``
    fields are predictable.
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


def _build_error(
    *,
    component_id: uuid.UUID | None = None,
    error_message: str = "synthetic error for tests",
) -> ClassificationError:
    """Construct a small valid ``ClassificationError`` for tests."""
    return ClassificationError(
        component_id=component_id,
        error_message=error_message,
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
    )


class TestSerializeResultEmpty:
    """Behavior on an empty ``ClassificationResult`` (R3.1, R3.4, R3.5)."""

    def test_empty_result_renders_canonical_form(self) -> None:
        """Empty input renders to the exact canonical JSON form."""
        result = ClassificationResult(records=[], errors=[])
        rendered = _serialize_result(result)

        # Exactly one trailing newline (R3.4).
        assert rendered.endswith("\n")
        assert not rendered.endswith("\n\n")

        # Canonical indent=2 form with the two top-level keys
        # in the contracted order (R3.5).
        assert rendered == '{\n  "records": [],\n  "errors": []\n}\n'


class TestSerializeResultPopulated:
    """Behavior on a populated ``ClassificationResult`` (R3.1-R3.5)."""

    def test_populated_result_parses_back_to_correct_shape(self) -> None:
        """The serialized JSON parses back to a dict with the right keys."""
        record = _build_record()
        error = _build_error()
        result = ClassificationResult(records=[record], errors=[error])

        rendered = _serialize_result(result)
        parsed = json.loads(rendered)

        assert list(parsed.keys()) == ["records", "errors"]
        assert len(parsed["records"]) == 1
        assert len(parsed["errors"]) == 1

    def test_records_appear_in_library_order(self) -> None:
        """``records`` list preserves the order from the input (R3.2)."""
        record_a = _build_record(component_id=uuid.UUID("00000000-0000-0000-0000-00000000000a"))
        record_b = _build_record(component_id=uuid.UUID("00000000-0000-0000-0000-00000000000b"))
        record_c = _build_record(component_id=uuid.UUID("00000000-0000-0000-0000-00000000000c"))

        result = ClassificationResult(
            records=[record_a, record_b, record_c],
            errors=[],
        )

        rendered = _serialize_result(result)
        parsed = json.loads(rendered)

        component_ids = [r["component_id"] for r in parsed["records"]]
        assert component_ids == [
            "00000000-0000-0000-0000-00000000000a",
            "00000000-0000-0000-0000-00000000000b",
            "00000000-0000-0000-0000-00000000000c",
        ]

    def test_errors_appear_in_library_order(self) -> None:
        """``errors`` list preserves the order from the input (R3.3)."""
        error_a = _build_error(error_message="err-A")
        error_b = _build_error(error_message="err-B")
        error_c = _build_error(error_message="err-C")

        result = ClassificationResult(
            records=[],
            errors=[error_a, error_b, error_c],
        )

        rendered = _serialize_result(result)
        parsed = json.loads(rendered)

        messages = [e["error_message"] for e in parsed["errors"]]
        assert messages == ["err-A", "err-B", "err-C"]

    def test_top_level_key_order_is_records_then_errors(self) -> None:
        """The JSON top-level keys are exactly ``["records", "errors"]`` (R3.5)."""
        result = ClassificationResult(
            records=[_build_record()],
            errors=[_build_error()],
        )

        rendered = _serialize_result(result)

        # The "records" key appears before the "errors" key in
        # the textual output. This pins the dict-literal-insertion-
        # order contract that the implementation relies on.
        records_index = rendered.index('"records"')
        errors_index = rendered.index('"errors"')
        assert records_index < errors_index

    def test_uses_indent_two(self) -> None:
        """Rendered JSON uses two-space indent (R3.4)."""
        result = ClassificationResult(records=[_build_record()], errors=[])
        rendered = _serialize_result(result)

        # Two-space indent for first-level entries; the dict
        # opens with `{\n  "records":` on the second line.
        assert rendered.startswith('{\n  "records":')


class TestSerializeResultDeterminism:
    """Two calls on the same input produce identical strings (R9.1 helper-level)."""

    def test_two_calls_produce_byte_equal_strings(self) -> None:
        """Determinism at the helper level: identical input → identical output."""
        result = ClassificationResult(
            records=[
                _build_record(component_id=uuid.UUID("00000000-0000-0000-0000-000000000010")),
                _build_record(component_id=uuid.UUID("00000000-0000-0000-0000-000000000011")),
            ],
            errors=[
                _build_error(error_message="determinism-test"),
            ],
        )

        first = _serialize_result(result)
        second = _serialize_result(result)
        assert first == second


class TestSerializeResultDualRecord:
    """R3.8 + R5.6 dual-record visibility passthrough."""

    def test_dual_record_is_not_collapsed(self) -> None:
        """When a component_id appears in both lists, both are preserved.

        The R5.6 dual-record contract from classification-pipeline:
        the missing-bytes signature-detection case emits both a
        ``ClassificationRecord`` and a ``ClassificationError``
        for the same ``component_id``. The CLI MUST NOT collapse,
        deduplicate, or filter either record (R3.8).
        """
        shared_id = uuid.UUID("00000000-0000-0000-0000-0000000000ff")
        record = _build_record(component_id=shared_id)
        error = _build_error(
            component_id=shared_id,
            error_message="signature: missing bytes",
        )

        result = ClassificationResult(records=[record], errors=[error])
        rendered = _serialize_result(result)
        parsed = json.loads(rendered)

        # Both halves of the dual-record contract are present.
        assert len(parsed["records"]) == 1
        assert len(parsed["errors"]) == 1
        assert parsed["records"][0]["component_id"] == str(shared_id)
        assert parsed["errors"][0]["component_id"] == str(shared_id)
