"""Smoke tests for the synthetic-baseline fixture (task 8)."""

from __future__ import annotations

from loki.models import BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


def test_build_returns_validated_baseline_record() -> None:
    record = synthetic_baseline.build()
    assert isinstance(record, BaselineRecord)
    assert record.vendor == "INTEL"
    assert record.model == "DEMO-X1"
    assert record.firmware_version == "1.0"


def test_build_classification_count_drives_manifest_size() -> None:
    record = synthetic_baseline.build(classification_count=5)
    assert len(record.component_manifest) == 5


def test_build_zero_classifications_is_legal() -> None:
    record = synthetic_baseline.build(classification_count=0)
    assert record.component_manifest == []


def test_build_is_deterministic() -> None:
    """Same arguments produce byte-identical records (same baseline_id)."""
    a = synthetic_baseline.build(vendor="ACME", model="M3", firmware_version="2.0")
    b = synthetic_baseline.build(vendor="ACME", model="M3", firmware_version="2.0")
    assert a.baseline_id == b.baseline_id
    assert a.source_image_hash == b.source_image_hash
    assert a.component_manifest == b.component_manifest


def test_build_distinct_args_produce_distinct_baseline_ids() -> None:
    a = synthetic_baseline.build(vendor="A", model="X", firmware_version="1.0")
    b = synthetic_baseline.build(vendor="B", model="X", firmware_version="1.0")
    assert a.baseline_id != b.baseline_id
    assert a.source_image_hash != b.source_image_hash


def test_build_supports_notes_field() -> None:
    record = synthetic_baseline.build(notes="curated for golden-file regression")
    assert record.notes == "curated for golden-file regression"


def test_build_classification_helper_returns_validated_record() -> None:
    record = synthetic_baseline.build()
    [first, *_] = record.component_manifest
    # Composite confidence is auto-computed from the four axis confidences.
    assert first.composite_confidence == 0.85
    assert first.classification_version == "demo-classifier-0.1"
