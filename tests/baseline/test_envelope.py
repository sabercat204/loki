"""Tests for the YAML envelope module (task 7)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.baseline.envelope import (
    Envelope,
    EnvelopeMalformedError,
    deserialize,
    serialize,
)
from loki.baseline.schema import SCHEMA_VERSION
from loki.models import BaselineRecord
from tests.baseline.fixtures import synthetic_baseline

_FIXED_TIMESTAMP = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


def _serialize_default(record: BaselineRecord | None = None) -> bytes:
    record = record or synthetic_baseline.build()
    return serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )


# ---------------------------------------------------------------------
# serialize()
# ---------------------------------------------------------------------


def test_serialize_returns_utf8_bytes_with_trailing_newline() -> None:
    payload = _serialize_default()
    assert isinstance(payload, bytes)
    assert payload.endswith(b"\n")
    # Round-trip the bytes through ``yaml.safe_load`` so we know they're valid.
    loaded = yaml.safe_load(payload)
    assert isinstance(loaded, dict)


def test_serialize_is_byte_identical_for_identical_inputs() -> None:
    """Property 25 (modulo `written_at`): same inputs -> same bytes."""
    record = synthetic_baseline.build()
    a = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    b = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=_FIXED_TIMESTAMP,
        written_by_extractor_version="loki-test-0.1",
    )
    assert a == b


def test_serialize_payload_keys_are_sorted() -> None:
    """`yaml.safe_dump(sort_keys=True)` emits envelope keys in lexicographic order."""
    payload = _serialize_default()
    text = payload.decode("utf-8")
    # The four envelope keys appear at column 0; check their order.
    leading = [
        line.split(":", 1)[0] for line in text.splitlines() if line and not line.startswith(" ")
    ]
    expected_order = sorted(
        ["schema_version", "written_at", "written_by_extractor_version", "baseline"]
    )
    # Filter out any keys not in our expected envelope set (defensive).
    keys_in_order = [k for k in leading if k in expected_order]
    assert keys_in_order == expected_order


def test_serialize_includes_schema_version() -> None:
    payload = _serialize_default()
    loaded = yaml.safe_load(payload)
    assert loaded["schema_version"] == SCHEMA_VERSION


def test_serialize_rejects_naive_datetime() -> None:
    record = synthetic_baseline.build()
    naive = datetime(2026, 5, 23, 12, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        serialize(
            record,
            schema_version=SCHEMA_VERSION,
            written_at=naive,
            written_by_extractor_version="loki-test-0.1",
        )


# ---------------------------------------------------------------------
# deserialize()
# ---------------------------------------------------------------------


def test_deserialize_round_trip(tmp_path: Path) -> None:
    """Parsing the bytes serialize() produced returns the same fields."""
    payload = _serialize_default()
    env = deserialize(payload, path=tmp_path / "x.yaml")
    assert isinstance(env, Envelope)
    assert env.schema_version == SCHEMA_VERSION
    assert env.written_at == _FIXED_TIMESTAMP
    assert env.written_by_extractor_version == "loki-test-0.1"
    assert isinstance(env.baseline, dict)
    assert env.baseline["baseline_version"] == "1.0.0"


def test_deserialize_rejects_malformed_yaml(tmp_path: Path) -> None:
    with pytest.raises(EnvelopeMalformedError, match="malformed yaml"):
        deserialize(b"key: value:\n  broken: : :", path=tmp_path / "x.yaml")


def test_deserialize_rejects_non_dict_top_level(tmp_path: Path) -> None:
    with pytest.raises(EnvelopeMalformedError, match="top-level YAML must be a mapping"):
        deserialize(b"- not\n- a\n- mapping\n", path=tmp_path / "x.yaml")


def test_deserialize_rejects_missing_required_key(tmp_path: Path) -> None:
    """Each missing key produces a `missing required envelope key: {key}` error."""
    payload = b"schema_version: '1.0.0'\nwritten_at: '2026-01-01T00:00:00+00:00'\nwritten_by_extractor_version: 'loki'\n"
    with pytest.raises(EnvelopeMalformedError, match=r"missing required envelope key: baseline"):
        deserialize(payload, path=tmp_path / "x.yaml")


def test_deserialize_rejects_non_string_schema_version(tmp_path: Path) -> None:
    payload = b"baseline: {}\nschema_version: 100\nwritten_at: '2026-01-01T00:00:00+00:00'\nwritten_by_extractor_version: 'loki'\n"
    with pytest.raises(EnvelopeMalformedError, match=r"schema_version.*string"):
        deserialize(payload, path=tmp_path / "x.yaml")


def test_deserialize_accepts_datetime_or_iso_string(tmp_path: Path) -> None:
    """`yaml.safe_load` may decode the timestamp as either type."""
    payload_string = (
        b"baseline: {}\nschema_version: '1.0.0'\n"
        b"written_at: '2026-01-01T00:00:00+00:00'\n"
        b"written_by_extractor_version: 'loki'\n"
    )
    env = deserialize(payload_string, path=tmp_path / "x.yaml")
    assert env.written_at == datetime(2026, 1, 1, tzinfo=UTC)


def test_deserialize_rejects_unparseable_timestamp(tmp_path: Path) -> None:
    payload = (
        b"baseline: {}\nschema_version: '1.0.0'\n"
        b"written_at: 'not a real timestamp'\n"
        b"written_by_extractor_version: 'loki'\n"
    )
    with pytest.raises(EnvelopeMalformedError, match="written_at"):
        deserialize(payload, path=tmp_path / "x.yaml")


def test_envelope_baseline_is_a_dict_copy(tmp_path: Path) -> None:
    """The baseline payload is copied so callers can mutate it safely."""
    payload = _serialize_default()
    env = deserialize(payload, path=tmp_path / "x.yaml")
    assert isinstance(env.baseline, dict)
    env.baseline["mutated"] = True
    # Re-deserializing the same payload doesn't see the mutation.
    env2 = deserialize(payload, path=tmp_path / "x.yaml")
    assert "mutated" not in env2.baseline
