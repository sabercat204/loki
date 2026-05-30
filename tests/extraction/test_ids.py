"""Tests for deterministic component / error id derivation.

Covers task 4 of .kiro/specs/extraction-pipeline/tasks.md and the
implementation half of Properties 19 and 20 from the design doc.
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from loki.extraction.ids import derive_component_id, derive_error_component_id
from loki.models import LOKI_NAMESPACE

_HEX_DIGITS = "0123456789abcdef"
_hash_strategy = st.text(alphabet=_HEX_DIGITS, min_size=64, max_size=64)
_offset_strategy = st.integers(min_value=0, max_value=2**32 - 1)
_error_kind_strategy = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", min_size=1, max_size=24
)


# ---------------------------------------------------------------------
# derive_component_id
# ---------------------------------------------------------------------


def test_component_id_is_deterministic_for_fixed_inputs() -> None:
    """Same inputs always produce the same UUID."""
    file_hash = "a" * 64
    offset = 0x40000
    raw_hash = "b" * 64
    first = derive_component_id(source_image_hash=file_hash, offset=offset, raw_hash=raw_hash)
    second = derive_component_id(source_image_hash=file_hash, offset=offset, raw_hash=raw_hash)
    assert first == second
    # Sanity check it really is a uuid5 of LOKI_NAMESPACE.
    payload = f"{file_hash}:0x{offset:x}:{raw_hash}"
    assert first == uuid.uuid5(LOKI_NAMESPACE, payload)


def test_component_id_differs_when_offset_differs() -> None:
    a = derive_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        raw_hash="b" * 64,
    )
    b = derive_component_id(
        source_image_hash="a" * 64,
        offset=0x200,
        raw_hash="b" * 64,
    )
    assert a != b


def test_component_id_differs_when_raw_hash_differs() -> None:
    a = derive_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        raw_hash="b" * 64,
    )
    b = derive_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        raw_hash="c" * 64,
    )
    assert a != b


def test_component_id_differs_when_source_image_hash_differs() -> None:
    a = derive_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        raw_hash="b" * 64,
    )
    b = derive_component_id(
        source_image_hash="d" * 64,
        offset=0x100,
        raw_hash="b" * 64,
    )
    assert a != b


def test_component_id_rejects_uppercase_hashes() -> None:
    """The contract requires lowercase 64-char hex; uppercase is rejected."""
    with pytest.raises(ValueError, match="lowercase"):
        derive_component_id(
            source_image_hash="A" * 64,
            offset=0,
            raw_hash="b" * 64,
        )
    with pytest.raises(ValueError, match="lowercase"):
        derive_component_id(
            source_image_hash="a" * 64,
            offset=0,
            raw_hash="B" * 64,
        )


def test_component_id_rejects_short_hashes() -> None:
    with pytest.raises(ValueError):
        derive_component_id(
            source_image_hash="a" * 63,
            offset=0,
            raw_hash="b" * 64,
        )


def test_component_id_rejects_negative_offset() -> None:
    with pytest.raises(ValueError, match=r"offset must be >= 0"):
        derive_component_id(
            source_image_hash="a" * 64,
            offset=-1,
            raw_hash="b" * 64,
        )


# ---------------------------------------------------------------------
# derive_error_component_id
# ---------------------------------------------------------------------


def test_error_component_id_is_deterministic() -> None:
    file_hash = "a" * 64
    offset = 0x40000
    error_kind = "FFS_HEADER_CRC"
    a = derive_error_component_id(source_image_hash=file_hash, offset=offset, error_kind=error_kind)
    b = derive_error_component_id(source_image_hash=file_hash, offset=offset, error_kind=error_kind)
    assert a == b


def test_error_component_id_differs_per_kind() -> None:
    a = derive_error_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        error_kind="FFS_HEADER_CRC",
    )
    b = derive_error_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        error_kind="DECOMPRESSION_FAILED",
    )
    assert a != b


def test_error_component_id_rejects_lowercase_kind() -> None:
    with pytest.raises(ValueError, match=r"error_kind must match"):
        derive_error_component_id(
            source_image_hash="a" * 64,
            offset=0,
            error_kind="lowercase_bad",
        )


def test_error_component_id_rejects_empty_kind() -> None:
    with pytest.raises(ValueError):
        derive_error_component_id(
            source_image_hash="a" * 64,
            offset=0,
            error_kind="",
        )


def test_error_component_id_disjoint_from_component_id() -> None:
    """A component-id and an error-id at the same offset must never collide.

    The disjoint payload prefixes (``raw_hash`` vs ``err:error_kind``)
    guarantee this; a regression here would silently corrupt baselines
    in downstream subsystems.
    """
    component = derive_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        raw_hash="b" * 64,
    )
    error = derive_error_component_id(
        source_image_hash="a" * 64,
        offset=0x100,
        error_kind="FFS_HEADER_CRC",
    )
    assert component != error


# ---------------------------------------------------------------------
# Hypothesis-backed properties
# ---------------------------------------------------------------------


@given(
    file_hash=_hash_strategy,
    offset=_offset_strategy,
    raw_hash=_hash_strategy,
)
def test_component_id_property_deterministic(file_hash: str, offset: int, raw_hash: str) -> None:
    """Property 19: same inputs always produce the same UUID."""
    a = derive_component_id(source_image_hash=file_hash, offset=offset, raw_hash=raw_hash)
    b = derive_component_id(source_image_hash=file_hash, offset=offset, raw_hash=raw_hash)
    assert a == b


@given(
    file_hash=_hash_strategy,
    offset=_offset_strategy,
    error_kind=_error_kind_strategy,
)
def test_error_id_property_deterministic(file_hash: str, offset: int, error_kind: str) -> None:
    """Property 20: same inputs always produce the same UUID."""
    a = derive_error_component_id(source_image_hash=file_hash, offset=offset, error_kind=error_kind)
    b = derive_error_component_id(source_image_hash=file_hash, offset=offset, error_kind=error_kind)
    assert a == b
