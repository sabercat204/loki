"""Smoke tests for the synthetic-component fixture.

Per task 10: builder produces Pydantic-validated
``ExtractedComponent`` instances; same inputs produce the same
``component_id`` sequence.
"""

from __future__ import annotations

import itertools
import uuid

from loki.models import ExtractedComponent
from tests.classification.fixtures import build_components


def test_default_shape_produces_four_components() -> None:
    components = build_components()
    assert len(components) == 4


def test_every_component_is_pydantic_validated_extracted_component(
    synthetic_components: list[ExtractedComponent],
) -> None:
    for component in synthetic_components:
        assert isinstance(component, ExtractedComponent)


def test_count_argument_controls_length() -> None:
    assert len(build_components(count=0)) == 0
    assert len(build_components(count=1)) == 1
    assert len(build_components(count=12)) == 12


def test_negative_count_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="count must be >= 0"):
        build_components(count=-1)


def test_same_inputs_produce_same_component_id_sequence() -> None:
    """Determinism: byte-identical sequence across runs."""
    a = build_components(count=8)
    b = build_components(count=8)
    a_ids = [c.component_id for c in a]
    b_ids = [c.component_id for c in b]
    assert a_ids == b_ids


def test_same_inputs_produce_same_full_payload() -> None:
    """Stronger determinism: same model_dump_json across runs."""
    a = build_components(count=8)
    b = build_components(count=8)
    assert [c.model_dump_json() for c in a] == [c.model_dump_json() for c in b]


def test_components_have_distinct_guids(
    synthetic_components: list[ExtractedComponent],
) -> None:
    guids = [c.guid for c in synthetic_components]
    assert len(set(guids)) == len(guids)


def test_components_have_distinct_component_ids(
    synthetic_components: list[ExtractedComponent],
) -> None:
    ids = [c.component_id for c in synthetic_components]
    assert len(set(ids)) == len(ids)


def test_components_have_increasing_offsets() -> None:
    components = build_components(count=8)
    offsets = [int(c.offset, 16) for c in components]
    assert offsets == sorted(offsets)


def test_components_have_arithmetic_progression_sizes() -> None:
    components = build_components(count=8)
    sizes = [c.size for c in components]
    deltas = {b - a for a, b in itertools.pairwise(sizes)}
    assert deltas == {256}  # arithmetic progression with step 256


def test_components_cycle_through_type_hints() -> None:
    """The 5-entry type-hint cycle should repeat at index 5."""
    components = build_components(count=10)
    assert components[0].component_type_hint == components[5].component_type_hint
    assert components[1].component_type_hint == components[6].component_type_hint


def test_include_inner_alternates_source_image_ids(
    synthetic_components_with_inner: list[ExtractedComponent],
) -> None:
    """When include_inner=True, even indices are outer, odd indices inner."""
    outer_id = synthetic_components_with_inner[0].source_image_id
    inner_id = synthetic_components_with_inner[1].source_image_id
    assert outer_id != inner_id
    assert synthetic_components_with_inner[2].source_image_id == outer_id
    assert synthetic_components_with_inner[3].source_image_id == inner_id


def test_explicit_source_image_id_is_used_for_outer_components() -> None:
    custom = uuid.uuid4()
    components = build_components(count=4, source_image_id=custom)
    for c in components:
        assert c.source_image_id == custom


def test_raw_hash_is_64_char_lowercase_hex(
    synthetic_components: list[ExtractedComponent],
) -> None:
    import re

    for c in synthetic_components:
        assert re.match(r"^[0-9a-f]{64}$", c.raw_hash) is not None
