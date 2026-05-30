"""Tests for filename slugification + collision handling (task 4)."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.baseline.naming import filename_for, slug, unique_filename_for
from loki.models import BaselineRecord

_FILENAME_RE = re.compile(r"^[a-z0-9._-]+\.yaml$")


def _baseline(
    *,
    vendor: str = "INTEL",
    model: str = "X1G11",
    firmware_version: str = "1.0",
    baseline_id: uuid.UUID | None = None,
) -> BaselineRecord:
    return BaselineRecord(
        baseline_id=baseline_id or uuid.uuid4(),
        name="test",
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
        created_timestamp=datetime.now(tz=UTC),
        component_manifest=[],
        source_image_hash="a" * 64,
        baseline_version="1.0.0",
    )


# ---------------------------------------------------------------------
# slug()
# ---------------------------------------------------------------------


def test_slug_lowercases() -> None:
    assert slug("INTEL") == "intel"


def test_slug_replaces_invalid_with_underscore() -> None:
    assert slug("X1 G11") == "x1_g11"
    assert slug("X1/G11") == "x1_g11"
    assert slug("a@b#c") == "a_b_c"


def test_slug_collapses_runs() -> None:
    assert slug("a   b") == "a_b"
    assert slug("a___b") == "a_b"
    assert slug("a   ___   b") == "a_b"


def test_slug_strips_leading_trailing_underscores() -> None:
    assert slug("/etc/passwd") == "etc_passwd"
    assert slug("___X___") == "x"


def test_slug_preserves_dots_dashes_digits() -> None:
    """v1.42-rc.1 should stay readable."""
    assert slug("v1.42-rc.1") == "v1.42-rc.1"


def test_slug_is_idempotent() -> None:
    """Property 28: slug(slug(value)) == slug(value)."""
    for value in ("INTEL", "X1 G11", "v1.42-rc.1", "a   b", "/etc/passwd"):
        assert slug(slug(value)) == slug(value)


@given(st.text(min_size=1, max_size=64))
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_slug_idempotent_property(value: str) -> None:
    """Property 28 (Hypothesis): slug is idempotent for any string."""
    assert slug(slug(value)) == slug(value)


@given(st.text(min_size=1, max_size=64))
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_slug_output_charset(value: str) -> None:
    """Slug output (when non-empty) only contains ``[a-z0-9._-]``."""
    result = slug(value)
    if result:
        assert re.match(r"^[a-z0-9._-]+$", result), f"bad slug for {value!r}: {result!r}"


# ---------------------------------------------------------------------
# filename_for()
# ---------------------------------------------------------------------


def test_filename_for_canonical_form() -> None:
    record = _baseline(vendor="INTEL", model="X1G11", firmware_version="1.42")
    assert filename_for(record) == "intel-x1g11-1.42.yaml"


def test_filename_for_handles_spaces_in_fields() -> None:
    record = _baseline(vendor="Acme Corp", model="Model 3", firmware_version="v 1.0")
    assert filename_for(record) == "acme_corp-model_3-v_1.0.yaml"


def test_filename_for_matches_yaml_pattern() -> None:
    record = _baseline()
    assert _FILENAME_RE.match(filename_for(record))


# ---------------------------------------------------------------------
# unique_filename_for()
# ---------------------------------------------------------------------


def test_unique_filename_returns_canonical_when_unused() -> None:
    record = _baseline()
    assert unique_filename_for(record, taken=set()) == filename_for(record)


def test_unique_filename_appends_baseline_id_suffix_on_collision() -> None:
    """Property 29: collisions get a -{8 hex} suffix to disambiguate."""
    bid = uuid.UUID("11112222-3333-4444-5555-666677778888")
    record = _baseline(baseline_id=bid)
    canonical = filename_for(record)
    other = unique_filename_for(record, taken={canonical})
    assert other != canonical
    assert other.startswith(canonical.removesuffix(".yaml") + "-")
    assert other.endswith(".yaml")
    assert "11112222" in other  # first 8 hex chars of baseline_id


def test_unique_filename_output_matches_yaml_pattern() -> None:
    record = _baseline()
    canonical = filename_for(record)
    disambiguated = unique_filename_for(record, taken={canonical})
    assert _FILENAME_RE.match(disambiguated)


def test_unique_filename_returns_distinct_outputs_for_different_records() -> None:
    """Property 29: two records with distinct baseline_ids never collide."""
    a = _baseline(baseline_id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000000"))
    b = _baseline(baseline_id=uuid.UUID("bbbbbbbb-0000-0000-0000-000000000000"))
    canonical = filename_for(a)
    assert canonical == filename_for(b)  # both records share the canonical name
    name_a = unique_filename_for(a, taken={canonical})
    name_b = unique_filename_for(b, taken={canonical, name_a})
    assert name_a != name_b
