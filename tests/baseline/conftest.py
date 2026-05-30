"""Per-package conftest for baseline-persistence tests.

Provides shared fixtures that point at the synthetic-baseline
builder under ``tests/baseline/fixtures/``. Per-test ``tmp_path``
isolation keeps individual tests from stepping on each other's
filesystem state.

Hypothesis strategies for property-based tests live here too. They
compose against the ``baseline_record()`` strategy from
``tests/conftest.py`` but expose a knob for the classification
count so determinism tests can vary the manifest depth (R9.2-R9.4).
"""

from __future__ import annotations

import pytest
from hypothesis import strategies as st

from loki.models import BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


@pytest.fixture()
def synthetic_baseline_record() -> BaselineRecord:
    """A default-shape :class:`BaselineRecord` for round-trip tests."""
    return synthetic_baseline.build()


# ---------------------------------------------------------------------
# Hypothesis strategies (task 14)
# ---------------------------------------------------------------------


@st.composite
def parameterized_baseline_record(
    draw: st.DrawFn,
    *,
    min_classifications: int = 0,
    max_classifications: int = 4,
) -> BaselineRecord:
    """Build a deterministic :class:`BaselineRecord` via the synthetic builder.

    Wraps :func:`tests.baseline.fixtures.synthetic_baseline.build` with
    randomized vendor/model/firmware_version triples and a
    randomized classification count. The resulting record is
    Pydantic-validated at construction time, mirroring the
    extraction-pipeline PBT pattern.

    Why not reach straight for ``baseline_record()`` from
    ``tests/conftest.py``? That strategy generates arbitrary text
    (including ``" "``, ``"."``, slashes), which is a fine torture
    test for the model layer's validators but trips two
    persistence-specific edge cases:

    - The ``slug()`` step in :func:`loki.baseline.naming.filename_for`
      collapses many distinct triples to the same canonical
      filename, which masks Property 24 (round-trip) under
      Property 29 (collision resolution). Determinism PBT is
      stronger when the filename is unambiguous.
    - The synthetic builder's :func:`uuid.uuid5` derivations make
      every record byte-deterministic across re-builds, which is
      what Property 25 requires anyway.
    """

    vendor = draw(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            min_size=1,
            max_size=12,
        )
    )
    model = draw(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
            min_size=1,
            max_size=16,
        )
    )
    firmware_version = draw(
        st.text(
            alphabet="0123456789.-",
            min_size=1,
            max_size=12,
        ).filter(lambda s: not s.startswith("-") and not s.endswith("-"))
    )
    classification_count = draw(
        st.integers(min_value=min_classifications, max_value=max_classifications)
    )

    return synthetic_baseline.build(
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
        classification_count=classification_count,
    )
