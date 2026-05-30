"""Deterministic ``ExtractedComponent`` fixture builder.

Used by every classification subsystem test that needs realistic
component inputs. Mirrors the synthetic-baseline / synthetic-binary
patterns from the other subsystems' fixture modules: every UUID
is derived via ``uuid.uuid5`` from a stable string seed so the
resulting sequence is byte-identical across runs and across
hosts.
"""

from __future__ import annotations

import uuid

from loki.models import LOKI_NAMESPACE, ExtractedComponent

__all__ = ["build_components"]

# A stable namespace UUID for the synthetic fixture's
# component-id / source-image-id derivations. Distinct from
# LOKI_NAMESPACE so synthetic test components can never collide
# with real-world component IDs.
_FIXTURE_NAMESPACE = uuid.uuid5(LOKI_NAMESPACE, "tests.classification.fixtures")

# Cycle of synthetic component_type_hint values. Five entries
# means the same hint repeats every five components, which gives
# rule-loader tests something to match against without hard-coding
# component count.
_TYPE_HINT_CYCLE: tuple[str, ...] = (
    "uefi_pe32",
    "uefi_raw",
    "dxe_driver",
    "pei_module",
    "pci_legacy_x86",
)


def _seed_uuid(label: str, index: int) -> uuid.UUID:
    """Derive a deterministic UUID for a synthetic component."""
    return uuid.uuid5(_FIXTURE_NAMESPACE, f"{label}-{index:04d}")


def _seed_hash(label: str, index: int) -> str:
    """Derive a deterministic 64-char lowercase hex string.

    Uses ``uuid5`` repeatedly to fill the 64 hex chars without
    pulling in ``random`` (the side-channels audit forbids it).
    """
    seeds: list[str] = []
    for chunk in range(2):  # 32 hex chars per UUID, x2 = 64
        seeds.append(uuid.uuid5(_FIXTURE_NAMESPACE, f"{label}-{index:04d}-{chunk}").hex)
    return "".join(seeds)[:64]


def build_components(
    *,
    count: int = 4,
    source_image_id: uuid.UUID | None = None,
    include_inner: bool = False,
) -> list[ExtractedComponent]:
    """Build a deterministic list of ``ExtractedComponent`` instances.

    Args:
        count: Number of components to produce. Must be ``>= 0``.
        source_image_id: ``source_image_id`` for the outer
            components. When ``None``, a deterministic synthetic
            id is used. When ``include_inner=True``, half the
            components carry a *different* synthetic
            ``source_image_id`` derived from a fake
            ``decompressed_hash`` to simulate inner-component
            emission per Requirement 7.3.
        include_inner: When ``True``, alternates outer and inner
            components in the resulting sequence (component 0 is
            outer, 1 is inner, 2 is outer, ...). When ``False``,
            every component is outer.

    Returns:
        A list of ``count`` validated ``ExtractedComponent``
        instances. Same arguments produce a byte-identical list
        across runs and hosts.

    Raises:
        ValueError: ``count < 0``.
    """
    if count < 0:
        raise ValueError(f"count must be >= 0, got {count}")

    outer_image_id: uuid.UUID = (
        source_image_id if source_image_id is not None else _seed_uuid("source-image-outer", 0)
    )
    # The "inner" image id mirrors the extraction pipeline's
    # uuid5(LOKI_NAMESPACE, decompressed_hash) derivation, but
    # uses a synthetic fake "decompressed_hash" for tests. The
    # actual hash bytes don't matter; what matters is that inner
    # and outer ids are reliably distinct.
    inner_image_id: uuid.UUID = uuid.uuid5(LOKI_NAMESPACE, _seed_hash("decompressed-payload", 0))

    components: list[ExtractedComponent] = []
    for i in range(count):
        is_inner = include_inner and (i % 2 == 1)
        components.append(
            ExtractedComponent(
                component_id=_seed_uuid("component", i),
                source_image_id=inner_image_id if is_inner else outer_image_id,
                offset=f"0x{(i * 0x1000):x}",
                size=1024 + (i * 256),
                raw_hash=_seed_hash("raw_hash", i),
                component_type_hint=_TYPE_HINT_CYCLE[i % len(_TYPE_HINT_CYCLE)],
                guid=str(uuid.uuid5(_FIXTURE_NAMESPACE, f"comp-guid-{i}")),
                name=f"COMP_{i:03d}",
                raw_path=None,
            )
        )
    return components
