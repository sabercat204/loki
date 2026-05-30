"""Builder for deterministic synthetic ``BaselineRecord`` instances.

Used by the determinism + golden-file tests. Every UUID is derived
from ``uuid.uuid5`` so two calls with the same arguments produce
byte-identical records.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from loki.models import (
    AxisClassification,
    BaselineRecord,
    ClassificationMethod,
    ClassificationRecord,
    ComponentTypeLabel,
    MutabilityLabel,
    SecurityPostureLabel,
    SignatureInfo,
    VendorLabel,
)

__all__ = ["DEFAULT_TIMESTAMP", "build", "build_classification"]


#: Stable timestamp used for every fixture record so tests don't
#: depend on the wall clock.
DEFAULT_TIMESTAMP: datetime = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

_NS_BASELINE = uuid.UUID("11111111-2222-3333-4444-555566667777")
_NS_CLASSIFICATION = uuid.UUID("11111111-2222-3333-4444-555566667778")
_NS_COMPONENT = uuid.UUID("11111111-2222-3333-4444-555566667779")
_NS_IMAGE = uuid.UUID("11111111-2222-3333-4444-55556666777a")


def _seeded_uuid(namespace: uuid.UUID, *parts: object) -> uuid.UUID:
    """Return a deterministic ``uuid5`` from ``parts`` joined by ``:``."""
    name = ":".join(str(p) for p in parts)
    return uuid.uuid5(namespace, name)


def _seeded_hash(seed: str) -> str:
    """Return a 64-char lowercase hex string derived from ``seed``.

    The model layer's ``BaselineRecord.source_image_hash`` validator
    rejects anything that isn't 64 lowercase hex chars; this helper
    builds one from a UUID5 seed.
    """
    base = uuid.uuid5(_NS_IMAGE, seed).hex
    return (base + base)[:64]


def build_classification(
    *,
    seed: str,
    source_image_hash: str,
) -> ClassificationRecord:
    """Build one deterministic ``ClassificationRecord`` from ``seed``."""

    component_id = _seeded_uuid(_NS_COMPONENT, seed)
    source_image_id = _seeded_uuid(_NS_IMAGE, source_image_hash)
    method = ClassificationMethod.RULE
    confidence = 0.85

    return ClassificationRecord(
        component_id=component_id,
        source_image_id=source_image_id,
        extraction_offset="0x40000",
        timestamp=DEFAULT_TIMESTAMP,
        type_axis=AxisClassification(
            label=ComponentTypeLabel.DXE_DRIVER,
            confidence=confidence,
            method=method,
        ),
        vendor_axis=AxisClassification(
            label=VendorLabel.INTEL,
            confidence=confidence,
            method=method,
        ),
        security_axis=AxisClassification(
            label=SecurityPostureLabel.SECURE,
            confidence=confidence,
            method=method,
        ),
        mutability_axis=AxisClassification(
            label=MutabilityLabel.READONLY,
            confidence=confidence,
            method=method,
        ),
        signature_info=SignatureInfo(present=True, verified=True, signer="DEMO-CA"),
        cve_matches=[],
        suspicion_triggers=[],
        classification_version="demo-classifier-0.1",
    )


def build(
    *,
    vendor: str = "INTEL",
    model: str = "DEMO-X1",
    firmware_version: str = "1.0",
    classification_count: int = 3,
    notes: str | None = None,
) -> BaselineRecord:
    """Return a deterministic :class:`BaselineRecord` for tests.

    Args:
        vendor: Free-form vendor name. Slugged into the eventual
            Baseline_Filename via :func:`loki.baseline.naming.slug`.
        model: Free-form model name.
        firmware_version: Free-form version string.
        classification_count: Number of synthetic
            :class:`ClassificationRecord` entries inside the
            ``component_manifest``.
        notes: Optional ``BaselineRecord.notes`` string.

    Returns:
        A Pydantic-validated :class:`BaselineRecord` whose UUIDs are
        deterministic across calls with the same arguments.
    """

    if classification_count < 0:
        raise ValueError(f"classification_count must be >= 0, got {classification_count}")

    seed_root = f"{vendor}|{model}|{firmware_version}"
    baseline_id = _seeded_uuid(_NS_BASELINE, seed_root)
    source_image_hash = _seeded_hash(seed_root)

    component_manifest = [
        build_classification(
            seed=f"{seed_root}|{i}",
            source_image_hash=source_image_hash,
        )
        for i in range(classification_count)
    ]

    return BaselineRecord(
        baseline_id=baseline_id,
        name=f"{vendor} {model} {firmware_version}",
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
        created_timestamp=DEFAULT_TIMESTAMP,
        notes=notes,
        component_manifest=component_manifest,
        source_image_hash=source_image_hash,
        baseline_version="1.0.0",
    )
