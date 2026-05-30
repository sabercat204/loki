"""Shared fixture builders for the analysis-engine test tree.

Underscore-prefixed module so pytest does not collect it as a test
module. The helpers live here rather than in ``conftest.py`` so they
are explicit imports in each test file (clearer than fixture
auto-injection for these short, deterministic builders).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Final

from loki.models import (
    AxisClassification,
    BaselineRecord,
    ClassificationMethod,
    ClassificationRecord,
    ComponentTypeLabel,
    FirmwareImage,
    MutabilityLabel,
    SecurityPostureLabel,
    SignatureInfo,
    VendorLabel,
)

# Default canonical severity_weights honoring R14.1's keyset.
VALID_WEIGHTS: Final[dict[str, float]] = {
    "type": 0.4,
    "vendor": 0.2,
    "security_posture": 0.3,
    "mutability": 0.1,
}


def make_axis(label: str, *, confidence: float = 1.0) -> AxisClassification:
    return AxisClassification(
        label=label,
        confidence=confidence,
        method=ClassificationMethod.RULE,
    )


def make_record(
    *,
    component_id: uuid.UUID | None = None,
    type_label: str = ComponentTypeLabel.UEFI_DRIVER,
    vendor_label: str = VendorLabel.INTEL,
    security_label: str = SecurityPostureLabel.SECURE,
    mutability_label: str = MutabilityLabel.READONLY,
    confidence: float = 1.0,
    composite_confidence_override: float | None = None,
    signature_info: SignatureInfo | None = None,
) -> ClassificationRecord:
    """Build a ClassificationRecord with all four axes populated.

    ``composite_confidence_override`` provides a way to set a value
    below the model's auto-computed minimum for tests that need to
    exercise classification_gap logic (the model layer's
    @model_validator overwrites composite_confidence on construction
    via the min() of axis confidences; pass a confidence below the
    chosen threshold to drive the override naturally).
    """
    record = ClassificationRecord(
        component_id=component_id or uuid.uuid4(),
        source_image_id=uuid.uuid4(),
        extraction_offset="0x00",
        timestamp=datetime.now(UTC),
        type_axis=make_axis(type_label, confidence=confidence),
        vendor_axis=make_axis(vendor_label, confidence=confidence),
        security_axis=make_axis(security_label, confidence=confidence),
        mutability_axis=make_axis(mutability_label, confidence=confidence),
        signature_info=signature_info,
        classification_version="1.0.0",
    )
    if composite_confidence_override is not None:
        # Bypass the auto-computed value by setting the field after
        # construction; the model is not frozen so this works.
        record.composite_confidence = composite_confidence_override
    return record


def make_baseline_record(
    *,
    baseline_id: uuid.UUID | None = None,
    vendor: str = "Intel",
    model: str = "X1",
    firmware_version: str = "1.0.0",
    component_manifest: list[ClassificationRecord] | None = None,
) -> BaselineRecord:
    return BaselineRecord(
        baseline_id=baseline_id or uuid.uuid4(),
        name="test-baseline",
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
        created_timestamp=datetime.now(UTC),
        component_manifest=component_manifest
        if component_manifest is not None
        else [make_record()],
        source_image_hash="0" * 64,
        baseline_version="1.0.0",
    )


def make_image(
    *,
    vendor: str = "Intel",
    model: str = "X1",
    firmware_version: str = "1.0.0",
) -> FirmwareImage:
    return FirmwareImage(
        file_path="/tmp/test.bin",
        file_hash="0" * 64,
        file_size=1024,
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
    )


def make_signature_info(*, present: bool, verified: bool = False) -> SignatureInfo:
    return SignatureInfo(present=present, verified=verified)
