"""Builds a coherent set of synthetic model instances for the demo workspace.

The intent is *honest scaffolding*: every instance is a real, validated
Pydantic model — running them through the actual validators ensures the
demo can't drift away from the model layer. The labels (``(demo)``)
applied in the UI come from callers, not from these instances.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from loki.models import (
    AxisClassification,
    BaselineComparison,
    BaselineRecord,
    BaselineRegistry,
    ClassificationMethod,
    ClassificationRecord,
    ComponentTypeLabel,
    DeltaType,
    DeviationRecord,
    FindingEvidence,
    FindingRecord,
    FirmwareImage,
    ImageAnalysisReport,
    MutabilityLabel,
    PostureRating,
    SecurityPostureLabel,
    SeverityLevel,
    SignatureInfo,
    VendorLabel,
)

__all__ = ["DemoWorkspace", "build_demo_workspace"]


@dataclass(frozen=True)
class DemoWorkspace:
    """Bundle of synthetic model instances for the demo workspace.

    All instances are valid Pydantic models — they pass every validator
    on construction. The view layer renders them read-only.
    """

    images: tuple[FirmwareImage, ...]
    baseline_registry: BaselineRegistry
    baseline_comparison: BaselineComparison
    image_report: ImageAnalysisReport


def _hex_hash(seed: str) -> str:
    """Return a deterministic 64-char lowercase hex string for ``seed``.

    Built from a UUID5 of the seed plus a fixed suffix so we get a
    stable 64-char value without re-deriving SHA-256 at import time.
    """

    h = uuid.uuid5(uuid.NAMESPACE_OID, f"loki-demo:{seed}").hex
    return (h + h)[:64]


def _build_classification(
    *,
    component_id: uuid.UUID,
    source_image_id: uuid.UUID,
    offset: str,
    timestamp: datetime,
    type_label: ComponentTypeLabel,
    vendor_label: VendorLabel,
    security_label: SecurityPostureLabel,
    mutability_label: MutabilityLabel,
    confidence: float,
    classification_version: str,
    signature_present: bool = True,
    signature_verified: bool = True,
    cve_matches: list[str] | None = None,
) -> ClassificationRecord:
    """Build a synthetic ClassificationRecord with consistent confidences.

    All four axes get the same ``confidence`` so the auto-computed
    composite is exactly that value — easier to reason about in the UI.
    """

    method = ClassificationMethod.RULE
    return ClassificationRecord(
        component_id=component_id,
        source_image_id=source_image_id,
        extraction_offset=offset,
        timestamp=timestamp,
        type_axis=AxisClassification(label=type_label, confidence=confidence, method=method),
        vendor_axis=AxisClassification(label=vendor_label, confidence=confidence, method=method),
        security_axis=AxisClassification(
            label=security_label, confidence=confidence, method=method
        ),
        mutability_axis=AxisClassification(
            label=mutability_label, confidence=confidence, method=method
        ),
        signature_info=SignatureInfo(
            present=signature_present,
            verified=signature_verified,
            signer="DEMO-CA" if signature_present else None,
        ),
        cve_matches=cve_matches or [],
        suspicion_triggers=[],
        classification_version=classification_version,
    )


def build_demo_workspace(*, now: datetime | None = None) -> DemoWorkspace:
    """Construct a full synthetic workspace.

    Returns:
        A :class:`DemoWorkspace` containing 2 firmware images, 1 baseline
        registry with a 5-component manifest, 1 baseline comparison
        showing 1 ADDED + 1 MODIFIED + 1 UNCHANGED, and 1 image
        analysis report with 3 findings spanning multiple severities.
    """

    timestamp = now or datetime.now(tz=UTC)
    classification_version = "demo-classifier-0.1"

    image_a = FirmwareImage(
        file_path="/firmware/demo/laptop-bios-1.42.rom",
        file_hash=_hex_hash("image-a"),
        file_size=8 * 1024 * 1024,
        vendor=VendorLabel.INTEL.value,
        model="DEMO-X1-G11",
        firmware_version="1.42",
        extraction_timestamp=timestamp,
    )
    image_b = FirmwareImage(
        file_path="/firmware/demo/laptop-bios-1.43.rom",
        file_hash=_hex_hash("image-b"),
        file_size=9 * 1024 * 1024,
        vendor=VendorLabel.INTEL.value,
        model="DEMO-X1-G11",
        firmware_version="1.43",
        extraction_timestamp=timestamp,
    )

    # image_id is auto-generated from file_hash via uuid5 — these are real UUIDs.
    assert image_a.image_id is not None
    assert image_b.image_id is not None

    # Five classification records spanning the four axes — one of each
    # type label, varied posture and mutability so the views have
    # something to show.
    component_specs = [
        (
            ComponentTypeLabel.DXE_DRIVER,
            VendorLabel.INTEL,
            SecurityPostureLabel.SECURE,
            MutabilityLabel.READONLY,
            0.92,
            "0x40000",
        ),
        (
            ComponentTypeLabel.PEI_MODULE,
            VendorLabel.INTEL,
            SecurityPostureLabel.SECURE,
            MutabilityLabel.READONLY,
            0.88,
            "0x80000",
        ),
        (
            ComponentTypeLabel.SMM_MODULE,
            VendorLabel.INTEL,
            SecurityPostureLabel.VULNERABLE,
            MutabilityLabel.MUTABLE,
            0.71,
            "0xC0000",
        ),
        (
            ComponentTypeLabel.OPTION_ROM,
            VendorLabel.UNKNOWN,
            SecurityPostureLabel.UNKNOWN,
            MutabilityLabel.MUTABLE,
            0.55,
            "0x100000",
        ),
        (
            ComponentTypeLabel.MICROCODE,
            VendorLabel.INTEL,
            SecurityPostureLabel.SECURE,
            MutabilityLabel.READONLY,
            0.95,
            "0x140000",
        ),
    ]
    baseline_components: list[ClassificationRecord] = []
    for type_label, vendor_label, security_label, mutability_label, conf, offset in component_specs:
        baseline_components.append(
            _build_classification(
                component_id=uuid.uuid4(),
                source_image_id=image_a.image_id,
                offset=offset,
                timestamp=timestamp,
                type_label=type_label,
                vendor_label=vendor_label,
                security_label=security_label,
                mutability_label=mutability_label,
                confidence=conf,
                classification_version=classification_version,
            )
        )

    baseline = BaselineRecord(
        baseline_id=uuid.uuid4(),
        name="DEMO-X1-G11 v1.42 reference",
        vendor=VendorLabel.INTEL.value,
        model="DEMO-X1-G11",
        firmware_version="1.42",
        created_timestamp=timestamp,
        notes="Synthetic baseline for GUI demo. Do not use for real analysis.",
        component_manifest=baseline_components,
        source_image_hash=image_a.file_hash,
        baseline_version="1.0.0",
    )
    registry = BaselineRegistry(baselines=[baseline])

    # One ADDED, one MODIFIED, one UNCHANGED — same coverage as the spec
    # asks for, all wired through a real BaselineComparison so the
    # auto-summary is correct.
    added_component_id = uuid.uuid4()
    modified_component = baseline_components[2]  # SMM module
    unchanged_component = baseline_components[0]  # DXE driver
    target_added = _build_classification(
        component_id=added_component_id,
        source_image_id=image_b.image_id,
        offset="0x180000",
        timestamp=timestamp,
        type_label=ComponentTypeLabel.UEFI_DRIVER,
        vendor_label=VendorLabel.UNKNOWN,
        security_label=SecurityPostureLabel.UNKNOWN,
        mutability_label=MutabilityLabel.MUTABLE,
        confidence=0.48,
        classification_version=classification_version,
        signature_present=False,
        signature_verified=False,
    )
    target_modified = _build_classification(
        component_id=modified_component.component_id,
        source_image_id=image_b.image_id,
        offset=modified_component.extraction_offset,
        timestamp=timestamp,
        type_label=ComponentTypeLabel.SMM_MODULE,
        vendor_label=VendorLabel.INTEL,
        security_label=SecurityPostureLabel.VULNERABLE,
        mutability_label=MutabilityLabel.MUTABLE,
        confidence=0.62,
        classification_version=classification_version,
        cve_matches=["CVE-2024-DEMO-0001"],
    )
    deviations = [
        DeviationRecord(
            deviation_id=uuid.uuid4(),
            component_id=added_component_id,
            delta_type=DeltaType.ADDED,
            target_state=target_added,
            description="New unsigned UEFI driver appeared at 0x180000.",
        ),
        DeviationRecord(
            deviation_id=uuid.uuid4(),
            component_id=modified_component.component_id,
            delta_type=DeltaType.MODIFIED,
            baseline_state=modified_component,
            target_state=target_modified,
            description="SMM module gained CVE-2024-DEMO-0001 match.",
        ),
        DeviationRecord(
            deviation_id=uuid.uuid4(),
            component_id=unchanged_component.component_id,
            delta_type=DeltaType.UNCHANGED,
            baseline_state=unchanged_component,
            target_state=unchanged_component,
            description="DXE driver unchanged from baseline.",
        ),
    ]
    comparison = BaselineComparison(
        baseline_id=baseline.baseline_id,
        target_image_id=image_b.image_id,
        comparison_timestamp=timestamp,
        deviations=deviations,
    )

    findings = [
        FindingRecord(
            finding_id=uuid.uuid4(),
            component_id=added_component_id,
            severity=SeverityLevel.HIGH,
            category="UNSIGNED_DRIVER",
            title="Unsigned UEFI driver appeared",
            description="A previously absent UEFI driver has been added with no signature.",
            evidence=FindingEvidence(
                classification_record=target_added,
                matched_rule="DEMO-RULE-001",
                raw_indicators=["unsigned-binary", "post-baseline-addition"],
            ),
            recommended_action="Investigate provenance; consider blocking until signed.",
        ),
        FindingRecord(
            finding_id=uuid.uuid4(),
            component_id=modified_component.component_id,
            severity=SeverityLevel.CRITICAL,
            category="CVE_INTRODUCED",
            title="SMM module now matches CVE-2024-DEMO-0001",
            description="A modified SMM module now matches a known SMM privilege-escalation CVE.",
            evidence=FindingEvidence(
                classification_record=target_modified,
                matched_cve="CVE-2024-DEMO-0001",
                raw_indicators=["smm-priv-esc", "cve-match"],
            ),
            recommended_action="Roll back to baseline firmware; coordinate with vendor.",
        ),
        FindingRecord(
            finding_id=uuid.uuid4(),
            component_id=baseline_components[3].component_id,
            severity=SeverityLevel.LOW,
            category="LOW_CONFIDENCE",
            title="Option ROM classification below review threshold",
            description="Option ROM classification confidence is 0.55, below the 0.60 review threshold.",
            evidence=FindingEvidence(
                classification_record=baseline_components[3],
                matched_rule="DEMO-RULE-LOW-CONF",
                raw_indicators=["needs-review"],
            ),
            recommended_action="Have an analyst review the classification.",
        ),
    ]

    report = ImageAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=timestamp,
        analysis_version="demo-analyzer-0.1",
        image_id=image_b.image_id,
        image_metadata=image_b,
        posture_rating=PostureRating.AT_RISK,
        findings=findings,
        baseline_comparison=comparison,
    )

    return DemoWorkspace(
        images=(image_a, image_b),
        baseline_registry=registry,
        baseline_comparison=comparison,
        image_report=report,
    )
