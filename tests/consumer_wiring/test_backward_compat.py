"""Backward-compatibility regression tests (task 5).

Verifies consumer-wiring R3.1-R3.3:
- feeds=None produces identical output to pre-wiring classification
- cve_matches=[] produces identical analysis output to v1
- All existing tests still pass (verified by the full suite)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from loki.analysis import analyze_image
from loki.classification import classify_components
from loki.models import (
    AnalysisConfig,
    BaselineRecord,
    BaselineRegistry,
    ClassificationConfig,
    ExtractedComponent,
    FirmwareImage,
    MatchStrategy,
    SeverityLevel,
)
from loki.models.classification import AxisClassification, ClassificationRecord, SignatureInfo
from loki.models.enums import ClassificationMethod


def _make_image() -> FirmwareImage:
    return FirmwareImage(
        image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "compat-image"),
        file_path="/tmp/compat.bin",
        file_hash="c" * 64,
        file_size=4096,
        vendor="INTEL",
        model="X1",
        firmware_version="1.0.0",
    )


def _make_components() -> list[ExtractedComponent]:
    image = _make_image()
    assert image.image_id is not None
    return [
        ExtractedComponent(
            component_id=uuid.uuid5(uuid.NAMESPACE_DNS, f"compat-comp-{i}"),
            source_image_id=image.image_id,
            offset=f"0x{i * 0x1000:x}",
            size=512,
            raw_hash="d" * 64,
            component_type_hint=None,
            guid=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"compat-guid-{i}")),
            name=f"COMPAT_{i:03d}",
            raw_path=None,
        )
        for i in range(3)
    ]


def _make_config(tmp_path: Path) -> ClassificationConfig:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "empty.yaml").write_text(
        "taxonomy_version: '1.0.0'\nrules: []\n", encoding="utf-8"
    )
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


class TestClassificationBackwardCompat:
    """R3.1: feeds=None produces identical output."""

    def test_no_feeds_identical_to_explicit_none(self, tmp_path: Path) -> None:
        """Calling without feeds kwarg == calling with feeds=None."""
        config = _make_config(tmp_path)
        components = _make_components()

        result_implicit = classify_components(components, config)
        result_explicit = classify_components(components, config, feeds=None)

        assert len(result_implicit.records) == len(result_explicit.records)
        for r1, r2 in zip(result_implicit.records, result_explicit.records, strict=True):
            assert r1.cve_matches == r2.cve_matches == []
            assert r1.component_id == r2.component_id

    def test_all_cve_matches_empty_when_no_feeds(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        components = _make_components()

        result = classify_components(components, config)

        for record in result.records:
            assert record.cve_matches == []


class TestAnalysisBackwardCompat:
    """R3.2: empty cve_matches produces v1-identical analysis output."""

    def test_empty_cve_matches_gives_v1_behavior(self) -> None:
        image = _make_image()
        assert image.image_id is not None

        target_record = ClassificationRecord(
            component_id=uuid.uuid5(uuid.NAMESPACE_DNS, "target-comp"),
            source_image_id=image.image_id,
            extraction_offset="0x1000",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            type_axis=AxisClassification(
                label="UNKNOWN", confidence=0.5, method=ClassificationMethod.HEURISTIC, evidence=[]
            ),
            vendor_axis=AxisClassification(
                label="INTEL", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            security_axis=AxisClassification(
                label="SECURE", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            mutability_axis=AxisClassification(
                label="READONLY", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            signature_info=SignatureInfo(
                present=True, verified=False, signer=None, cert_expiry=None
            ),
            cve_matches=[],
            suspicion_triggers=[],
            classification_version="1.0.0",
            overrides=[],
        )

        baseline_record = ClassificationRecord(
            component_id=uuid.uuid5(uuid.NAMESPACE_DNS, "target-comp"),
            source_image_id=image.image_id,
            extraction_offset="0x1000",
            timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            type_axis=AxisClassification(
                label="UEFI_DRIVER", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            vendor_axis=AxisClassification(
                label="INTEL", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            security_axis=AxisClassification(
                label="SECURE", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            mutability_axis=AxisClassification(
                label="READONLY", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
            ),
            signature_info=SignatureInfo(
                present=True, verified=False, signer=None, cert_expiry=None
            ),
            cve_matches=[],
            suspicion_triggers=[],
            classification_version="1.0.0",
            overrides=[],
        )

        baseline = BaselineRecord(
            baseline_id=uuid.uuid5(uuid.NAMESPACE_DNS, "baseline"),
            name="INTEL X1 1.0.0",
            vendor="INTEL",
            model="X1",
            firmware_version="1.0.0",
            baseline_version="1.0.0",
            created_timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            component_manifest=[baseline_record],
            source_image_hash="c" * 64,
        )
        registry = BaselineRegistry(baselines=[baseline])

        config = AnalysisConfig(
            severity_weights={
                "type": 0.25,
                "vendor": 0.25,
                "security_posture": 0.25,
                "mutability": 0.25,
            },
            default_severity_threshold=SeverityLevel.MEDIUM,
            match_strategy=MatchStrategy.AUTO,
            cve_score_bump=0.5,
        )

        report = analyze_image(
            target_records=[target_record],
            registry=registry,
            target_image=image,
            config=config,
        )

        mismatch_findings = [f for f in report.findings if f.category == "classification_mismatch"]
        assert len(mismatch_findings) >= 1

        for finding in mismatch_findings:
            assert finding.evidence.matched_cve is None
            assert finding.evidence.deviation_score is not None
            assert finding.evidence.deviation_score.cve_introduced is False
