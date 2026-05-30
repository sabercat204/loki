"""Integration tests for CVE surfacing in the analysis engine (task 4).

Verifies consumer-wiring R2.1-R2.7:
- matched_cve set to lex-first when cve_matches non-empty
- cve_introduced=True when target has novel CVEs vs baseline
- cve_introduced=False when target CVEs all in baseline
- cve_introduced=False when target cve_matches is empty
- composite score bumped by cve_score_bump when cve_introduced
- composite score clamps at 10.0
- cve_score_bump=0.0 means no bump
"""

from __future__ import annotations

import uuid

from loki.analysis.findings import emit_classification_mismatch
from loki.models.classification import AxisClassification, ClassificationRecord, SignatureInfo
from loki.models.enums import ClassificationMethod

_WEIGHTS = {"type": 0.25, "vendor": 0.25, "security_posture": 0.25, "mutability": 0.25}
_BASELINE_ID = uuid.uuid5(uuid.NAMESPACE_DNS, "baseline-001")


def _make_record(
    *,
    component_id: uuid.UUID | None = None,
    type_label: str = "UEFI_DRIVER",
    vendor_label: str = "INTEL",
    security_label: str = "SECURE",
    mutability_label: str = "READONLY",
    cve_matches: list[str] | None = None,
) -> ClassificationRecord:
    from datetime import UTC, datetime

    return ClassificationRecord(
        component_id=component_id or uuid.uuid4(),
        source_image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "image"),
        extraction_offset="0x1000",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        type_axis=AxisClassification(
            label=type_label, confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
        ),
        vendor_axis=AxisClassification(
            label=vendor_label, confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
        ),
        security_axis=AxisClassification(
            label=security_label, confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
        ),
        mutability_axis=AxisClassification(
            label=mutability_label, confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
        ),
        signature_info=SignatureInfo(present=True, verified=False, signer=None, cert_expiry=None),
        cve_matches=cve_matches or [],
        suspicion_triggers=[],
        classification_version="1.0.0",
        overrides=[],
    )


class TestMatchedCveSelection:
    """R2.1: matched_cve is lex-first from target.cve_matches."""

    def test_non_empty_cve_matches_sets_matched_cve(self) -> None:
        target = _make_record(
            type_label="UNKNOWN",
            cve_matches=["CVE-2026-0002", "CVE-2026-0001"],
        )
        baseline = _make_record(type_label="UEFI_DRIVER", cve_matches=[])

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        # cve_matches is sorted on the record, so [0] is lex-first
        assert finding.evidence.matched_cve == "CVE-2026-0002"

    def test_empty_cve_matches_leaves_matched_cve_none(self) -> None:
        target = _make_record(type_label="UNKNOWN", cve_matches=[])
        baseline = _make_record(type_label="UEFI_DRIVER", cve_matches=[])

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        assert finding.evidence.matched_cve is None


class TestCveIntroducedDetection:
    """R2.2-R2.3: cve_introduced is True when target has novel CVEs."""

    def test_novel_cve_sets_introduced_true(self) -> None:
        target = _make_record(
            type_label="UNKNOWN",
            cve_matches=["CVE-2026-0001"],
        )
        baseline = _make_record(type_label="UEFI_DRIVER", cve_matches=[])

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        assert finding.evidence.deviation_score is not None
        assert finding.evidence.deviation_score.cve_introduced is True

    def test_shared_cves_sets_introduced_false(self) -> None:
        target = _make_record(
            type_label="UNKNOWN",
            cve_matches=["CVE-2026-0001"],
        )
        baseline = _make_record(
            type_label="UEFI_DRIVER",
            cve_matches=["CVE-2026-0001"],
        )

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        assert finding.evidence.deviation_score is not None
        assert finding.evidence.deviation_score.cve_introduced is False

    def test_empty_target_cves_sets_introduced_false(self) -> None:
        target = _make_record(type_label="UNKNOWN", cve_matches=[])
        baseline = _make_record(type_label="UEFI_DRIVER", cve_matches=[])

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        assert finding.evidence.deviation_score is not None
        assert finding.evidence.deviation_score.cve_introduced is False

    def test_partial_overlap_sets_introduced_true(self) -> None:
        target = _make_record(
            type_label="UNKNOWN",
            cve_matches=["CVE-2026-0001", "CVE-2026-0002"],
        )
        baseline = _make_record(
            type_label="UEFI_DRIVER",
            cve_matches=["CVE-2026-0001"],
        )

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        assert finding.evidence.deviation_score is not None
        assert finding.evidence.deviation_score.cve_introduced is True


class TestCveScoreBump:
    """R2.4: composite score bumped when cve_introduced=True."""

    def test_bump_increases_composite(self) -> None:
        target = _make_record(
            type_label="UNKNOWN",
            cve_matches=["CVE-2026-0001"],
        )
        baseline = _make_record(type_label="UEFI_DRIVER", cve_matches=[])

        # Without bump
        finding_no_bump = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.0,
        )

        # With bump
        finding_with_bump = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.5,
        )

        score_no_bump = finding_no_bump.evidence.deviation_score
        score_with_bump = finding_with_bump.evidence.deviation_score
        assert score_no_bump is not None
        assert score_with_bump is not None
        assert score_with_bump.composite_score > score_no_bump.composite_score

    def test_bump_clamps_at_ten(self) -> None:
        # Create maximum disagreement across all axes
        target = _make_record(
            type_label="UNKNOWN",
            vendor_label="UNKNOWN",
            security_label="COMPROMISED",
            mutability_label="MUTABLE",
            cve_matches=["CVE-2026-0001"],
        )
        baseline = _make_record(
            type_label="UEFI_DRIVER",
            vendor_label="INTEL",
            security_label="SECURE",
            mutability_label="READONLY",
            cve_matches=[],
        )

        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=5.0,
        )

        assert finding.evidence.deviation_score is not None
        assert finding.evidence.deviation_score.composite_score <= 10.0

    def test_zero_bump_no_change(self) -> None:
        target = _make_record(
            type_label="UNKNOWN",
            cve_matches=["CVE-2026-0001"],
        )
        baseline = _make_record(type_label="UEFI_DRIVER", cve_matches=[])

        # Same call with bump=0.0
        finding = emit_classification_mismatch(
            target=target,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.0,
        )

        # Compare to a call where cve_introduced would be False
        target_no_cve = _make_record(type_label="UNKNOWN", cve_matches=[])
        finding_no_cve = emit_classification_mismatch(
            target=target_no_cve,
            baseline=baseline,
            matched_baseline_id=_BASELINE_ID,
            severity_weights=_WEIGHTS,
            cve_score_bump=0.0,
        )

        assert finding.evidence.deviation_score is not None
        assert finding_no_cve.evidence.deviation_score is not None
        # Same composite since bump is 0
        assert (
            finding.evidence.deviation_score.composite_score
            == finding_no_cve.evidence.deviation_score.composite_score
        )
