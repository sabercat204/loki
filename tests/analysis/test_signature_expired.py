"""Tests for the signature_expired finding category."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from loki.analysis.findings import emit_signature_expired
from loki.models.classification import (
    AxisClassification,
    ClassificationRecord,
    SignatureInfo,
)
from loki.models.enums import ClassificationMethod, SeverityLevel


def _make_record(
    *,
    verified: bool = True,
    cert_expiry: datetime | None = None,
) -> ClassificationRecord:
    axis = AxisClassification(
        label="UNKNOWN",
        confidence=0.5,
        method=ClassificationMethod.HEURISTIC,
    )
    return ClassificationRecord(
        component_id=uuid.uuid4(),
        source_image_id=uuid.uuid4(),
        extraction_offset="0x1000",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        type_axis=axis,
        vendor_axis=axis,
        security_axis=axis,
        mutability_axis=axis,
        signature_info=SignatureInfo(
            present=True,
            verified=verified,
            signer="Test Signer",
            cert_expiry=cert_expiry,
        ),
        classification_version="1.0.0",
    )


class TestEmitSignatureExpired:
    def test_finding_category(self) -> None:
        expiry = datetime(2024, 1, 1, tzinfo=UTC)
        record = _make_record(cert_expiry=expiry)
        finding = emit_signature_expired(
            target=record,
            matched_baseline_id=uuid.uuid4(),
            expiry_iso=expiry.isoformat(),
        )
        assert finding.category == "signature_expired"

    def test_severity_is_medium(self) -> None:
        expiry = datetime(2024, 1, 1, tzinfo=UTC)
        record = _make_record(cert_expiry=expiry)
        finding = emit_signature_expired(
            target=record,
            matched_baseline_id=uuid.uuid4(),
            expiry_iso=expiry.isoformat(),
        )
        assert finding.severity == SeverityLevel.MEDIUM

    def test_expiry_in_raw_indicators(self) -> None:
        expiry = datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)
        record = _make_record(cert_expiry=expiry)
        finding = emit_signature_expired(
            target=record,
            matched_baseline_id=uuid.uuid4(),
            expiry_iso=expiry.isoformat(),
        )
        assert any("cert_expiry=" in ind for ind in finding.evidence.raw_indicators)

    def test_deterministic_finding_id(self) -> None:
        expiry = datetime(2024, 1, 1, tzinfo=UTC)
        record = _make_record(cert_expiry=expiry)
        baseline_id = uuid.uuid4()
        f1 = emit_signature_expired(
            target=record,
            matched_baseline_id=baseline_id,
            expiry_iso=expiry.isoformat(),
        )
        f2 = emit_signature_expired(
            target=record,
            matched_baseline_id=baseline_id,
            expiry_iso=expiry.isoformat(),
        )
        assert f1.finding_id == f2.finding_id

    def test_recommended_action(self) -> None:
        expiry = datetime(2024, 1, 1, tzinfo=UTC)
        record = _make_record(cert_expiry=expiry)
        finding = emit_signature_expired(
            target=record,
            matched_baseline_id=uuid.uuid4(),
            expiry_iso=expiry.isoformat(),
        )
        assert "Re-sign" in finding.recommended_action
