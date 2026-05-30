"""Hypothesis property tests for consumer-wiring (task 7).

Properties P69-P71 from the consumer-wiring design:
- P69: CVE population determinism
- P70: CVE introduction detection correctness
- P71: Backward compatibility
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.analysis.findings import emit_classification_mismatch
from loki.classification import classify_components
from loki.feeds.models import CVELookupResult, CVEMatch
from loki.feeds.registry import FeedRegistry
from loki.models import ClassificationConfig, ExtractedComponent, FirmwareImage
from loki.models.classification import AxisClassification, ClassificationRecord, SignatureInfo
from loki.models.enums import ClassificationMethod

_SLOW_SETTINGS = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

_WEIGHTS = {"type": 0.25, "vendor": 0.25, "security_posture": 0.25, "mutability": 0.25}
_BASELINE_ID = uuid.uuid5(uuid.NAMESPACE_DNS, "p70-baseline")


def _make_image() -> FirmwareImage:
    return FirmwareImage(
        image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "prop-image"),
        file_path="/tmp/prop.bin",
        file_hash="e" * 64,
        file_size=4096,
        vendor="INTEL",
        model="X1",
        firmware_version="1.0.0",
    )


def _make_components(count: int = 2) -> list[ExtractedComponent]:
    image = _make_image()
    assert image.image_id is not None
    return [
        ExtractedComponent(
            component_id=uuid.uuid5(uuid.NAMESPACE_DNS, f"prop-comp-{i}"),
            source_image_id=image.image_id,
            offset=f"0x{i * 0x1000:x}",
            size=512,
            raw_hash="f" * 64,
            component_type_hint=None,
            guid=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"prop-guid-{i}")),
            name=f"PROP_{i:03d}",
            raw_path=None,
        )
        for i in range(count)
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


def _make_record(cve_matches: list[str] | None = None) -> ClassificationRecord:
    return ClassificationRecord(
        component_id=uuid.uuid4(),
        source_image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "img"),
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
        signature_info=SignatureInfo(present=True, verified=False, signer=None, cert_expiry=None),
        cve_matches=cve_matches or [],
        suspicion_triggers=[],
        classification_version="1.0.0",
        overrides=[],
    )


# P69: CVE population determinism
@_SLOW_SETTINGS
@given(run_count=st.integers(min_value=2, max_value=3))
def test_p69_cve_population_determinism(
    run_count: int, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Two classify_components calls with same registry produce equal cve_matches."""
    tmp_path = tmp_path_factory.mktemp("p69")
    config = _make_config(tmp_path)
    components = _make_components(2)
    image = _make_image()

    mock_registry = MagicMock(spec=FeedRegistry)
    mock_registry.cve_lookup.return_value = CVELookupResult(
        matches=[
            CVEMatch(
                cve_id="CVE-2026-0001",
                vendor="intel",
                product="unknown_x1",
                version="1.0.0",
                published_date=datetime(2026, 1, 1, tzinfo=UTC),
                cvss_v3_score=7.5,
                cvss_v3_severity="HIGH",
            )
        ],
        stale_warning=False,
    )

    results = []
    for _ in range(run_count):
        r = classify_components(components, config, feeds=mock_registry, source_image=image)
        results.append(r)

    for i in range(1, len(results)):
        for r1, r2 in zip(results[0].records, results[i].records, strict=True):
            assert r1.cve_matches == r2.cve_matches


# P70: CVE introduction detection correctness
@_SLOW_SETTINGS
@given(
    target_cves=st.lists(
        st.from_regex(r"CVE-2026-[0-9]{4}", fullmatch=True),
        min_size=1,
        max_size=3,
        unique=True,
    ),
    baseline_cves=st.lists(
        st.from_regex(r"CVE-2026-[0-9]{4}", fullmatch=True),
        min_size=0,
        max_size=3,
        unique=True,
    ),
)
def test_p70_cve_introduction_detection(target_cves: list[str], baseline_cves: list[str]) -> None:
    """cve_introduced is True iff target has novel CVEs vs baseline."""
    target = _make_record(cve_matches=sorted(target_cves))
    baseline_rec = _make_record(cve_matches=sorted(baseline_cves))
    baseline_rec.type_axis = AxisClassification(
        label="UEFI_DRIVER", confidence=0.9, method=ClassificationMethod.RULE, evidence=[]
    )

    finding = emit_classification_mismatch(
        target=target,
        baseline=baseline_rec,
        matched_baseline_id=_BASELINE_ID,
        severity_weights=_WEIGHTS,
        cve_score_bump=0.5,
    )

    expected_introduced = bool(set(target_cves) - set(baseline_cves))
    assert finding.evidence.deviation_score is not None
    assert finding.evidence.deviation_score.cve_introduced == expected_introduced


# P71: Backward compatibility
def test_p71_no_feeds_identical_output(tmp_path: Path) -> None:
    """feeds=None produces output identical to omitting the kwarg entirely."""
    config = _make_config(tmp_path)
    components = _make_components(3)

    r1 = classify_components(components, config)
    r2 = classify_components(components, config, feeds=None)

    assert len(r1.records) == len(r2.records)
    for rec1, rec2 in zip(r1.records, r2.records, strict=True):
        assert rec1.cve_matches == rec2.cve_matches == []
