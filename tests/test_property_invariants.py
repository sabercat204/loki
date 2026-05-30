"""Domain-invariant properties (Properties 3 through 11 from spec).

These properties capture the model layer's domain rules: deterministic
ID generation, hash format validation, bounded numeric ranges,
auto-computed fields, registry lookup correctness, and config
constraints.
"""

from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from loki.models import (
    LOKI_NAMESPACE,
    AnalysisConfig,
    AxisClassification,
    BaselineComparison,
    BaselineRecord,
    BaselineRegistry,
    ClassificationMethod,
    ClassificationRecord,
    DeltaType,
    DeviationRecord,
    DeviationScore,
    ExtractionManifest,
    FirmwareImage,
    ImageAnalysisReport,
    SeverityLevel,
)
from tests.conftest import (
    baseline_registry,
    classification_record,
    extraction_manifest,
    image_analysis_report,
    valid_semver,
    valid_sha256,
)

_HEALTH = settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


# Feature: loki-data-models, Property 3: Deterministic Image ID Generation


@_HEALTH
@given(valid_sha256)
def test_property_3_image_id_is_deterministic(file_hash: str) -> None:
    expected = uuid.uuid5(LOKI_NAMESPACE, file_hash)
    image = FirmwareImage(file_path="/x", file_hash=file_hash, file_size=1)
    assert image.image_id == expected


@_HEALTH
@given(valid_sha256)
def test_property_3_same_hash_same_id(file_hash: str) -> None:
    a = FirmwareImage(file_path="/x", file_hash=file_hash, file_size=1)
    b = FirmwareImage(file_path="/y", file_hash=file_hash, file_size=2)
    assert a.image_id == b.image_id


# Feature: loki-data-models, Property 4: SHA-256 Hash Format Validation

_INVALID_HASH_EXAMPLES = [
    "",
    "a" * 63,
    "a" * 65,
    "G" * 64,  # uppercase invalid for file_hash
    "z" * 64,
    "0" * 63 + "X",
    " " * 64,
    "0123456789",
]


@pytest.mark.parametrize("bad_hash", _INVALID_HASH_EXAMPLES)
def test_property_4_bad_file_hash_rejected(bad_hash: str) -> None:
    with pytest.raises(ValidationError):
        FirmwareImage(file_path="/x", file_hash=bad_hash, file_size=1)


@_HEALTH
@given(
    st.text(min_size=0, max_size=128).filter(
        lambda s: not (len(s) == 64 and all(c in "0123456789abcdef" for c in s))
    )
)
def test_property_4_arbitrary_invalid_hash_rejected(bad_hash: str) -> None:
    with pytest.raises(ValidationError):
        FirmwareImage(file_path="/x", file_hash=bad_hash, file_size=1)


# Feature: loki-data-models, Property 5: Bounded Float Validation


@_HEALTH
@given(st.floats(allow_nan=False, allow_infinity=False).filter(lambda v: v < 0.0 or v > 1.0))
def test_property_5_axis_confidence_out_of_range_rejected(value: float) -> None:
    with pytest.raises(ValidationError):
        AxisClassification(
            label=SeverityLevel.LOW,
            confidence=value,
            method=ClassificationMethod.RULE,
        )


@_HEALTH
@given(st.floats(allow_nan=False, allow_infinity=False).filter(lambda v: v < 0.0 or v > 10.0))
def test_property_5_deviation_composite_score_out_of_range_rejected(
    value: float,
) -> None:
    from loki.models import (
        MutabilityChange,
        SecurityDirection,
        SignatureDelta,
    )

    with pytest.raises(ValidationError):
        DeviationScore(
            base_severity=SeverityLevel.LOW,
            component_criticality=0.5,
            security_direction=SecurityDirection.UNCHANGED,
            signature_delta=SignatureDelta.NONE,
            cve_introduced=False,
            mutability_change=MutabilityChange.NONE,
            composite_score=value,
            priority_rank=1,
        )


# Feature: loki-data-models, Property 6:
# ClassificationRecord Computed Fields Invariant


@_HEALTH
@given(classification_record())
def test_property_6_composite_confidence_is_min_of_axes(
    record: ClassificationRecord,
) -> None:
    expected_min = min(
        record.type_axis.confidence,
        record.vendor_axis.confidence,
        record.security_axis.confidence,
        record.mutability_axis.confidence,
    )
    assert record.composite_confidence == expected_min


@_HEALTH
@given(classification_record())
def test_property_6_needs_review_iff_below_threshold(
    record: ClassificationRecord,
) -> None:
    assert record.needs_review == (record.composite_confidence < 0.60)


# Feature: loki-data-models, Property 7:
# ExtractionManifest Component Count Invariant


@_HEALTH
@given(extraction_manifest())
def test_property_7_total_components_matches_list_length(
    manifest: ExtractionManifest,
) -> None:
    assert manifest.total_components == len(manifest.components)


# Feature: loki-data-models, Property 8: BaselineComparison Summary Invariant


@_HEALTH
@given(
    st.lists(
        st.builds(
            DeviationRecord,
            deviation_id=st.uuids(),
            component_id=st.uuids(),
            delta_type=st.sampled_from(list(DeltaType)),
            baseline_state=st.none(),
            target_state=st.none(),
            description=st.text(min_size=1, max_size=20),
        ),
        min_size=0,
        max_size=10,
    )
)
def test_property_8_summary_counts_match_deviations(
    deviations: list[DeviationRecord],
) -> None:
    from datetime import datetime

    cmp = BaselineComparison(
        baseline_id=uuid.uuid4(),
        target_image_id=uuid.uuid4(),
        comparison_timestamp=datetime.now(tz=UTC),
        deviations=deviations,
    )
    expected: dict[DeltaType, int] = dict(Counter(d.delta_type for d in deviations))
    assert cmp.summary == expected


# Feature: loki-data-models, Property 9: BaselineRegistry Lookup Correctness


@_HEALTH
@given(baseline_registry())
def test_property_9_get_by_id_returns_matching_or_none(
    registry: BaselineRegistry,
) -> None:
    for record in registry.baselines:
        assert registry.get_by_id(record.baseline_id) is record
    assert registry.get_by_id(uuid.uuid4()) is None


@_HEALTH
@given(baseline_registry())
def test_property_9_get_by_vendor_model_filters_correctly(
    registry: BaselineRegistry,
) -> None:
    for record in registry.baselines:
        results = registry.get_by_vendor_model(record.vendor, record.model)
        assert all(r.vendor == record.vendor and r.model == record.model for r in results)
        assert record in results


@_HEALTH
@given(baseline_registry())
def test_property_9_get_by_vendor_model_version_returns_first_match(
    registry: BaselineRegistry,
) -> None:
    for record in registry.baselines:
        match = registry.get_by_vendor_model_version(
            record.vendor, record.model, record.firmware_version
        )
        assert match is not None
        assert match.vendor == record.vendor
        assert match.model == record.model
        assert match.firmware_version == record.firmware_version


# Feature: loki-data-models, Property 10:
# ImageAnalysisReport Summary Invariant


@_HEALTH
@given(image_analysis_report())
def test_property_10_summary_findings_match_distribution(
    report: ImageAnalysisReport,
) -> None:
    expected: dict[SeverityLevel, int] = dict(Counter(f.severity for f in report.findings))
    assert report.summary.findings_by_severity == expected


# Feature: loki-data-models, Property 11: Severity Weights Sum Validation


@_HEALTH
@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=10, alphabet="abcdef"),
        values=st.floats(min_value=0.01, max_value=10.0, allow_nan=False),
        min_size=2,
        max_size=5,
    ).filter(lambda d: not math.isclose(sum(d.values()), 1.0, abs_tol=1e-6))
)
def test_property_11_invalid_severity_weights_rejected(
    weights: dict[str, float],
) -> None:
    with pytest.raises(ValidationError):
        AnalysisConfig(
            severity_weights=weights,
            default_severity_threshold=SeverityLevel.MEDIUM,
        )


def test_property_11_valid_severity_weights_accepted() -> None:
    cfg = AnalysisConfig(
        severity_weights={"critical": 0.5, "high": 0.3, "medium": 0.2},
        default_severity_threshold=SeverityLevel.HIGH,
    )
    assert math.isclose(sum(cfg.severity_weights.values()), 1.0, abs_tol=1e-6)


def test_property_11_baseline_record_semver(_: Any = None) -> None:
    """Defensive: check semver pattern enforced on BaselineRecord."""
    from datetime import datetime

    with pytest.raises(ValidationError):
        BaselineRecord(
            baseline_id=uuid.uuid4(),
            name="x",
            vendor="v",
            model="m",
            firmware_version="1.0",
            created_timestamp=datetime.now(tz=UTC),
            component_manifest=[],
            source_image_hash="a" * 64,
            baseline_version="not-a-semver",
        )


@_HEALTH
@given(valid_semver)
def test_property_11_baseline_record_valid_semver_accepted(
    semver: str,
) -> None:
    from datetime import datetime

    BaselineRecord(
        baseline_id=uuid.uuid4(),
        name="x",
        vendor="v",
        model="m",
        firmware_version="1.0",
        created_timestamp=datetime.now(tz=UTC),
        component_manifest=[],
        source_image_hash="a" * 64,
        baseline_version=semver,
    )
