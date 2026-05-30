"""Shared Hypothesis strategies for LOKI model tests.

These strategies generate valid model instances for property-based testing.
They are deliberately conservative — generating too many edge-case values
slows tests down without improving coverage. Each strategy targets the
constructor's stated contract (the ranges, formats, and required fields
the validators enforce).
"""

from __future__ import annotations

import string
import uuid
from datetime import UTC, datetime

from hypothesis import strategies as st

from loki.models import (
    ActionRecord,
    AnalysisConfig,
    AxisClassification,
    BaselineComparison,
    BaselineConfig,
    BaselineRecord,
    BaselineRegistry,
    ClassificationConfig,
    ClassificationMethod,
    ClassificationRecord,
    ColorMode,
    ComponentTypeLabel,
    DeltaType,
    DeviationRecord,
    DeviationScore,
    ExtractedComponent,
    ExtractionConfig,
    ExtractionError,
    ExtractionManifest,
    FeedsConfig,
    FindingEvidence,
    FindingRecord,
    FirmwareImage,
    FleetAnalysisReport,
    FleetConfig,
    GeneralConfig,
    ImageAnalysisReport,
    LogLevel,
    LokiConfig,
    MutabilityChange,
    MutabilityLabel,
    OutputFormat,
    OverrideRecord,
    PostureRating,
    SecurityDirection,
    SecurityPostureLabel,
    SeverityLevel,
    SignatureDelta,
    SignatureInfo,
    VendorLabel,
)

# -- Primitive strategies --------------------------------------------------

valid_sha256 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


def _hex_offset_text() -> st.SearchStrategy[str]:
    return st.text(alphabet="0123456789abcdefABCDEF", min_size=1, max_size=8).map(
        lambda s: f"0x{s}"
    )


valid_hex_offset = _hex_offset_text()


valid_semver = st.tuples(
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}")


# Datetimes restricted to a sane historical-future range to avoid
# Hypothesis-generated extreme values that pyyaml mishandles.
valid_datetime = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2100, 1, 1),
    timezones=st.just(UTC),
)


_NON_EMPTY_STRING_ALPHABET = string.ascii_letters + string.digits + "_-./ "


def non_empty_text(min_size: int = 1, max_size: int = 50) -> st.SearchStrategy[str]:
    return st.text(
        alphabet=_NON_EMPTY_STRING_ALPHABET, min_size=min_size, max_size=max_size
    ).filter(lambda s: bool(s.strip()))


# -- Enum strategies -------------------------------------------------------

component_type_label = st.sampled_from(list(ComponentTypeLabel))
vendor_label = st.sampled_from(list(VendorLabel))
security_posture_label = st.sampled_from(list(SecurityPostureLabel))
mutability_label = st.sampled_from(list(MutabilityLabel))
classification_method = st.sampled_from(list(ClassificationMethod))
delta_type = st.sampled_from(list(DeltaType))
severity_level = st.sampled_from(list(SeverityLevel))
posture_rating = st.sampled_from(list(PostureRating))
security_direction = st.sampled_from(list(SecurityDirection))
signature_delta = st.sampled_from(list(SignatureDelta))
mutability_change = st.sampled_from(list(MutabilityChange))
output_format = st.sampled_from(list(OutputFormat))
color_mode = st.sampled_from(list(ColorMode))
log_level = st.sampled_from(list(LogLevel))


# -- Model strategies ------------------------------------------------------


@st.composite
def firmware_image(draw: st.DrawFn) -> FirmwareImage:
    return FirmwareImage(
        file_path=draw(non_empty_text()),
        file_hash=draw(valid_sha256),
        file_size=draw(st.integers(min_value=1, max_value=10**12)),
        vendor=draw(st.one_of(st.none(), non_empty_text())),
        model=draw(st.one_of(st.none(), non_empty_text())),
        firmware_version=draw(st.one_of(st.none(), non_empty_text())),
        extraction_timestamp=draw(st.one_of(st.none(), valid_datetime)),
    )


@st.composite
def extracted_component(
    draw: st.DrawFn, source_image_id: uuid.UUID | None = None
) -> ExtractedComponent:
    return ExtractedComponent(
        component_id=uuid.uuid4(),
        source_image_id=source_image_id or uuid.uuid4(),
        offset=draw(valid_hex_offset),
        size=draw(st.integers(min_value=1, max_value=10**9)),
        raw_hash=draw(valid_sha256),
        component_type_hint=draw(st.one_of(st.none(), non_empty_text())),
        guid=draw(st.one_of(st.none(), non_empty_text())),
        name=draw(st.one_of(st.none(), non_empty_text())),
        raw_path=draw(st.one_of(st.none(), non_empty_text())),
    )


@st.composite
def extraction_error(draw: st.DrawFn) -> ExtractionError:
    return ExtractionError(
        component_id=draw(st.one_of(st.none(), st.uuids())),
        error_message=draw(non_empty_text()),
        timestamp=draw(valid_datetime),
    )


@st.composite
def extraction_manifest(draw: st.DrawFn) -> ExtractionManifest:
    image = draw(firmware_image())
    components = draw(
        st.lists(
            extracted_component(source_image_id=image.image_id),
            min_size=0,
            max_size=5,
        )
    )
    return ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=draw(valid_datetime),
        extractor_version=draw(non_empty_text()),
        extraction_errors=draw(st.lists(extraction_error(), min_size=0, max_size=3)),
    )


@st.composite
def axis_classification(draw: st.DrawFn) -> AxisClassification:
    label_strategy = draw(
        st.sampled_from(
            [
                component_type_label,
                vendor_label,
                security_posture_label,
                mutability_label,
            ]
        )
    )
    return AxisClassification(
        label=draw(label_strategy),
        confidence=draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False)),
        method=draw(classification_method),
        rule_id=draw(st.one_of(st.none(), non_empty_text())),
        evidence=draw(st.one_of(st.none(), st.lists(non_empty_text(), max_size=3))),
    )


@st.composite
def signature_info(draw: st.DrawFn) -> SignatureInfo:
    return SignatureInfo(
        present=draw(st.booleans()),
        verified=draw(st.booleans()),
        signer=draw(st.one_of(st.none(), non_empty_text())),
        cert_expiry=draw(st.one_of(st.none(), valid_datetime)),
    )


@st.composite
def override_record(draw: st.DrawFn) -> OverrideRecord:
    return OverrideRecord(
        original_label=draw(non_empty_text()),
        override_label=draw(non_empty_text()),
        analyst=draw(non_empty_text()),
        timestamp=draw(valid_datetime),
        justification=draw(non_empty_text(min_size=3)),
    )


@st.composite
def classification_record(draw: st.DrawFn) -> ClassificationRecord:
    return ClassificationRecord(
        component_id=uuid.uuid4(),
        source_image_id=uuid.uuid4(),
        extraction_offset=draw(valid_hex_offset),
        timestamp=draw(valid_datetime),
        type_axis=draw(axis_classification()),
        vendor_axis=draw(axis_classification()),
        security_axis=draw(axis_classification()),
        mutability_axis=draw(axis_classification()),
        signature_info=draw(st.one_of(st.none(), signature_info())),
        cve_matches=draw(st.lists(non_empty_text(), max_size=3)),
        suspicion_triggers=draw(st.lists(non_empty_text(), max_size=3)),
        classification_version=draw(non_empty_text()),
        overrides=draw(st.lists(override_record(), max_size=2)),
    )


@st.composite
def baseline_record(draw: st.DrawFn) -> BaselineRecord:
    return BaselineRecord(
        baseline_id=uuid.uuid4(),
        name=draw(non_empty_text()),
        vendor=draw(non_empty_text()),
        model=draw(non_empty_text()),
        firmware_version=draw(non_empty_text()),
        created_timestamp=draw(valid_datetime),
        notes=draw(st.one_of(st.none(), non_empty_text())),
        component_manifest=draw(st.lists(classification_record(), max_size=3)),
        source_image_hash=draw(valid_sha256),
        baseline_version=draw(valid_semver),
    )


@st.composite
def baseline_registry(draw: st.DrawFn) -> BaselineRegistry:
    return BaselineRegistry(
        baselines=draw(st.lists(baseline_record(), max_size=3)),
    )


@st.composite
def deviation_record(draw: st.DrawFn) -> DeviationRecord:
    return DeviationRecord(
        deviation_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        delta_type=draw(delta_type),
        baseline_state=draw(st.one_of(st.none(), classification_record())),
        target_state=draw(st.one_of(st.none(), classification_record())),
        description=draw(non_empty_text()),
    )


@st.composite
def baseline_comparison(draw: st.DrawFn) -> BaselineComparison:
    return BaselineComparison(
        baseline_id=uuid.uuid4(),
        target_image_id=uuid.uuid4(),
        comparison_timestamp=draw(valid_datetime),
        deviations=draw(st.lists(deviation_record(), min_size=0, max_size=5)),
    )


@st.composite
def deviation_score(draw: st.DrawFn) -> DeviationScore:
    return DeviationScore(
        base_severity=draw(severity_level),
        component_criticality=draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False)),
        security_direction=draw(security_direction),
        signature_delta=draw(signature_delta),
        cve_introduced=draw(st.booleans()),
        mutability_change=draw(mutability_change),
        composite_score=draw(st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
        priority_rank=draw(st.integers(min_value=1, max_value=1000)),
    )


@st.composite
def finding_evidence(draw: st.DrawFn) -> FindingEvidence:
    return FindingEvidence(
        classification_record=draw(st.one_of(st.none(), classification_record())),
        matched_rule=draw(st.one_of(st.none(), non_empty_text())),
        matched_cve=draw(st.one_of(st.none(), non_empty_text())),
        matched_signature=draw(st.one_of(st.none(), non_empty_text())),
        raw_indicators=draw(st.lists(non_empty_text(), max_size=3)),
    )


@st.composite
def finding_record(draw: st.DrawFn) -> FindingRecord:
    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=uuid.uuid4(),
        severity=draw(severity_level),
        category=draw(non_empty_text()),
        title=draw(non_empty_text()),
        description=draw(non_empty_text()),
        evidence=draw(finding_evidence()),
        recommended_action=draw(non_empty_text()),
    )


@st.composite
def action_record(draw: st.DrawFn) -> ActionRecord:
    return ActionRecord(
        action_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        action_type=draw(non_empty_text()),
        description=draw(non_empty_text()),
        reference=draw(st.one_of(st.none(), non_empty_text())),
    )


@st.composite
def image_analysis_report(draw: st.DrawFn) -> ImageAnalysisReport:
    image = draw(firmware_image())
    assert image.image_id is not None  # auto-generated by validator
    return ImageAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=draw(valid_datetime),
        analysis_version=draw(non_empty_text()),
        image_id=image.image_id,
        image_metadata=image,
        posture_rating=draw(posture_rating),
        findings=draw(st.lists(finding_record(), max_size=4)),
        recommended_actions=draw(st.lists(action_record(), max_size=2)),
        baseline_comparison=draw(st.one_of(st.none(), baseline_comparison())),
    )


@st.composite
def fleet_analysis_report(draw: st.DrawFn) -> FleetAnalysisReport:
    return FleetAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=draw(valid_datetime),
        fleet_id=draw(non_empty_text()),
        image_count=draw(st.integers(min_value=0, max_value=1000)),
        fleet_posture=draw(
            st.dictionaries(
                keys=posture_rating,
                values=st.integers(min_value=0, max_value=100),
                max_size=5,
            )
        ),
        common_findings=draw(st.lists(finding_record(), max_size=3)),
        outlier_images=draw(st.lists(st.uuids(), max_size=3)),
        systemic_risks=draw(st.lists(non_empty_text(), max_size=3)),
        recommended_actions=draw(st.lists(action_record(), max_size=2)),
    )


@st.composite
def loki_config(draw: st.DrawFn) -> LokiConfig:
    weights_pairs = draw(
        st.lists(
            st.tuples(non_empty_text(), st.floats(min_value=0.05, max_value=1.0)),
            min_size=2,
            max_size=5,
            unique_by=lambda t: t[0],
        )
    )
    keys = [k for k, _ in weights_pairs]
    raw_values = [v for _, v in weights_pairs]
    total = sum(raw_values)
    normalized = {k: v / total for k, v in zip(keys, raw_values, strict=True)}
    # Re-normalize to compensate for floating-point drift.
    drift = 1.0 - sum(normalized.values())
    first_key = next(iter(normalized))
    normalized[first_key] += drift
    return LokiConfig(
        general=GeneralConfig(
            default_output_format=draw(output_format),
            color=draw(color_mode),
            verbosity=draw(st.integers(min_value=0, max_value=3)),
            log_level=draw(log_level),
        ),
        extraction=ExtractionConfig(
            default_output_dir=draw(non_empty_text()),
            max_component_size=draw(st.integers(min_value=1, max_value=10**9)),
            timeout_per_component=draw(st.integers(min_value=1, max_value=3600)),
        ),
        classification=ClassificationConfig(
            taxonomy_version=draw(non_empty_text()),
            confidence_threshold=draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False)),
            rules_path=draw(non_empty_text()),
        ),
        analysis=AnalysisConfig(
            severity_weights=normalized,
            default_severity_threshold=draw(severity_level),
            report_template=draw(st.one_of(st.none(), non_empty_text())),
        ),
        baseline=BaselineConfig(
            storage_path=draw(non_empty_text()),
            auto_match=draw(st.booleans()),
        ),
        feeds=FeedsConfig(
            nvd_url=draw(non_empty_text()),
            update_interval=draw(st.integers(min_value=1, max_value=86400)),
            cache_path=draw(non_empty_text()),
            implant_rules_path=draw(non_empty_text()),
        ),
        fleet=FleetConfig(
            default_severity_threshold=draw(severity_level),
            storage_path=draw(non_empty_text()),
        ),
    )
