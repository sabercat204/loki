"""Round-trip serialization properties (Properties 1 and 2 from spec).

These are the headline correctness guarantees for the model layer:
every model serializes losslessly to JSON and YAML and back. If any
validator rejects re-validated data, or if any computed field drifts
on round-trip, this is the test that catches it.
"""

from __future__ import annotations

from typing import Any

import yaml
from hypothesis import HealthCheck, given, settings
from pydantic import BaseModel

from loki.models import (
    ActionRecord,
    AxisClassification,
    BaselineComparison,
    BaselineRecord,
    BaselineRegistry,
    ClassificationRecord,
    DeviationRecord,
    DeviationScore,
    ExtractedComponent,
    ExtractionError,
    ExtractionManifest,
    FindingEvidence,
    FindingRecord,
    FirmwareImage,
    FleetAnalysisReport,
    ImageAnalysisReport,
    LokiConfig,
    OverrideRecord,
    SignatureInfo,
)
from tests.conftest import (
    action_record,
    axis_classification,
    baseline_comparison,
    baseline_record,
    baseline_registry,
    classification_record,
    deviation_record,
    deviation_score,
    extracted_component,
    extraction_error,
    extraction_manifest,
    finding_evidence,
    finding_record,
    firmware_image,
    fleet_analysis_report,
    image_analysis_report,
    loki_config,
    override_record,
    signature_info,
)

_RELAXED_HEALTH = settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow],
)


def _json_round_trip(model: BaseModel) -> BaseModel:
    return type(model).model_validate_json(model.model_dump_json())


def _yaml_round_trip(model: BaseModel) -> BaseModel:
    dumped: dict[str, Any] = model.model_dump(mode="json")
    yaml_text = yaml.safe_dump(dumped, sort_keys=True)
    loaded = yaml.safe_load(yaml_text)
    # YAML deserialization mirrors what ``LokiConfig.from_yaml`` does:
    # plain strings need to coerce to UUID, datetime, and StrEnum on input.
    # ``strict=False`` enables that coercion path; the field-level
    # validators (hash format, hex offset, semver, etc.) still run.
    return type(model).model_validate(loaded, strict=False)


# Feature: loki-data-models, Property 1: JSON Serialization Round-Trip


@_RELAXED_HEALTH
@given(firmware_image())
def test_json_round_trip_firmware_image(model: FirmwareImage) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(extracted_component())
def test_json_round_trip_extracted_component(model: ExtractedComponent) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(extraction_error())
def test_json_round_trip_extraction_error(model: ExtractionError) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(extraction_manifest())
def test_json_round_trip_extraction_manifest(model: ExtractionManifest) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(axis_classification())
def test_json_round_trip_axis_classification(model: AxisClassification) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(signature_info())
def test_json_round_trip_signature_info(model: SignatureInfo) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(override_record())
def test_json_round_trip_override_record(model: OverrideRecord) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(classification_record())
def test_json_round_trip_classification_record(model: ClassificationRecord) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(baseline_record())
def test_json_round_trip_baseline_record(model: BaselineRecord) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(baseline_registry())
def test_json_round_trip_baseline_registry(model: BaselineRegistry) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(deviation_record())
def test_json_round_trip_deviation_record(model: DeviationRecord) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(baseline_comparison())
def test_json_round_trip_baseline_comparison(model: BaselineComparison) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(deviation_score())
def test_json_round_trip_deviation_score(model: DeviationScore) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(finding_evidence())
def test_json_round_trip_finding_evidence(model: FindingEvidence) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(finding_record())
def test_json_round_trip_finding_record(model: FindingRecord) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(action_record())
def test_json_round_trip_action_record(model: ActionRecord) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(image_analysis_report())
def test_json_round_trip_image_analysis_report(model: ImageAnalysisReport) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(fleet_analysis_report())
def test_json_round_trip_fleet_analysis_report(model: FleetAnalysisReport) -> None:
    assert _json_round_trip(model) == model


@_RELAXED_HEALTH
@given(loki_config())
def test_json_round_trip_loki_config(model: LokiConfig) -> None:
    assert _json_round_trip(model) == model


# Feature: loki-data-models, Property 2: YAML Serialization Round-Trip


@_RELAXED_HEALTH
@given(firmware_image())
def test_yaml_round_trip_firmware_image(model: FirmwareImage) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(extracted_component())
def test_yaml_round_trip_extracted_component(model: ExtractedComponent) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(extraction_manifest())
def test_yaml_round_trip_extraction_manifest(model: ExtractionManifest) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(classification_record())
def test_yaml_round_trip_classification_record(model: ClassificationRecord) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(baseline_record())
def test_yaml_round_trip_baseline_record(model: BaselineRecord) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(baseline_comparison())
def test_yaml_round_trip_baseline_comparison(model: BaselineComparison) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(deviation_score())
def test_yaml_round_trip_deviation_score(model: DeviationScore) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(finding_record())
def test_yaml_round_trip_finding_record(model: FindingRecord) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(image_analysis_report())
def test_yaml_round_trip_image_analysis_report(model: ImageAnalysisReport) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(fleet_analysis_report())
def test_yaml_round_trip_fleet_analysis_report(model: FleetAnalysisReport) -> None:
    assert _yaml_round_trip(model) == model


@_RELAXED_HEALTH
@given(loki_config())
def test_yaml_round_trip_loki_config(model: LokiConfig) -> None:
    assert _yaml_round_trip(model) == model
