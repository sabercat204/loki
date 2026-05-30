# Implementation Plan: LOKI Data Models

## Overview

Implement the complete Pydantic v2 data model layer for the LOKI firmware analysis platform as a Python package at `loki/models/`. Models are built bottom-up following the dependency DAG: enums → firmware → classification → baseline → analysis → reports → config → `__init__.py` re-exports. Property-based tests (Hypothesis) validate correctness properties from the design; unit tests cover construction, validation, and edge cases.

## Tasks

- [x] 1. Set up package structure and enum types
  - [x] 1.1 Create package skeleton with `loki/__init__.py` and `loki/models/__init__.py` (empty placeholder)
    - Create `loki/__init__.py` (empty or minimal)
    - Create `loki/models/__init__.py` with a placeholder comment
    - _Requirements: US-006 file structure, Technical Constraints (no circular imports)_

  - [x] 1.2 Implement all StrEnum types in `loki/models/enums.py`
    - Define `ComponentTypeLabel`, `VendorLabel`, `SecurityPostureLabel`, `MutabilityLabel`, `ClassificationMethod`, `DeltaType`, `SeverityLevel`, `PostureRating`, `SecurityDirection`, `SignatureDelta`, `MutabilityChange`, `OutputFormat`, `ColorMode`, `LogLevel`
    - Each enum must inherit from `StrEnum`
    - Include docstrings for each enum
    - _Requirements: US-003 (3.1), US-004 (4.3), US-005 (5.1), US-006 (6.1)_

  - [ ]* 1.3 Write unit tests for enum serialization
    - Verify each enum value serializes to its string name
    - Verify all expected members exist on each enum
    - _Requirements: US-003 (3.1), US-005 (5.1), US-006 (6.1)_

- [x] 2. Implement firmware models
  - [x] 2.1 Implement `FirmwareImage`, `ExtractedComponent`, `ExtractionError`, and `ExtractionManifest` in `loki/models/firmware.py`
    - Define `LOKI_NAMESPACE` UUID constant
    - `FirmwareImage`: auto-generate `image_id` via `uuid5(LOKI_NAMESPACE, file_hash)` if not provided; validate `file_hash` (64 lowercase hex chars); validate `file_size > 0`
    - `ExtractedComponent`: validate `offset` matches `^0x[0-9a-fA-F]+$`; validate `raw_hash` (64 hex chars)
    - `ExtractionError`: validate `error_message` non-empty
    - `ExtractionManifest`: auto-compute `total_components = len(components)` via `@model_validator(mode='after')`
    - All models use `ConfigDict(strict=True, frozen=False)`
    - _Requirements: US-001 (1.1, 1.2, 1.3), US-002 (2.1, 2.2)_

  - [ ]* 2.2 Write property test: Deterministic Image ID Generation (Property 3)
    - **Property 3: Deterministic Image ID Generation**
    - For any valid SHA-256 hash, `FirmwareImage` without `image_id` produces `uuid5(LOKI_NAMESPACE, file_hash)`, and two instances with the same hash produce the same ID
    - **Validates: Requirements US-001 (1.1, 1.2)**

  - [ ]* 2.3 Write property test: SHA-256 Hash Format Validation (Property 4)
    - **Property 4: SHA-256 Hash Format Validation**
    - For any string that is not exactly 64 lowercase hex chars, constructing `FirmwareImage` or `ExtractedComponent` with it raises `ValidationError`
    - **Validates: Requirements US-001 (1.3), US-002 (2.1)**

  - [ ]* 2.4 Write property test: ExtractionManifest Component Count Invariant (Property 7)
    - **Property 7: ExtractionManifest Component Count Invariant**
    - For any valid `ExtractionManifest`, `total_components == len(components)`
    - **Validates: Requirements US-002 (2.2)**

  - [ ]* 2.5 Write unit tests for firmware models
    - Test valid construction of `FirmwareImage`, `ExtractedComponent`, `ExtractionManifest`
    - Test rejection of invalid `file_hash`, `file_size <= 0`, invalid `offset` format
    - _Requirements: US-001 (1.1, 1.2, 1.3), US-002 (2.1, 2.2)_

- [x] 3. Implement classification models
  - [x] 3.1 Implement `AxisClassification`, `SignatureInfo`, `OverrideRecord`, and `ClassificationRecord` in `loki/models/classification.py`
    - `AxisClassification`: validate `confidence` in `[0.0, 1.0]`
    - `OverrideRecord`: validate `justification` non-empty
    - `ClassificationRecord`: auto-compute `composite_confidence = min(axis.confidence for axis in [type_axis, vendor_axis, security_axis, mutability_axis])`; auto-set `needs_review = composite_confidence < 0.60`
    - _Requirements: US-003 (3.1, 3.2, 3.3, 3.4)_

  - [ ]* 3.2 Write property test: Bounded Float Validation (Property 5)
    - **Property 5: Bounded Float Validation**
    - For any float outside `[0.0, 1.0]`, constructing `AxisClassification` raises `ValidationError`
    - **Validates: Requirements US-003 (3.2)**

  - [ ]* 3.3 Write property test: ClassificationRecord Computed Fields Invariant (Property 6)
    - **Property 6: ClassificationRecord Computed Fields Invariant**
    - For any valid `ClassificationRecord`, `composite_confidence == min(axes)` and `needs_review == (composite_confidence < 0.60)`
    - **Validates: Requirements US-003 (3.3, 3.4)**

  - [ ]* 3.4 Write unit tests for classification models
    - Test valid construction, `OverrideRecord` with empty justification rejection, confidence boundary values
    - _Requirements: US-003 (3.1, 3.2, 3.3, 3.4)_

- [x] 4. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement baseline models
  - [x] 5.1 Implement `BaselineRecord`, `BaselineRegistry`, `DeviationRecord`, and `BaselineComparison` in `loki/models/baseline.py`
    - `BaselineRecord`: validate `baseline_version` matches `^\d+\.\d+\.\d+$`; validate `source_image_hash` (64 hex chars)
    - `BaselineRegistry`: implement `get_by_id`, `get_by_vendor_model`, `get_by_vendor_model_version` methods
    - `BaselineComparison`: auto-compute `summary` as counts by `DeltaType` from `deviations` list
    - _Requirements: US-004 (4.1, 4.2, 4.3)_

  - [ ]* 5.2 Write property test: BaselineComparison Summary Invariant (Property 8)
    - **Property 8: BaselineComparison Summary Invariant**
    - For any valid `BaselineComparison`, `summary[delta_type]` equals the count of deviations with that delta type
    - **Validates: Requirements US-004 (4.3)**

  - [ ]* 5.3 Write property test: BaselineRegistry Lookup Correctness (Property 9)
    - **Property 9: BaselineRegistry Lookup Correctness**
    - For any `BaselineRegistry`, `get_by_id` returns the correct record or `None`; `get_by_vendor_model` returns exact matches; `get_by_vendor_model_version` returns the single match or `None`
    - **Validates: Requirements US-004 (4.2)**

  - [ ]* 5.4 Write unit tests for baseline models
    - Test valid construction, invalid semver rejection, empty registry lookups, duplicate vendor+model scenarios
    - _Requirements: US-004 (4.1, 4.2, 4.3)_

- [x] 6. Implement analysis models
  - [x] 6.1 Implement `DeviationScore`, `FindingEvidence`, `FindingRecord`, and `ActionRecord` in `loki/models/analysis.py`
    - `DeviationScore`: validate `composite_score` in `[0.0, 10.0]`; validate `priority_rank >= 1`
    - `FindingEvidence`: structured sub-model with optional fields
    - _Requirements: US-005 (5.1, 5.2)_

  - [ ]* 6.2 Write property test: Bounded Float Validation for DeviationScore (Property 5 — composite_score)
    - **Property 5 (continued): Bounded Float Validation — DeviationScore**
    - For any float outside `[0.0, 10.0]`, constructing `DeviationScore` with that `composite_score` raises `ValidationError`
    - **Validates: Requirements US-005 (5.1)**

  - [ ]* 6.3 Write unit tests for analysis models
    - Test valid construction, out-of-range composite_score rejection, priority_rank < 1 rejection
    - _Requirements: US-005 (5.1, 5.2)_

- [x] 7. Implement report models
  - [x] 7.1 Implement `ReportSummary`, `ImageAnalysisReport`, and `FleetAnalysisReport` in `loki/models/reports.py`
    - `ImageAnalysisReport`: auto-compute `summary` (ReportSummary) from `findings` list — count findings by severity
    - `FleetAnalysisReport`: fleet-level aggregation model
    - _Requirements: US-005 (5.3, 5.4)_

  - [ ]* 7.2 Write property test: ImageAnalysisReport Summary Invariant (Property 10)
    - **Property 10: ImageAnalysisReport Summary Invariant**
    - For any valid `ImageAnalysisReport`, `summary.findings_by_severity` matches the severity distribution of `findings`
    - **Validates: Requirements US-005 (5.3)**

  - [ ]* 7.3 Write unit tests for report models
    - Test valid construction, summary auto-computation with various finding distributions
    - _Requirements: US-005 (5.3, 5.4)_

- [x] 8. Implement config models
  - [x] 8.1 Implement all config sub-models and `LokiConfig` in `loki/models/config.py`
    - `GeneralConfig`, `ExtractionConfig`, `ClassificationConfig`, `AnalysisConfig`, `BaselineConfig`, `FeedsConfig`, `FleetConfig`
    - `AnalysisConfig`: validate `severity_weights` values sum to 1.0 (within float tolerance)
    - `LokiConfig`: compose all sub-configs; implement `@classmethod from_yaml(path: Path) -> LokiConfig`
    - _Requirements: US-006 (6.1, 6.2, 6.3)_

  - [ ]* 8.2 Write property test: Severity Weights Sum Validation (Property 11)
    - **Property 11: Severity Weights Sum Validation**
    - For any dict of weights not summing to 1.0 (within tolerance), constructing `AnalysisConfig` raises `ValidationError`
    - **Validates: Requirements US-006 (6.1)**

  - [ ]* 8.3 Write unit tests for config models
    - Test valid construction of all sub-configs, `LokiConfig.from_yaml()` with a YAML fixture, invalid weights rejection
    - _Requirements: US-006 (6.1, 6.2, 6.3)_

- [x] 9. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Wire up `__init__.py` re-exports and serialization round-trip tests
  - [x] 10.1 Populate `loki/models/__init__.py` with re-exports of all public models and enums
    - Import and re-export every public model and enum so consumers can do `from loki.models import FirmwareImage, ClassificationRecord, LokiConfig`
    - _Requirements: Technical Constraints (package exports), Definition of Done (no circular imports)_

  - [ ]* 10.2 Write property test: JSON Serialization Round-Trip (Property 1)
    - **Property 1: JSON Serialization Round-Trip**
    - For any valid model instance, `model_validate_json(model_dump_json())` produces an equal object
    - Test across all model types: `FirmwareImage`, `ExtractedComponent`, `ExtractionManifest`, `AxisClassification`, `ClassificationRecord`, `BaselineRecord`, `BaselineComparison`, `DeviationScore`, `FindingRecord`, `ImageAnalysisReport`, `FleetAnalysisReport`, `LokiConfig`
    - **Validates: Requirements US-001 (1.1), US-002 (2.1, 2.2), US-003 (3.1, 3.2, 3.3), US-004 (4.1, 4.2), US-005 (5.1, 5.2, 5.3, 5.4), US-006 (6.1, 6.3)**

  - [ ]* 10.3 Write property test: YAML Serialization Round-Trip (Property 2)
    - **Property 2: YAML Serialization Round-Trip**
    - For any valid model instance, `model_validate(yaml.safe_load(yaml.safe_dump(model_dump())))` produces an equal object
    - Test across all model types
    - **Validates: Requirements US-001 (1.1), US-002 (2.1, 2.2), US-003 (3.1, 3.2, 3.3), US-004 (4.1, 4.2), US-005 (5.1, 5.2, 5.3, 5.4), US-006 (6.1, 6.3)**

  - [ ]* 10.4 Write smoke tests for package imports
    - Verify `from loki.models import *` succeeds without circular import errors
    - Verify all public models are accessible from `loki.models`
    - _Requirements: Technical Constraints (no circular imports), Definition of Done_

- [x] 11. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints at tasks 4, 9, and 11 ensure incremental validation
- Property tests use Hypothesis with `@settings(max_examples=100)` and custom strategies for generating valid model instances
- Unit tests use pytest with representative example data
- All models use `ConfigDict(strict=True, frozen=False)` per technical constraints
