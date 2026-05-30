
# Requirements: LOKI Data Models

## Overview

Define all core data models for the LOKI firmware analysis platform. Models serve as the shared type system imported by every other subsystem (CLI, extraction, classification, baseline, analysis). All models must be serializable to JSON and YAML, validated on construction, and documented with field-level descriptions.

## Tech Stack

- Python 3.11+
- Pydantic v2 (BaseModel with strict validation)
- Package path: `loki/models/`
- Serialization: `.model_dump_json()` / `.model_dump()` with YAML export via `pyyaml`

## User Stories

### US-001: Firmware Image Model
**As** an analyst running a scan,
**I want** a typed representation of a firmware image and its metadata,
**So that** every downstream operation references a consistent image identity.

**Acceptance Criteria:**
- `FirmwareImage` model with fields: image_id (auto-generated UUID), file_path, file_hash (SHA-256), file_size, vendor (optional), model (optional), firmware_version (optional), extraction_timestamp (optional, ISO-8601)
- image_id generated deterministically from file_hash if not provided
- Validates file_hash format on construction

### US-002: Extracted Component Model
**As** the extraction pipeline,
**I want** a typed representation of each extracted firmware component,
**So that** classification and analysis receive structured input.

**Acceptance Criteria:**
- `ExtractedComponent` model with fields: component_id (UUID), source_image_id, offset (hex string), size, raw_hash (SHA-256), component_type_hint (optional string), guid (optional string), name (optional string), raw_path (optional file path to extracted bytes)
- `ExtractionManifest` model containing: source_image (FirmwareImage reference), components (list of ExtractedComponent), extraction_timestamp, extractor_version, total_components count, extraction_errors (list of error records)

### US-003: Classification Record Model
**As** the classification pipeline,
**I want** typed models for every taxonomic axis and the composite classification record,
**So that** classification output is validated and self-documenting.

**Acceptance Criteria:**
- Enum types for each axis: `ComponentTypeLabel`, `VendorLabel`, `SecurityPostureLabel`, `MutabilityLabel`
- `AxisClassification` model with fields: label (enum), confidence (float 0.0-1.0), method (enum: signature, rule, heuristic), rule_id (optional), evidence (optional list of strings)
- `SignatureInfo` model with fields: present (bool), verified (bool), signer (optional string), cert_expiry (optional ISO-8601)
- `ClassificationRecord` model with fields: component_id, source_image_id, extraction_offset, timestamp, axes (type, vendor, security, mutability — each an AxisClassification), security-specific fields (signature_info, cve_matches list, suspicion_triggers list), composite_confidence (float), needs_review (bool), classification_version, overrides (list of OverrideRecord)
- `OverrideRecord` model with fields: original_label, override_label, analyst, timestamp, justification (required string)
- Composite confidence auto-calculated as min of all axis confidences
- needs_review auto-set to True if any axis confidence below 0.60

### US-004: Baseline Models
**As** the baseline management subsystem (GLEIPNIR),
**I want** typed models for baseline records, registry, and comparison output,
**So that** baseline CRUD and deviation analysis operate on validated structures.

**Acceptance Criteria:**
- `BaselineRecord` model with fields: baseline_id (UUID), name, vendor, model, firmware_version, created_timestamp, notes (optional), component_manifest (list of ClassificationRecord), source_image_hash, baseline_version (semver string)
- `BaselineRegistry` model as a container for multiple BaselineRecord entries with lookup by id, vendor+model, and vendor+model+version
- `DeltaType` enum: ADDED, REMOVED, MODIFIED, RECLASSIFIED, UNCHANGED
- `BaselineComparison` model with fields: baseline_id, target_image_id, comparison_timestamp, deviations (list of DeviationRecord), summary (added/removed/modified/reclassified/unchanged counts)
- `DeviationRecord` model with fields: deviation_id, component_id, delta_type, baseline_state (optional ClassificationRecord), target_state (optional ClassificationRecord), description

### US-005: Analysis and Report Models
**As** the analysis engine,
**I want** typed models for findings, severity scoring, deviation scoring, and all report types,
**So that** report assembly produces validated, schema-conformant output.

**Acceptance Criteria:**
- `SeverityLevel` enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `PostureRating` enum: COMPROMISED, AT_RISK, DEGRADED, BASELINE, HARDENED
- `DeviationScore` model with fields: base_severity, component_criticality (float), security_direction (enum: DEGRADED, UNCHANGED, IMPROVED), signature_delta (enum: LOST, GAINED, CHANGED, NONE), cve_introduced (bool), mutability_change (enum: BECAME_MUTABLE, BECAME_READONLY, NONE), composite_score (float 0.0-10.0), priority_rank (int)
- `FindingRecord` model with fields: finding_id, component_id, severity, category (string), title, description, evidence (classification_record ref, matched_rule, matched_cve, matched_signature, raw_indicators list), recommended_action (string)
- `ActionRecord` model with fields: action_id, finding_id, action_type, description, reference (optional string)
- `ImageAnalysisReport` model with fields: report_id, timestamp, analysis_version, image_id, image_metadata (FirmwareImage), posture_rating, summary (component counts + finding counts by severity), findings list, recommended_actions list, baseline_comparison (optional BaselineComparison)
- `FleetAnalysisReport` model with fields: report_id, timestamp, fleet_id, image_count, fleet_posture (counts per PostureRating), common_findings, outlier_images, systemic_risks, recommended_actions

### US-006: Configuration Models
**As** an operator configuring LOKI,
**I want** typed configuration models that validate on load,
**So that** misconfiguration is caught before pipeline execution.

**Acceptance Criteria:**
- `GeneralConfig` model: default_output_format (enum: human, json, yaml), color (enum: auto, always, never), verbosity (int), log_level (enum: debug, info, warn, error)
- `ExtractionConfig` model: default_output_dir, max_component_size, timeout_per_component
- `ClassificationConfig` model: taxonomy_version, confidence_threshold (float), rules_path
- `AnalysisConfig` model: severity_weights (dict of factor name to float, must sum to 1.0), default_severity_threshold, report_template
- `BaselineConfig` model: storage_path, auto_match (bool)
- `FeedsConfig` model: nvd_url, update_interval, cache_path, implant_rules_path
- `FleetConfig` model: default_severity_threshold, storage_path
- `LokiConfig` root model composing all sub-configs with YAML file loading via class method

## Technical Constraints

- All models inherit from Pydantic BaseModel with `model_config = ConfigDict(strict=True, frozen=False)`
- All timestamp fields use `datetime` type with ISO-8601 serialization
- All ID fields use `uuid.UUID` type with string serialization
- All hex offset fields use `str` type with `0x` prefix validation
- All hash fields use `str` type with SHA-256 format validation (64 hex chars)
- Enum types use Python `StrEnum` for JSON-friendly serialization
- Package exports all public models from `loki/models/__init__.py`
- Every model includes a docstring describing its role in the pipeline
- No circular imports — dependency order: enums -> base models -> composite models -> config models -> report models

## File Structure

    loki/
      __init__.py
      models/
        __init__.py          # Re-exports all public models
        enums.py             # All enum types
        firmware.py          # FirmwareImage, ExtractedComponent, ExtractionManifest
        classification.py    # AxisClassification, ClassificationRecord, OverrideRecord, SignatureInfo
        baseline.py          # BaselineRecord, BaselineRegistry, BaselineComparison, DeviationRecord
        analysis.py          # FindingRecord, DeviationScore, ActionRecord
        reports.py           # ImageAnalysisReport, FleetAnalysisReport
        config.py            # All config models + LokiConfig root

## Definition of Done

- All models instantiable with valid data
- All models reject invalid data with clear Pydantic validation errors
- All models serialize to JSON and deserialize back without data loss
- All models serialize to YAML via pyyaml
- `pytest` test suite covering: valid construction, invalid construction (validation errors), serialization round-trip, composite_confidence auto-calculation, needs_review auto-flag
- No circular import errors when importing from `loki.models`
- Type hints pass `mypy --strict`

