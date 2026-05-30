
# Implementation Plan

## Overview

This is the executable task list for the **analysis-engine** spec. Tasks are ordered so that each one builds on previous tasks and leaves the repo in a verifiable state (every checkpoint passes `pytest`, `mypy --strict`, `ruff check`, and `ruff format --check`).

Each task lists the exact files it touches, the test surface it adds, and the design / requirement references it implements. Sub-bullets under each task are checklist items the implementer ticks off as they go; they are not separate tasks.

Honest scope reminder: this plan covers the analysis engine only. Per the requirements introduction, fleet analysis (`analyze_fleet`), CVE matching, signature verification, persistence of `ImageAnalysisReport`, analyst overrides, the `loki analyze` CLI surface, and the GUI analysis view are explicitly out of scope and have their own (future) specs. v1 ships only the library API at `from loki.analysis import analyze_image`.

The seven design defaults locked in at the design CAST gate (D1: free function, not class; D2: `errors.py` module; D3: `FindingEvidence.deviation_score` direct model-layer extension; D4: `AnalysisConfig` extensions direct model-layer; D5: `MatchStrategy` StrEnum in `enums.py`; D6: `AnalysisProgressEvent` strips `component_id`; D7: Properties P43-P52) are baked into this task list. The eighth deferred decision (D8: multi-paragraph property descriptions accepted with non-blocking format-checker warnings) does not affect implementation.

## Pre-flight checklist

Before starting, confirm the repo is healthy:

```bash
.venv/bin/pytest -q
.venv/bin/mypy --strict loki tests scripts
.venv/bin/ruff check
.venv/bin/ruff format --check
```

All four must be green. The current checkpoint per `loki/HANDOFF.md` is **897 passed, 6 deselected** with mypy clean across **176 source files**. The analysis work assumes the model layer, extraction pipeline, baseline-persistence, and classification-pipeline subsystems are all intact and at their v1 contracts.

The analysis subsystem's threat context is STANDARD per the loom harness. No new credential handling, no new network egress, no new destructive operations — analysis reads `ClassificationRecord` / `BaselineRecord` instances from in-memory inputs and produces an `ImageAnalysisReport` to the caller.

## Tasks

- [x] 1. Scaffold the `loki/analysis/` package skeleton

  - Create `loki/analysis/__init__.py`, `api.py`, `pipeline.py`, `version.py`, `matching.py`, `pairing.py`, `findings.py`, `scoring.py`, `posture.py`, `report.py`, `errors.py`, `timing.py` as empty modules with docstrings + `__all__: list[str] = []`.
  - Create `tests/analysis/__init__.py` and an empty `tests/analysis/conftest.py` so pytest can collect from the new tree.
  - Verify the empty subsystem imports cleanly: `.venv/bin/python -c "import loki.analysis"`.
  - Run the four verification gates and confirm test count is unchanged (897 / 6 deselected). Source file count rises from 176 to 188 (12 new modules + 2 new test-tree modules; one is `__init__.py` which counts).
  - _Requirements: none — pure scaffolding_
  - _Design: Architecture — Module layout_


- [x] 2. Implement the `ANALYSIS_VERSION` constant module

  - In `loki/analysis/version.py` define `ANALYSIS_VERSION: str = "1.0.0"`.
  - Document in the module docstring that R1.5 contracts a semver string in `^\d+\.\d+\.\d+$` form, that R15.8's `report_id` derivation is keyed on this value, and that a minor bump is required when any finding-emission or scoring behavior changes (currently a manual discipline; future work could enforce via a property test).
  - Re-export `ANALYSIS_VERSION` from `loki.analysis.__init__`.
  - Add `tests/analysis/test_version.py` covering: the constant exists, is a string, and matches `^\d+\.\d+\.\d+$`.
  - _Requirements: 1.5, 15.8_
  - _Design: Architecture — Module layout_

- [x] 3. Add the `MatchStrategy` StrEnum (D5 default)

  - In `loki/models/enums.py` append a `MatchStrategy(StrEnum)` with three values: `EXPLICIT`, `AUTO`, `EXPLICIT_OR_AUTO`. Match the docstring style of the existing 14 StrEnums.
  - Add `MatchStrategy` to the module's `__all__` list.
  - Re-export `MatchStrategy` from `loki/models/__init__.py`.
  - Add `tests/analysis/test_match_strategy_enum.py` covering: the three values exist, serialize to the documented string forms, and are imported from both `loki.models` and `loki.models.enums`. (Existing `tests/test_enums.py` covers per-value invariants if it exists; otherwise mirror the pattern.)
  - Update the model-layer spec triple if it has an enum-coverage section that needs the new value.
  - _Requirements: 2.1, 14.2_
  - _Design: Data Models — `MatchStrategy` enum_

- [x] 4. Extend `AnalysisConfig` with `match_strategy`, `confidence_gap_threshold`, `baseline_id` (D4 default)

  - In `loki/models/config.py` extend the `AnalysisConfig` Pydantic model with three new fields:
    - `match_strategy: MatchStrategy = MatchStrategy.AUTO`
    - `confidence_gap_threshold: float = Field(default=0.6, ge=0.0, le=1.0)`
    - `baseline_id: uuid.UUID | None = None`
  - Add the necessary imports (`uuid`, `MatchStrategy`, `Field` if not already imported) at the top of `config.py`.
  - The existing `severity_weights` validator stays unchanged. The four-key set check (`{"type", "vendor", "security_posture", "mutability"}`) is enforced engine-side at run time by task 8 (matching), not at the model layer; this preserves the model layer's job-of-being-a-data-shape (the keyset check is engine-specific to v1's interpretation).
  - Update `tests/test_config.py` (or whatever covers `AnalysisConfig`) to:
    - Construct an `AnalysisConfig` with the three new fields supplied. Verify Pydantic accepts.
    - Construct an `AnalysisConfig` without the three new fields supplied. Verify the defaults apply.
    - Test `confidence_gap_threshold` rejection at `-0.1` and `1.1`.
    - Test `baseline_id` accepts a valid UUID and `None`.
    - Test the YAML round-trip via `LokiConfig.from_yaml` with all three new fields specified in the YAML.
  - _Requirements: 14.2, 14.3, 14.4_
  - _Design: Data Models — `AnalysisConfig` extension_

- [x] 5. Extend `FindingEvidence` with `deviation_score` (D3 default)

  - In `loki/models/analysis.py` extend the `FindingEvidence` Pydantic model with one new optional field: `deviation_score: DeviationScore | None = None`.
  - Order the field after `raw_indicators` so the JSON / YAML serialized order is predictable.
  - Existing call sites that construct `FindingEvidence(...)` keep their argument shape; the new field is optional and defaults to `None`.
  - The Pydantic strict-mode validator covers the new field automatically; no custom validator is needed.
  - Update `tests/test_analysis.py` (or `tests/test_models_analysis.py` if that's the file name) to:
    - Construct a `FindingEvidence` with `deviation_score=None` (default). Verify Pydantic accepts.
    - Construct a `FindingEvidence` with a valid `DeviationScore`. Verify the field round-trips through `model_dump`.
    - Verify the JSON serialization carries the new field when populated and omits it as `null` when default.
    - Verify the YAML round-trip preserves the populated `DeviationScore`.
  - _Requirements: 9.1_
  - _Design: Data Models — `FindingEvidence.deviation_score` extension_

- [x] 6. Implement the typed exception hierarchy (D2 default — `loki/analysis/errors.py`)

  - In `loki/analysis/errors.py` define:
    - `AnalysisError(Exception)` — root parent.
    - `AnalysisConfigError(AnalysisError)` carrying `field_name: str` and a free-form message.
    - `BaselineNotFoundError(AnalysisError)` carrying either `baseline_id: uuid.UUID` or `vendor_model_version: tuple[str, str, str]` (exactly one of the two; the constructor raises `ValueError` if both or neither are passed).
    - `AnalysisInputError(AnalysisError)` carrying `side: str` (literal `"target"` or `"baseline"`), `duplicates: list[uuid.UUID]`, and an optional `baseline_id: uuid.UUID | None` (set only when `side == "baseline"`).
    - `AnalysisReportConstructionError(AnalysisError)` carrying `loc: tuple[int | str, ...]` (the Pydantic field path) and a sanitized message.
  - Each exception has a typed `__init__` matching the design's documented kwargs.
  - Module docstring documents that `AnalysisError` is the only exception type that escapes the public `analyze_image` entry point, and that cooperative cancellation is a return-path (not a throw-path; no `AnalysisCancelledError` member in v1 per R16.6).
  - Re-export every exception class from `loki.analysis.__init__`.
  - Add `tests/analysis/test_errors.py` covering:
    - Every exception class is constructible with the documented kwargs.
    - All four are subclasses of `AnalysisError`.
    - `BaselineNotFoundError` rejects both `baseline_id` and `vendor_model_version` set together; rejects both unset; accepts exactly one.
    - `AnalysisInputError`'s `str()` includes the duplicate component_id values for the target side and the offending baseline_id for the baseline side.
    - `AnalysisReportConstructionError`'s `str()` includes the dotted `loc` path.
    - `AnalysisConfigError`'s `str()` includes the offending field_name.
  - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_
  - _Design: Architecture — Exception hierarchy; Error handling_

- [x] 7. Implement the timing helper

  - In `loki/analysis/timing.py` implement a `Stopwatch` context manager (`time.monotonic`-based) returning the wall-clock duration in milliseconds via a `duration_ms` property after exit. Mirror the classification timing module structure.
  - The module is the **single permitted clock-using module** inside `loki.analysis` (mirroring extraction + classification's pattern). The side-channels audit (task 22) pins this.
  - Add `tests/analysis/test_timing.py` covering: the stopwatch records monotonic time; `duration_ms` is `>= 0` after a no-op exit; using the stopwatch as a context manager records the duration on exit; `duration_ms` access before exit raises a documented exception (mirror classification's pattern).
  - _Requirements: 15.4_
  - _Design: Determinism — discipline 1 (no environmental side-channels); Property 51_


- [x] 8. Implement baseline matching (Match_Strategy resolution)

  - In `loki/analysis/matching.py` implement:
    - `validate_analysis_config(config: AnalysisConfig) -> None`: enforces R14.1's keyset check on `severity_weights` (`{"type", "vendor", "security_posture", "mutability"}`); raises `AnalysisConfigError` on violation. The model layer already enforces sum-to-1.0, the field-range validator on `confidence_gap_threshold`, and the StrEnum check on `match_strategy`; this helper covers only what the model layer doesn't.
    - `resolve_matched_baseline(config: AnalysisConfig, registry: BaselineRegistry, target_image: FirmwareImage) -> BaselineRecord`: implements R2's three-strategy resolution. Raises `AnalysisConfigError` when `match_strategy=EXPLICIT` but `baseline_id` is unset. Raises `BaselineNotFoundError` on lookup miss (carrying `baseline_id` for explicit-path miss, `(vendor, model, firmware_version)` for auto-path miss).
  - The two functions are pure (no logging, no side effects beyond their return values + raised exceptions).
  - Add `tests/analysis/test_matching.py` covering:
    - **Config validation:** valid four-key `severity_weights` accepts; missing `type` key raises; extra `extra_axis` key raises; `severity_weights={}` raises.
    - **EXPLICIT strategy:** `baseline_id` set + lookup hit returns the matched record; `baseline_id` set + lookup miss raises `BaselineNotFoundError(baseline_id=...)`; `baseline_id` unset raises `AnalysisConfigError`.
    - **AUTO strategy:** vendor+model+version triple finds a match; lookup miss raises `BaselineNotFoundError(vendor_model_version=...)` carrying the offending tuple.
    - **EXPLICIT_OR_AUTO strategy:** `baseline_id` set + lookup hit returns the matched record (no auto-fallback consulted); `baseline_id` set + lookup miss raises (per R2.5; no silent auto-fallback); `baseline_id` unset + auto-match hit returns the auto-matched record; `baseline_id` unset + auto-match miss raises.
    - **Read-only registry:** the registry / records passed in are not mutated by the resolver (use `model_dump` before/after).
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 14.1, 16.2, 16.3_
  - _Design: Sequence walkthrough — Matched_Baseline resolution; Architecture — `loki/analysis/matching.py`_

- [x] 9. Implement Component_Pairing logic

  - In `loki/analysis/pairing.py` implement:
    - `check_pairing_preconditions(target_records: Sequence[ClassificationRecord], baseline_manifest: list[ClassificationRecord], baseline_id: uuid.UUID) -> None`: enforces R3.6 + R3.7 by detecting duplicate `component_id` values on either side. Raises `AnalysisInputError(side="target", duplicates=[...])` for target-side duplicates; raises `AnalysisInputError(side="baseline", duplicates=[...], baseline_id=...)` for baseline-side duplicates.
    - `build_baseline_index(baseline_manifest: list[ClassificationRecord]) -> dict[uuid.UUID, ClassificationRecord]`: returns the dict keyed by `component_id` for O(1) pairing lookup (R18.2). Pre-condition: no duplicates (enforced by the precondition checker).
    - `pair_records(target_records, baseline_index) -> Iterator[tuple[ClassificationRecord, ClassificationRecord | None]]`: yields `(target, paired_baseline)` tuples in target-input order; `paired_baseline` is `None` for unpaired Target_Records.
    - `unpaired_baselines(baseline_index, consumed_ids) -> list[ClassificationRecord]`: returns the list of baseline records whose `component_id` was not consumed during pairing, sorted by ascending `component_id` (R3.4).
  - The four functions are pure.
  - Add `tests/analysis/test_pairing.py` covering:
    - **Duplicate detection:** target-side duplicate raises with both component_ids in the message; baseline-side duplicate raises with the baseline_id and both component_ids; unique on both sides accepts.
    - **Pairing iteration:** preserves target input order; emits `None` for unpaired target records; emits the matched baseline for paired records.
    - **Unpaired baselines sort:** ascending `component_id` order; empty when every baseline was consumed.
    - **Linear time over the union of inputs:** smoke check (not a strict perf assertion) that 1024+1024 pairing completes under a generous wall-clock budget.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 16.4, 18.2_
  - _Design: Sequence walkthrough — Component_Pairing; Architecture — `loki/analysis/pairing.py`_

- [x] 10. Implement `derive_finding_id` and the Cancellation_Marker helper

  - In `loki/analysis/findings.py` implement:
    - `derive_finding_id(*, baseline_id: uuid.UUID, finding_category: str, target_component_id: uuid.UUID) -> uuid.UUID`: returns `uuid.uuid5(LOKI_NAMESPACE, f"{baseline_id}:{finding_category}:{target_component_id}")` per R15.7. Pure.
    - `ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID: uuid.UUID = uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")` module constant per R7.2.
    - `make_cancellation_marker(*, baseline_id: uuid.UUID, cancelled_at_index: int) -> FindingRecord` constructing the Cancellation_Marker per R7.1-R7.7. The marker carries `severity=SeverityLevel.INFO`, `component_id=ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID`, `title="analysis cancelled"`, `description="cooperative cancellation observed; partial findings returned"`, `evidence.raw_indicators=[f"cancelled-at-index={cancelled_at_index}"]`, and `recommended_action=""` (v1 leaves recommended_actions at the model default per R17.3; the per-finding `recommended_action: str` field on `FindingRecord` is required but not part of `recommended_actions: list[ActionRecord]`).
  - Add `tests/analysis/test_finding_id.py` covering:
    - **Determinism:** same `(baseline_id, category, target_component_id)` produces same UUID across two calls.
    - **Distinct categories produce distinct UUIDs:** `classification_mismatch` vs `signature_regression` for the same `(baseline_id, target_component_id)` pair.
    - **Distinct baselines produce distinct UUIDs:** different `baseline_id` for the same `(category, target_component_id)` pair.
    - **Sentinel UUID:** `ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID` is bit-equal to `uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")`.
  - Add `tests/analysis/test_cancellation_marker.py` covering:
    - **Field invariants:** `severity == INFO`, `component_id == sentinel`, `title == "analysis cancelled"`, `description == "cooperative cancellation observed; partial findings returned"`, `evidence.raw_indicators == [f"cancelled-at-index={N}"]` for various N.
    - **Deterministic finding_id:** two cancellations of the same baseline at any index produce the same `finding_id` per R7.7.
    - **Pydantic round-trip:** the constructed Cancellation_Marker round-trips through `FindingRecord.model_dump_json` + `model_validate_json`.
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.7, 15.7_
  - _Design: Per-category finding emitters — `derive_finding_id`; Architecture — Cancellation_Marker_


- [x] 11. Implement scoring helpers (Axis_Score, Composite_Score, DeviationScore axes)

  - In `loki/analysis/scoring.py` implement six pure functions per the design's "Per-category finding emitters" → scoring helpers section:
    - `axis_score(target_axis: AxisClassification, baseline_axis: AxisClassification) -> float`: returns `0.0` if labels agree, `target.confidence * baseline.confidence` if they disagree (R9.3). Result lies in `[0.0, 1.0]`.
    - `composite_score(*, type_score, vendor_score, security_score, mutability_score, severity_weights: dict[str, float]) -> float`: returns `10.0 * sum(w_i * s_i)` over the four `(type, vendor, security_posture, mutability)` keys (R9.4). Result lies in `[0.0, 10.0]`.
    - `base_severity_from_composite(score: float) -> SeverityLevel`: returns `CRITICAL` for `>= 8.0`, `HIGH` for `>= 6.0`, `MEDIUM` for `>= 4.0`, `LOW` for `>= 2.0`, `INFO` otherwise (R10.7).
    - `security_direction(target_label, baseline_label) -> SecurityDirection`: implements R11's three-way mapping.
    - `signature_delta(target_sig, baseline_sig) -> SignatureDelta`: implements R12's mapping; v1 never returns `CHANGED` per R12.3.
    - `mutability_change(target_label, baseline_label) -> MutabilityChange`: implements R13's three-way mapping.
  - All six functions are pure: no logging, no side effects, deterministic.
  - Module docstring documents the v1 reservations: `SignatureDelta.CHANGED` is reserved for a future revision per R12.3.
  - Add `tests/analysis/test_scoring.py` covering each helper with both example-based and Hypothesis-based tests:
    - **`axis_score`:** identical labels → 0.0; disagreeing labels → confidence product; result always in `[0.0, 1.0]`.
    - **`composite_score`:** weighted sum produces value in `[0.0, 10.0]`; max-disagree on every axis with full confidence on both sides → 10.0; full-agree on every axis → 0.0; arbitrary inputs respect the formula bit-exactly.
    - **`base_severity_from_composite`:** the five threshold boundaries (0.0, 2.0, 4.0, 6.0, 8.0, 10.0) map to `INFO, LOW, MEDIUM, HIGH, CRITICAL` per the closed mapping.
    - **`security_direction`:** all 9 label pairings (3x3) map to the documented direction.
    - **`signature_delta`:** all 4 documented input cases (and the None-on-either-side case) map correctly; v1 never returns `CHANGED`.
    - **`mutability_change`:** all 9 label pairings (3x3) map to the documented direction.
  - _Requirements: 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 10.7, 11.1, 11.2, 11.3, 12.1, 12.2, 12.3, 12.4, 13.1, 13.2, 13.3_
  - _Design: Per-category finding emitters — scoring helpers; Property 46_

- [x] 12. Implement PostureRating derivation (R17.5 six-rule cascade)

  - In `loki/analysis/posture.py` implement:
    - `derive_posture_rating(findings: Sequence[FindingRecord]) -> PostureRating`: walks the finding list once, collecting the four flags (`has_signature_regression_high`, `has_missing_required`, `has_classification_mismatch_critical`, `has_any_finding`) and the `max_classification_mismatch_score`. Returns the matching rating per the six-rule cascade in the design's PostureRating derivation section.
  - The function is pure.
  - Add `tests/analysis/test_posture.py` covering each cascade rule:
    - **Rule 1a (signature_regression: HIGH):** finding list with one `signature_regression` of severity HIGH → `COMPROMISED`.
    - **Rule 1b (missing_required_component):** finding list with one `missing_required_component` (any severity; v1 always HIGH) → `COMPROMISED`.
    - **Rule 1c (classification_mismatch: CRITICAL — G4-B HARDEN):** finding list with one `classification_mismatch` whose `evidence.deviation_score.composite_score == 8.0` → `COMPROMISED`. Boundary value 8.0 inclusive.
    - **Rule 2 (AT_RISK):** finding list with one `classification_mismatch` whose `composite_score == 6.0` → `AT_RISK`. Boundary value 6.0 inclusive. `composite_score == 7.99` → `AT_RISK` (just below CRITICAL).
    - **Rule 3 (DEGRADED — score-based):** finding list with one `classification_mismatch` whose `composite_score == 2.0` → `DEGRADED`. Boundary value 2.0 inclusive. `composite_score == 5.99` → `DEGRADED`.
    - **Rule 4 (DEGRADED — catch-all G3-A HARDEN):** finding list with **only** `unexpected_component` (severity MEDIUM) → `DEGRADED` via catch-all. Same with **only** `signature_regression: MEDIUM`. Same with **only** `classification_gap`. Same with **only** `analysis_cancelled`. Same with a mix of MEDIUM/LOW non-COMPROMISED-trigger findings.
    - **Rule 5 (BASELINE):** empty finding list → `BASELINE`.
    - **HARDENED reserved:** for every test input, the function never returns `HARDENED`.
    - **Cascade ordering:** finding list with both `signature_regression: HIGH` and `classification_mismatch: 6.0` → `COMPROMISED` (rule 1 wins, not rule 2). Finding list with `classification_mismatch: 8.0` AND `classification_mismatch: 6.0` → `COMPROMISED` (rule 1c).
    - **Multi-finding monotonicity:** adding a new `classification_mismatch: 5.0` finding to an existing `BASELINE` rating produces `DEGRADED` (rule 3); adding a new `signature_regression: HIGH` to any non-COMPROMISED rating produces `COMPROMISED`.
  - Property test: any combination of randomly-generated findings produces a defined rating; the result is one of `{COMPROMISED, AT_RISK, DEGRADED, BASELINE}`. Validates Property 49.
  - _Requirements: 17.5 (post-HARDEN amendment)_
  - _Design: PostureRating derivation; Property 49_


- [x] 13. Implement the `classification_mismatch` finding emitter

  - In `loki/analysis/findings.py` add `emit_classification_mismatch(*, target: ClassificationRecord, baseline: ClassificationRecord, matched_baseline_id: uuid.UUID, severity_weights: dict[str, float]) -> FindingRecord` per R4.1-R4.8.
  - The emitter:
    - Computes the four `Axis_Score` values via `axis_score()` for each of the four axes.
    - Computes `composite_score` via `composite_score()`.
    - Derives `base_severity` via `base_severity_from_composite()` (R10.7).
    - Computes `security_direction`, `signature_delta`, `mutability_change` via the matching helpers.
    - Sets `component_criticality = baseline.composite_confidence` per R9.7.
    - Sets `cve_introduced = False` per R9.9.
    - Constructs a `DeviationScore` with `priority_rank=0` as a placeholder; the pipeline's second pass fills in the real rank per R9.10.
    - Constructs a `FindingRecord` with `category="classification_mismatch"`, `severity=base_severity`, `component_id=target.component_id`, `evidence.classification_record=target`, `evidence.deviation_score=<the constructed DeviationScore>`, deterministic `finding_id` via `derive_finding_id`, and templated `title` + `description` strings derived from the disagreeing axes (both fields are in the Forbidden_Leakage_Field_Set; never logged).
  - Pre-condition enforced by the pipeline (not the emitter): at least one axis label disagrees per R4.2; emitter does not double-check.
  - Add `tests/analysis/test_findings_classification_mismatch.py` covering:
    - **Single-axis mismatch:** type axis disagrees, others agree → emits one finding; `DeviationScore.composite_score` reflects only the one axis weighted by `severity_weights["type"] * 10.0 * (target.confidence * baseline.confidence)`.
    - **All-axes mismatch:** all four axes disagree at full confidence → `composite_score == 10.0` → severity `CRITICAL`.
    - **No-axis mismatch:** every axis agrees → emitter is not called by the pipeline (pre-condition); direct call would still produce a finding with `composite_score == 0.0` and severity `INFO` (defensive).
    - **DeviationScore embedding:** `finding.evidence.deviation_score` is non-None and carries the four `DeviationScore` axes (`security_direction`, `signature_delta`, `mutability_change`, `component_criticality`).
    - **finding_id derivation:** stable across two emitter calls with the same inputs.
    - **Severity boundary:** `composite_score == 6.0` → `severity == HIGH`; `composite_score == 7.99` → `severity == HIGH`; `composite_score == 8.0` → `severity == CRITICAL`.
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 9.1, 9.2, 9.3, 9.4, 9.6, 9.7, 9.8, 9.9, 10.7, 11, 12, 13_
  - _Design: Per-category finding emitters — `classification_mismatch`_

- [x] 14. Implement the `signature_regression` finding emitter

  - In `loki/analysis/findings.py` add `emit_signature_regression(*, target: ClassificationRecord, baseline: ClassificationRecord, matched_baseline_id: uuid.UUID) -> FindingRecord` per R5.1-R5.6.
  - The emitter:
    - Determines direction: baseline-signed/target-unsigned (severity HIGH, evidence.matched_signature `"BASELINE_SIGNED"`) vs the reverse (severity MEDIUM, evidence.matched_signature `"TARGET_SIGNED"`).
    - Sets `category="signature_regression"`, `component_id=target.component_id`, `evidence.classification_record=target`, deterministic `finding_id`.
    - Does NOT construct a `DeviationScore` (R9.11; only classification_mismatch findings carry one).
    - Title and description templates per the design's emitter spec (no leakage).
  - Pre-condition enforced by the pipeline: both `target.signature_info` and `baseline.signature_info` are non-None and `present` differs (R5.1, R5.2).
  - Add `tests/analysis/test_findings_signature_regression.py` covering:
    - **Baseline-signed, target-unsigned:** severity `HIGH`, `evidence.matched_signature == "BASELINE_SIGNED"`.
    - **Target-signed, baseline-unsigned:** severity `MEDIUM`, `evidence.matched_signature == "TARGET_SIGNED"`.
    - **`evidence.deviation_score` is None.**
    - **finding_id stability** across two calls with the same inputs.
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 9.11_
  - _Design: Per-category finding emitters — `signature_regression`_

- [x] 15. Implement the `unexpected_component` finding emitter

  - In `loki/analysis/findings.py` add `emit_unexpected_component(*, target: ClassificationRecord, matched_baseline_id: uuid.UUID) -> FindingRecord` per R6.1-R6.7.
  - The emitter:
    - Sets `category="unexpected_component"`, `severity=SeverityLevel.MEDIUM` (flat per R6.5), `component_id=target.component_id`, `evidence.classification_record=target`, deterministic `finding_id`.
    - Does NOT construct a `DeviationScore` (R9.11).
  - Pre-condition enforced by the pipeline: target.component_id is unpaired in the baseline_index per R6.1.
  - Add `tests/analysis/test_findings_unexpected_component.py` covering:
    - **Severity flat MEDIUM:** independent of any input axis or signature info.
    - **`evidence.classification_record == target`:** the unpaired Target_Record itself.
    - **`evidence.deviation_score` is None.**
    - **finding_id stability** across two calls.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 9.11_
  - _Design: Per-category finding emitters — `unexpected_component`_

- [x] 16. Implement the `missing_required_component` finding emitter

  - In `loki/analysis/findings.py` add `emit_missing_required_component(*, baseline: ClassificationRecord, matched_baseline_id: uuid.UUID) -> FindingRecord` per R8.1-R8.6.
  - The emitter:
    - Sets `category="missing_required_component"`, `severity=SeverityLevel.HIGH` (flat per R8.5), `component_id=baseline.component_id` (baseline's id, since target carries no record per R8.3), `evidence.classification_record=baseline`, deterministic `finding_id` derived with `target_component_id=baseline.component_id`.
    - Does NOT construct a `DeviationScore` (R9.11).
  - Pre-condition enforced by the pipeline: baseline.component_id is unpaired in the target_records sequence per R8.1.
  - Add `tests/analysis/test_findings_missing_required.py` covering:
    - **Severity flat HIGH.**
    - **`component_id == baseline.component_id`:** the field's value comes from the baseline manifest, not from any target record.
    - **`evidence.classification_record == baseline`:** the unpaired baseline record itself.
    - **`evidence.deviation_score` is None.**
    - **finding_id stability** across two calls.
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 9.11_
  - _Design: Per-category finding emitters — `missing_required_component`_

- [x] 17. Implement the `classification_gap` finding emitter

  - In `loki/analysis/findings.py` add `emit_classification_gap(*, target: ClassificationRecord, matched_baseline_id: uuid.UUID) -> FindingRecord` per R10.1-R10.6.
  - The emitter:
    - Sets `category="classification_gap"`, `severity=SeverityLevel.LOW` (flat per R10.6; gaps are diagnostic, not threats), `component_id=target.component_id`, `evidence.classification_record=target`, deterministic `finding_id`.
    - Does NOT construct a `DeviationScore` (R9.11).
  - Pre-condition enforced by the pipeline: `target.composite_confidence < config.confidence_gap_threshold` per R10.1.
  - Add `tests/analysis/test_findings_classification_gap.py` covering:
    - **Severity flat LOW.**
    - **Fires for paired Target_Records:** when target.composite_confidence is below threshold and a baseline counterpart exists; the classification_gap finding is independent of pairing per R10.2.
    - **Fires for unpaired Target_Records:** when target.composite_confidence is below threshold and no baseline counterpart exists per R6.7.
    - **`evidence.deviation_score` is None.**
    - **finding_id stability** across two calls.
  - _Requirements: 6.7, 9.11, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_
  - _Design: Per-category finding emitters — `classification_gap`_


- [x] 18. Implement report assembly

  - In `loki/analysis/report.py` implement:
    - `assign_priority_ranks(findings: list[FindingRecord]) -> None`: in-place mutation of `classification_mismatch` findings' embedded `DeviationScore.priority_rank` per R9.10. Sort by descending `composite_score` with ties broken by ascending `component_id`; lowest rank integer (1) corresponds to the highest-Composite_Score finding. Non-`classification_mismatch` findings are untouched.
    - `derive_report_id(*, target_image_id: uuid.UUID, baseline_id: uuid.UUID, analysis_version: str) -> uuid.UUID`: returns `uuid.uuid5(LOKI_NAMESPACE, f"{target_image_id}:{baseline_id}:{analysis_version}")` per R15.8.
    - `assemble_report(*, target_image: FirmwareImage, matched_baseline: BaselineRecord, findings: list[FindingRecord], run_started_at: datetime, posture_rating: PostureRating) -> ImageAnalysisReport`: constructs the final `ImageAnalysisReport` per R17, including the `BaselineComparison` whose `comparison_timestamp` equals `run_started_at` per R17.4 post-HARDEN, `deviations=[]` per R17.4, and `recommended_actions=[]` per R17.3. Wraps any `pydantic.ValidationError` raised during construction as `AnalysisReportConstructionError` per R16.5.
  - The three functions are pure (the `assign_priority_ranks` mutator mutates only the input list it received; no global state).
  - Add `tests/analysis/test_report.py` covering:
    - **`assign_priority_ranks` correctness:** three classification_mismatch findings with composite_scores `(7.0, 4.0, 8.5)` end up with ranks `(2, 3, 1)` respectively; tied composite_scores break by ascending `component_id`.
    - **Priority pass leaves non-mismatch findings untouched:** an `unexpected_component` finding's `evidence.deviation_score` remains `None`.
    - **`derive_report_id` determinism:** same `(target_image_id, baseline_id, analysis_version)` produces same UUID; different `analysis_version` produces a different UUID (ANALYSIS_VERSION-keyed contract per R15.8).
    - **`assemble_report` happy path:** constructs an `ImageAnalysisReport` with the expected `report_id`, `timestamp == run_started_at`, `image_metadata == target_image`, `posture_rating == passed-in value`, `findings == passed-in list`, `recommended_actions == []`, `baseline_comparison.baseline_id == matched_baseline.baseline_id`, `baseline_comparison.target_image_id == target_image.image_id`, `baseline_comparison.comparison_timestamp == run_started_at`, `baseline_comparison.deviations == []`.
    - **`AnalysisReportConstructionError` wrapping:** force a Pydantic validation failure (e.g. by passing a malformed `FindingRecord` constructed via `model_construct`) and verify the exception's `loc` and `message` are populated and that no value from the Forbidden_Leakage_Field_Set appears in the message.
    - **Round-trip:** the assembled report serializes losslessly through `model_dump_json` + `model_validate_json` (R15.5, R17.6).
  - _Requirements: 9.10, 15.5, 15.8, 16.5, 17.1, 17.2, 17.3, 17.4 (post-HARDEN), 17.6_
  - _Design: Sequence walkthrough — priority_rank second pass, BaselineComparison construction, report assembly; Architecture — `loki/analysis/report.py`_

- [x] 19. Implement the `AnalysisPipeline` (internal)

  - In `loki/analysis/pipeline.py` implement `AnalysisPipeline`:
    - **Constructor** validates `config` via `validate_analysis_config` (R14), resolves the Matched_Baseline via `resolve_matched_baseline` (R2), and runs `check_pairing_preconditions` (R3.6, R3.7). All three may raise typed exceptions before any finding emission.
    - **`run` method** orchestrates the sequence walkthrough end-to-end:
      1. Capture `run_started_at = datetime.now(UTC)` (single timestamp anchor per R1.6).
      2. INFO log per R20.1: matched-baseline `(vendor, model, firmware_version, baseline_version)` tuple, target count, configured `match_strategy`. SHALL NOT log `baseline_id` or `source_image_hash`.
      3. Open a `Stopwatch` from the timing module.
      4. Build `baseline_index` via `build_baseline_index`.
      5. Iterate `target_records` in input order. At the top of each iteration: check `cancel()`; if True, emit Cancellation_Marker via `make_cancellation_marker` and break (R7.1). Otherwise call `progress(AnalysisProgressEvent(index=index, total=N))` if a callback is supplied (R19.2).
      6. For each Target_Record: pair via `baseline_index.get(target.component_id)`. If unpaired, emit `unexpected_component`. If paired and any axis disagrees, emit `classification_mismatch`. If paired and signature_info.present differs (both non-None), emit `signature_regression`. Independent of pairing: if `target.composite_confidence < config.confidence_gap_threshold`, emit `classification_gap`.
      7. After the target-loop completes (or after cancellation), iterate `unpaired_baselines` in ascending component_id order and emit one `missing_required_component` per record (only if cancellation did NOT fire — per R7.1, no further per-pair / unexpected / missing emissions after the marker).
      8. Run `assign_priority_ranks` (in-place) over the assembled findings list (R9.10).
      9. Derive `posture_rating` via `derive_posture_rating(findings)` (R17.5).
      10. Construct `report_id` via `derive_report_id`.
      11. Construct the `ImageAnalysisReport` via `assemble_report`.
      12. INFO log per R20.2: stopwatch's `duration_ms` and per-category counts (`classification_mismatch=N1, signature_regression=N2, unexpected_component=N3, missing_required_component=N4, classification_gap=N5, analysis_cancelled=N6`).
      13. Return the report.
    - The pipeline is single-use (one `run` call per pipeline instance, per the classification pattern). Holds no per-run mutable state across calls.
    - The class is `loki.analysis.pipeline:AnalysisPipeline` and is **not** re-exported from `loki.analysis.__init__` per D1 (free-function public surface).
  - The `loki.analysis` logger emits only the two INFO records and any WARNING records on internal exception paths per R20.4. No per-finding log records (R20.3).
  - Add `tests/analysis/test_pipeline.py` covering:
    - **Constructor fails fast:** invalid config → `AnalysisConfigError`; baseline lookup miss → `BaselineNotFoundError`; duplicate target component_id → `AnalysisInputError(side="target", ...)`; duplicate baseline component_id → `AnalysisInputError(side="baseline", baseline_id=...)`. None of these construct a partial pipeline state.
    - **Empty target_records (R1.3):** returns an `ImageAnalysisReport` with `findings=[]`, `summary.findings_by_severity={}`, posture rating `BASELINE`. Matched_Baseline is still resolved.
    - **Two-paragraph happy path:** target_records with one paired-disagree + one unpaired + one missing-required → three findings in the documented order. Verify priority_rank assigned to the classification_mismatch.
    - **Combined per-pair findings:** a paired component that disagrees on type + has signature regression + has low composite_confidence emits three findings (classification_mismatch, signature_regression, classification_gap) all with the same `component_id` but distinct `finding_id` values per R4.8.
    - **Cancellation:** cancellation fires at index 5 of 10; the report carries findings 1-4's emissions plus the Cancellation_Marker as the last entry; no missing_required_component findings appear (per R7.1, the post-cancellation pass is skipped).
    - **Progress callback contract:** progress is invoked once per Target_Record at the start of that record's per-pair evaluation; called from the calling thread only; carries `index` (1-based) and `total` (input length); does NOT carry `component_id` per D6.
    - **Determinism (smoke):** two runs on the same inputs produce equal reports under `model_dump(mode="json")` after stripping `timestamp`. Full Hypothesis property in task 23.
    - **No state leakage across calls:** two consecutive runs on the same pipeline instance? — Not supported per the single-use contract. Two consecutive `analyze_image` calls (each constructing a fresh pipeline) on the same inputs produce equal reports.
    - **R20.1 + R20.2 log content:** captured INFO records carry the documented fields and ONLY those fields (no `baseline_id`, no `source_image_hash`, no `component_id` from any finding).
  - _Requirements: 1.1-1.11, 2 (via construction), 3 (via construction), 4-13 (per-pair + per-side emission), 14 (via construction), 15 (determinism orchestration), 17 (report construction), 18.4 (synchronous), 19.2-19.4 (progress callback / logger name), 20.1, 20.2_
  - _Design: Sequence walkthrough; Architecture — `AnalysisPipeline`_

- [x] 20. Implement the public `analyze_image` entry point

  - In `loki/analysis/api.py` implement:
    - The `AnalysisProgressEvent` dataclass per the design's "Public API surface" section (D6 default — strips `component_id`).
    - Type aliases `AnalysisProgressCallback = Callable[[AnalysisProgressEvent], None]` and `AnalysisCancellationToken = Callable[[], bool]`.
    - The free-function `analyze_image(target_records, registry, target_image, config, *, progress=None, cancel=None) -> ImageAnalysisReport`. Constructs an `AnalysisPipeline` from the four inputs (which validates and resolves), then calls `pipeline.run(progress=progress, cancel=cancel)` and returns the result. No additional logic; the pipeline does the work.
  - Re-export from `loki/analysis/__init__.py` exactly:
    ```python
    from loki.analysis.api import (
        AnalysisProgressEvent,
        AnalysisProgressCallback,
        AnalysisCancellationToken,
        analyze_image,
    )
    from loki.analysis.errors import (
        AnalysisConfigError,
        AnalysisError,
        AnalysisInputError,
        AnalysisReportConstructionError,
        BaselineNotFoundError,
    )
    from loki.analysis.version import ANALYSIS_VERSION
    ```
  - The `__init__.py` module docstring documents the determinism contract per R15.1-R15.8.
  - Add `tests/analysis/test_api.py` covering:
    - **Public surface smoke:** every name in the documented re-export list is importable from `loki.analysis`.
    - **Happy-path call:** `analyze_image` with valid inputs returns a Pydantic-validated `ImageAnalysisReport`. The report's `analysis_version` matches `ANALYSIS_VERSION`.
    - **Cancellation contract:** passing a token that returns True at index 5 returns a partial report with the Cancellation_Marker as the last entry; the engine does NOT raise.
    - **Progress callback contract:** passing a callback receives one `AnalysisProgressEvent` per Target_Record processed; callback runs on the calling thread.
    - **No `loki.gui` import:** importing `loki.analysis` does not trigger any `loki.gui` import (R1.9). Verify via `sys.modules` snapshot before/after.
  - _Requirements: 1.1, 1.2, 1.3, 1.7, 1.9, 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7_
  - _Design: Architecture — Public API surface; Architecture — Module re-exports_


- [x] 21. Add the static side-channels AST audit

  - Add `tests/analysis/test_no_side_channels.py` mirroring `tests/extraction/test_no_side_channels.py` and `tests/classification/test_no_side_channels.py`.
  - The test AST-walks every Python file in `loki/analysis/` and asserts none of them imports from `os.environ`, `random`, `secrets`, `socket`, `urllib`, `requests`, `httpx`, or calls `time.time()` or `time.monotonic()` outside the `loki.analysis.timing` module. The exact import-set to forbid mirrors the classification audit's list per R15.4.
  - The audit walks files via `ast.parse` and inspects `ast.Import` / `ast.ImportFrom` / `ast.Attribute` nodes.
  - The audit explicitly permits `loki.analysis.timing` to import from `time` (exactly the `monotonic` function); other modules in `loki.analysis` are forbidden from importing `time` at all.
  - _Requirements: 15.3, 15.4_
  - _Design: No-leakage audits — Static AST audit (side channels portion); Property 51_

- [x] 22. Add the static no-leakage AST audit

  - Add `tests/analysis/test_no_log_leakage.py` mirroring `tests/classification/test_no_log_leakage.py`.
  - The test AST-walks every Python file in `loki/analysis/` and asserts that no `logging.Logger.{debug,info,warning,error,exception}` call has a `format`-style or `%`-style argument that references any field in the Forbidden_Leakage_Field_Set:
    - `component_id` (target's, baseline's, sentinel's — any UUID attribute on `ClassificationRecord`, `BaselineRecord`, or `FindingRecord`)
    - `signature_info.signer`
    - `BaselineRecord.source_image_hash`
    - `AxisClassification.evidence`
    - `FindingEvidence.matched_rule`
    - `FindingEvidence.matched_cve`
    - `FindingEvidence.matched_signature`
    - `FindingEvidence.raw_indicators`
    - `FindingRecord.title`
    - `FindingRecord.description`
  - The audit permits the run-summary INFO records described in R20.1, R20.2 because they reference only `(vendor, model, firmware_version, baseline_version)`, `target_count`, `match_strategy`, `duration_ms`, and the per-category counts — none of which are in the Forbidden_Leakage_Field_Set.
  - _Requirements: 20.3, 20.4, 20.5_
  - _Design: No-leakage audits — Static AST audit (logging portion); Property 50 (static side)_

- [x] 23. Add the dynamic no-leakage caplog audit

  - Add `tests/analysis/test_log_no_leakage.py` mirroring `tests/extraction/test_log_no_leakage.py`, `tests/baseline/test_log_no_leakage.py`, and `tests/classification/test_log_no_leakage.py`.
  - The test uses pytest's `caplog` fixture to capture every log record emitted during a curated set of analysis runs (paired-disagreement, signature-regression, unexpected-component, missing-required-component, classification-gap, cancellation), and asserts that no record's formatted message contains any value derived from the Forbidden_Leakage_Field_Set.
  - The test exercises ~6 input scenarios using small fixtures; each scenario checks a different category's emission path.
  - The test should explicitly assert that the run-finish summary INFO record is present and contains the documented fields per R20.2 (positive assertion alongside the negative no-leakage assertion).
  - _Requirements: 20.3, 20.4, 20.5_
  - _Design: No-leakage audits — Dynamic caplog audit; Property 50 (dynamic side)_

- [x] 24. Add the Hypothesis property-based test suite (P43-P52)

  - Add `tests/analysis/test_properties.py` covering each of the ten Properties P43-P52 from the design's Correctness Properties section.
  - Strategies live in `tests/analysis/conftest.py`; build:
    - A strategy for `AnalysisConfig` that always produces a valid four-key `severity_weights` summing to 1.0, valid `confidence_gap_threshold`, and a chosen `match_strategy` per the test's needs.
    - A strategy for `ClassificationRecord` (target or baseline). Compose from existing `tests/classification/conftest.py` strategies if available; otherwise build a fresh one yielding records with valid axes, optional `signature_info`, and configurable `composite_confidence`.
    - A strategy for `(target_records, matched_baseline)` pairs that respects "no duplicates on either side" and produces a configurable mix of paired / target-only / baseline-only entries.
    - A strategy for `FirmwareImage` consistent with the model's invariants.
  - Hypothesis settings: `max_examples=50` for in-memory matcher / scorer / pairing properties (P44, P45, P46, P49, P51); `max_examples=25` for full-pipeline properties (P43, P47, P48, P50, P52); both with `suppress_health_check=[HealthCheck.too_slow]`. Mirror the classification convention.
  - **P43:** every successful `analyze_image` returns a Pydantic-validated `ImageAnalysisReport`; sample 25 input combinations, verify every report `model_dump_json` round-trips through `model_validate_json`.
  - **P44:** baseline matching is deterministic per Match_Strategy; sample 50 `(BaselineRegistry, AnalysisConfig)` pairs, verify two `analyze_image` calls produce equal `baseline_comparison.baseline_id`.
  - **P45:** pairing is a bijection-with-defects; sample 50 `(target_records, baseline_manifest)` pairs, verify the partition contract (paired emits 0+ per-pair findings; target-only emits exactly one `unexpected_component` plus 0/1 `classification_gap`; baseline-only emits exactly one `missing_required_component`).
  - **P46:** Axis_Score and Composite_Score are deterministic; sample 50 `(target_axis, baseline_axis, severity_weights)` tuples, verify the documented invariants (value ranges, agreeing-labels-yield-zero, max-disagree-yields-10.0).
  - **P47:** two runs produce equal reports modulo timestamp (and modulo cancellation index); sample 25 input combinations, two-call equality after stripping `timestamp`.
  - **P48:** `ImageAnalysisReport` round-trips through JSON and YAML losslessly; sample 25 reports, verify `model_validate_json(r.model_dump_json()) == r` and the YAML round-trip.
  - **P49:** PostureRating is a closed function; sample 50 random finding lists (from a strategy that builds finding lists with mixed categories, severities, and composite_scores), verify the result is one of the four v1 PostureRating values and that `HARDENED` is never returned.
  - **P50:** Forbidden_Leakage_Field_Set is never logged; sample 25 input combinations, run the analysis under `caplog`, assert no record's message contains any forbidden value.
  - **P51:** No environmental side channels; this is the AST audit's domain — Property 51's Hypothesis side is a smoke test that two runs in different `os.environ` settings produce equal reports.
  - **P52:** Cancellation_Marker contract; sample 25 cancelled runs (cancellation token returns True at a Hypothesis-chosen index), verify the marker contract (last entry, severity INFO, sentinel component_id, `cancelled-at-index=N` in raw_indicators, deterministic finding_id, no other entry in findings has `category=="analysis_cancelled"`).
  - _Requirements: 1.10, 2 (P44), 3 (P45), 7 (P52), 9 (P46), 15 (P47), 17.5 (P49), 17.6 (P48), 20 (P50)_
  - _Design: Correctness Properties P43-P52; Testing Strategy_

- [x] 25. Add the performance smoke test (slow marker)

  - Add `tests/analysis/test_performance.py` with the `slow` marker mirroring `tests/classification/test_performance.py`.
  - Test the R18.1 budget: 1024-component target + 1024-component baseline run completes under 5 seconds wall time on a 2024-class developer laptop with a local SSD, exclusive of progress-callback overhead.
  - Construct fixture inputs once at module level; reuse across the test. Use `time.monotonic()` directly in the test (not via the timing module — the test is allowed to clock itself).
  - The test should pass at ~1 second on the operator's reference machine; the 5-second budget is conservative.
  - Document in the module docstring that the test is excluded from `pytest -q` by the project's `addopts = "-ra --strict-markers -m 'not slow'"`; operators run it locally with `pytest -m slow tests/analysis/test_performance.py` before declaring a release.
  - _Requirements: 18.1, 18.2, 18.3, 18.4_
  - _Design: Performance and resource use; Testing Strategy_

- [x] 26. Add an end-to-end smoke test

  - Add `tests/test_analysis_smoke.py` exercising the extract → classify → analyze chain:
    - Extract a curated firmware fixture via `extract_firmware`.
    - Classify the resulting components via `classify_components`.
    - Construct a `BaselineRegistry` containing a baseline whose component_manifest mirrors a slightly-modified copy of the classification output (one axis label flipped, one component dropped, one component added).
    - Analyze via `analyze_image`.
    - Verify the resulting `ImageAnalysisReport` carries the expected mix of findings: at least one `classification_mismatch` (axis flip), one `unexpected_component` (added), one `missing_required_component` (dropped). Verify `posture_rating` is `AT_RISK` or `COMPROMISED` depending on the flipped axis's contribution to `composite_score`.
    - Verify the public API exports work: `from loki.analysis import analyze_image, AnalysisProgressEvent, ANALYSIS_VERSION` succeeds.
  - The smoke is the integration-level guarantee that the four upstream subsystems still talk to analysis correctly. Mirrors `tests/test_classification_smoke.py`.
  - _Requirements: end-to-end_
  - _Design: Testing Strategy — End-to-end smoke_


- [x] 27. Update README, STATE, and HANDOFF

  - Update the **Status** table in `loki/README.md` to mark the analysis-engine subsystem as `IMPLEMENTED` and add a short `## Analysis engine` section describing the public entry point, the six finding categories, the PostureRating cascade (briefly), the determinism contract, and the run-summary log records. Mirror the depth of the classification section.
  - Update `loki/STATE.md` to reflect the new subsystem state: 5 IMPLEMENTED + APPROVED subsystems (was 4); analysis-engine moves from PROPOSED+APPROVED to IMPLEMENTED+APPROVED. Bump the test count baseline from 897 to whatever the new total is.
  - Update `loki/HANDOFF.md` (the project-local one): move the existing `loki/HANDOFF.md` content to `loki/HANDOFF.archive.md` (per project convention; mirror what classification's wave 8 did), and write a fresh `loki/HANDOFF.md` describing the new IMPLEMENTED state, the new test count, the new module layout, and the carry-forward constraints. The new HANDOFF should call out the seven D-defaults (now baked into shipped code) and the 10 properties P43-P52.
  - Update `loki/loom-loki.md` (the harness): bump the analysis-engine subsystem entry's `lifecycle_stage` from `PROPOSED` to `IMPLEMENTED`. Add an evolution-log entry recording the BIND. Bump the loom version to v0.4.0 (minor bump per §10's "Most likely v0.2.0 trigger: analysis-engine BIND" — the BIND has now landed at the implementation level too, so the next minor bump is the right level).
  - Update `Sloptropy/STATE_AND_NEXT_STEPS.md`'s loki section to reflect the IMPLEMENTED state.
  - _Requirements: all_
  - _Design: all_

- [x] 28. Final verification gate

  - Run the four checks and confirm green:
    ```bash
    .venv/bin/pytest -q
    .venv/bin/mypy --strict loki tests scripts
    .venv/bin/ruff check
    .venv/bin/ruff format --check
    ```
  - Run the slow performance gate locally:
    ```bash
    .venv/bin/pytest -m slow tests/analysis/test_performance.py
    ```
  - Run the offscreen GUI smoke (existing CI gate, must remain green):
    ```bash
    QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py
    ```
  - Smoke the public API surface:
    ```bash
    .venv/bin/python -c "from loki.analysis import analyze_image, AnalysisProgressEvent, ANALYSIS_VERSION; print(ANALYSIS_VERSION)"
    ```
  - Document the final test counts in the README, and update `loki/HANDOFF.md` to reflect that analysis-engine is landed (this task ratifies the doc updates from task 27).
  - _Requirements: all_
  - _Design: all_

## Task Dependency Graph

The dependency graph organizes tasks into waves. All tasks in a wave can be executed in parallel; each wave waits for the previous one.

```json
{
  "waves": [
    {
      "name": "wave-1-skeleton",
      "tasks": ["1"]
    },
    {
      "name": "wave-2-foundations",
      "tasks": ["2", "3", "4", "5", "6", "7"]
    },
    {
      "name": "wave-3-matching-pairing-finding-id",
      "tasks": ["8", "9", "10"]
    },
    {
      "name": "wave-4-scoring-posture",
      "tasks": ["11", "12"]
    },
    {
      "name": "wave-5-emitters",
      "tasks": ["13", "14", "15", "16", "17"]
    },
    {
      "name": "wave-6-pipeline-and-api",
      "tasks": ["18", "19", "20"]
    },
    {
      "name": "wave-7-cross-cutting",
      "tasks": ["21", "22", "23", "24", "25", "26"]
    },
    {
      "name": "wave-8-docs-and-gate",
      "tasks": ["27", "28"]
    }
  ]
}
```

Suggested implementation cadence aligned to the waves:

- **Day 1 — Waves 1-2.** Skeleton, version constant, `MatchStrategy` enum, `AnalysisConfig` + `FindingEvidence` model-layer extensions, exception hierarchy, timing helper. Pure data-shape work. Smallest meaningful change first.
- **Day 2 — Waves 3-4.** Matching, pairing, finding_id helper + Cancellation_Marker; scoring helpers; PostureRating cascade. The non-pipeline business logic lands here as pure functions.
- **Day 3 — Wave 5.** The five per-category emitters. Each is small enough to land + test in one ~1-2 hour focused chunk.
- **Day 4 — Wave 6.** Report assembly, `AnalysisPipeline`, public `analyze_image` entry point. The subsystem becomes importable end-to-end.
- **Day 5 — Wave 7.** Cross-cutting tests: side-channels audit, no-leakage logging audits (static + dynamic), Hypothesis P43-P52, performance smoke, end-to-end smoke. Tasks within this wave are independent and can be done by separate sessions in parallel.
- **Day 6 — Wave 8.** Documentation refresh and the final verification gate.

The cadence is intentionally similar to classification's six-day plan because the subsystem has comparable scope (10 vs 10 properties, a similar pipeline shape, the same upstream / downstream coupling). Implementations land at most one wave per session per the project's standing discipline; sessions that try to span multiple waves tend to muddy the spec / code separation.

## Notes

- **Stick to the design's Module layout exactly.** If a new responsibility doesn't fit any of the listed modules (`api.py`, `pipeline.py`, `version.py`, `matching.py`, `pairing.py`, `findings.py`, `scoring.py`, `posture.py`, `report.py`, `errors.py`, `timing.py`), raise it as an open question rather than inventing a new module on the fly — that's a sign the design needs an update first.
- **The determinism contract (Properties 43-52) is the single hardest thing to keep correct over time.** Whenever you touch `pipeline.py`, `findings.py`, `scoring.py`, `posture.py`, or `report.py`, re-run `tests/analysis/test_properties.py` together with `tests/analysis/test_pipeline.py`'s determinism case — not just individually.
- **The `slow` marker is already registered in `pyproject.toml`** and `addopts = "-ra --strict-markers -m 'not slow'"` keeps the performance test off the default `pytest -q` run. Don't change that; the budget in R18.1 is slow and noisy in CI by design.
- **The Forbidden_Leakage_Field_Set audit (tasks 22 + 23) is the trickiest test to keep correct.** The static AST audit only catches *direct* attribute accesses inside logger calls; if someone formats a `component_id` into a local variable and then logs the variable, the static audit misses it. The dynamic capture catches that case. Run both as a pair; failures in either should block a checkpoint.
- **The `AnalysisProgressEvent` field set is a documented D6 default.** It strips `component_id` deliberately. If a future revision needs `component_id` for "show in workspace" jump-to-component buttons, the event can extend with an optional `component_id: uuid.UUID | None = None` field at that time, and tasks 19 and 20 are the only ones that need editing. The leakage discipline would need a deliberate amendment with a documented rationale at that point — not a casual change.
- **The seven judgment calls baked into this task list (D1-D7) and the eighth (D8: format-checker warning posture) are recorded in the design's Deferred decisions section.** If any need to change, the affected tasks are: 20 (D1 free function), 6 (D2 errors module), 5 (D3 FindingEvidence extension), 4 (D4 AnalysisConfig extension), 3 (D5 MatchStrategy enum), 20 (D6 progress event shape), 24 (D7 P43-P52 numbering). None ripple beyond two or three tasks.
- **The `filterwarnings = ["error"]` pytest config will surface any `DeprecationWarning` emitted during analysis.** PyYAML and Pydantic occasionally emit these on minor upgrades; if a warning fires, follow the extraction-pipeline's pattern: either upgrade the pin or add a narrow `filterwarnings("ignore", ...)` in `tests/analysis/conftest.py` with a documented rationale.
- **v1 ships exactly the library API.** `loki analyze` (CLI), `analyze_fleet`, the GUI analysis view, CVE-feed integration, signature verification, persistence of `ImageAnalysisReport`, analyst overrides, and `recommended_actions` generation are all out of scope and have their own (future) specs. Don't pre-emptively add CLI hooks, fleet code paths, Qt imports, or feed-lookup hooks to this subsystem.
- **Property numbering picks up at P43 by project-wide convention** (see `loki/HANDOFF.md` carry-forward constraints). The next subsystem to ship a Tier 3 spec triple (currently `feeds` per OT-LK-002) picks up at P53.
- **Cross-subsystem property referencing is fine.** Properties P43-P52 may cross-reference earlier properties (e.g. classification's P33-P42 establish `ClassificationRecord` invariants that analysis relies on); the analysis property tests do not need to re-validate those invariants.
