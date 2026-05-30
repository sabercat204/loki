
# Requirements Document

## Introduction

The Analysis Engine is the LOKI subsystem that turns a sequence of
`ClassificationRecord` instances produced by the classification
pipeline, plus a `BaselineRegistry` loaded by GLEIPNIR, into a
validated `ImageAnalysisReport` describing how a target firmware
image deviates from the matched baseline. It is the consumer of the
classification pipeline's output and the producer of the records
that downstream report renderers, the future analysis CLI, and the
future GUI analysis view will display.

This spec covers analysis only:

- The shape of the public entry point (`analyze_image`) and the
  return value (`ImageAnalysisReport`).
- Baseline matching: how the engine picks the matched baseline from
  the registry, given an explicit baseline id, an auto-match by
  vendor+model+firmware_version, or both.
- Per-component comparison between the target image's
  `ClassificationRecord` set and the matched baseline's
  `BaselineRecord.component_manifest`.
- The six `FindingRecord` categories v1 emits:
  `classification_mismatch`, `signature_regression`,
  `unexpected_component`, `missing_required_component`,
  `classification_gap`, and the cooperative-cancellation
  marker `analysis_cancelled` (emitted only when the caller's
  cancellation token returns `True`; see Requirement 7).
- Per-axis and composite `DeviationScore` computation, weighted by
  `AnalysisConfig.severity_weights` keyed on the four taxonomic
  axes.
- `FindingEvidence` content rules and the analysis engine's
  extension of the Forbidden_Leakage_Field_Set.
- Determinism, round-trip, performance bounds, and observability,
  carried forward from the four shipped subsystems.

It does not cover:

- The CVE-feed subsystem. v1 SHALL accept an empty CVE corpus and
  produce findings without it; `cve_matches` on the consumed
  `ClassificationRecord` instances is always `[]` per
  classification R6, and `FindingEvidence.matched_cve` SHALL
  remain `None` in v1.
- Fleet analysis. The model layer defines `FleetAnalysisReport`,
  but the engine that produces it (`analyze_fleet`) is deferred
  to a future spec. v1 ships only single-image analysis.
- Signature verification. The engine reads
  `ClassificationRecord.signature_info` (whose `verified` field
  is always `False` per classification R5.2) and emits
  `signature_regression` findings on presence changes only; no
  cryptographic verification is performed.
- Persistence of `ImageAnalysisReport`. v1 returns the report to
  the caller; on-disk storage of analysis results is a separate
  future spec.
- Analyst overrides on findings. The model layer's
  `OverrideRecord` is consumed by classification only; analysis
  v1 does not produce or persist overrides.
- A CLI subcommand surface (`loki analyze`). The CLI surface for
  analysis is a separate future spec, mirroring the
  classification pipeline's library-API-only-in-v1 pattern.
- A GUI integration surface. The GUI's Analysis tab is currently
  a scaffold placeholder; wiring it to this engine is a separate
  future spec.
- New configuration fields beyond the two extensions called out
  in Requirement 14: `AnalysisConfig` already exists in
  `loki/models/config.py`, and v1 of this engine extends it with
  `match_strategy` and `confidence_gap_threshold`. The model
  layer's existing `severity_weights`,
  `default_severity_threshold`, and `report_template` fields are
  consumed per the rules in Requirement 14.

The shape and quality bar mirror `extraction-pipeline`,
`baseline-persistence`, and `classification-pipeline`. Determinism,
the typed exception hierarchy, the report-with-findings result
shape, the no-side-channels audit, and the no-content-leakage
audit all carry forward from the upstream subsystems.

## Glossary

- **Analysis_Engine**: The subsystem specified by this document.
  The single public callable that takes a sequence of
  `ClassificationRecord` instances, a `BaselineRegistry`, a
  `FirmwareImage`, and an `AnalysisConfig`, and returns a
  validated `ImageAnalysisReport`.
- **Target_Image**: The `FirmwareImage` being analyzed in a single
  `analyze_image` call. The Analysis_Engine consumes the image's
  metadata (vendor, model, firmware_version) for baseline
  matching and embeds it on the returned
  `ImageAnalysisReport.image_metadata`.
- **Target_Records**: The sequence of `ClassificationRecord`
  instances passed to `analyze_image` for the Target_Image. Each
  record carries a `component_id` whose identity is preserved
  end-to-end from extraction through classification.
- **Matched_Baseline**: The single `BaselineRecord` selected from
  the supplied `BaselineRegistry` for one `analyze_image` call.
  The Matched_Baseline is immutable for the duration of the call.
- **Baseline_Manifest**: The `Matched_Baseline.component_manifest`
  field, which is itself a list of `ClassificationRecord` records
  describing the components GLEIPNIR persisted as the expected
  state of the baseline.
- **Match_Strategy**: An enum carried on `AnalysisConfig` that
  controls how `analyze_image` selects the Matched_Baseline. v1
  defines exactly three values: `EXPLICIT` (use a caller-supplied
  `baseline_id` only), `AUTO` (auto-match by vendor + model +
  firmware_version only), and `EXPLICIT_OR_AUTO` (use the
  caller-supplied `baseline_id` if set, otherwise fall back to
  auto-match).
- **Component_Pairing**: The bijection-with-defects between
  Target_Records and Baseline_Manifest. The Analysis_Engine pairs
  records by `component_id` first; unpaired Target_Records become
  `unexpected_component` findings, and unpaired Baseline_Manifest
  records become `missing_required_component` findings.
- **Finding_Category**: One of the six strings v1 of the
  Analysis_Engine writes to `FindingRecord.category`:
  `classification_mismatch`, `signature_regression`,
  `unexpected_component`, `missing_required_component`,
  `classification_gap`, and `analysis_cancelled`. The first
  five are emitted per the per-pair finding rules in
  Requirements 4, 5, 6, 8, and 10; the sixth is emitted only
  when the caller's optional cancellation token returns
  `True`, per Requirement 7. Future categories MAY be added
  by successor specs without revising this one, but the v1
  set is closed.
- **Cancellation_Marker**: The single
  `FindingRecord` of category `analysis_cancelled` emitted
  by Requirement 7 when cooperative cancellation is
  observed. The marker carries `severity =
  SeverityLevel.INFO`, a deterministic
  sentinel `component_id =
  uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")`, and the
  1-based index of the Target_Record that was about to be
  processed in `evidence.raw_indicators[0]` (formatted as
  the string `"cancelled-at-index=N"`).
- **Axis_Score**: A float in `[0.0, 1.0]` describing how far one
  taxonomic axis (type, vendor, security_posture, mutability) of
  one Target_Record drifts from the corresponding axis of its
  paired Baseline_Manifest record. `0.0` means identical;
  `1.0` means the labels disagree at maximum confidence on both
  sides.
- **Composite_Score**: A float in `[0.0, 10.0]` carried on
  `DeviationScore.composite_score`. v1 derives it as the
  weighted sum of the four Axis_Scores using
  `AnalysisConfig.severity_weights` as weights and scaling by
  10.0 so that a perfect mismatch on every axis lands at the
  upper bound.
- **Severity_Threshold**: The `SeverityLevel` value carried on
  `AnalysisConfig.default_severity_threshold`. The
  Analysis_Engine SHALL NOT, in v1, filter findings by this
  threshold; consumers (CLI, GUI, future report renderers) are
  responsible for applying the threshold at presentation time.
- **Confidence_Gap_Threshold**: The float in `[0.0, 1.0]` carried
  on `AnalysisConfig.confidence_gap_threshold`. The
  Analysis_Engine emits a `classification_gap` finding when a
  Target_Record's `composite_confidence` is strictly less than
  this threshold.
- **Forbidden_Leakage_Field_Set**: The set of values the
  Analysis_Engine SHALL NOT log under any circumstance. The set
  inherits classification's
  `{component_id, signer, source_image_hash, evidence}` and
  adds `FindingEvidence.matched_rule`,
  `FindingEvidence.matched_cve`,
  `FindingEvidence.matched_signature`,
  `FindingEvidence.raw_indicators`, `FindingRecord.title`, and
  `FindingRecord.description`. The persisted
  `ImageAnalysisReport` carries every one of these values; logs,
  progress events, and diagnostic counters do not.
- **Out_Of_Scope_Operation**: Anything beyond producing a single
  `ImageAnalysisReport` for one Target_Image: fleet analysis,
  CVE matching, signature verification, persistence, CLI/GUI
  integration, analyst overrides. Explicitly deferred.

## Requirements

### Requirement 1: Public entry point and input handling

**User Story:** As a LOKI consumer (the future analysis CLI, the
future GUI analysis view, or test harnesses), I want a single
typed entry point that accepts a sequence of classification
records, a baseline registry, the target firmware image, and an
analysis config, and returns a validated `ImageAnalysisReport`,
so that I can run analysis without knowing how baselines are
matched or findings are scored.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL expose exactly one public entry
   point that accepts a sequence of `ClassificationRecord`
   instances (the Target_Records), a `BaselineRegistry`, a
   `FirmwareImage` (the Target_Image), and an `AnalysisConfig`
   instance, and returns an `ImageAnalysisReport` instance.
2. THE Analysis_Engine SHALL expose its public entry point in a
   stable module path under `loki.analysis` so that future CLI,
   GUI, and test code can import it as
   `from loki.analysis import analyze_image`.
3. WHEN the entry point is called with an empty sequence of
   Target_Records, THE Analysis_Engine SHALL return an
   `ImageAnalysisReport` whose `findings` list is empty and
   whose `summary.findings_by_severity` reflects the empty
   finding set; the engine SHALL still resolve the
   Matched_Baseline per Requirement 2.
4. THE Analysis_Engine SHALL accept its `AnalysisConfig` from
   the caller without itself reading any config file, mirroring
   the extraction and classification pipelines' contracts;
   configuration sourcing remains the caller's responsibility.
5. WHEN the entry point completes successfully, THE
   Analysis_Engine SHALL populate
   `ImageAnalysisReport.analysis_version` with the
   Analysis_Engine's own semantic version string in
   `^\d+\.\d+\.\d+$` form.
6. WHEN the entry point completes successfully, THE
   Analysis_Engine SHALL populate
   `ImageAnalysisReport.timestamp` with the UTC wall-clock
   time at which the run began; the model layer's
   `FindingRecord` does not carry an independent timestamp
   field, so the report's single timestamp anchors every
   finding produced in the run.
7. WHEN the entry point completes successfully, THE
   Analysis_Engine SHALL populate
   `ImageAnalysisReport.image_id` with the
   `Target_Image.image_id` and SHALL populate
   `ImageAnalysisReport.image_metadata` with the supplied
   Target_Image verbatim.
8. THE Analysis_Engine SHALL run synchronously on the calling
   thread and SHALL NOT spawn worker threads, asyncio tasks,
   or process pools in v1.
9. THE Analysis_Engine SHALL NOT depend on any `loki.gui`
   module, so that the future CLI and headless test harnesses
   can use the engine without importing PyQt6.
10. WHERE the caller passes an optional cancellation token (a
    callable returning `bool`), THE Analysis_Engine SHALL check
    the token between Component_Pairings and, when the token
    returns `True`, SHALL stop further finding emission, SHALL
    construct the `ImageAnalysisReport` from the findings
    already emitted plus exactly one final `FindingRecord` of
    category `analysis_cancelled` per Requirement 7, and SHALL
    return that report; the engine SHALL NOT raise on
    cancellation, mirroring the classification pipeline's
    partial-result-with-cancellation-record contract for
    consistency with the four shipped subsystems' typed-error
    boundaries (whole-run config / lookup / input failures
    raise; cooperative cancellation produces a partial result).
11. THE Analysis_Engine SHALL run end-to-end on a single
    `analyze_image` call without observing any state from a
    prior call; the engine SHALL NOT cache findings, scored
    deviations, or matched-baseline selections across calls.

### Requirement 2: Baseline matching

**User Story:** As an analyst, I want the engine to pick the
right baseline for the target image without forcing me to know
its UUID, but I also want to be able to override that choice
when a vendor's released two firmware versions with identical
metadata, so that the auto-match path covers the common case
and the explicit-id path covers the long tail.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL select the Matched_Baseline using
   the Match_Strategy carried on
   `AnalysisConfig.match_strategy`, which v1 defines as one of
   exactly three string values: `EXPLICIT`, `AUTO`, and
   `EXPLICIT_OR_AUTO`.
2. WHEN `AnalysisConfig.match_strategy` is `EXPLICIT`, THE
   Analysis_Engine SHALL look up the Matched_Baseline by
   calling `BaselineRegistry.get_by_id` with the
   `baseline_id` carried on `AnalysisConfig`; IF the
   `baseline_id` field on `AnalysisConfig` is unset, THEN THE
   Analysis_Engine SHALL raise a typed
   `AnalysisConfigError` naming the offending strategy.
3. WHEN `AnalysisConfig.match_strategy` is `AUTO`, THE
   Analysis_Engine SHALL look up the Matched_Baseline by
   calling
   `BaselineRegistry.get_by_vendor_model_version(Target_Image.vendor, Target_Image.model, Target_Image.firmware_version)`;
   IF the lookup returns `None`, THEN THE Analysis_Engine
   SHALL raise a typed
   `BaselineNotFoundError` carrying the offending
   `(vendor, model, firmware_version)` tuple.
4. WHEN `AnalysisConfig.match_strategy` is `EXPLICIT_OR_AUTO`,
   THE Analysis_Engine SHALL first attempt explicit lookup per
   acceptance criterion 2.2 if a `baseline_id` is set on
   `AnalysisConfig`, and SHALL fall back to auto-match per
   acceptance criterion 2.3 only when the `baseline_id` field
   is unset.
5. IF the explicit lookup in acceptance criterion 2.2 returns
   `None` for a `baseline_id` that was set, THEN THE
   Analysis_Engine SHALL raise a typed
   `BaselineNotFoundError` carrying the offending
   `baseline_id` and SHALL NOT silently fall back to
   auto-match.
6. WHEN auto-match is consulted (per acceptance criterion 2.3
   or the fallback in acceptance criterion 2.4) and
   `BaselineRegistry.get_by_vendor_model` returns more than
   one record while
   `BaselineRegistry.get_by_vendor_model_version` returns a
   single record, THE Analysis_Engine SHALL select the single
   record returned by the version-specific lookup; the
   multi-record case where the version-specific lookup also
   returns `None` is covered by acceptance criterion 2.3.
7. THE Analysis_Engine SHALL embed the resolved
   Matched_Baseline's `baseline_id` in the returned report's
   `baseline_comparison.baseline_id` field whenever the
   engine populates `baseline_comparison`; the model layer's
   existing `BaselineComparison` invariants apply.
8. THE Analysis_Engine SHALL NOT mutate the supplied
   `BaselineRegistry` or any `BaselineRecord` it contains;
   the registry is read-only for the duration of one
   `analyze_image` call.

### Requirement 3: Component_Pairing

**User Story:** As an analyst, I want every component in the
target image to be paired with its baseline counterpart by
stable component_id, so that one renamed module does not
masquerade as a new component and so that the engine reports
true added / removed / changed components rather than mass
churn.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL pair each Target_Record with the
   Baseline_Manifest record that shares the same
   `ClassificationRecord.component_id`, using `component_id`
   as the sole pairing key in v1.
2. WHEN a Target_Record's `component_id` matches no record in
   the Baseline_Manifest, THE Analysis_Engine SHALL treat the
   Target_Record as an unpaired addition and SHALL emit one
   `unexpected_component` finding per Requirement 6.
3. WHEN a Baseline_Manifest record's `component_id` matches no
   record in the Target_Records, THE Analysis_Engine SHALL
   treat the baseline record as an unpaired requirement and
   SHALL emit one `missing_required_component` finding per
   Requirement 8.
4. THE Analysis_Engine SHALL preserve the input ordering of
   Target_Records when emitting findings; for each
   Target_Record encountered in the input sequence, the engine
   SHALL emit zero or more findings concerning that
   Target_Record before advancing to the next, and after the
   last Target_Record SHALL emit
   `missing_required_component` findings ordered by ascending
   `component_id` of the unpaired baseline records.
5. THE Analysis_Engine SHALL NOT, in v1, attempt fuzzy
   pairing by `name`, `extraction_offset`, or any other field;
   `component_id` is the closed pairing key.
6. WHEN two Target_Records share the same `component_id`, THE
   Analysis_Engine SHALL raise a typed
   `AnalysisInputError` naming the duplicated `component_id`
   and SHALL NOT produce a partial `ImageAnalysisReport`.
7. WHEN two Baseline_Manifest records share the same
   `component_id`, THE Analysis_Engine SHALL raise a typed
   `AnalysisInputError` naming the duplicated `component_id`
   and the offending `Matched_Baseline.baseline_id`.

### Requirement 4: classification_mismatch finding

**User Story:** As an analyst, I want one finding per paired
component whose taxonomic classification has drifted from the
baseline, with explicit per-axis breakdown, so that I can see
at a glance whether the drift is on type, vendor, security
posture, or mutability.

#### Acceptance Criteria

1. WHEN a paired (Target_Record, Baseline_Manifest record)
   pair disagrees on the `label` field of any of the four
   `AxisClassification` axes (`type_axis`, `vendor_axis`,
   `security_axis`, `mutability_axis`), THE Analysis_Engine
   SHALL emit exactly one `classification_mismatch` finding
   for that pair.
2. WHEN every axis label agrees and signature presence agrees
   between the paired records, THE Analysis_Engine SHALL NOT
   emit a `classification_mismatch` finding for that pair.
3. THE Analysis_Engine SHALL set the emitted finding's
   `category` to the literal string
   `classification_mismatch`.
4. THE Analysis_Engine SHALL set the emitted finding's
   `component_id` to the paired Target_Record's
   `component_id`.
5. THE Analysis_Engine SHALL populate the emitted finding's
   `evidence.classification_record` with the Target_Record
   itself, so that downstream consumers can see exactly which
   target classification produced the finding.
6. THE Analysis_Engine SHALL set the emitted finding's
   `severity` per Requirement 10; the severity SHALL be
   derived from the Composite_Score, not chosen arbitrarily.
7. THE Analysis_Engine SHALL emit at most one
   `classification_mismatch` finding per paired component, even
   when more than one axis disagrees; the per-axis breakdown
   SHALL be reflected in the attached `DeviationScore` per
   Requirement 9.
8. WHERE the paired component also satisfies the conditions
   of `signature_regression` (Requirement 5) or
   `classification_gap` (Requirement 10), THE Analysis_Engine
   SHALL emit one finding per applicable category for the
   same component; the categories are not mutually exclusive.

### Requirement 5: signature_regression finding

**User Story:** As an analyst, I want a finding whenever a
component that was signed in the baseline appears unsigned in
the target image (or vice versa), so that loss-of-signing is
surfaced even when the four taxonomic axes have not changed.

#### Acceptance Criteria

1. WHEN a paired (Target_Record, Baseline_Manifest record)
   pair has both records carrying a `signature_info` value
   that is not `None`, and the `signature_info.present` field
   differs between the two records, THE Analysis_Engine SHALL
   emit exactly one `signature_regression` finding for that
   pair.
2. WHERE either the Target_Record or the Baseline_Manifest
   record carries `signature_info=None`, THE Analysis_Engine
   SHALL NOT emit a `signature_regression` finding for that
   pair, regardless of the other side; absence of the
   signature subrecord on one side is treated as "unknown,"
   not as "unsigned."
3. THE Analysis_Engine SHALL set the emitted finding's
   `category` to the literal string `signature_regression`.
4. THE Analysis_Engine SHALL set the emitted finding's
   `component_id` to the paired Target_Record's
   `component_id`.
5. THE Analysis_Engine SHALL populate the emitted finding's
   `evidence.classification_record` with the Target_Record
   and SHALL set
   `evidence.matched_signature` to the literal string
   `"BASELINE_SIGNED"` when the baseline was signed and the
   target is not, or `"TARGET_SIGNED"` when the target is
   signed and the baseline was not; v1 SHALL NOT, however,
   populate the field with any signer identity (signature
   verification remains Out_Of_Scope_Operation).
6. THE Analysis_Engine SHALL set the emitted finding's
   `severity` to `SeverityLevel.HIGH` when the regression is
   "baseline-signed, target-unsigned" and to
   `SeverityLevel.MEDIUM` when the regression is the
   reverse direction; v1 SHALL NOT derive
   signature_regression severity from `AnalysisConfig.severity_weights`.

### Requirement 6: unexpected_component finding

**User Story:** As an analyst, I want a finding for every
component present in the target image whose `component_id`
does not appear in the baseline manifest, so that newly-introduced
modules surface for review even when their classifications
look ordinary.

#### Acceptance Criteria

1. WHEN the Component_Pairing identifies a Target_Record whose
   `component_id` matches no record in the Baseline_Manifest,
   THE Analysis_Engine SHALL emit exactly one
   `unexpected_component` finding for that Target_Record.
2. THE Analysis_Engine SHALL set the emitted finding's
   `category` to the literal string `unexpected_component`.
3. THE Analysis_Engine SHALL set the emitted finding's
   `component_id` to the unpaired Target_Record's
   `component_id`.
4. THE Analysis_Engine SHALL populate the emitted finding's
   `evidence.classification_record` with the unpaired
   Target_Record itself.
5. THE Analysis_Engine SHALL set the emitted finding's
   `severity` to `SeverityLevel.MEDIUM` in v1, independent of
   `AnalysisConfig.severity_weights`; future revisions MAY
   weight unexpected components by axis-specific risk without
   revising v1's contract.
6. THE Analysis_Engine SHALL NOT, in v1, emit a
   `classification_mismatch` or `signature_regression`
   finding for an unpaired Target_Record, since neither
   category is well-defined without a baseline counterpart.
7. THE Analysis_Engine SHALL still emit a `classification_gap`
   finding (Requirement 10) for an unpaired Target_Record when
   the gap condition is satisfied; the absence of a baseline
   counterpart does not exempt the target component from
   confidence checks.

### Requirement 7: analysis_cancelled finding (Cancellation_Marker)

**User Story:** As a GUI consumer wiring `analyze_image` onto
a background `QThread`, I want cooperative cancellation to
stop the run promptly and return whatever findings have been
emitted so far plus a single, audit-friendly Cancellation_Marker
finding, so that "stop now" buttons return useful partial
state without the GUI having to catch a typed exception
across the thread boundary.

#### Acceptance Criteria

1. WHEN the optional cancellation token from acceptance
   criterion 1.10 returns `True` between Component_Pairings,
   THE Analysis_Engine SHALL emit exactly one
   `FindingRecord` whose `category` is the literal string
   `analysis_cancelled` and SHALL NOT emit any further
   per-pair, `unexpected_component`, or
   `missing_required_component` findings after that point.
2. THE Analysis_Engine SHALL set the Cancellation_Marker
   finding's `component_id` to the deterministic sentinel
   UUID `uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")`,
   so that the marker has a stable identity across runs and
   cannot collide with any real `ExtractedComponent.component_id`
   (the sentinel is derived from a fixed string namespace,
   while real component_ids are derived from
   `(file_hash, offset, raw_hash)` tuples per extraction's
   determinism contract).
3. THE Analysis_Engine SHALL set the Cancellation_Marker
   finding's `severity` to `SeverityLevel.INFO`; the marker
   is diagnostic, not a threat indicator.
4. THE Analysis_Engine SHALL populate the Cancellation_Marker
   finding's `evidence.raw_indicators` with a single entry of
   the form `"cancelled-at-index=N"` where `N` is the 1-based
   index of the Target_Record that was about to be processed
   when cancellation was observed; the index value SHALL NOT
   appear in any log record (it is in the persisted report
   only).
5. THE Analysis_Engine SHALL set the Cancellation_Marker
   finding's `title` and `description` to fixed, non-leaking
   strings (e.g. `title = "analysis cancelled"`,
   `description = "cooperative cancellation observed; partial findings returned"`)
   so that the marker contains no value derived from
   Target_Record contents.
6. THE Analysis_Engine SHALL emit the Cancellation_Marker as
   the LAST entry in `ImageAnalysisReport.findings`, after
   any paired-component, `unexpected_component`, or
   `missing_required_component` findings that were already
   emitted before cancellation was observed; this ordering
   makes the marker easy to detect by reading the last
   element of the list.
7. THE Analysis_Engine SHALL derive the Cancellation_Marker
   finding's `finding_id` per acceptance criterion 15.7 with
   `finding_category = "analysis_cancelled"` and
   `target_component_id = uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")`,
   so that two cancellations of the same baseline at the
   same index produce the same `finding_id`.
8. THE Analysis_Engine SHALL still construct and validate
   the returned `ImageAnalysisReport` per Requirement 17
   when cancellation is observed; the partial report's
   `posture_rating` is computed from the findings actually
   emitted (including the Cancellation_Marker), and the
   `summary.findings_by_severity` count reflects every
   emitted finding including the marker.
9. THE Analysis_Engine SHALL NOT emit a Cancellation_Marker
   when the cancellation token is omitted by the caller,
   regardless of any internal interruption; the marker is
   the cooperative-cancellation signal only, not a
   general-purpose "interrupted" indicator.

### Requirement 8: missing_required_component finding

**User Story:** As an analyst, I want a finding for every
component present in the baseline manifest whose
`component_id` does not appear in the target image, so that a
removed (or stripped) module surfaces as a deviation rather
than as silent absence.

#### Acceptance Criteria

1. WHEN the Component_Pairing identifies a Baseline_Manifest
   record whose `component_id` matches no record in the
   Target_Records, THE Analysis_Engine SHALL emit exactly one
   `missing_required_component` finding for that baseline
   record.
2. THE Analysis_Engine SHALL set the emitted finding's
   `category` to the literal string
   `missing_required_component`.
3. THE Analysis_Engine SHALL set the emitted finding's
   `component_id` to the unpaired baseline record's
   `component_id` (the same UUID GLEIPNIR persisted; the
   target image does not contain a record with this id, but
   the field is non-optional on `FindingRecord`).
4. THE Analysis_Engine SHALL populate the emitted finding's
   `evidence.classification_record` with the unpaired
   baseline record itself, so that consumers can see what
   was expected.
5. THE Analysis_Engine SHALL set the emitted finding's
   `severity` to `SeverityLevel.HIGH` in v1, independent of
   `AnalysisConfig.severity_weights`; missing-required
   findings represent removal of a component that the
   baseline curator named as expected, and the strict default
   reflects that.
6. THE Analysis_Engine SHALL NOT, in v1, infer that a missing
   required component is "intentionally removed" versus
   "stripped by an attacker"; both cases produce the same
   finding category with the same severity, and the
   distinction is left to the consumer.

### Requirement 9: DeviationScore computation

**User Story:** As an analyst triaging a long list of findings,
I want every `classification_mismatch` finding to carry a
per-axis breakdown plus a single composite score derived from
the configured severity weights, so that I can rank findings
without re-deriving the math at the consumer side.

#### Acceptance Criteria

1. WHEN the Analysis_Engine emits a
   `classification_mismatch` finding for a paired component,
   THE Analysis_Engine SHALL also construct a
   `DeviationScore` for that component and SHALL embed the
   score on the persisted finding via a new optional
   `FindingEvidence.deviation_score` field of type
   `DeviationScore | None`; v1 of this engine SHALL extend
   the `FindingEvidence` model with this field, defaulted to
   `None`. The change SHALL be backwards-compatible because
   every existing call site treats `FindingEvidence` as a
   constructed-once value with a small set of populated
   fields.
2. THE Analysis_Engine SHALL compute four Axis_Scores for each
   paired (Target_Record, Baseline_Manifest record) pair, one
   for each of the axes `type_axis`, `vendor_axis`,
   `security_axis`, `mutability_axis`.
3. THE Analysis_Engine SHALL compute each Axis_Score as the
   product `target_axis.confidence * baseline_axis.confidence`
   when `target_axis.label != baseline_axis.label`, and as
   `0.0` when `target_axis.label == baseline_axis.label`; the
   resulting value lies in `[0.0, 1.0]` because both
   confidences are constrained to `[0.0, 1.0]` by the model
   layer.
4. THE Analysis_Engine SHALL compute the Composite_Score as
   `10.0 * (w_type * s_type + w_vendor * s_vendor + w_security * s_security + w_mutability * s_mutability)`,
   where `s_*` are the Axis_Scores and `w_*` are the
   `AnalysisConfig.severity_weights` values keyed by the four
   strings `type`, `vendor`, `security_posture`,
   `mutability`.
5. WHEN `AnalysisConfig.severity_weights` does not contain
   exactly the four keys `type`, `vendor`,
   `security_posture`, `mutability`, THE Analysis_Engine
   SHALL raise a typed `AnalysisConfigError` at the start of
   the run naming the missing or extra keys; the model
   layer's existing sum-to-1.0 validator catches the weight
   total, and this engine adds the key-set check.
6. THE Analysis_Engine SHALL set `DeviationScore.base_severity`
   to the `SeverityLevel` value derived from the
   Composite_Score per Requirement 10, so that the persisted
   `DeviationScore.base_severity` and the persisted
   `FindingRecord.severity` agree.
7. THE Analysis_Engine SHALL set
   `DeviationScore.component_criticality` to the paired
   Baseline_Manifest record's `composite_confidence` value,
   so that components the baseline classified with high
   confidence get a higher criticality than components the
   baseline classified with low confidence; the field's range
   `[0.0, 1.0]` is enforced by the model layer.
8. THE Analysis_Engine SHALL set
   `DeviationScore.security_direction` per the rules in
   Requirement 11, `DeviationScore.signature_delta` per the
   rules in Requirement 12, and
   `DeviationScore.mutability_change` per the rules in
   Requirement 13.
9. THE Analysis_Engine SHALL set
   `DeviationScore.cve_introduced` to `False` for every
   emitted score in v1; CVE matching is
   Out_Of_Scope_Operation per the introduction.
10. THE Analysis_Engine SHALL set
    `DeviationScore.priority_rank` to the 1-based ordinal
    position of the finding when all
    `classification_mismatch` findings emitted in the run are
    sorted by descending Composite_Score with ties broken by
    ascending `component_id`; the lowest priority_rank
    integer (`1`) corresponds to the highest-Composite_Score
    finding.
11. THE Analysis_Engine SHALL NOT compute a `DeviationScore`
    for `unexpected_component`,
    `missing_required_component`,
    `signature_regression`, or `classification_gap` findings
    in v1; only `classification_mismatch` findings carry an
    embedded `DeviationScore`.

### Requirement 10: classification_gap finding and severity derivation

**User Story:** As an analyst, I want the engine to surface
components whose classification confidence is below the
configured threshold as their own finding category, so that
"the engine could not tell" is distinguishable from "the
engine could tell, and the answer was bad."

#### Acceptance Criteria

1. WHEN a Target_Record's
   `composite_confidence` is strictly less than
   `AnalysisConfig.confidence_gap_threshold`, THE
   Analysis_Engine SHALL emit exactly one
   `classification_gap` finding for that Target_Record.
2. THE Analysis_Engine SHALL emit the
   `classification_gap` finding regardless of whether the
   Target_Record was paired with a Baseline_Manifest record;
   the gap condition concerns target classification quality
   only.
3. THE Analysis_Engine SHALL set the emitted finding's
   `category` to the literal string
   `classification_gap`.
4. THE Analysis_Engine SHALL set the emitted finding's
   `component_id` to the Target_Record's
   `component_id`.
5. THE Analysis_Engine SHALL populate the emitted finding's
   `evidence.classification_record` with the Target_Record
   itself.
6. THE Analysis_Engine SHALL set the emitted finding's
   `severity` to `SeverityLevel.LOW` in v1, independent of
   `AnalysisConfig.severity_weights`; classification gaps
   are diagnostic, not threat indicators, and the severity
   reflects that.
7. THE Analysis_Engine SHALL derive the severity of every
   `classification_mismatch` finding from the finding's
   Composite_Score per the closed mapping
   `composite_score >= 8.0 -> CRITICAL`,
   `6.0 <= composite_score < 8.0 -> HIGH`,
   `4.0 <= composite_score < 6.0 -> MEDIUM`,
   `2.0 <= composite_score < 4.0 -> LOW`,
   `composite_score < 2.0 -> INFO`.
8. THE Analysis_Engine SHALL NOT, in v1, filter findings by
   `AnalysisConfig.default_severity_threshold`; consumers
   apply the threshold at presentation time per the
   Severity_Threshold definition in the Glossary.

### Requirement 11: SecurityDirection on DeviationScore

**User Story:** As an analyst, I want each
`classification_mismatch` finding's `DeviationScore` to
record whether the security posture moved up, down, or stayed
flat, so that I can ignore "improved security" findings on
sight.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL set
   `DeviationScore.security_direction` to
   `SecurityDirection.DEGRADED` when the paired
   Target_Record's `security_axis.label` is
   `SecurityPostureLabel.VULNERABLE` and the paired
   Baseline_Manifest record's `security_axis.label` is
   `SecurityPostureLabel.SECURE`.
2. THE Analysis_Engine SHALL set
   `DeviationScore.security_direction` to
   `SecurityDirection.IMPROVED` when the paired
   Target_Record's `security_axis.label` is
   `SecurityPostureLabel.SECURE` and the paired
   Baseline_Manifest record's `security_axis.label` is
   `SecurityPostureLabel.VULNERABLE`.
3. THE Analysis_Engine SHALL set
   `DeviationScore.security_direction` to
   `SecurityDirection.UNCHANGED` in every other case,
   including when either side is
   `SecurityPostureLabel.UNKNOWN`.

### Requirement 12: SignatureDelta on DeviationScore

**User Story:** As an analyst, I want each
`classification_mismatch` finding's `DeviationScore` to
record whether the component lost, gained, or kept its
signature, so that signature changes inside a mismatch
finding are visible without opening a separate
`signature_regression` finding for the same component.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL set
   `DeviationScore.signature_delta` to
   `SignatureDelta.LOST` when the paired Baseline_Manifest
   record carries `signature_info.present == True` and the
   paired Target_Record carries
   `signature_info.present == False`.
2. THE Analysis_Engine SHALL set
   `DeviationScore.signature_delta` to
   `SignatureDelta.GAINED` when the paired Baseline_Manifest
   record carries `signature_info.present == False` and the
   paired Target_Record carries
   `signature_info.present == True`.
3. THE Analysis_Engine SHALL set
   `DeviationScore.signature_delta` to
   `SignatureDelta.CHANGED` when both sides carry
   `signature_info.present == True` but the future signer-or-
   cert-expiry comparison would return non-equal; v1 SHALL
   NOT, however, emit `SignatureDelta.CHANGED` because v1
   does not parse signer identity (classification R5.3) or
   certificate expiry (classification R5.4); the value is
   reserved for a future revision.
4. THE Analysis_Engine SHALL set
   `DeviationScore.signature_delta` to
   `SignatureDelta.NONE` in every other case, including when
   either side carries `signature_info=None`.

### Requirement 13: MutabilityChange on DeviationScore

**User Story:** As an analyst, I want each
`classification_mismatch` finding's `DeviationScore` to
record whether the component's mutability axis flipped from
`READONLY` to `MUTABLE` or vice versa, so that "this firmware
chunk is now writable when it used to be locked" surfaces
inside the same finding as the rest of the deviation.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL set
   `DeviationScore.mutability_change` to
   `MutabilityChange.BECAME_MUTABLE` when the paired
   Baseline_Manifest record's `mutability_axis.label` is
   `MutabilityLabel.READONLY` and the paired Target_Record's
   `mutability_axis.label` is `MutabilityLabel.MUTABLE`.
2. THE Analysis_Engine SHALL set
   `DeviationScore.mutability_change` to
   `MutabilityChange.BECAME_READONLY` when the paired
   Baseline_Manifest record's `mutability_axis.label` is
   `MutabilityLabel.MUTABLE` and the paired Target_Record's
   `mutability_axis.label` is `MutabilityLabel.READONLY`.
3. THE Analysis_Engine SHALL set
   `DeviationScore.mutability_change` to
   `MutabilityChange.NONE` in every other case, including
   when either side is `MutabilityLabel.UNKNOWN`.

### Requirement 14: AnalysisConfig consumption

**User Story:** As a config curator, I want a single contract
for which `AnalysisConfig` fields the engine consumes and
which it leaves to consumers, so that I can tune the engine
without guessing whether a field is live.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL consume
   `AnalysisConfig.severity_weights` for the per-axis
   weighting in Composite_Score computation per Requirement 9; the v1 keyset is exactly
   `{"type", "vendor", "security_posture", "mutability"}`.
2. THE Analysis_Engine SHALL consume the new field
   `AnalysisConfig.match_strategy` (a string-typed enum with
   exactly the values `EXPLICIT`, `AUTO`, and
   `EXPLICIT_OR_AUTO`) per Requirement 2; v1 of this engine
   SHALL extend `AnalysisConfig` with this field.
3. THE Analysis_Engine SHALL consume the new field
   `AnalysisConfig.confidence_gap_threshold` (a float in
   `[0.0, 1.0]`) per Requirement 10; v1 of this engine SHALL
   extend `AnalysisConfig` with this field.
4. THE Analysis_Engine SHALL consume the optional new field
   `AnalysisConfig.baseline_id` (a `uuid.UUID | None`) per
   Requirement 2; the field's default value SHALL be `None`,
   and v1 of this engine SHALL extend `AnalysisConfig` with
   this field.
5. THE Analysis_Engine SHALL NOT consume
   `AnalysisConfig.default_severity_threshold` in v1 for any
   filtering or finding-emission decision; the engine still
   reads the field's value into the persisted report's
   diagnostic state for downstream consumers, but no engine-
   internal control flow branches on it. The field is
   reserved for consumer-side filtering at presentation time
   per the Severity_Threshold definition in the Glossary, and
   a future revision MAY consume it for engine-side filtering
   without revising this spec.
6. THE Analysis_Engine SHALL NOT consume
   `AnalysisConfig.report_template` in v1 for any decision
   that affects report contents; the field is reserved for
   the future report-rendering subsystem.
7. WHEN any of the four fields named in acceptance criteria
   14.1 through 14.4 fails its declared validator, THE
   Analysis_Engine SHALL raise a typed `AnalysisConfigError`
   at the start of the run before performing any baseline
   match or finding emission.

### Requirement 15: Determinism and reproducibility

**User Story:** As a tester and as the property-based test
suite, I want analysis to be deterministic given the same
target records, the same baseline registry, and the same
config, so that round-trip, idempotence, and equivalence
properties can be tested under Hypothesis and so that
re-analyzing an image produces stable findings.

#### Acceptance Criteria

1. WHEN the Analysis_Engine is invoked twice on the same
   inputs and the same Analysis_Engine version, THE
   Analysis_Engine SHALL produce two
   `ImageAnalysisReport` values whose `findings` and
   `summary` and embedded `DeviationScore` values are equal
   under `model_dump(mode="json")` after stripping the
   `timestamp` field on the report; the equality SHALL
   include the order of findings in the `findings` list.
   WHERE both runs were terminated by cooperative
   cancellation per Requirement 7, the equality SHALL
   additionally strip the Cancellation_Marker's
   `evidence.raw_indicators` (which carries the
   `"cancelled-at-index=N"` value derived from the index at
   which cancellation was observed and is therefore not
   stable across two cancellation runs that happen to fire
   at different indices); all other fields on the
   Cancellation_Marker, including its `finding_id` per
   acceptance criterion 7.7 and its `category` and
   `severity`, SHALL match.
2. THE Analysis_Engine SHALL preserve a deterministic
   ordering of findings: paired-component findings appear in
   the input order of Target_Records, then
   `unexpected_component` findings appear in the input order
   of Target_Records (which is identical to the previous
   clause for those records), then
   `missing_required_component` findings appear in
   ascending order of unpaired Baseline_Manifest record
   `component_id`, and the optional Cancellation_Marker (per
   Requirement 7) appears as the final entry of
   `ImageAnalysisReport.findings` when cancellation was
   observed.
3. WHEN the Analysis_Engine is invoked, THE
   Analysis_Engine SHALL NOT consult environment variables,
   the random number generator, the system clock (other than
   for the wall-clock `timestamp` field permitted by
   acceptance criterion 1.6), or any network resource for
   any decision that affects report contents.
4. THE Analysis_Engine SHALL NOT, in v1, import any symbol
   from `os.environ`, `random`, `secrets`, `socket`,
   `urllib`, `requests`, `httpx`, or `time.time()` /
   `time.monotonic()` outside a designated timing module
   (mirroring the extraction, baseline, and classification
   pipelines' side-channels audits).
5. FOR ALL valid input sequences the engine accepts,
   serializing every emitted `ImageAnalysisReport` to JSON
   via `model_dump_json()` and deserializing via
   `model_validate_json()` SHALL produce a report equal to
   the original (round-trip property).
6. WHEN the Analysis_Engine is invoked twice on the same
   inputs and the second invocation receives the first
   invocation's report as a no-op input baseline (i.e. the
   second invocation is given the same Target_Records and
   the same Matched_Baseline that produced the first
   report), THE Analysis_Engine SHALL produce a report on
   the second run equal to the first run's report under
   `model_dump(mode="json")` modulo the `timestamp` field
   (idempotence property).
7. THE Analysis_Engine SHALL derive every UUID it generates
   for a `FindingRecord.finding_id` from a deterministic
   UUIDv5 of the namespace `LOKI_NAMESPACE` and the tuple
   `(Matched_Baseline.baseline_id, finding_category, target_component_id)`,
   so that the same input pair always produces the same
   `finding_id` across runs and across hosts.
8. THE Analysis_Engine SHALL derive every
   `ImageAnalysisReport.report_id` it generates as the
   UUIDv5 of `LOKI_NAMESPACE` and the tuple
   `(Target_Image.image_id, Matched_Baseline.baseline_id, analysis_version)`,
   so that the same target-and-baseline pair always
   produces the same `report_id` across runs.

### Requirement 16: Error handling and typed exceptions

**User Story:** As a caller of the Analysis_Engine (the future
analysis CLI, GUI, tests), I want every failure mode mapped to
a specific typed exception so that one bad input never produces
a partial report and so that config and baseline-lookup
mistakes surface loudly.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL expose a typed exception
   hierarchy rooted at `AnalysisError` (subclass of
   `Exception`) and SHALL raise only subclasses of
   `AnalysisError` from its public entry points.
2. THE Analysis_Engine SHALL raise `AnalysisConfigError` when
   `AnalysisConfig` violates any rule of Requirement 14
   (missing weight key, unknown match strategy, out-of-range
   `confidence_gap_threshold`, etc.) before performing any
   baseline match or finding emission.
3. THE Analysis_Engine SHALL raise `BaselineNotFoundError`
   when baseline matching fails per Requirement 2.
4. THE Analysis_Engine SHALL raise `AnalysisInputError` when
   the supplied Target_Records or Baseline_Manifest contains
   duplicate `component_id` values per Requirement 3.
5. WHEN final-report construction fails its own Pydantic
   validation, THE Analysis_Engine SHALL raise a typed
   `AnalysisReportConstructionError` that names the
   offending field path and SHALL NOT return a partially
   constructed report.
6. WHEN cancellation is observed per Requirement 1.10, THE
   Analysis_Engine SHALL NOT raise; the engine returns a
   partial `ImageAnalysisReport` carrying an
   `analysis_cancelled` finding per Requirement 7, and the
   typed exception hierarchy carries no
   `AnalysisCancelledError` member in v1.
7. THE Analysis_Engine SHALL NOT, in v1, surface
   per-component analysis failures as silent dropped
   findings; the engine produces zero findings for a paired
   component only when the matching rules in Requirements 4
   through 13 explicitly produce zero. Any internal
   exception during finding construction SHALL propagate as
   an `AnalysisError` subclass and SHALL NOT be swallowed.

### Requirement 17: Report construction and validation

**User Story:** As a downstream consumer (the future report
renderer, GUI, persistence layer), I want the engine's output
to be an `ImageAnalysisReport` that has already passed every
model-layer invariant, so that I never have to re-validate
before rendering or persisting.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL construct its return value by
   instantiating `ImageAnalysisReport` directly, so that all
   Pydantic v2 strict validators run before the value leaves
   the subsystem.
2. THE Analysis_Engine SHALL ensure that every emitted
   `FindingRecord` has a unique `finding_id` within the
   returned `ImageAnalysisReport.findings` list, derived per
   acceptance criterion 15.7.
3. THE Analysis_Engine SHALL leave
   `ImageAnalysisReport.recommended_actions` at its
   model-layer default (the empty list `[]`) for v1;
   recommended-actions generation is a future revision and
   does not block v1.
4. THE Analysis_Engine SHALL leave
   `ImageAnalysisReport.baseline_comparison` populated as a
   `BaselineComparison` whose `baseline_id` equals the
   Matched_Baseline's `baseline_id`, whose `target_image_id`
   equals `Target_Image.image_id`, whose
   `comparison_timestamp` equals
   `ImageAnalysisReport.timestamp` (the same UTC wall-clock
   moment captured at run start per acceptance criterion
   1.6, so that the engine's two timestamp fields move in
   lockstep and the determinism property in acceptance
   criterion 15.1 strips a single timestamp value), and
   whose `deviations` list is the empty list `[]` in v1; the
   model-layer `summary` field is auto-computed from the
   empty list.
   v1 of the engine SHALL NOT, however, populate
   `BaselineComparison.deviations` directly; the
   `DeviationRecord` model is reserved for a future
   `BaselineComparison` subsystem and the analysis engine
   carries deviations through `FindingRecord` plus the
   embedded `DeviationScore` per Requirement 9 instead.
5. THE Analysis_Engine SHALL set
   `ImageAnalysisReport.posture_rating` per the closed
   mapping based on the Composite_Score of the highest-
   priority `classification_mismatch` finding plus the
   presence of `missing_required_component` or
   `signature_regression` findings:
   - `PostureRating.COMPROMISED` if any
     `signature_regression` finding has severity `HIGH`, or
     any `missing_required_component` finding is emitted, or
     any `classification_mismatch` finding has Composite_Score
     >= 8.0 (i.e. severity CRITICAL per acceptance criterion
     10.7); v1 of this engine treats critical-severity
     classification drift as posture-equivalent to evidence
     of tampering, on the operationally-driven principle that
     a single CRITICAL drift finding warrants the most severe
     posture label rather than AT_RISK;
   - `PostureRating.AT_RISK` if any
     `classification_mismatch` finding has Composite_Score
     >= 6.0;
   - `PostureRating.DEGRADED` if any
     `classification_mismatch` finding has Composite_Score
     >= 2.0 but no other rule above fires;
   - `PostureRating.DEGRADED` if any finding of any category
     is emitted but no rule above fires; this catches runs
     whose only findings are `unexpected_component`,
     `signature_regression: MEDIUM`, or `classification_gap`,
     so that the `PostureRating` field is always populated for
     a run that emitted at least one finding;
   - `PostureRating.BASELINE` if no findings are emitted at
     all;
   - `PostureRating.HARDENED` is reserved for a future
     revision and SHALL NOT be emitted by v1.
6. WHEN final-report construction succeeds, THE
   Analysis_Engine SHALL guarantee that the returned
   `ImageAnalysisReport` serializes losslessly through both
   JSON (`model_dump_json` + `model_validate_json`) and YAML
   (`model_dump` + `yaml.safe_dump` + `yaml.safe_load` +
   `model_validate`); IF construction fails, THEN THE
   Analysis_Engine SHALL NOT attempt serialization of any
   intermediate state.

### Requirement 18: Performance bounds and resource use

**User Story:** As an analyst working with realistic firmware
images, I want analysis of a 1024-component target against a
1024-component baseline to complete in bounded memory and
bounded time, so that the GUI stays responsive and CI runs
do not exhaust runner resources.

#### Acceptance Criteria

1. WHEN the Analysis_Engine is invoked on a Target_Records
   sequence of up to 1024 records and a Matched_Baseline
   whose `component_manifest` carries up to 1024 records,
   THE Analysis_Engine SHALL complete in under 5 seconds of
   wall time on a 2024-class developer laptop with a local
   SSD, exclusive of any caller-supplied callback overhead.
2. THE Analysis_Engine SHALL evaluate Component_Pairing and
   per-pair finding rules in linear time in the size of the
   union of Target_Records and Baseline_Manifest; v1 SHALL
   NOT support a per-axis indexing optimization and SHALL
   build a single dict keyed by `component_id` to drive
   pairing.
3. THE Analysis_Engine SHALL keep peak resident memory
   attributable to analysis under a fixed working set of
   64 MiB plus the size of the inputs (Target_Records,
   Matched_Baseline, AnalysisConfig); v1 SHALL NOT cache the
   full BaselineRegistry.
4. THE Analysis_Engine SHALL run synchronously on the
   calling thread per acceptance criterion 1.8; this
   requirement reasserts the constraint for performance
   reasoning and is not redundant with Requirement 1.

### Requirement 19: Integration surface for the GUI and CLI

**User Story:** As the author of the future analysis CLI
subcommand and of the future GUI analysis view, I want a
stable, typed integration surface that does not leak engine
internals, so that I can render progress and findings without
poking at internal pipeline state.

#### Acceptance Criteria

1. THE Analysis_Engine SHALL expose its public entry point
   as `from loki.analysis import analyze_image` per
   acceptance criterion 1.2; the module path SHALL be
   stable across v1 patch releases.
2. WHERE the caller passes an optional progress callback (a
   callable accepting a structured `AnalysisProgressEvent`
   carrying the 1-based component index and the total
   target-record count), THE Analysis_Engine SHALL invoke
   the callback exactly once per Target_Record at the start
   of that record's per-pair evaluation, on the calling
   thread.
3. THE Analysis_Engine SHALL guarantee that the progress
   callback, if supplied, is invoked from the calling thread
   only.
4. THE Analysis_Engine SHALL log its activity through
   Python's standard `logging` module under the logger name
   `loki.analysis` so that GUI and CLI consumers can attach
   their own handlers without monkey-patching.
5. THE Analysis_Engine SHALL NOT, in v1, expose a CLI
   subcommand surface (`loki analyze` or similar); the CLI
   surface for analysis is a separate spec.
6. THE Analysis_Engine SHALL NOT, in v1, expose a GUI
   integration surface; the GUI's analysis view is a
   separate spec.
7. THE Analysis_Engine SHALL NOT, in v1, expose an
   `analyze_fleet` entry point; fleet analysis is deferred
   to a future spec.

### Requirement 20: Observability and diagnostics

**User Story:** As a developer debugging a failed analysis on
a real-world firmware image, I want enough structured logging
and diagnostic state to identify which Matched_Baseline was
chosen, how many findings were emitted in each category, and
how long the run took, without leaking the contents of any
analyzed component.

#### Acceptance Criteria

1. WHEN the Analysis_Engine begins a run, THE
   Analysis_Engine SHALL log an INFO record naming the
   resolved Matched_Baseline's
   `(vendor, model, firmware_version, baseline_version)`
   tuple, the count of Target_Records, and the configured
   `match_strategy`. The log record SHALL NOT include the
   Matched_Baseline's `baseline_id` or
   `source_image_hash`.
2. WHEN the Analysis_Engine finishes a run, THE
   Analysis_Engine SHALL log an INFO record summarizing the
   wall-clock duration in milliseconds and the per-category
   finding counts (e.g.
   `classification_mismatch=N1, signature_regression=N2,
   unexpected_component=N3, missing_required_component=N4,
   classification_gap=N5, analysis_cancelled=N6`). The
   `analysis_cancelled` count SHALL be `0` for every run
   that completes without cooperative cancellation, and `1`
   for every cancelled run.
3. WHEN the Analysis_Engine emits a finding, THE
   Analysis_Engine SHALL NOT log the finding's `title`,
   `description`, `evidence.matched_rule`,
   `evidence.matched_cve`, `evidence.matched_signature`,
   `evidence.raw_indicators`, `evidence.classification_record`,
   or `component_id`; the per-finding emission SHALL produce
   no per-finding log record at all in v1 (the run-finish
   summary in acceptance criterion 20.2 is sufficient).
4. WHEN the Analysis_Engine catches an internal exception
   that it raises as a typed `AnalysisError` subclass, THE
   Analysis_Engine SHALL log a WARNING record carrying the
   exception class name and a redacted message; the logged
   record SHALL NOT carry any value from the
   Forbidden_Leakage_Field_Set.
5. THE Analysis_Engine SHALL NOT, at any time (including
   while idle, during initialization, during shutdown, or
   while no input is being processed), log any value in the
   Forbidden_Leakage_Field_Set: `component_id`, `signer`,
   `source_image_hash`, `evidence` (the classification
   per-axis evidence string), `FindingEvidence.matched_rule`,
   `FindingEvidence.matched_cve`,
   `FindingEvidence.matched_signature`,
   `FindingEvidence.raw_indicators`, `FindingRecord.title`,
   or `FindingRecord.description`. Inspection of report
   contents for debugging SHALL be performed via the future
   `loki analyze show` CLI subcommand or by inspecting the
   returned `ImageAnalysisReport`, not via log records.
6. THE Analysis_Engine SHALL log its activity through
   Python's standard `logging` module under the logger name
   `loki.analysis` per acceptance criterion 19.4.
