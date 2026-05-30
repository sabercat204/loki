# Requirements Document

## Introduction

The Classification Pipeline is the LOKI subsystem that turns
`ExtractedComponent` records produced by the extraction pipeline into
validated `ClassificationRecord` instances along the four taxonomic
axes already defined in `loki/models/enums.py`: type, vendor, security
posture, and mutability. It is the consumer of the extraction
pipeline's output and the producer of the records that GLEIPNIR
persists inside `BaselineRecord.component_manifest`.

This spec covers classification only:

- The shape of the rule files on disk (YAML), the rule schema, and the
  rule-loading lifecycle.
- The matcher language used to bind rules to extracted components.
- Per-axis classification by independent rule passes; no cross-axis
  inference.
- The decision rule for picking the winning rule when multiple rules
  fire on the same axis (max-confidence wins, deterministic
  tie-break).
- The fallback behavior when no rule fires for an axis (`UNKNOWN`
  label at confidence `0.0`).
- Signature presence detection (no verification).
- The public entry point shape (`classify_components`) and the
  `ClassificationResult` container that carries records plus
  per-component errors.
- Determinism, round-trip, and observability bounds, including the
  forbidden-leakage field set for logs.
- Treatment of inner components emitted by the extraction pipeline
  from decompressed UEFI sections.

It does not cover:

- The CVE-feed subsystem. `cve_matches` SHALL remain `[]` in v1; a
  future CVE-feed subsystem will populate the field on a later pass.
- Signature verification. `SignatureInfo.verified` SHALL remain
  `False` in v1; a future trust-root-aware subsystem may verify
  signatures without revising this spec.
- Cross-axis inference. The four axes classify independently in v1.
- The `BaselineComparison` subsystem (deviation scoring) and the
  analysis engine.
- Persistence of `ClassificationRecord` instances. GLEIPNIR already
  persists them as part of `BaselineRecord.component_manifest`; this
  spec produces records and hands them to the caller.
- Defining new configuration. `ClassificationConfig.taxonomy_version`,
  `ClassificationConfig.confidence_threshold`, and
  `ClassificationConfig.rules_path` already exist in
  `loki/models/config.py`; this spec consumes them and does not
  extend them. v1 does not, however, gate any classification
  decision on `ClassificationConfig.confidence_threshold` -
  the field is reserved for the analysis engine's review-flag
  use, and the v1 review gate is the model layer's hard-coded
  `needs_review = composite_confidence < 0.60` invariant
  (Requirement 4.10).

The shape and quality bar mirror `extraction-pipeline/requirements.md`
and `baseline-persistence/requirements.md`. Determinism, the typed
exception hierarchy, the manifest-with-errors result shape, the
no-side-channels audit, and the no-content-leakage audit all carry
forward from the upstream subsystems.

## Glossary

- **Classification_Pipeline**: The subsystem specified by this
  document. The single public callable that takes a sequence of
  `ExtractedComponent` records plus a `ClassificationConfig` and
  returns a validated `ClassificationResult`.
- **Rule_Set**: The collection of `Rule` records loaded from the
  YAML files under `ClassificationConfig.rules_path` at pipeline
  construction. Immutable for the lifetime of a pipeline instance.
- **Rule**: A single declarative record loaded from a rule file.
  Each Rule has a unique `rule_id`, an `axis` it targets (one of
  `type`, `vendor`, `security_posture`, `mutability`), a `Matcher`
  block, and an `Effect` block.
- **Matcher**: The condition portion of a Rule. A Matcher binds a
  Rule to a subset of `ExtractedComponent` instances by combining
  predicates over the component's fields (`guid`, `name`,
  `component_type_hint`, `size`, `raw_hash`) under conjunction.
- **Effect**: The output portion of a Rule. An Effect specifies the
  axis label the Rule asserts when its Matcher fires, plus the
  per-axis confidence in `[0.0, 1.0]` and an optional
  human-readable `evidence` string.
- **Axis**: One of the four taxonomic axes (`type`, `vendor`,
  `security_posture`, `mutability`) defined by `AxisClassification`
  on `ClassificationRecord` and the four StrEnum types in
  `loki/models/enums.py` (`ComponentTypeLabel`, `VendorLabel`,
  `SecurityPostureLabel`, `MutabilityLabel`).
- **Axis_Classifier**: The internal component that runs every Rule
  whose `axis` field equals a given Axis against a single
  `ExtractedComponent` and produces the `AxisClassification` for
  that axis.
- **Winning_Rule**: For a given Axis on a given component, the Rule
  whose Matcher fires and whose Effect carries the highest
  `confidence`. Ties are broken by lexicographic `rule_id` order
  (Requirement 4).
- **Classification_Result**: The output container returned by the
  Classification_Pipeline's public entry point. Carries the list of
  `ClassificationRecord` instances produced for components that
  classified successfully and the list of `ClassificationError`
  records for components that did not, mirroring
  `ExtractionManifest`'s manifest-with-errors shape.
- **Classification_Error**: A typed record analogous to
  `ExtractionError`. Carries the `component_id` of the component
  that failed (or `None` for whole-run failures), an
  `error_message`, and a UTC `timestamp`.
- **Inner_Component**: An `ExtractedComponent` produced by the
  extraction pipeline from a decompressed UEFI section. Identified
  by a synthetic `source_image_id` derived as
  `uuid5(LOKI_NAMESPACE, decompressed_hash)` and a
  `component_id` derived from
  `(decompressed_hash, offset, raw_hash)`. Inner_Components are in
  scope for classification and are treated identically to outer
  components.
- **Forbidden_Leakage_Field_Set**: The set of fields the
  Classification_Pipeline SHALL NOT log under any circumstance:
  `ExtractedComponent.component_id` (and `ClassificationRecord`'s
  copy of it), `SignatureInfo.signer`, the parent
  `BaselineRecord.source_image_hash`, and the per-axis `evidence`
  strings carried by `AxisClassification.evidence`.
- **Out_Of_Scope_Operation**: Anything beyond classification of an
  `ExtractedComponent` into a `ClassificationRecord` per the four
  taxonomic axes - signature verification, CVE matching, deviation
  scoring, persistence. Explicitly deferred.

## Requirements

### Requirement 1: Public entry point and input handling

**User Story:** As a LOKI consumer (the classification step that
populates `BaselineRecord.component_manifest`, future CLI commands,
or test harnesses), I want a single typed entry point that accepts
a sequence of extracted components plus a `ClassificationConfig`
and returns a validated `ClassificationResult`, so that I can run
classification without knowing how rules are stored or evaluated.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL expose exactly one public
   entry point that accepts a sequence of `ExtractedComponent`
   instances and a `ClassificationConfig` instance, and returns a
   `ClassificationResult` instance.
2. THE Classification_Pipeline SHALL expose its public entry point
   in a stable module path under `loki.classification` so that GUI,
   CLI, and test code can import it as
   `from loki.classification import classify_components`.
3. WHEN the entry point is called with an empty sequence of
   components, THE Classification_Pipeline SHALL return a
   `ClassificationResult` with an empty `records` list and an
   empty `errors` list.
4. THE Classification_Pipeline SHALL accept its
   `ClassificationConfig` from the caller without itself reading
   any config file, mirroring the extraction pipeline's
   contract; configuration sourcing remains the caller's
   responsibility.
5. WHEN the entry point completes successfully, THE
   Classification_Pipeline SHALL populate every emitted
   `ClassificationRecord.classification_version` with the
   Classification_Pipeline's own semantic version string in
   `^\d+\.\d+\.\d+$` form.
6. WHEN the entry point completes successfully, THE
   Classification_Pipeline SHALL populate every emitted
   `ClassificationRecord.timestamp` with the UTC wall-clock time
   at which the run began, identical across every record produced
   by a single call.
7. THE Classification_Pipeline SHALL run synchronously on the
   calling thread and SHALL NOT spawn worker threads, asyncio
   tasks, or process pools in v1.
8. THE Classification_Pipeline SHALL not depend on any
   `loki.gui` module, so that the CLI and headless test harnesses
   can use the pipeline without importing PyQt6.
9. WHERE the caller passes a cancellation token (a callable
   returning `bool`), THE Classification_Pipeline SHALL check the
   token between components and, if cancellation is requested,
   SHALL stop further classification, emit one
   `Classification_Error` with
   `error_message == "classification cancelled by caller"`, and
   return the partial `ClassificationResult` accumulated so far.

### Requirement 2: Rule file format and rule loading

**User Story:** As a rule curator, I want rules to live in
human-readable YAML files under `ClassificationConfig.rules_path`,
so that I can review individual rules in git diffs, edit one
without touching the rest, and ship rule changes via configuration
rather than code.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL load rules from one or more
   YAML files inside the directory referred to by
   `ClassificationConfig.rules_path`, by enumerating every file
   whose name ends in `.yaml` or `.yml` directly inside that
   directory and parsing each via `yaml.safe_load`.
2. THE Classification_Pipeline SHALL treat every file under
   `ClassificationConfig.rules_path` whose name does not end in
   `.yaml` or `.yml` as foreign and SHALL ignore it during rule
   loading.
3. THE Classification_Pipeline SHALL load and validate the
   complete Rule_Set exactly once, at pipeline construction, and
   SHALL hold the validated Rule_Set immutably for the lifetime
   of the pipeline instance.
4. IF the directory referred to by
   `ClassificationConfig.rules_path` does not exist, is not a
   directory, or is not readable by the current process, THEN
   THE Classification_Pipeline SHALL raise a typed
   `ClassificationConfigError` that names the offending path and
   SHALL NOT return a partially constructed pipeline.
5. THE Classification_Pipeline SHALL accept each YAML rule file
   as a top-level mapping with exactly two keys: `taxonomy_version`
   (string) and `rules` (list of Rule records).
6. WHEN a YAML rule file's `taxonomy_version` does not equal
   `ClassificationConfig.taxonomy_version`, THE
   Classification_Pipeline SHALL raise
   `ClassificationConfigError` carrying the file path, the
   expected version, and the observed version, and SHALL NOT
   load any rule from that file.
7. THE Classification_Pipeline SHALL accept each Rule entry as a
   mapping with the keys `rule_id` (string,
   `^[a-z0-9][a-z0-9._-]{0,127}$`), `axis` (one of `type`,
   `vendor`, `security_posture`, `mutability`), `matcher`
   (Matcher mapping per Requirement 3), and `effect` (Effect
   mapping per Requirement 4); WHERE the entry includes any
   key not in this set, THE Classification_Pipeline SHALL raise
   `ClassificationConfigError`.
8. WHEN two loaded Rule entries share the same `rule_id`, THE
   Classification_Pipeline SHALL raise
   `ClassificationConfigError` carrying both source file paths
   and the duplicated `rule_id` and SHALL NOT proceed.
9. IF any rule file fails YAML parsing, schema validation
   (acceptance criteria 2.5 through 2.8), or Matcher validation
   (Requirement 3) or Effect validation (Requirement 4), THEN
   THE Classification_Pipeline SHALL raise
   `ClassificationConfigError` and SHALL NOT enter the
   classification phase; rule-load errors SHALL NOT appear in
   the per-component `errors` list of `ClassificationResult`.

### Requirement 3: Matcher language

**User Story:** As a rule curator, I want a small declarative
matcher vocabulary that can bind rules to components based on
their extraction-time identity (GUID, name, type hint, size,
content hash), so that I can write deterministic rules without
embedding regex or code execution in YAML.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL accept a Matcher as a
   mapping whose keys are drawn from the closed set
   {`guid`, `name`, `component_type_hint`, `size`, `raw_hash`}
   and whose values are predicates per acceptance criteria 3.2
   through 3.6; WHERE a Matcher includes any key outside this
   set, THE Classification_Pipeline SHALL raise
   `ClassificationConfigError`.
2. THE Classification_Pipeline SHALL accept the `guid` predicate
   as either (a) a single canonical lower-case `8-4-4-4-12` UUID
   string, which fires when
   `ExtractedComponent.guid` equals it case-insensitively, or
   (b) a mapping `{in: [list of UUID strings]}`, which fires
   when `ExtractedComponent.guid` equals any element
   case-insensitively; the Matcher SHALL NOT fire when the
   component's `guid` is `None`.
3. THE Classification_Pipeline SHALL accept the `name` predicate
   as a mapping with exactly one key from {`equals`, `prefix`,
   `suffix`, `contains`} whose value is a non-empty string; the
   Matcher SHALL NOT fire when the component's `name` is `None`,
   and matches SHALL be case-sensitive.
4. THE Classification_Pipeline SHALL accept the
   `component_type_hint` predicate as either (a) a non-empty
   string, which fires when
   `ExtractedComponent.component_type_hint` equals it
   case-sensitively, or (b) a mapping `{in: [list of strings]}`,
   which fires when `component_type_hint` equals any element;
   the Matcher SHALL NOT fire when the component's
   `component_type_hint` is `None`. THE Classification_Pipeline
   SHALL NOT, in v1, validate the predicate's string value
   against any closed set of known hint values; a mistyped hint
   silently fails to fire, leaving the axis to fall through to
   the no-rule-fires fallback per Requirement 4.8.
5. THE Classification_Pipeline SHALL accept the `size` predicate
   as a mapping with one or more keys from {`min`, `max`} whose
   values are non-negative integers, where `min` requires
   `ExtractedComponent.size` to be greater than or equal to its
   value and `max` requires `ExtractedComponent.size` to be less
   than or equal to its value.
6. THE Classification_Pipeline SHALL accept the `raw_hash`
   predicate as either (a) a single 64-character lower-case
   hexadecimal string, which fires when
   `ExtractedComponent.raw_hash` equals it, or (b) a mapping
   `{in: [list of 64-character lower-case hex strings]}`, which
   fires when `ExtractedComponent.raw_hash` equals any element.
7. WHEN a Matcher contains more than one predicate key, THE
   Classification_Pipeline SHALL fire the Matcher only when
   every predicate fires for the component (conjunctive
   semantics); v1 SHALL NOT support disjunctive matchers at the
   Matcher level (disjunction is achieved by writing multiple
   Rules with the same axis).
8. THE Classification_Pipeline SHALL NOT support regular
   expressions, glob patterns, or arbitrary code execution
   inside Matchers in v1.
9. WHEN a Matcher predicate value fails type validation
   (acceptance criteria 3.2 through 3.6), THE
   Classification_Pipeline SHALL raise
   `ClassificationConfigError` carrying the rule's `rule_id`,
   the predicate key, and the offending value.

### Requirement 4: Effect schema and per-axis classification

**User Story:** As a rule curator, I want each rule to assert one
axis label with an explicit confidence, and I want the pipeline to
pick the highest-confidence firing rule per axis with a
deterministic tie-break, so that classification outcomes do not
depend on rule file ordering or Python iteration order.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL accept an Effect as a mapping
   with exactly the keys `label` (string), `confidence` (float in
   `[0.0, 1.0]`), `method` (one of the `ClassificationMethod`
   values: `SIGNATURE`, `RULE`, `HEURISTIC`), and the optional
   key `evidence` (non-empty string); WHERE an Effect includes
   any key outside this set, THE Classification_Pipeline SHALL
   raise `ClassificationConfigError`.
2. WHEN a Rule's `axis` is `type`, THE Classification_Pipeline
   SHALL require `Effect.label` to be a member of
   `ComponentTypeLabel`; WHEN the axis is `vendor`,
   `Effect.label` SHALL be a member of `VendorLabel`; WHEN the
   axis is `security_posture`, `Effect.label` SHALL be a member
   of `SecurityPostureLabel`; WHEN the axis is `mutability`,
   `Effect.label` SHALL be a member of `MutabilityLabel`.
3. THE Classification_Pipeline SHALL classify each axis of a
   given component independently of every other axis; the
   Classification_Pipeline SHALL NOT, in v1, allow the result of
   one axis classification to influence any other axis
   classification.
4. WHEN the Classification_Pipeline classifies an axis for a
   component, THE Classification_Pipeline SHALL collect every
   Rule whose `axis` equals that axis and whose Matcher fires
   on the component, and SHALL select the Winning_Rule as the
   firing Rule with the maximum `Effect.confidence`.
5. WHEN two or more firing Rules tie on `Effect.confidence` for
   a single axis on a single component, THE
   Classification_Pipeline SHALL break the tie by selecting the
   Rule with the lexicographically smallest `rule_id`.
6. WHEN a Winning_Rule is selected for an axis on a component,
   THE Classification_Pipeline SHALL populate that axis's
   `AxisClassification` with `label = Effect.label`,
   `confidence = Effect.confidence`,
   `method = Effect.method`, and `rule_id = Rule.rule_id`.
7. WHERE the Winning_Rule's Effect carries an `evidence` string,
   THE Classification_Pipeline SHALL populate
   `AxisClassification.evidence` with a single-element list
   `[Effect.evidence]`; WHERE the Winning_Rule's Effect does
   not carry an `evidence` string, `AxisClassification.evidence`
   SHALL be `None`.
8. WHEN no Rule fires for a given axis on a given component,
   THE Classification_Pipeline SHALL populate that axis's
   `AxisClassification` with the axis's `UNKNOWN` enum value,
   `confidence = 0.0`, `method = ClassificationMethod.HEURISTIC`,
   `rule_id = None`, and `evidence = None`.
9. WHEN every emitted `ClassificationRecord` is constructed, THE
   Classification_Pipeline SHALL rely on the model layer's
   `composite_confidence = min(...)` and `needs_review =
   composite_confidence < 0.60` invariants without overriding
   either; the Classification_Pipeline SHALL NOT compute either
   field itself.
10. THE Classification_Pipeline SHALL NOT, in v1, gate any
    rule-firing, winning-rule selection, or
    `AxisClassification` construction decision on
    `ClassificationConfig.confidence_threshold`; the field is
    reserved for the analysis engine's review-flag policy and a
    future spec MAY extend its semantics without revising this
    one.

### Requirement 5: Signature handling

**User Story:** As a downstream consumer, I want
`ClassificationRecord.signature_info` populated with whether a
component carries a code-signing signature, without relying on
this subsystem to verify it, so that classification work stays
fast and offline-deterministic.

#### Acceptance Criteria

1. WHEN the Classification_Pipeline classifies an
   `ExtractedComponent`, THE Classification_Pipeline SHALL
   populate `ClassificationRecord.signature_info` with a
   `SignatureInfo` instance whose `present` field is `True`
   when the component's bytes carry a recognized code-signing
   structure detected by the signature-detection step, and
   `False` otherwise (including when bytes are unreadable per
   acceptance criterion 5.6).
2. THE Classification_Pipeline SHALL set
   `SignatureInfo.verified` to `False` for every emitted
   `ClassificationRecord` in v1; signature verification is
   Out_Of_Scope_Operation and a future spec may relax this.
3. THE Classification_Pipeline SHALL set `SignatureInfo.signer`
   to `None` for every emitted `ClassificationRecord` in v1; v1
   does not parse signer identity.
4. THE Classification_Pipeline SHALL set
   `SignatureInfo.cert_expiry` to `None` for every emitted
   `ClassificationRecord` in v1.
5. THE Classification_Pipeline's signature-detection step SHALL
   recognize at minimum the PE32 Authenticode security
   directory entry and the UEFI EFI_FIRMWARE_IMAGE_AUTHENTICATION
   wrapper as evidence of a present signature.
6. WHERE the Classification_Pipeline cannot read the component's
   raw bytes (`ExtractedComponent.raw_path` is `None` or the
   referenced file is missing or unreadable), THE
   Classification_Pipeline SHALL set `SignatureInfo.present` to
   `False` and SHALL emit one `Classification_Error` for the
   component with an `error_message` identifying the missing-bytes
   condition; the corresponding `ClassificationRecord` SHALL
   still be emitted with all four axes classified per
   Requirements 3 and 4. This is the only contracted case in v1
   where a single component appears in both
   `ClassificationResult.records` and
   `ClassificationResult.errors`; downstream consumers SHALL
   treat the pairing as "rule-only classification with a known
   signature-detection limitation" rather than as a hard
   failure.
7. THE Classification_Pipeline SHALL NOT consult any network
   resource, trust root, or external certificate store while
   detecting signature presence.

### Requirement 6: CVE matching - explicitly out of scope

**User Story:** As a downstream consumer, I want
`ClassificationRecord.cve_matches` to be a stable empty list in
v1 so that I do not depend on a CVE feed that does not yet exist.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL leave
   `ClassificationRecord.cve_matches` at its model-layer
   default (the empty list `[]`) for every emitted record in
   v1; v1 SHALL NOT write any CVE entry to the field.
2. THE Classification_Pipeline SHALL NOT load, parse, or query
   any CVE feed, NVD database, or vulnerability data source in
   v1; CVE matching is Out_Of_Scope_Operation.

### Requirement 7: Inner-component classification

**User Story:** As a firmware analyst, I want components carved
from decompressed UEFI sections (Inner_Components emitted by the
extraction pipeline) to be classified the same way as outer
components, so that a baseline derived from a UEFI image with
compressed volumes covers every walkable level uniformly.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL classify every
   `ExtractedComponent` in the input sequence regardless of
   whether the component is an outer component or an
   Inner_Component; the Classification_Pipeline SHALL NOT
   inspect a component's `source_image_id` to decide whether to
   classify it.
2. THE Classification_Pipeline SHALL apply the full Rule_Set to
   Inner_Components without any filtering, derating, or
   restriction relative to outer components.
3. WHEN the Classification_Pipeline classifies an
   Inner_Component, THE
   Classification_Pipeline SHALL set
   `ClassificationRecord.source_image_id` to the
   `ExtractedComponent.source_image_id` of that Inner_Component
   verbatim (preserving the synthetic-UUID derivation chosen by
   the extraction pipeline).
4. THE Classification_Pipeline SHALL NOT, in v1, walk inner
   bytes itself or perform any decompression; it operates only
   on the `ExtractedComponent` records the extraction pipeline
   emits.
5. THE Classification_Pipeline SHALL NOT, in v1, accept an
   `inner_component` key in any Matcher mapping; rule curators
   that wish to target only Inner_Components or only outer
   components SHALL express the distinction through the
   existing Matcher predicates over fields the extraction
   pipeline already records (e.g. via the parent volume's
   `component_type_hint` or `guid`).

### Requirement 8: Determinism and reproducibility

**User Story:** As a tester and as the property-based test suite,
I want classification to be deterministic given the same input
sequence and the same Rule_Set, so that round-trip, idempotence,
and equivalence properties can be tested under Hypothesis and so
that re-classifying a baseline produces stable records.

#### Acceptance Criteria

1. WHEN the Classification_Pipeline is invoked twice on the same
   input sequence with the same `ClassificationConfig` and the
   same Classification_Pipeline version, THE
   Classification_Pipeline SHALL produce two
   `ClassificationResult` values whose `records` lists are
   equal under `model_dump(mode="json")` after stripping the
   `timestamp` field on every record; the equality SHALL include
   the auto-computed `composite_confidence` and `needs_review`
   fields, which derive deterministically from the four axis
   confidences via the model layer's invariants per acceptance
   criterion 4.9.
2. WHEN the Classification_Pipeline is invoked twice on the
   same input sequence with the same Rule_Set, THE
   Classification_Pipeline SHALL produce identical sequences
   of `ClassificationRecord` instances, in the same order, with
   identical per-axis `rule_id` selections.
3. THE Classification_Pipeline SHALL preserve the input
   ordering of `ExtractedComponent` records in the emitted
   `ClassificationResult.records` list; the Classification_Pipeline
   SHALL NOT re-order components.
4. WHEN the Classification_Pipeline is invoked, THE
   Classification_Pipeline SHALL NOT consult environment
   variables, the random number generator, the system clock
   (other than for the wall-clock `timestamp` field permitted by
   acceptance criterion 1.6), or any network resource for any
   decision that affects record contents.
5. THE Classification_Pipeline SHALL NOT, in v1, import any
   symbol from `os.environ`, `random`, `secrets`, `socket`,
   `urllib`, `requests`, `httpx`, or `time.time()` /
   `time.monotonic()` outside a designated timing module
   (mirroring the extraction-pipeline side-channels audit).
6. FOR ALL valid input sequences the pipeline accepts,
   serializing every emitted `ClassificationRecord` to JSON via
   `model_dump_json()` and deserializing via
   `model_validate_json()` SHALL produce a record equal to the
   original (round-trip property).
7. WHEN the Classification_Pipeline is invoked twice in
   succession on the same input sequence and the second
   invocation receives the first invocation's records as a
   no-op input baseline, THE Classification_Pipeline SHALL
   produce records on the second run equal to the first run's
   records under `model_dump(mode="json")` modulo the
   `timestamp` field (idempotence property).

### Requirement 9: Error handling and typed exceptions

**User Story:** As a caller of the Classification_Pipeline (the
classification step that builds baselines, future CLI commands,
GUI, tests), I want every failure mode mapped to a specific typed
exception or to a per-component `Classification_Error`, so that
one bad component never hides the rest and so that rule-curation
mistakes surface loudly.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL expose a typed exception
   hierarchy rooted at `ClassificationError` (subclass of
   `Exception`) and SHALL raise only subclasses of
   `ClassificationError` from its public entry points.
2. THE Classification_Pipeline SHALL distinguish whole-run
   failures (raised as exceptions) from per-component failures
   (recorded as `Classification_Error` records inside
   `ClassificationResult.errors`); rule-load failures and
   pipeline-construction failures SHALL be whole-run failures
   per Requirement 2.9, and per-component classification
   failures SHALL be per-component failures. Per-component
   `records` and `errors` partition components in v1 except
   for the missing-bytes signature-detection case in
   acceptance criterion 5.6, which intentionally produces both
   a `ClassificationRecord` and a `Classification_Error` for
   the same component.
3. WHEN any per-component failure occurs - either an exception
   raised mid-classification (rule evaluation crash,
   signature-detection unexpected error, etc.) or a final
   `ClassificationRecord` model-layer Pydantic validation
   rejection (for example because the chosen axis label is out
   of range despite passing rule-load validation) - THE
   Classification_Pipeline SHALL record a `Classification_Error`
   carrying the component's `component_id` and a non-empty
   `error_message` that names the failure category, SHALL NOT
   emit a `ClassificationRecord` for that component, SHALL NOT
   raise an exception out of the entry point, and SHALL
   continue with the remaining components.
4. THE Classification_Pipeline SHALL populate every emitted
   `Classification_Error.timestamp` with the UTC wall-clock
   time at which the error was recorded.
5. WHEN every component classifies successfully, THE
   Classification_Pipeline SHALL return a
   `ClassificationResult` whose `errors` list is empty.

### Requirement 10: Result construction and validation

**User Story:** As a downstream consumer (the baseline builder,
GUI, analysis engine), I want the pipeline's output to be a
`ClassificationResult` whose embedded `ClassificationRecord`
instances have already passed every model-layer invariant, so
that I never have to re-validate before persisting or analyzing.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL construct each emitted
   `ClassificationRecord` by instantiating `ClassificationRecord`
   directly, so that the model layer's strict validators run
   before the value leaves the subsystem.
2. THE Classification_Pipeline SHALL ensure that for every
   emitted `ClassificationRecord`,
   `ClassificationRecord.component_id` equals the
   `ExtractedComponent.component_id` of the input component,
   `ClassificationRecord.source_image_id` equals
   `ExtractedComponent.source_image_id`, and
   `ClassificationRecord.extraction_offset` equals
   `ExtractedComponent.offset`.
3. THE Classification_Pipeline SHALL leave
   `ClassificationRecord.overrides` at its model-layer default
   (the empty list `[]`) for every emitted record; v1 SHALL
   NOT write any `OverrideRecord` instance to the field.
   Analyst overrides are Out_Of_Scope_Operation for v1 and are
   added by a downstream subsystem that mutates persisted
   baselines.
4. THE Classification_Pipeline SHALL leave
   `ClassificationRecord.suspicion_triggers` at its model-layer
   default (the empty list `[]`) for every emitted record in
   v1; populating this field is the analysis engine's
   responsibility.
5. WHEN every component classifies successfully, THE
   Classification_Pipeline SHALL return a
   `ClassificationResult` whose `records` list has the same
   length as the input sequence and whose entries appear in the
   same order as the input.

### Requirement 11: Performance bounds and resource use

**User Story:** As a baseline builder operating on full SPI
flash dumps that contain hundreds of components, I want
classification of a realistic component set to complete in
bounded memory and bounded time, so that the GUI stays
responsive and CI runs do not exhaust runner resources.

#### Acceptance Criteria

1. WHEN the Classification_Pipeline is invoked on an input
   sequence of up to 4096 `ExtractedComponent` records and a
   Rule_Set of up to 1024 Rules, THE Classification_Pipeline
   SHALL complete in under 30 seconds of wall time on a
   2024-class developer laptop with a local SSD, exclusive of
   signature-detection file I/O.
2. WHEN the Classification_Pipeline performs signature
   detection by reading a component's bytes from
   `ExtractedComponent.raw_path`, THE Classification_Pipeline
   SHALL read the file in chunks of 1 MiB or less rather than
   loading the entire component into memory at once, mirroring
   the extraction pipeline's Streaming_Read contract.
3. WHEN the Classification_Pipeline performs signature-detection
   I/O over an input sequence of up to 4096
   `ExtractedComponent` records whose total on-disk byte
   footprint under their `raw_path` files is up to 256 MiB,
   THE Classification_Pipeline SHALL complete the
   signature-detection phase in under 60 seconds of wall time
   on a 2024-class developer laptop with a local SSD; this
   budget is separate from the matcher-evaluation budget in
   acceptance criterion 11.1.
4. THE Classification_Pipeline SHALL keep peak resident memory
   attributable to classification under a fixed working set of
   64 MiB plus the size of the loaded Rule_Set, independently of
   the size of the input component sequence.
5. THE Classification_Pipeline SHALL evaluate Matchers in
   linear time in the number of Rules per axis (no quadratic
   blowup over the input sequence); v1 SHALL NOT, however,
   require a rule-indexing optimization (e.g. GUID-keyed
   prefilters), which is deferred to a future revision.

### Requirement 12: Integration surface for the GUI and CLI

**User Story:** As the author of the future CLI subcommand and
of the GUI tab that surfaces classification results, I want a
stable, typed integration surface that does not leak rule-engine
internals, so that I can render progress and results without
poking at internal pipeline state.

#### Acceptance Criteria

1. THE Classification_Pipeline SHALL expose a typed progress
   callback parameter on its public entry point that, if
   supplied, is invoked with structured progress events (current
   component index, total component count) at component
   granularity.
2. THE Classification_Pipeline SHALL guarantee that the progress
   callback, if supplied, is invoked from the calling thread
   only.
3. THE Classification_Pipeline SHALL log its activity through
   Python's standard `logging` module under the logger name
   `loki.classification` so that GUI and CLI consumers can
   attach their own handlers without monkey-patching.
4. THE Classification_Pipeline SHALL NOT, in v1, expose a CLI
   subcommand surface (`loki classify` or similar); the CLI
   surface for classification is a separate spec.
5. THE Classification_Pipeline SHALL NOT, in v1, expose a GUI
   integration surface; the GUI's classification view is a
   separate spec.

### Requirement 13: Observability and diagnostics

**User Story:** As a developer debugging a failed classification
on a real-world firmware dump, I want enough structured logging
and diagnostic state to identify which rule fired (or did not
fire) for which component, without leaking the contents of any
classified component.

#### Acceptance Criteria

1. WHEN the Classification_Pipeline is constructed, THE
   Classification_Pipeline SHALL log an INFO record summarizing
   the rules-directory path, the count of YAML rule files
   loaded, and the count of Rules in the validated Rule_Set.
2. WHEN the Classification_Pipeline begins a classification
   run, THE Classification_Pipeline SHALL log an INFO record
   carrying the count of input components and the
   classification version.
3. WHEN the Classification_Pipeline finishes a classification
   run, THE Classification_Pipeline SHALL log an INFO record
   summarizing the wall-clock duration in milliseconds, the
   count of records emitted, and the count of errors emitted.
4. WHEN the Classification_Pipeline emits a
   `Classification_Error`, THE Classification_Pipeline SHALL
   log a WARNING record carrying the same `error_message` and
   the count of axes that had been classified before the
   failure (a small integer in `[0, 4]`); the logged record
   SHALL NOT carry the failed component's `component_id`,
   `source_image_id`, or any per-axis evidence string.
5. THE Classification_Pipeline SHALL NOT, at any time, log any
   member of the Forbidden_Leakage_Field_Set:
   `ExtractedComponent.component_id` or its mirrored
   `ClassificationRecord.component_id`, `SignatureInfo.signer`,
   the parent `BaselineRecord.source_image_hash`, or any value
   carried in `AxisClassification.evidence`.
6. THE Classification_Pipeline SHALL NOT, at any time
   (including while idle, during initialization, during
   shutdown, or while no input is being processed), log the
   raw contents of any classified component, the bytes read
   for signature detection, or any per-axis evidence string;
   inspection of classification records for debugging SHALL be
   performed via the future `loki classify show` CLI subcommand
   or by inspecting the returned `ClassificationResult`, not
   via log records.
