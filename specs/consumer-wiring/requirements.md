
# Requirements — Consumer Wiring (CVE Feed Integration)

## Introduction

The Consumer Wiring spec bridges the Feeds subsystem's lookup API
into its two declared consumers: the **classification pipeline**
(which populates `ClassificationRecord.cve_matches`) and the
**analysis engine** (which surfaces the populated values through
`FindingEvidence.matched_cve` and `DeviationScore.cve_introduced`).

The Feeds subsystem (v1.0.0, IMPLEMENTED) explicitly scoped the
consumer integration as out-of-scope for its own spec:

> "A CVE-to-finding rendering surface. The Feeds subsystem
> populates `ClassificationRecord.cve_matches`; the analysis
> engine then surfaces those values via its existing
> `FindingEvidence.matched_cve` and
> `DeviationScore.cve_introduced` channels."
> — `specs/feeds/requirements.md`, Non-goals

Classification pipeline R6 contracts `cve_matches` as always `[]`
in v1. Analysis engine R9.9 contracts `cve_introduced` as always
`False` in v1. This spec supersedes both v1 contracts — it is the
v2 amendment that lifts those deferral gates.

### Scope

- Wire `FeedRegistry.cve_lookup` into the classification pipeline
  so `ClassificationRecord.cve_matches` carries real CVE IDs when
  a `FeedsConfig` is provided.
- Wire `ClassificationRecord.cve_matches` into the analysis
  engine's `classification_mismatch` finding emitter so
  `FindingEvidence.matched_cve` and `DeviationScore.cve_introduced`
  carry real values.
- Preserve full backward compatibility: when no `FeedsConfig` is
  provided (or feeds are unreachable), the v1 behavior is
  unchanged (`cve_matches=[]`, `matched_cve=None`,
  `cve_introduced=False`).

### Non-goals (explicit)

- Modifying the Feeds subsystem itself. Its library API is
  consumed verbatim.
- Adding new finding categories to the analysis engine. Only the
  existing `classification_mismatch` category is affected.
- GUI integration. The populated fields render through the
  existing model views; no GUI spec change needed.
- Fleet CVE rollup. That is fleet-analysis territory.
- Implant-rule integration into classification. v1 of the
  consumer wiring covers CVE lookup only; implant-rule lookup
  wiring is reserved for a future spec.
- Adding `FeedsConfig` as a required parameter. It remains
  optional; feeds integration is opt-in.

## Requirements

### Requirement 1: Classification pipeline CVE population

**User Story:** As a firmware analyst, I want each
`ClassificationRecord` produced by the classification pipeline to
carry a list of matching CVE identifiers drawn from the Feeds
cache, so that downstream consumers (the analysis engine, the GUI,
export tools) can surface CVE relevance without a separate lookup
step.

#### Acceptance Criteria

1. WHEN a pre-constructed `FeedRegistry` is supplied to
   `classify_components`, THE classification pipeline SHALL
   call `cve_lookup` for each component and assign the
   resulting CVE ID list to
   `ClassificationRecord.cve_matches`.
2. WHEN no `FeedRegistry` is supplied (the parameter is
   `None` or omitted), THE classification pipeline SHALL leave
   `cve_matches` at its model-layer default (`[]`) for every
   emitted record — identical to v1 behavior.
3. THE classification pipeline SHALL derive the
   `CVELookupQuery` for each component using
   `derive_cve_query(record, source_image)` from
   `loki.feeds.registry`.
4. THE classification pipeline SHALL call `cve_lookup` with
   `allow_refresh=False` — the classification pipeline is not
   the right place to trigger network egress. Operators
   refresh the cache explicitly via `loki feeds refresh`.
5. THE classification pipeline SHALL handle lookup failures
   (any `FeedsError` subclass) by logging a WARNING and leaving
   `cve_matches=[]` for that record — a feed failure SHALL NOT
   abort classification.
6. THE `cve_matches` field SHALL carry only the CVE ID strings
   (e.g. `["CVE-2026-0001", "CVE-2026-0002"]`), sorted
   lexicographically ascending, with no duplicates.
7. THE classification pipeline's determinism contract (R10.1
   from classification-pipeline) SHALL hold modulo
   `cve_matches`: same input + same Cache_DB state produces
   the same `cve_matches` on every run.
8. THE `classify_components` function signature SHALL accept
   an optional `feeds: FeedRegistry | None = None` keyword
   argument. No positional-argument change.
9. THE `classify_components` function signature SHALL accept
   an optional `source_image: FirmwareImage | None = None`
   keyword argument. WHEN `feeds` is not `None` and
   `source_image` is `None`, THE pipeline SHALL raise
   `ClassificationConfigError` — feeds lookup requires the
   firmware version from the source image.
10. THE classification pipeline SHALL NOT import from
    `loki.feeds` at module level — only inside the code path
    gated on `feeds is not None`. This preserves the
    `import loki.classification` fast path for callers that
    don't use feeds.

### Requirement 2: Analysis engine CVE surfacing

**User Story:** As a firmware analyst reviewing an
`ImageAnalysisReport`, I want each `classification_mismatch`
finding to tell me whether a new CVE was introduced relative
to the baseline, so that I can prioritize vulnerabilities that
the firmware update introduced.

#### Acceptance Criteria

1. WHEN a `classification_mismatch` finding is emitted and the
   target `ClassificationRecord.cve_matches` is non-empty, THE
   analysis engine SHALL set `FindingEvidence.matched_cve` to
   the lexicographically-first CVE ID from `cve_matches` (the
   list is sorted ascending, so this is the lowest CVE ID —
   deterministic and stable). A future revision may select by
   highest-CVSS when CVSS data is available on the record.
2. WHEN the target's `cve_matches` contains at least one CVE ID
   that is NOT present in the paired baseline record's
   `cve_matches`, THE analysis engine SHALL set
   `DeviationScore.cve_introduced` to `True`.
3. WHEN the target's `cve_matches` is empty OR every CVE in the
   target also appears in the baseline, THE analysis engine
   SHALL set `DeviationScore.cve_introduced` to `False` —
   identical to v1 behavior.
4. WHEN `cve_introduced` is `True`, THE analysis engine SHALL
   add `AnalysisConfig.cve_score_bump` (default `0.5`) to the
   raw Composite_Score BEFORE clamping to `[0.0, 10.0]` — a
   CVE introduction is a material severity escalation. The
   bump is configurable so operators can tune escalation
   sensitivity.
5. THE `AnalysisConfig` model SHALL gain a
   `cve_score_bump: float = 0.5` field with a
   `Field(ge=0.0, le=5.0)` constraint.
6. THE analysis engine SHALL NOT import from `loki.feeds` —
   it reads `cve_matches` from the `ClassificationRecord`
   model field only. No coupling to the Feeds subsystem.
7. THE analysis engine's determinism contract (R15.1 from
   analysis-engine) SHALL hold: same input records (including
   `cve_matches` values) produce the same report.

### Requirement 3: Backward compatibility

**User Story:** As an operator who has not configured feeds, I
want the classification and analysis subsystems to work exactly
as they did before, with no behavioral change.

#### Acceptance Criteria

1. WHEN `feeds=None` is passed to `classify_components` (or
   omitted), THE classification pipeline SHALL produce
   byte-identical output to v1 for the same inputs.
2. WHEN every `ClassificationRecord.cve_matches` in the target
   set is `[]`, THE analysis engine SHALL produce byte-identical
   output to v1 for the same inputs (all `matched_cve=None`,
   all `cve_introduced=False`).
3. No existing test SHALL be broken by this change. The existing
   1556-test baseline SHALL continue to pass.
4. THE `classify_components` function's existing positional
   arguments and keyword arguments (`progress`, `cancel`)
   SHALL NOT change position or semantics.

### Requirement 4: CLI integration

**User Story:** As an operator using `loki classify`, I want to
optionally supply a config path so that the classify CLI wires
up feeds automatically.

#### Acceptance Criteria

1. THE `loki classify` subcommand SHALL accept an optional
   `--feeds-config` flag pointing to a loki config YAML that
   contains a `feeds` section.
2. WHEN `--feeds-config` is supplied, THE CLI SHALL construct a
   `FeedRegistry.from_config(config.feeds)` and pass it as the
   `feeds` keyword argument to `classify_components`.
3. WHEN `--feeds-config` is omitted, THE CLI SHALL pass
   `feeds=None` — identical to v1.
4. WHEN `FeedRegistry.from_config` raises `FeedsConfigError`,
   THE CLI SHALL print a diagnostic to stderr and exit 2
   (config error) — classification SHALL NOT proceed with a
   broken feed registry.

### Requirement 5: Testing

**User Story:** As a developer, I want the consumer-wiring
integration to be covered by tests that exercise both the
populated and unpopulated paths.

#### Acceptance Criteria

1. At least one integration test SHALL classify a set of
   synthetic components with a pre-populated `FeedRegistry`
   and assert `cve_matches` is populated on matching records.
2. At least one integration test SHALL classify the same
   components WITHOUT feeds and assert `cve_matches` remains
   `[]` on every record.
3. At least one integration test SHALL run `analyze_image`
   against records with populated `cve_matches` and assert
   `matched_cve` and `cve_introduced` carry real values on
   the relevant `classification_mismatch` finding.
4. At least one integration test SHALL run `analyze_image`
   against records with empty `cve_matches` and assert the
   v1 behavior (`matched_cve=None`, `cve_introduced=False`).
5. At least one test SHALL verify that a `FeedsError` during
   lookup is handled gracefully (WARNING logged,
   `cve_matches=[]`, classification continues).
6. The test count SHALL increase; no existing tests SHALL
   break.

### Requirement 6: Performance

**User Story:** As an operator classifying thousands of
components, I want feeds integration to add minimal overhead.

#### Acceptance Criteria

1. THE per-component CVE lookup overhead SHALL be bounded by
   the Feeds subsystem's R12.1 contract (50 ms per lookup
   against 200k CVEs); since the classification pipeline calls
   with `allow_refresh=False`, no network latency applies.
2. THE analysis engine's per-finding CVE check SHALL be
   bounded-constant for realistic inputs (set intersection
   on lists of typically 0-5 entries); no additional
   performance test is required beyond the existing R18.1
   budget.
