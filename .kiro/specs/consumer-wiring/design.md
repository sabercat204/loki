
# Design Document — Consumer Wiring (CVE Feed Integration)

## Overview

This spec wires the Feeds subsystem's `cve_lookup` API into its two
declared consumers: the classification pipeline (populates
`ClassificationRecord.cve_matches`) and the analysis engine (surfaces
`FindingEvidence.matched_cve` and `DeviationScore.cve_introduced`).
The wiring is opt-in: when no `FeedRegistry` is supplied, both
subsystems behave identically to their v1 contracts.

## Architecture

### Classification pipeline changes

The public entry point `classify_components` gains one keyword
argument:

```python
def classify_components(
    components: Sequence[ExtractedComponent],
    config: ClassificationConfig,
    *,
    progress: Callable[[ProgressEvent], None] | None = None,
    cancel: Callable[[], bool] | None = None,
    feeds: FeedRegistry | None = None,          # NEW (G1-A)
    source_image: FirmwareImage | None = None,  # NEW (G1-A)
) -> ClassificationResult:
```

When `feeds is not None` and `source_image is None`, the pipeline
raises `ClassificationConfigError` — feeds lookup requires the
firmware version from the source image (TENSION G1-A).

When `feeds is not None`, the pipeline:

1. After building each `ClassificationRecord` (axes + signature),
   derives a `CVELookupQuery` via `derive_cve_query(record, source_image)`.
2. Calls `feeds.cve_lookup(query, allow_refresh=False)`.
3. Extracts the CVE ID strings from the result matches, deduplicates,
   sorts lexicographically, and assigns to `cve_matches`.
4. On any `FeedsError`, logs a WARNING and leaves `cve_matches=[]`.

The `loki.feeds` import is deferred inside the pipeline's
`_populate_cve_matches` helper — never at module level.

### Analysis engine changes

The analysis engine's `emit_classification_mismatch` function in
`loki/analysis/findings.py` currently hardcodes:

```python
matched_cve=None,
...
cve_introduced=False,
```

After this spec:

1. `matched_cve` is set to the lexicographically-first CVE from
   `target_record.cve_matches` (the list is sorted ascending;
   lex-first is deterministic and stable — TENSION G2-B). When
   `cve_matches` is empty, remains `None`.
2. `cve_introduced` is set to `True` when the target's
   `cve_matches` contains at least one CVE ID not present in the
   baseline record's `cve_matches`. Otherwise `False`.
3. When `cve_introduced is True`, the raw composite score is
   bumped by `config.cve_score_bump` (default 0.5) before the
   existing `[0.0, 10.0]` clamp.

The analysis engine reads only from the model field
(`ClassificationRecord.cve_matches`) — no import from `loki.feeds`.

### Model layer changes

`AnalysisConfig` gains one field:

```python
cve_score_bump: float = Field(default=0.5, ge=0.0, le=5.0)
```

No other model changes. `ClassificationRecord.cve_matches` is
already `list[str]` with a default of `[]`.

### CLI changes

`loki classify` gains `--feeds-config PATH`:

- When supplied, constructs `LokiConfig.from_yaml(path)` and
  `FeedRegistry.from_config(config.feeds)`, passes it as
  `feeds=registry`.
- When omitted, passes `feeds=None`.
- On `FeedsConfigError`, prints to stderr and exits 2 (config
  error) — classification does not proceed.

### Data flow

```
[Operator]
    |
    v
loki classify --feeds-config loki.yaml manifest.json --rules-path ./rules
    |
    v
classify_components(components, config, feeds=registry, source_image=manifest.source_image)
    |
    |--- per component:
    |       build ClassificationRecord (axes + signature)
    |       derive_cve_query(record, source_image)
    |       registry.cve_lookup(query, allow_refresh=False)
    |       record.cve_matches = sorted CVE IDs
    |
    v
ClassificationResult (records with populated cve_matches)
    |
    v
analyze_image(target_records, baseline_registry, image, config)
    |
    |--- per classification_mismatch:
    |       target.cve_matches vs baseline.cve_matches
    |       matched_cve = highest-CVSS from target.cve_matches
    |       cve_introduced = any(target CVE not in baseline CVEs)
    |       if cve_introduced: composite_score += config.cve_score_bump
    |
    v
ImageAnalysisReport (findings with real matched_cve/cve_introduced)
```

## Design decisions

### D1: `feeds` parameter on `classify_components` rather than config

The `FeedRegistry` is an already-constructed, validated object
rather than a raw `FeedsConfig`. This means the caller owns
construction and error handling; the pipeline receives a
ready-to-use registry. This mirrors how the classification pipeline
takes a `ClassificationConfig` (not a path to a config file).

### D2: `allow_refresh=False` on every lookup

The classification pipeline is a batch operation. Triggering
network refreshes mid-classification would introduce
non-determinism and unpredictable latency. Operators warm the cache
before classification via `loki feeds refresh`.

### D3: Lexicographic-first selection for `matched_cve` (TENSION G2-B)

When multiple CVEs match, the finding surfaces the
lexicographically-first CVE ID as `matched_cve`. Since
`cve_matches` is sorted ascending, this is deterministic and
stable. A future revision may select by highest-CVSS when CVSS
data is available on the `ClassificationRecord` (requires
enriching `cve_matches` from `list[str]` to a richer type). The
full list remains available on `cve_matches` for detailed review.

### D4: Configurable `cve_score_bump` with 0.5 default (TENSION G3-A)

A fixed bump is simple to reason about but operators with different
risk profiles may want to tune it. The `[0.0, 5.0]` range prevents
a single CVE introduction from dominating the 10-point composite
scale while still allowing meaningful escalation.

**Cascade interaction (G3-A):** The bump is applied BEFORE the
PostureRating six-rule cascade evaluates composite_score thresholds.
This means a CVE introduction CAN push a finding across a posture
boundary (e.g. 7.5 + 0.5 = 8.0 → COMPROMISED). This is the
intended escalation behavior: a newly-introduced CVE is a material
severity increase that should be reflected in the posture rating.

### D5: No `loki.feeds` import in analysis engine

The analysis engine reads the model field only. This preserves the
clean dependency graph: `analysis -> models` (not
`analysis -> feeds`). The feeds subsystem is a producer; the
analysis engine is a consumer of the model layer's data.

### D6: Graceful degradation on feed errors

A broken or missing feed cache should never abort classification.
The WARNING log + empty `cve_matches` fallback means operators get
their classification results even if feeds are misconfigured. They
can re-run with a healthy cache later.

### D7: Baseline bootstrap behavior (TENSION G4-A)

Existing baselines classified under the v1 spec have
`cve_matches=[]` on every record. When the analysis engine compares
a newly-classified target (with populated `cve_matches`) against a
v1 baseline (`cve_matches=[]`), every target CVE will appear as
"introduced" — `cve_introduced=True` on every mismatch finding.

This is the expected bootstrap behavior. Operators should
regenerate baselines by re-classifying with feeds enabled to get
accurate `cve_introduced` comparisons. The alternative (treating
`baseline.cve_matches=[]` as "unknown" and suppressing
`cve_introduced`) would mask real CVE introductions on baselines
that genuinely had zero CVEs.

## Correctness Properties

### Property 69: CVE population determinism

For the same input components + same Cache_DB state + same config,
two `classify_components` invocations with the same `FeedRegistry`
produce byte-equal `cve_matches` on every record.

**Validates: R1.7**

### Property 70: CVE introduction detection correctness

For every `classification_mismatch` finding where
`target.cve_matches` contains at least one CVE not in
`baseline.cve_matches`, `cve_introduced` is `True` and the
composite score is bumped by `cve_score_bump`.

**Validates: R2.2, R2.4**

### Property 71: Backward compatibility

When `feeds=None` is passed to `classify_components`, the output
is byte-identical to calling without the `feeds` parameter.
When all `cve_matches` are `[]`, analysis output is byte-identical
to v1.

**Validates: R3.1, R3.2**

## Testing Strategy

Tests live at `tests/consumer_wiring/`:

- `test_classification_cve_population.py` — R1 integration tests
- `test_analysis_cve_surfacing.py` — R2 integration tests
- `test_backward_compat.py` — R3 regression tests
- `test_cli_feeds_config.py` — R4 CLI flag tests
- `test_error_handling.py` — R1.5 graceful degradation
- `test_properties.py` — Hypothesis P69-P71

## Module layout

No new modules are created. Changes touch:

- `loki/classification/pipeline.py` — add `feeds` + `source_image`
  parameter plumbing + `_populate_cve_matches` helper
- `loki/classification/api.py` — thread `feeds` + `source_image`
  through to pipeline
- `loki/analysis/findings.py` — update `emit_classification_mismatch`
- `loki/analysis/scoring.py` — add `cve_score_bump` to composite
  score calculation
- `loki/models/config.py` — add `cve_score_bump` field to
  `AnalysisConfig`
- `loki/classify_helpers.py` — add `--feeds-config` handling
- `loki/cli.py` — register `--feeds-config` flag

## Performance impact

Per-component overhead is bounded by the Feeds R12.1 contract:
one SQLite query per component taking <= 50 ms against 200k CVEs.
For a 4096-component run, worst case is 4096 * 50 ms = 204 s — but
actual performance is ~0.5 ms per lookup (indexed query), so a
4096-component classification adds ~2 s total. This is well within
the classification pipeline's existing R11.1 30 s budget for
4096 components x 1024 rules.

The analysis engine change is O(1) per finding: a set intersection
on small lists (typically 0-5 CVE IDs). No measurable impact on
the R18.1 budget.
