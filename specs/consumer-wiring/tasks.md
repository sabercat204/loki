
# Implementation Plan — Consumer Wiring

## Overview

Wires `FeedRegistry.cve_lookup` into the classification pipeline and
surfaces the populated `cve_matches` in the analysis engine's
`classification_mismatch` findings. Six requirements, three
properties (P69-P71), twelve tasks across four waves.

## Pre-flight checklist

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m ruff check
.venv/bin/python -m ruff format --check
```

Current checkpoint: **1556 passed, 12 deselected**, mypy clean
across **278 source files**.

## Tasks

- [x] 1. Add `cve_score_bump` field to `AnalysisConfig`

  - In `loki/models/config.py`, add `cve_score_bump: float = Field(default=0.5, ge=0.0, le=5.0)` to `AnalysisConfig`.
  - Update any existing test that constructs `AnalysisConfig` to confirm the new field defaults correctly.
  - Add a test in `tests/test_config.py` (or `tests/analysis/test_analysis_config_extension.py`) covering: default is 0.5, accepts 0.0, accepts 5.0, rejects negative, rejects > 5.0, YAML round-trip.
  - Run verification gates.
  - _Requirements: R2.5_
  - _Design: Model layer changes_

- [x] 2. Thread `feeds` and `source_image` parameters through `classify_components`

  - In `loki/classification/api.py`, add `feeds: FeedRegistry | None = None` and `source_image: FirmwareImage | None = None` keyword arguments to `classify_components` and thread them through to the pipeline constructor.
  - In `loki/classification/pipeline.py`, accept `feeds` and `source_image` in `ClassificationPipeline.__init__` and store as `self._feeds` and `self._source_image`.
  - In the pipeline constructor: if `feeds is not None` and `source_image is None`, raise `ClassificationConfigError` with a clear message.
  - Use `TYPE_CHECKING` guard for the `FeedRegistry` and `FirmwareImage` type annotations to avoid runtime import.
  - Verify: `classify_components(components, config)` still works identically (no `feeds` = `None`).
  - Run verification gates. All existing tests must pass unchanged.
  - _Requirements: R1.8, R1.9, R3.4_
  - _Design: D1, G1-A_

- [x] 3. Implement `_populate_cve_matches` helper in classification pipeline

  - In `loki/classification/pipeline.py`, add a private method `_populate_cve_matches(self, record, source_image) -> list[str]`.
  - Implementation: if `self._feeds is None`, return `[]`. Otherwise, import `derive_cve_query` and `CVELookupQuery` inside the method body (lazy import per R1.10). Call `derive_cve_query(record, self._source_image)` to build the query. Call `self._feeds.cve_lookup(query, allow_refresh=False)`. Extract `match.cve_id` from results, deduplicate, sort, return.
  - Wrap the entire body in a try/except for any `Exception` (not just `FeedsError`) to be maximally defensive — log WARNING, return `[]`.
  - Wire `_populate_cve_matches` into the record-building loop: after record construction, call the helper and assign result to `record.cve_matches` (the model is not frozen, so direct assignment works).
  - Add `tests/consumer_wiring/__init__.py` and `tests/consumer_wiring/test_classification_cve_population.py` with tests covering:
    - `feeds=None` → `cve_matches=[]` on all records.
    - `feeds` supplied with matching cache → `cve_matches` populated.
    - `feeds` supplied with no matches → `cve_matches=[]`.
    - CVE IDs sorted and deduplicated.
    - `FeedsError` during lookup → WARNING logged, `cve_matches=[]`, classification continues.
  - _Requirements: R1.1-R1.7, R1.9_
  - _Design: Classification pipeline changes; D2, D6_

- [x] 4. Update `emit_classification_mismatch` to surface CVE data

  - In `loki/analysis/findings.py`, update `emit_classification_mismatch`:
    - Read `target_record.cve_matches`. If non-empty, set `matched_cve` to `target_record.cve_matches[0]` (lex-first per TENSION G2-B; the list is sorted ascending).
    - Compare `target_record.cve_matches` against the paired `baseline_record.cve_matches` (set difference). If any CVE in target is not in baseline, set `cve_introduced=True`.
  - In `loki/analysis/findings.py`, update the composite score calculation within `emit_classification_mismatch`: when `cve_introduced=True`, add `cve_score_bump` (passed as a parameter from the pipeline, sourced from `config.cve_score_bump`) to the raw composite before the existing `[0.0, 10.0]` clamp.
  - Add `tests/consumer_wiring/test_analysis_cve_surfacing.py` covering:
    - Target with `cve_matches=["CVE-2026-0001"]`, baseline with `cve_matches=[]` → `matched_cve="CVE-2026-0001"`, `cve_introduced=True`, composite score bumped.
    - Target with `cve_matches=["CVE-2026-0001"]`, baseline with `cve_matches=["CVE-2026-0001"]` → `cve_introduced=False`, no bump.
    - Target with `cve_matches=[]` → `matched_cve=None`, `cve_introduced=False` (v1 behavior).
    - Composite score with bump does not exceed 10.0 (clamp test).
    - `cve_score_bump=0.0` config → no bump even with `cve_introduced=True`.
  - _Requirements: R2.1-R2.4, R2.6-R2.7_
  - _Design: Analysis engine changes; D3, D4, D5_

- [x] 5. Add backward-compatibility regression tests

  - Create `tests/consumer_wiring/test_backward_compat.py`:
    - Classify synthetic components with `feeds=None`, compare output to a reference run from before this spec. Assert byte-identical JSON (modulo timestamp).
    - Run `analyze_image` against records with `cve_matches=[]`, assert all `matched_cve=None` and `cve_introduced=False`.
    - Assert test count has not decreased.
  - _Requirements: R3.1-R3.3_
  - _Design: Property 71_

- [x] 6. Wire `--feeds-config` into `loki classify` CLI

  - In `loki/cli.py` (or `loki/classify_helpers.py`), add `--feeds-config` optional argument to the classify subcommand parser.
  - In the classify handler: when `--feeds-config` is supplied, construct `LokiConfig.from_yaml(path)` and `FeedRegistry.from_config(config.feeds)`. On `FeedsConfigError`, print diagnostic to stderr and exit 2.
  - Pass `feeds=registry` and `source_image=manifest.source_image` to `classify_components`.
  - Add `tests/consumer_wiring/test_cli_feeds_config.py` covering:
    - `--feeds-config` omitted → works as before.
    - `--feeds-config` with valid config + pre-populated cache → `cve_matches` populated in stdout JSON.
    - `--feeds-config` with invalid config → exit 2.
    - `--feeds-config` with nonexistent file → exit 2.
  - _Requirements: R4.1-R4.4_
  - _Design: CLI changes_

- [x] 7. Add Hypothesis property tests (P69-P71)

  - Create `tests/consumer_wiring/test_properties.py`:
    - **P69**: Two `classify_components` calls with the same `FeedRegistry` produce byte-equal `cve_matches`. `max_examples=25`.
    - **P70**: For every mismatch finding where target has novel CVEs, `cve_introduced=True` and score is bumped. Parameterized across several synthetic configurations.
    - **P71**: `feeds=None` → output identical to pre-wiring reference. Deterministic.
  - _Requirements: R5.1-R5.4_
  - _Design: Properties P69-P71_

- [x] 8. Add error-handling tests

  - Create `tests/consumer_wiring/test_error_handling.py`:
    - Monkey-patch `FeedRegistry.cve_lookup` to raise `FeedsNetworkError`.
    - Assert: WARNING logged, `cve_matches=[]` on affected record, classification continues to completion, exit code 0.
    - Monkey-patch to raise generic `Exception`.
    - Assert: same graceful degradation.
  - _Requirements: R1.5, R5.5_
  - _Design: D6_

- [x] 9. Document CVSS selection as deferred improvement

  - Task 4 already uses lex-first per TENSION G2-B. This task is documentation-only.
  - Add a brief code comment in `emit_classification_mismatch` at the `matched_cve` assignment noting: "lex-first for v1; future revision may select by highest-CVSS when cve_matches carries score data."
  - _Requirements: R2.1_
  - _Design: D3 (G2-B)_

- [x] 10. Run full verification suite

  - Run all four gates:
    ```bash
    .venv/bin/python -m pytest -q
    .venv/bin/python -m mypy --strict loki tests scripts
    .venv/bin/python -m ruff check
    .venv/bin/python -m ruff format --check
    ```
  - Confirm: all existing tests pass, new tests pass, no regressions.
  - Confirm: `from loki.classification import classify_components` still works.
  - Confirm: `from loki.analysis import analyze_image` still works.
  - Confirm: `loki classify --help` shows `--feeds-config`.
  - Record final test count.
  - _Requirements: all — final gate_
  - _Design: all_

## Wave plan

- **Wave 1 (tasks 1-2).** Model extension + parameter threading. Pure structural — no behavior change, all existing tests pass.
- **Wave 2 (tasks 3-4).** Core wiring: classification CVE population + analysis CVE surfacing. The two integration points land with their own test coverage.
- **Wave 3 (tasks 5-8).** Backward-compat regression, CLI flag, property tests, error handling. Confidence-building coverage.
- **Wave 4 (tasks 9-10).** CVSS selection refinement note + final verification gate.

## Notes

- **Property numbering picks up at P69** per the platform-wide convention (feeds ended at P68).
- **The `ClassificationRecord` model is NOT frozen.** Direct assignment to `record.cve_matches` works after construction. If it were frozen, we'd need a model rebuild step.
- **The analysis engine does NOT import `loki.feeds`.** It reads `cve_matches` from the model field only. This is critical for the dependency graph.
- **`allow_refresh=False` is non-negotiable.** The classification pipeline must not trigger network egress.
- **The CVSS-based selection for `matched_cve` is deferred** pending CVSS data availability on the `ClassificationRecord` (the `cve_matches` field carries only string IDs, not full `CVEMatch` objects). For now, lex-first is deterministic and stable.
