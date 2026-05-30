# Implementation Plan

## Overview

This is the executable task list for the **classification-pipeline**
spec. Tasks are ordered so that each one builds on previous tasks
and leaves the repo in a verifiable state (every checkpoint passes
`pytest`, `mypy --strict`, `ruff check`, and `ruff format --check`).

Each task lists the exact files it touches, the test surface it
adds, and the design / requirement references it implements.
Sub-bullets under each task are checklist items the implementer
ticks off as they go; they are not separate tasks.

Honest scope reminder: this plan covers classification only.
Signature verification, CVE matching, cross-axis inference,
classification persistence, the `loki classify` CLI surface, and
the GUI classification view are explicitly out of scope and have
their own (future) specs. v1 ships only the library API at
`from loki.classification import classify_components`.

## Pre-flight checklist

Before starting, confirm the repo is healthy:

```bash
.venv/bin/pytest -q
.venv/bin/mypy --strict loki tests scripts
.venv/bin/ruff check
.venv/bin/ruff format --check
```

All four must be green. The current checkpoint is **566 passed,
4 deselected** with mypy clean across **132 source files**. The
classification work assumes the model layer, extraction pipeline,
and baseline-persistence subsystems are all intact.

## Tasks

- [x] 1. Scaffold the `loki/classification/` package skeleton

  - Create `loki/classification/__init__.py`,
    `api.py`, `pipeline.py`, `version.py`, `classifier.py`,
    `signatures.py`, `errors.py`, `timing.py` as empty modules
    with docstrings + `__all__: list[str] = []`.
  - Create the `rules/` subpackage:
    `loki/classification/rules/__init__.py`, `loader.py`,
    `schema.py`, `matcher.py`, all empty with docstrings +
    `__all__: list[str] = []`.
  - Create `tests/classification/__init__.py` and an empty
    `tests/classification/conftest.py` so pytest can collect
    from the new tree.
  - Create `tests/classification/rules/__init__.py` so the
    nested test package collects.
  - Verify the empty subsystem imports cleanly:
    `.venv/bin/python -c "import loki.classification"`.
  - _Requirements: none — pure scaffolding_
  - _Design: Components and Interfaces — Module layout_

- [x] 2. Implement the `CLASSIFICATION_VERSION` constant module

  - In `loki/classification/version.py` define
    `CLASSIFICATION_VERSION: str = "1.0.0"`.
  - Document in the module docstring that R1.5 contracts a
    semver string in `^\d+\.\d+\.\d+$` form and that a minor
    bump is required when any rule-evaluation behavior changes
    (currently a manual discipline; future work could enforce
    via a property test).
  - Re-export `CLASSIFICATION_VERSION` from
    `loki.classification.__init__`.
  - Add `tests/classification/test_version.py` covering: the
    constant exists, is a string, and matches
    `^\d+\.\d+\.\d+$`.
  - _Requirements: 1.5_
  - _Design: Components and Interfaces — Module layout_

- [x] 3. Implement the typed exception hierarchy + `ClassificationError` model

  - In `loki/classification/errors.py` define:
    - `ClassificationPipelineError(Exception)` — root parent.
    - `ClassificationConfigError(ClassificationPipelineError)`
      carrying `path: Path` and a free-form message. Used for
      whole-directory and whole-file failures.
    - `ClassificationRuleError(ClassificationPipelineError)`
      carrying `path: Path`, `rule_id: str | None`, and a
      free-form message. Used for individual-rule schema /
      matcher / effect validation failures.
    - `ClassificationError(BaseModel)` — Pydantic model with
      `component_id: uuid.UUID | None`, `error_message: str`
      (validator: non-empty), and `timestamp: datetime`
      (UTC). Mirrors `ExtractionError` structurally.
  - Each exception class is a normal `Exception` subclass with
    typed `__init__` (no Pydantic — these are control-flow
    exceptions, not data models).
  - Re-export every public exception and the
    `ClassificationError` model from
    `loki.classification.__init__`.
  - Add `tests/classification/test_exceptions.py` covering:
    every exception class is constructible with the documented
    kwargs; `ClassificationConfigError` and
    `ClassificationRuleError` are subclasses of
    `ClassificationPipelineError`; `str()` includes the path
    and any rule_id; `ClassificationError` rejects an empty /
    whitespace-only `error_message`.
  - _Requirements: 9.1, 9.3, 9.4_
  - _Design: Components and Interfaces — Exception hierarchy;
    Error Handling_

- [x] 4. Implement the timing helper

  - In `loki/classification/timing.py` implement a `Stopwatch`
    context manager (`time.monotonic`-based) returning the
    wall-clock duration in milliseconds via a `duration_ms`
    property after exit.
  - The module is the **single permitted clock-using module**
    inside `loki.classification` (mirroring extraction's
    pattern). The side-channels audit (task 18) pins this.
  - Add `tests/classification/test_timing.py` covering: the
    stopwatch records monotonic time; `duration_ms` is `>= 0`
    inside any reasonable run; using the stopwatch as a
    context manager records the duration on exit.
  - _Requirements: 8.5_
  - _Design: Determinism contract; Property 41_

- [x] 5. Implement the rule schema (Pydantic typed shapes)

  - In `loki/classification/rules/schema.py` implement the
    eight typed shapes from the design's "Rule schema"
    section:
    - `GuidPredicate(values: tuple[str, ...])` — frozen,
      `extra="forbid"`. Validator normalizes every UUID to
      canonical lower-case `8-4-4-4-12` form and rejects
      non-UUID strings.
    - `NamePredicate(op: Literal["equals","prefix","suffix","contains"], value: str)`.
      Validator rejects empty / whitespace `value`.
    - `TypeHintPredicate(values: tuple[str, ...])`. Rejects
      empty `values` and rejects empty / whitespace strings
      inside `values`.
    - `SizePredicate(min: int | None, max: int | None)`.
      Validator: at least one of `min` / `max` must be set;
      both must be non-negative; if both set, `min <= max`.
    - `RawHashPredicate(values: tuple[str, ...])`. Validator
      lower-cases every value and rejects anything not
      matching `^[0-9a-f]{64}$`.
    - `Matcher(guid: GuidPredicate | None, name: NamePredicate
      | None, component_type_hint: TypeHintPredicate | None,
      size: SizePredicate | None, raw_hash: RawHashPredicate
      | None)` — frozen, `extra="forbid"`. Validator: at
      least one predicate must be set (R3.1's closed key set
      with at least one populated key).
    - `Effect(label: str, confidence: float [0.0, 1.0],
      method: ClassificationMethod, evidence: str | None)` —
      frozen, `extra="forbid"`. Validator: `evidence`, when
      present, is non-empty after `strip()`.
    - `Rule(rule_id: str, axis: Literal["type","vendor",
      "security_posture","mutability"], matcher: Matcher,
      effect: Effect)` — frozen, `extra="forbid"`. Validator:
      `rule_id` matches `^[a-z0-9][a-z0-9._-]{0,127}$`.
    - `RuleSet(taxonomy_version: str, rules: tuple[Rule, ...],
      sources: tuple[Path, ...])` — frozen.
  - Re-export `Effect`, `Matcher`, `Rule`, `RuleSet` from
    `loki/classification/rules/__init__.py` and from
    `loki/classification/__init__.py`.
  - Add `tests/classification/rules/test_schema.py` covering
    every validator (positive and negative cases for each):
    GUID normalization; non-UUID rejected; name op closed
    set; size predicate requires at least one of min/max;
    raw_hash hex constraint; rule_id charset; matcher
    requires at least one predicate; effect rejects extra
    keys; effect rejects negative or > 1.0 confidence;
    evidence empty rejected.
  - _Requirements: 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.8,
    3.9, 4.1, 4.2_
  - _Design: Components and Interfaces — Rule schema_

- [x] 6. Implement the rule-set loader

  - In `loki/classification/rules/loader.py` implement
    `load_rule_set(config: ClassificationConfig) -> RuleSet`
    exactly per the design's "Rule-set loader" section:
    1. Resolve `config.rules_path`. Raise
       `ClassificationConfigError` on missing dir, not a
       directory, or not readable. Carry the path and
       human-readable reason (R2.4).
    2. Enumerate depth-1 entries; ignore those not ending in
       `.yaml` / `.yml` (R2.2).
    3. Sort the remaining file paths lexicographically
       before parsing.
    4. For each file:
       a. `yaml.safe_load`. On `yaml.YAMLError` raise
          `ClassificationConfigError`.
       b. Validate top-level shape `{taxonomy_version, rules}`
          with no extra keys (R2.5). Raise
          `ClassificationConfigError` on schema mismatch.
       c. Compare `taxonomy_version` against
          `config.taxonomy_version`; on mismatch raise
          `ClassificationConfigError` carrying expected and
          observed (R2.6).
       d. For each entry in `rules`:
          - Pre-process predicate sugar forms:
            * `guid: "<single-uuid>"` → `GuidPredicate(values=("<lc>",))`.
            * `guid: {in: [...]}` → `GuidPredicate(values=tuple(lc(...)))`.
            * `name: {equals: "..."}` → `NamePredicate(op="equals", value="...")` (and analogous for prefix / suffix / contains).
            * `component_type_hint: "<single>"` → `TypeHintPredicate(values=("<single>",))`.
            * `component_type_hint: {in: [...]}` → `TypeHintPredicate(values=tuple(...))`.
            * `size: {min: N, max: M}` → `SizePredicate(min=N, max=M)`.
            * `raw_hash: "<single-hex>"` → `RawHashPredicate(values=("<lc>",))`.
            * `raw_hash: {in: [...]}` → `RawHashPredicate(values=tuple(lc(...)))`.
          - Validate the `Rule` Pydantic model (R2.7, R3.9).
          - On any per-rule failure raise
            `ClassificationRuleError` carrying file path,
            `rule_id` (or `None` if the rule_id itself was
            invalid), and a human-readable message.
    5. After every file is parsed, scan the accumulated rule
       list for duplicate `rule_id` values. On any duplicate
       raise `ClassificationConfigError` carrying both source
       file paths and the duplicated `rule_id` (R2.8).
    6. Return `RuleSet(taxonomy_version, tuple(rules), tuple(sources))`.
  - Logger: emit one INFO record at the end summarizing files
    parsed and rules loaded — but do **not** emit at this
    layer; the pipeline construction logs the summary instead
    (R13.1). The loader is a pure function from the logging
    perspective.
  - Add `tests/classification/rules/test_loader.py` covering:
    happy path with one file; ignores non-YAML files;
    raises `ClassificationConfigError` for missing /
    not-a-dir / unreadable rules dir; raises for bad top-level
    shape; raises for taxonomy_version mismatch; raises for
    duplicate rule_id (with both paths in the message); sugar
    forms (single-string vs `{in: [...]}`) normalize to the
    same `RuleSet` representation; multiple files parse in
    lexicographic order; loader is reproducible across two
    invocations.
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.8, 2.9_
  - _Design: Components and Interfaces — Rule-set loader_

- [x] 7. Implement the matcher evaluator

  - In `loki/classification/rules/matcher.py` implement
    `matches(rule: Rule, component: ExtractedComponent) -> bool`
    per the design's "Matcher evaluator" section.
  - Conjunctive evaluation: every populated predicate must
    fire. Predicate-vs-`None`-field returns `False` (R3.2-R3.4
    on `None`-field semantics).
  - Predicate evaluation rules:
    - `guid`: case-insensitive equality after lower-casing
      `component.guid` (canonical normalization at load time
      makes this a single `in` check).
    - `name`: case-sensitive `equals` / `startswith` /
      `endswith` / substring per `op`.
    - `component_type_hint`: case-sensitive equality / `in`.
    - `size`: bounds check on `component.size`.
    - `raw_hash`: equality / `in` on `component.raw_hash`.
  - Order of predicate evaluation: `guid`, `name`,
    `component_type_hint`, `size`, `raw_hash` — cheap-first
    short-circuit (R3.7's conjunction is order-independent
    for correctness; the order is purely for performance).
  - Add `tests/classification/rules/test_matcher.py` covering
    every predicate variant individually plus the conjunctive
    case: every single-predicate matcher fires for the
    crafted matching component and does not fire for the
    crafted mismatching one; multi-predicate matcher fires
    only when every predicate fires; `None`-field semantics
    (predicate set, component field None → no fire) for each
    of `guid`, `name`, `component_type_hint`. Also: empty
    string in component fields where present.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_
  - _Design: Components and Interfaces — Matcher evaluator_

- [x] 8. Implement the per-axis classifier

  - In `loki/classification/classifier.py` implement
    `classify_axis(rules: tuple[Rule, ...], axis: str,
    component: ExtractedComponent) -> AxisClassification`
    per the design's "Per-axis classifier" section.
  - Algorithm:
    1. Filter `rules` to those with `rule.axis == axis`.
    2. For each, call `matches(rule, component)`. Collect
       firing rules into a list.
    3. If empty, return the axis-specific `UNKNOWN`
       fallback: `AxisClassification(label=AXIS_UNKNOWN.value,
       confidence=0.0, method=ClassificationMethod.HEURISTIC,
       rule_id=None, evidence=None)` (R4.8). The
       `AXIS_UNKNOWN` lookup is a `dict[str, StrEnum]` mapping
       `"type"` → `ComponentTypeLabel.UNKNOWN`, etc.
    4. Otherwise pick the Winning_Rule via
       `min(firing, key=lambda r: (-r.effect.confidence, r.rule_id))`
       (R4.4-R4.5).
    5. Build the `AxisClassification` with `label =
       winner.effect.label`, `confidence = winner.effect.confidence`,
       `method = winner.effect.method`, `rule_id =
       winner.rule_id`, `evidence = [winner.effect.evidence]
       if winner.effect.evidence else None` (R4.6-R4.7).
  - Add `tests/classification/test_classifier.py` covering:
    no-rule-fires fallback for each axis (returns the right
    `UNKNOWN` value with confidence 0.0); single firing rule
    is the winner; max-confidence wins; tie-break by
    lexicographic `rule_id`; evidence wraps in a list when
    present, `None` when absent; the four axes classify
    independently (a rule on `vendor` does not affect the
    `type` axis even if its matcher fires on the same
    component).
  - _Requirements: 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_
  - _Design: Components and Interfaces — Per-axis classifier;
    Property 34_

- [x] 9. Implement the signature detector

  - In `loki/classification/signatures.py` implement
    `detect_signature(component: ExtractedComponent) ->
    tuple[bool, str | None]` per the design's "Signature
    detection" section.
  - Two recognizers:
    - **PE32 Authenticode.** Open `component.raw_path` if
      not None, read the first 1 MiB (R11.2), verify the
      `MZ` signature, follow `e_lfanew` to the PE header,
      verify `PE\\x00\\x00`, parse the optional header to
      reach the Security data-directory entry (index 4).
      `present = (entry.VirtualAddress > 0 and entry.Size > 0)`.
      Return `(present, None)` on success.
    - **UEFI EFI_FIRMWARE_IMAGE_AUTHENTICATION.** Inspect
      the first ~50 bytes of `raw_path`: 24-byte `EFI_TIME`
      followed by `WIN_CERTIFICATE_UEFI_GUID` whose
      `CertType` GUID equals
      `4aafd29d-68df-49ee-8aa9-347d375665a7`
      (`EFI_CERT_TYPE_PKCS7_GUID`). When `component_type_hint`
      is one of the UEFI capsule / firmware variants AND the
      header parses cleanly with that GUID, `present = True`.
  - Recognizer dispatch: try PE32 first, then UEFI; the first
    `True` wins. Both recognizers are pure functions over
    bounded byte ranges.
  - Error path: when `component.raw_path` is `None` return
    `(False, "signature detection failed: raw_path missing")`.
    When the file is missing / unreadable return
    `(False, "signature detection failed: file unreadable: errno=N")`.
    Catch `FileNotFoundError`, `PermissionError`, `OSError`
    explicitly; let other exceptions bubble (the pipeline's
    per-component try/except converts them to `ClassificationError`).
  - The recognizers do not parse certificates, do not consult
    any trust root, and do not attempt verification (R5.2-R5.4,
    R5.7). `SignatureInfo.signer` and
    `SignatureInfo.cert_expiry` are populated as `None` by
    the pipeline, not the recognizer.
  - Add `tests/classification/test_signatures.py` covering:
    PE32 with valid signature returns `(True, None)`; PE32
    without signature (security-directory zero) returns
    `(False, None)`; UEFI auth wrapper with the right
    `CertType` GUID returns `(True, None)`; non-firmware
    component with no signature returns `(False, None)`;
    `raw_path` is None returns the missing-bytes error;
    `raw_path` points at a non-existent file returns the
    unreadable error; `raw_path` points at a 4-byte file
    (shorter than minimum recognizer prefix) returns
    `(False, None)` rather than crashing.
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 11.2,
    11.4_
  - _Design: Components and Interfaces — Signature detection_

- [x] 10. Author the synthetic component fixture

  - Create `tests/classification/fixtures/__init__.py` and
    `tests/classification/fixtures/synthetic_components.py`
    exporting:
    - `build_components(*, count=4, source_image_id=None,
      include_inner=False) -> list[ExtractedComponent]`.
    - The builder uses `uuid.uuid5` seeds for every UUID so
      the resulting sequence is byte-identical across runs
      (mirrors extraction and persistence fixture patterns).
    - When `include_inner=True`, half the components carry
      a synthetic `source_image_id` derived from a fake
      `decompressed_hash` to simulate inner-component
      emission.
    - Each component gets a distinct `guid` (deterministic
      formula like `uuid5(LOKI_NAMESPACE, f"comp-{i}")`),
      `name` (`f"COMP_{i:03d}"`), `component_type_hint`
      (cycling through a small set), `size` (an arithmetic
      progression so size predicates can be tested), and
      `raw_hash` (deterministic from the index).
  - Wire it into `tests/classification/conftest.py` as
    fixtures `synthetic_components` (default-shape, no
    inner) and `synthetic_components_with_inner`.
  - Add `tests/classification/test_fixtures.py` smoke-checking
    the builder produces Pydantic-validated
    `ExtractedComponent` instances; same inputs produce the
    same `component_id` sequence.
  - _Requirements: none — test infrastructure for tasks 12-19_
  - _Design: Testing Strategy — Synthetic fixture_

- [x] 11. Author the synthetic rules fixture

  - Create `tests/classification/fixtures/synthetic_rules.py`
    exporting:
    - `build_rule_files(rules_dir: Path, *,
      axis_distribution: dict[str, int] | None = None) ->
      RuleSet` — writes deterministic YAML rule files into
      `rules_dir` and returns the `RuleSet` the loader
      should produce.
    - Default `axis_distribution`: `{"type": 4, "vendor": 4,
      "security_posture": 2, "mutability": 2}` (12 rules
      total across the four axes).
    - Each rule has a deterministic `rule_id` like
      `synthetic.{axis}.{idx:03d}`.
    - Rules' matchers reference the synthetic-component
      fixture's GUIDs / names so the resulting classification
      is deterministic and predictable.
  - Wire it into `tests/classification/conftest.py` as a
    fixture `synthetic_rules_dir` (a `tmp_path` containing
    the rule files) and `synthetic_rule_set` (the expected
    `RuleSet`).
  - Add `tests/classification/fixtures/test_rules_fixture.py`
    smoke-checking that the YAML files round-trip through
    `load_rule_set` to the expected `RuleSet`.
  - _Requirements: none — test infrastructure for tasks 12-19_
  - _Design: Testing Strategy — Synthetic fixture_

- [x] 12. Implement the `ClassificationPipeline` (internal)

  - In `loki/classification/pipeline.py` implement
    `ClassificationPipeline` with `__init__(config:
    ClassificationConfig)` and
    `classify(components, *, progress=None, cancel=None) ->
    ClassificationResult`.
  - `__init__`:
    1. `self._rules = load_rule_set(config)` (R2.3). Errors
       from the loader propagate as
       `ClassificationConfigError` /
       `ClassificationRuleError`.
    2. `self._taxonomy_version = config.taxonomy_version`.
    3. `self._classification_version = CLASSIFICATION_VERSION`.
    4. Emit one INFO record at logger
       `loki.classification.pipeline`:
       `"classification pipeline ready rules_path=%s
       files=%d rules=%d taxonomy_version=%s
       classification_version=%s"` (R13.1).
  - `classify`:
    1. `run_started_at = datetime.now(tz=UTC)` (R1.6, R8.1);
       open a `Stopwatch` from `loki.classification.timing`
       for duration (R13.3).
    2. INFO log `"classification run starting components=%d
       classification_version=%s"` (R13.2).
    3. For each `(index, component)` in
       `enumerate(components, start=1)`:
       - cancel check (R1.9): on True append a
         `ClassificationError(component_id=None,
         error_message="classification cancelled by caller",
         timestamp=datetime.now(tz=UTC))` and break.
       - Build the four axis classifications via
         `classify_axis(self._rules.rules, axis, component)`
         for each of `"type"`, `"vendor"`,
         `"security_posture"`, `"mutability"` (R4.3).
         Wrap in try/except around each axis call; on
         exception, count axes successfully built so far,
         append a `ClassificationError(component_id=
         component.component_id, error_message=f"rule
         evaluation crashed: {type(e).__name__}",
         timestamp=...)`, log a WARNING
         `"classification per-component failure
         axes_classified=%d"` with no other component data
         (R13.4), `continue`.
       - Signature detection: `present, sig_error =
         detect_signature(component)`. Build
         `SignatureInfo(present=present, verified=False,
         signer=None, cert_expiry=None)` (R5.1-R5.4).
         If `sig_error is not None`, append a
         `ClassificationError(component_id=
         component.component_id, error_message=sig_error,
         timestamp=...)` (R5.6 first half) and continue
         past the error to record construction (the dual-
         record contract).
       - Construct the `ClassificationRecord` with all four
         axes, the signature_info, `cve_matches=[]` (R6),
         `suspicion_triggers=[]` (R10.4),
         `overrides=[]` (R10.3),
         `classification_version=self._classification_version`,
         `timestamp=run_started_at`,
         `component_id=component.component_id`,
         `source_image_id=component.source_image_id`
         (R7.3, R10.2),
         `extraction_offset=component.offset`. The
         model layer auto-computes
         `composite_confidence` and `needs_review` (R4.9).
         On `pydantic.ValidationError`, append a
         `ClassificationError(component_id=
         component.component_id, error_message=f"record
         validation failed: {summarize(e)}",
         timestamp=...)`, log a WARNING with
         `axes_classified=4` (R13.4), do not append the
         record, continue (R9.3).
       - Append `record` to `records`.
       - If `progress` callable, invoke
         `progress(ProgressEvent(index=index,
         total=len(components),
         component_id=str(component.component_id)))`
         (R12.1, R12.2). The callback runs on the calling
         thread (synchronous semantics; R1.7).
    4. After the loop, INFO log `"classification run finished
       records=%d errors=%d duration=%.1fms"` (R13.3).
    5. Return `ClassificationResult(records=records,
       errors=errors)`.
  - `summarize(e)` is a small helper that converts a
    `pydantic.ValidationError` into a single-line summary
    suitable for an error message: count of errors plus the
    first error's `loc` / `msg`. Keeping the summary small
    avoids accidental leakage; the full Pydantic message
    can include field values which may include
    `component_id`.
  - Add `tests/classification/test_pipeline.py` covering the
    happy path: synthetic components + synthetic rules →
    classification produces records in input order, with
    deterministic axis selections, with `composite_confidence`
    correctly computed by the model layer.
  - _Requirements: 1.6, 1.7, 4.3, 4.6, 4.7, 4.8, 4.9, 5.1,
    5.2, 5.3, 5.4, 5.6, 6.1, 6.2, 7.1, 7.2, 7.3, 8.1, 8.2,
    8.3, 9.3, 10.1, 10.2, 10.3, 10.4, 10.5, 12.1, 12.2,
    12.3, 13.1, 13.2, 13.3, 13.4_
  - _Design: Architecture — Pipeline construction; Classify
    flow_

- [x] 13. Implement the public `classify_components` entry point

  - In `loki/classification/api.py` implement:
    - `ProgressEvent` frozen dataclass (`index`, `total`,
      `component_id: str`).
    - `ClassificationResult` frozen dataclass (`records:
      list[ClassificationRecord]`,
      `errors: list[ClassificationError]`).
    - Type aliases `ProgressCallback =
      Callable[[ProgressEvent], None]` and
      `CancellationToken = Callable[[], bool]`.
    - `classify_components(components, config, *,
      progress=None, cancel=None) -> ClassificationResult`
      that constructs a single `ClassificationPipeline(config)`
      and invokes `pipeline.classify(components,
      progress=progress, cancel=cancel)`.
  - Empty-input contract (R1.3): when `components` is an
    empty sequence, return `ClassificationResult([], [])`
    without constructing a pipeline if doing so would be
    wasteful — but the design says construct anyway so the
    rule-load errors surface eagerly. Decision: construct
    the pipeline regardless, then handle the empty-loop
    naturally in `classify`. Document the choice in a
    comment.
  - Re-export `classify_components`, `ClassificationResult`,
    `ProgressEvent`, `ProgressCallback`, `CancellationToken`
    from `loki.classification.__init__`.
  - The synchronous-on-calling-thread guarantee (R1.7) is
    structural; document it in the entry point's docstring.
  - Add `tests/classification/test_api_contract.py` covering
    the documented surface: the import path is stable
    (`from loki.classification import classify_components`);
    empty input returns empty result; rule-load failures
    raise the typed exception subclasses; the entry point
    is synchronous (no asyncio detection); the progress
    callback is invoked once per component on the calling
    thread (use `threading.get_ident()` to verify); the
    cancel token short-circuits between components and
    yields a partial `ClassificationResult` carrying a
    cancellation `ClassificationError`.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8,
    1.9_
  - _Design: Components and Interfaces — Public API surface;
    Architecture — Classify flow_

- [x] 14. Add the per-component error tests

  - Add `tests/classification/test_pipeline_errors.py`
    covering R9 in detail:
    - Per-component rule-evaluation crash: monkeypatch
      `matches` to raise on a specific rule; assert one
      `ClassificationError` with the documented message
      shape (`"rule evaluation crashed: {ExceptionClass}"`),
      no record for that component, all other components
      classify normally, the entry point doesn't raise.
    - `pydantic.ValidationError` on record construction:
      pre-poison a `ClassificationConfig` so the
      `taxonomy_version` mismatches what's in
      `synthetic_rules` to verify rule-load errors don't
      land in `errors` (they raise);
      then poison a single component's `offset` to fail
      `ClassificationRecord._validate_extraction_offset`
      and assert the error path (`"record validation
      failed: ..."`).
    - The `errors` list is empty when every component
      classifies successfully (R9.5).
    - Per-component errors and successful records can
      interleave in the same run.
    - `ClassificationError.timestamp` is UTC.
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_
  - _Design: Error Handling_

- [x] 15. Add the dual-record (R5.6) test

  - Add `tests/classification/test_pipeline_dual_record.py`
    covering R5.6 explicitly:
    - Component with `raw_path=None`: emit one
      `ClassificationRecord` with `signature_info.present
      == False`, all four axes classified per Requirements
      3 and 4 (no axis is suppressed), AND one
      `ClassificationError(component_id=..., error_message=
      "signature detection failed: raw_path missing")`.
      Both reference the same `component_id`.
    - Component with `raw_path` pointing at a non-existent
      file: same dual-record outcome with the
      "file unreadable" message variant.
    - Verifies Property 42 from the design.
  - _Requirements: 5.6_
  - _Design: The R5.6 dual-record contract; Property 42_

- [x] 16. Add the inner-component handling tests

  - Add `tests/classification/test_pipeline_inner.py`
    covering R7:
    - Inner components (with synthetic `source_image_id`
      from `uuid5(LOKI_NAMESPACE, decompressed_hash)`)
      classify identically to outer components.
    - The pipeline does not branch on `source_image_id`.
    - The full Rule_Set applies to inner components without
      filtering, derating, or restriction (R7.2).
    - `ClassificationRecord.source_image_id` for an inner
      component matches the input component's
      `source_image_id` verbatim (R7.3).
    - The pipeline does not, for any component, read bytes
      outside the component's own `raw_path` (verify by
      capturing all `open()` calls during a run).
  - Use `synthetic_components_with_inner` fixture from
    task 10.
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_
  - _Design: Inner-component handling_

- [x] 17. Add the progress + cancellation tests

  - Add `tests/classification/test_pipeline_progress.py`
    covering R12.1-R12.2:
    - The progress callback is invoked exactly once per
      successfully classified component, in input order,
      with `index` 1-based and `total = len(components)`.
    - Progress events carry the component's `component_id`
      as a string.
    - The callback runs on the calling thread (assert via
      `threading.get_ident()`).
    - Optional callback omitted: classification works the
      same with no observable behavior change.
  - Add `tests/classification/test_pipeline_cancel.py`
    covering R1.9:
    - A cancel token returning True after N components
      stops classification at that point; result has
      exactly N records plus one
      `ClassificationError(component_id=None,
      error_message="classification cancelled by caller")`.
    - A cancel token that always returns True yields an
      empty `records` list and a single cancellation
      error.
    - A cancel token that always returns False is
      indistinguishable from no cancel token.
  - _Requirements: 1.9, 12.1, 12.2_
  - _Design: Progress callback and the leakage rule;
    Architecture — Classify flow_

- [x] 18. Add the static side-channel audit test

  - Add `tests/classification/test_no_side_channels.py`
    walking `loki.classification.__path__`, parsing each
    `.py` file with `ast`, and failing on:
    - Any `Import` / `ImportFrom` of `os.environ`,
      `random`, `secrets`, `socket`, `urllib`, `requests`,
      `httpx`.
    - Any `time.time()` / `time.monotonic()` call outside
      `loki/classification/timing.py`.
    - Any `datetime.now(...)` call outside the pipeline
      module (`pipeline.py` is the only place that records
      timestamps; the loader / matcher / classifier /
      signatures must not).
  - The test pinpoints the file and line of the offending
    import / call on failure.
  - This implements Property 41.
  - _Requirements: 8.4, 8.5_
  - _Design: Property 41_

- [x] 19. Add the no-leakage logging audits (static + dynamic)

  - Add `tests/classification/test_no_log_leakage.py`
    (static audit, AST-based): walks every `.py` in
    `loki/classification/`, parses with `ast`, finds every
    `logger.{info,warning,error,debug}` call, and asserts
    that no format string or argument expression
    references the Forbidden_Leakage_Field_Set:
    `component.component_id`, `record.component_id`,
    `signature_info.signer`, `record.source_image_id`,
    `axis.evidence`. Implementation walks `Attribute`
    nodes inside `Call.args` for the matching attribute
    paths.
  - Add `tests/classification/test_log_no_leakage.py`
    (dynamic capture): use `caplog` to capture every
    record emitted on `loki.classification` during:
    - A curated happy-path classification run.
    - A curated per-component-failure run (force one
      component to crash mid-classification).
    - A curated dual-record run (R5.6 case).
    Then assert no captured message contains the test
    fixture's `component_id` UUID hex, `source_image_hash`
    hex, or `evidence` substring. This covers R13.5 and
    R13.6 ("at any time" — runs include init, classify,
    and the natural shutdown).
  - This implements Property 40.
  - _Requirements: 13.4, 13.5, 13.6_
  - _Design: Logging strategy; Property 40_

- [x] 20. Add the Hypothesis property-based test suite

  - Author `tests/classification/test_determinism.py`
    covering Properties 35-38:
    - Property 35: two runs on the same input + same
      `RuleSet` produce equal records under
      `model_dump(mode="json")` after stripping
      `timestamp`. Strategy: `synthetic_components` with
      parameterized count and `synthetic_rules` with
      parameterized axis distribution.
    - Property 36: input order is preserved in the
      records list (subsequence by `component_id`).
    - Property 37: every emitted `ClassificationRecord`
      round-trips through
      `model_validate_json(model_dump_json())` losslessly.
    - Property 38: re-classification is idempotent (same
      input twice produces equal records modulo
      timestamp).
  - Author `tests/classification/test_classifier_property.py`
    covering Property 34 (per-axis Winning_Rule selection
    is deterministic): generate two random permutations of
    the same firing-rules list, run `classify_axis` against
    the same component, assert identical
    `AxisClassification.rule_id`.
  - Author `tests/classification/test_manifest_invariants.py`
    covering Property 33 (every emitted record passes
    Pydantic re-validation): re-construct via
    `ClassificationRecord.model_validate(record.model_dump(mode="json"))`
    and assert it round-trips.
  - Hypothesis settings per the project convention:
    `max_examples=50` for in-memory matcher / classifier
    properties, `max_examples=25` for full-pipeline
    properties (which read rule files and emit records).
    Both set `suppress_health_check=[HealthCheck.too_slow]`.
  - Strategy generators live in
    `tests/classification/conftest.py`, building on the
    synthetic fixtures from tasks 10 and 11.
  - _Requirements: 8.1, 8.2, 8.3, 8.6, 8.7_
  - _Design: Correctness Properties — Properties 33-38;
    Testing Strategy — Hypothesis budget_

- [x] 21. Add the golden-file regression test

  - Build a deterministic classification run via
    `synthetic_components` + `synthetic_rules` with fixed
    parameters; run `classify_components` against them;
    capture the resulting `ClassificationResult.records`
    list.
  - Commit the rule files at
    `tests/classification/fixtures/golden/canonical_rules_v1.yaml`
    (single concatenated YAML containing all the synthetic
    rules with `taxonomy_version: "1.0.0"`).
  - Commit the expected output at
    `tests/classification/fixtures/golden/canonical_classifications_v1.json`
    — `[r.model_dump(mode="json") for r in result.records]`
    with the `timestamp` field nulled.
  - Add `tests/classification/test_golden.py` that:
    1. Loads the canonical rule file into a `tmp_path` /
       `rules` directory.
    2. Calls `classify_components(synthetic_components(),
       ClassificationConfig(taxonomy_version="1.0.0",
       confidence_threshold=0.6, rules_path=str(tmp_path /
       "rules")))`.
    3. Strips `timestamp` from every record dump and
       compares against the committed JSON.
  - Document regeneration procedure in
    `tests/classification/fixtures/README.md` (mirrors the
    other subsystems' README format): when the schema or
    synthetic builder changes, bump the fixture filename
    to `_v2.yaml` / `_v2.json` rather than overwriting
    history.
  - _Requirements: 8.6_
  - _Design: Testing Strategy — Golden-file regression_

- [x] 22. Add the performance smoke tests

  - Add `tests/classification/test_performance.py` (marked
    `slow`, skipped on CI by default — the `slow` marker is
    already registered in `pyproject.toml`).
  - Two tests:
    1. **R11.1 budget:** Build 4096 synthetic components
       and 1024 synthetic rules (extend the fixtures in
       tasks 10/11 with `count=4096` and
       `axis_distribution` summing to 1024). Run
       `classify_components` with `progress=None,
       cancel=None`. Assert wall-clock duration < 30s on
       the reference dev laptop. Note: this measurement
       excludes signature-detection I/O time per R11.1's
       "exclusive of signature-detection file I/O" clause —
       set every component's `raw_path = None` so the
       signature detector returns the missing-bytes error
       quickly without touching the disk. (The per-
       component error rows produced are expected and
       part of the R5.6 contract; the test asserts both
       `len(result.records) == 4096` and
       `len(result.errors) == 4096`.)
    2. **R11.3 budget:** Build 4096 synthetic components
       whose `raw_path` files together total ≤ 256 MiB on
       a `tmp_path` SSD; the per-file payload is a
       valid PE32 stub so the signature detector reads but
       does not error. Assert signature-detection-phase
       wall time < 60s. Implementation: instrument
       `signatures.py` to record cumulative time inside
       `detect_signature` calls, OR run the full pipeline
       and subtract the matcher-only-phase time from a
       prior `raw_path = None` run.
  - Both tests use `tracemalloc` to additionally verify
    R11.4's 64 MiB peak memory budget plus the
    rule-set size; assert peak resident increase ≤ 64 MiB
    + rule-set bytes.
  - The R11.5 linearity property (no quadratic blowup) is
    not asserted directly but emerges from the algorithm:
    R rules per axis × N components is exactly N×R operations.
  - _Requirements: 11.1, 11.2, 11.3, 11.4_
  - _Design: Per-axis evaluation; Signature-detection I/O
    budget; Testing Strategy — Performance tests_

- [x] 23. Add an end-to-end smoke test

  - Add `tests/test_classification_smoke.py` exercising the
    full extract → classify path on the existing demo
    workspace fixture used by the GUI smoke run:
    1. Run `extract_firmware` on
       `scripts/smoke_gui.py`-style fixture inputs (or the
       extraction subsystem's golden binary at
       `tests/extraction/fixtures/golden/uefi_volume_v1.bin`).
    2. Build a minimal rule file pointing at one of the
       components' GUIDs.
    3. Run `classify_components` against the manifest's
       components.
    4. Assert at least one rule fires, at least one
       `UNKNOWN` fallback emerges (covering both code
       paths in a single smoke), and the result
       round-trips through JSON.
  - This file lives under `tests/` (not
    `tests/classification/`) because it spans both the
    extraction and classification subsystems.
  - _Requirements: 1.1, 1.2, 8.6_
  - _Design: Testing Strategy — Plus integration tests_

- [x] 24. Update README and Status

  - Update the **Status** table in `README.md` to mark the
    classification-pipeline subsystem `DONE — specs/classification-pipeline/`
    on the spec column and `DONE` on the implementation
    column.
  - Add a `## Classification pipeline` section between the
    Baseline persistence section and the Development
    section, describing:
    - The public entry point
      (`from loki.classification import classify_components`).
    - The YAML rule-file layout under
      `ClassificationConfig.rules_path`.
    - The four taxonomic axes and the `UNKNOWN` fallback.
    - The R5.6 dual-record contract (one component can
      appear in both `records` and `errors`).
    - Determinism caveats from the design's deferred-
      decisions section (no rule indexing, no disjunctive
      matchers, no regex predicates).
  - Update the **Repository layout** tree to include
    `loki/classification/` and `tests/classification/`.
  - Update **Verification at the current checkpoint** with
    the new test count and source file count after running
    the gates.
  - Update **Next moves** to remove "Classification" and
    surface the next priority (likely Analysis engine or
    CVE-feed ingestion).
  - _Requirements: none — pure documentation_
  - _Design: Overview; Goals and non-goals_

- [x] 25. Final verification gate

  - Run the four checks and confirm green:
    ```bash
    .venv/bin/pytest -q
    .venv/bin/mypy --strict loki tests scripts
    .venv/bin/ruff check
    .venv/bin/ruff format --check
    ```
  - Run the slow performance tests once locally:
    ```bash
    .venv/bin/pytest -m slow tests/classification/test_performance.py
    ```
  - Run the offscreen GUI smoke check to confirm the new
    package didn't break anything:
    ```bash
    QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py
    ```
  - Document the final test counts in the README, and
    update `HANDOFF.md` to reflect that classification is
    landed (move the previous handoff to
    `HANDOFF.archive.md` per project convention).
  - _Requirements: all_
  - _Design: all_

## Task Dependency Graph

The dependency graph organizes tasks into waves. All tasks in a
wave can be executed in parallel; each wave waits for the previous
one.

```json
{
  "waves": [
    {
      "name": "wave-1-skeleton",
      "tasks": ["1"]
    },
    {
      "name": "wave-2-foundations",
      "tasks": ["2", "3", "4", "5", "10", "11"]
    },
    {
      "name": "wave-3-rules-loading",
      "tasks": ["6", "7"]
    },
    {
      "name": "wave-4-classifier-and-signatures",
      "tasks": ["8", "9"]
    },
    {
      "name": "wave-5-pipeline-and-api",
      "tasks": ["12", "13"]
    },
    {
      "name": "wave-6-behavioral-tests",
      "tasks": ["14", "15", "16", "17"]
    },
    {
      "name": "wave-7-cross-cutting",
      "tasks": ["18", "19", "20", "21", "22", "23"]
    },
    {
      "name": "wave-8-docs-and-gate",
      "tasks": ["24", "25"]
    }
  ]
}
```

Suggested implementation cadence aligned to the waves:

- **Day 1 — Waves 1–2.** Skeleton, version constant, errors,
  timing helper, rule schema, synthetic component + rule
  fixtures. Pure utilities and Pydantic shapes.
- **Day 2 — Waves 3–4.** Rule-set loader, matcher evaluator,
  per-axis classifier, signature detector. The classification
  algorithm lands here.
- **Day 3 — Wave 5.** `ClassificationPipeline` plus the public
  `classify_components` entry point. The subsystem is
  importable end-to-end.
- **Day 4 — Wave 6.** Behavioral tests for per-component
  errors, the R5.6 dual-record contract, inner-component
  handling, progress + cancellation. Each task is small enough
  to pair with a manual exploratory run.
- **Day 5 — Wave 7.** Cross-cutting tests: side-channels
  audit, no-leakage logging audits, Hypothesis PBT, golden
  file, performance smoke, end-to-end smoke. Tasks within
  this wave are independent and can be done by separate
  sessions in parallel.
- **Day 6 — Wave 8.** Documentation refresh and the final
  verification gate.

## Notes

- Stick to the design's Module layout exactly. If a new
  responsibility doesn't fit any of the listed modules, raise
  it as an open question rather than inventing a new module on
  the fly — that's a sign the design needs an update first.
- The determinism contract (Properties 33-42) is the single
  hardest thing to keep correct over time. Whenever you touch
  `classifier.py`, `pipeline.py`, or any rule schema /
  matcher / loader code, re-run
  `tests/classification/test_determinism.py` together with
  `tests/classification/test_manifest_invariants.py` and
  `tests/classification/test_classifier_property.py` — not
  just individually.
- The `slow` marker is already registered in `pyproject.toml`
  and `addopts = "-ra --strict-markers -m 'not slow'"` keeps
  the performance tests off the default `pytest -q` run.
  Don't change that; the budgets in R11.1 / R11.3 are slow
  and noisy in CI by design.
- The Forbidden_Leakage_Field_Set audit (task 19) is the
  trickiest test to keep correct. The static AST audit only
  catches *direct* attribute accesses inside logger calls; if
  someone formats a `component_id` into a local variable and
  then logs the variable, the audit misses it. The dynamic
  capture catches that case. Run both as a pair; failures
  in either should block a checkpoint.
- The `ProgressEvent.component_id` field is a documented
  judgment call (design's deferred-decisions §8). The static
  no-leakage audit excludes the progress callback by
  scoping itself to `loki.classification` log calls only;
  if a stricter R13.5 reading is preferred later, dropping
  the field is the cheap revert and only task 13 and task 17
  need editing.
- The five judgment calls flagged in the design's tail (free
  function vs. class, `ProgressEvent.component_id`,
  `ClassificationError` location, lexicographic file sort,
  WARNING records omit the error message) are baked into
  this task list. If any need to change, the affected tasks
  are 13 (free function), 12-13-17 (progress), 3 (errors
  module), 6 (loader sort), 12 (WARNING content). None
  ripple beyond two or three tasks.
- The `filterwarnings = ["error"]` pytest config will surface
  any `DeprecationWarning` emitted during classification.
  PyYAML and Pydantic occasionally emit these on minor
  upgrades; if a warning fires, follow the extraction
  pipeline's pattern: either upgrade the pin or add a narrow
  `filterwarnings("ignore", ...)` in
  `tests/classification/conftest.py` with a documented
  rationale.
- v1 ships exactly the library API. `loki classify` (CLI)
  and the GUI classification view are out of scope and have
  their own (future) specs. Don't pre-emptively add CLI
  hooks or Qt imports to this subsystem.
