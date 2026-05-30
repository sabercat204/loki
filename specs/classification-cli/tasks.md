

# Implementation Plan

## Overview

This is the executable task list for the **classification-cli** spec. Tasks are ordered so that each one builds on previous tasks and leaves the repo in a verifiable state (every checkpoint passes `pytest`, `mypy --strict`, `ruff check`, and `ruff format --check`).

Each task lists the exact files it touches, the test surface it adds, and the design / requirement references it implements. Sub-bullets under each task are checklist items the implementer ticks off as they go; they are not separate tasks.

Honest scope reminder: this plan covers the `loki classify` subcommand only. Per the requirements introduction, running extraction in the same process, persisting `ClassificationResult` to disk, the `loki classify rules-check` and `loki classify show` subcommands, exposing `confidence_threshold` as a flag, reading config from `LokiConfig.from_yaml`, auto-detecting YAML manifests, streaming JSONL output, GUI integration, and `ExtractionManifest` schema migration are explicitly out of scope and have their own (future) specs or are explicitly deferred.

The seven design defaults locked in at design BIND (D1: helpers in a new `classify_helpers.py` module rather than inline in `cli.py`; D2: `_CancelFlag` is a tiny `@dataclass`; D3: `--debug` sets `propagate = False` for the duration of the run; D4: TTY guard fires first when manifest is `-`; D5: exit code 4 covers both `ClassificationPipelineError` catchall and unexpected `Exception`; D6: helpers are module-private with single-leading-underscore names; D7: `_load_manifest` returns `int` on failure rather than raising) are baked into this task list. The three open questions Q1-Q3 from design.md are pinned by implementation choices in tasks 18 and 22.

## Pre-flight checklist

Before starting, confirm the repo is healthy:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m ruff check
.venv/bin/python -m ruff format --check
```

All four must be green. The current checkpoint per `loki/HANDOFF.md` is **1211 passed, 8 deselected** with mypy clean across **217 source files**. The classification-cli work assumes the model layer, extraction pipeline, baseline-persistence, classification-pipeline, and analysis-engine subsystems are all intact and at their v1 contracts.

The classify-cli subsystem's threat context is STANDARD per the loom harness. No new credential handling, no new network egress, no new destructive operations — the CLI reads an `ExtractionManifest` from disk or stdin, calls the classification library in-process, and writes JSON + diagnostic lines to stdout/stderr.

The `.venv/bin/*` entry-point shebangs are stale per the HANDOFF.md workspace observation; use `.venv/bin/python -m <tool>` everywhere. The standing directive against `fs_write` against existing files applies; new file creation goes through `touch` + `fs_append`, in-place edits go through `str_replace`, and rewrites go through `delete_file` + `touch` + `fs_append`.

## Tasks

- [x] 1. Scaffold the `tests/classify_cli/` test tree

  - Create `tests/classify_cli/__init__.py` (empty) and `tests/classify_cli/conftest.py` with three shared fixtures: `tmp_rules_path` (builds a small valid rules dir under `tmp_path` with one rule per axis), `sample_manifest_json` (builds a small valid `ExtractionManifest` and returns its JSON-serialized form as a string), and `cli_argv` (helper to construct argv lists like `["classify", "manifest.json", "--rules-path", "/tmp/rules"]` so tests don't repeat the boilerplate).
  - Add a fourth fixture `capture_classify_run` that wraps `loki.cli.main(...)` with `capsys`-style stdout/stderr capture and returns a `(exit_code, stdout, stderr)` triple. Use the design's "in-process invocation via `loki.cli.main(["classify", ...])`" pattern; only the SIGINT end-to-end test (task 17) uses `subprocess.Popen`.
  - Verify the empty test tree imports cleanly: `.venv/bin/python -c "import tests.classify_cli"`.
  - Run the four verification gates and confirm test count is unchanged (1211 / 8 deselected). Source file count rises from 217 to 219 (2 new test-tree modules).
  - Pinned Q1 (test fixture sharing) by making the classify-cli fixtures bespoke rather than re-exporting from `tests/classification/conftest.py`. The CLI tests stay self-contained.
  - _Requirements: none — pure scaffolding_
  - _Design: Architecture — Module layout; Open questions Q1_

- [x] 2. Create the `loki/classify_helpers.py` module skeleton

  - Create `loki/classify_helpers.py` as a new module with a docstring documenting its private-helper purpose (D6 default — single-leading-underscore names, no `__all__`).
  - Add the seven helper-function and dataclass stubs as `pass` bodies with type annotations only: `_CancelFlag` dataclass, `_load_manifest`, `_install_sigint_handler`, `_install_debug_logger`, `_build_progress_callback`, `_serialize_result`, `_format_summary_line`.
  - Add the `_CLASSIFY_EXIT_CODES: dict[str, int]` table with all eight entries (BadInput, SerializationError, ClassificationPipelineError, UnexpectedException, ClassificationRuleError, ClassificationConfigError, Sigint).
  - Verify the module imports cleanly: `.venv/bin/python -c "from loki import classify_helpers"`.
  - The module is module-internal; do NOT re-export from `loki/__init__.py`. Importers reach into it via `from loki.classify_helpers import ...` (D1, D6 defaults).
  - Run the four verification gates. Source file count rises to 220.
  - _Requirements: none — pure scaffolding_
  - _Design: Architecture — Module layout; Internal helpers; D1 + D6 defaults_

- [x] 3. Implement the `_CancelFlag` dataclass (D2 default)

  - In `loki/classify_helpers.py` implement `_CancelFlag` as a `@dataclass` (not `frozen=True` — it's mutable) with one field `value: bool = False`.
  - Module docstring on the dataclass explains that the no-lock contract is safe because the SIGINT handler runs on the main thread synchronously (between the library's per-component iterations), the library is single-threaded per upstream R1.7, and the only cross-handler reads happen between iterations. R1.11 contracts the CLI does not spawn worker threads, asyncio tasks, or process pools.
  - Add `tests/classify_cli/test_helpers.py` with a basic test: `_CancelFlag(value=False)` constructs; the `value` attribute is mutable (`flag.value = True` works); two instances with the same value compare equal under dataclass-generated `__eq__`.
  - Run the four verification gates.
  - _Requirements: 6.1_
  - _Design: Internal helpers — `_CancelFlag`; D2 default; Concurrency model_

- [x] 4. Implement `_load_manifest` (R1.2-R1.8)

  - In `loki/classify_helpers.py` implement `_load_manifest(manifest_arg: str) -> ExtractionManifest | int` per design §Architecture's pseudocode.
  - The integer-return-on-failure pattern (D7 default) keeps the handler linear; the handler tests `isinstance(result, int)` to branch.
  - TTY guard fires FIRST when `manifest_arg == "-"` (D4 default; before any read).
  - Wraps `path.read_text(encoding="utf-8")` in `try/except (OSError, FileNotFoundError)`; wraps `json.loads(text)` in `try/except json.JSONDecodeError`; wraps `ExtractionManifest.model_validate(payload, strict=True)` in `try/except ValidationError`.
  - Validation error summarization mirrors the bounded format from `loki/classification/pipeline.py:_summarize` — error count + first error's loc + first error's msg only; no field values reproduced (R10.4 no-leakage discipline).
  - Add `tests/classify_cli/test_input_paths.py` covering R1.2-R1.8: file path success, file path missing, file path unreadable (e.g. directory), JSON parse failure, Pydantic validation failure, stdin TTY guard (mock `sys.stdin.isatty()` to True), stdin success (use `monkeypatch.setattr(sys, 'stdin', io.StringIO(json_text))`).
  - Run the four verification gates.
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_
  - _Design: Internal helpers — `_load_manifest`; D4 + D7 defaults; Error handling Layer 1_

- [x] 5. Implement `_install_sigint_handler` (R6.1)

  - In `loki/classify_helpers.py` implement `_install_sigint_handler() -> tuple[_CancelFlag, Callable[[], None]]` per design §Architecture's code shape.
  - Returns `(cancel_flag, restore)` pair. The signal handler is excluded from coverage with `# pragma: no cover - signal` because pytest's signal-injection patterns are environment-dependent.
  - The previous SIGINT handler is captured via `signal.signal(signal.SIGINT, _handler)` (which returns the old handler) and restored via `signal.signal(signal.SIGINT, previous)` in the `_restore` closure.
  - R6.5 (double-Ctrl-C is no-op): the installed handler simply re-flips the already-True flag; no second installation logic needed.
  - Extend `tests/classify_cli/test_helpers.py` with a test that the handler installation + restoration cycle preserves the previous handler (use `signal.getsignal(signal.SIGINT)` before/after to verify); use a synthetic previous handler to make the equality check deterministic.
  - Run the four verification gates.
  - _Requirements: 6.1, 6.5_
  - _Design: Internal helpers — `_install_sigint_handler`; Concurrency model_

- [x] 6. Implement `_install_debug_logger` (R7.2-R7.5; G5-A propagate=False)

  - In `loki/classify_helpers.py` implement `_install_debug_logger(*, enabled: bool) -> Callable[[], None]` per design §Architecture's code shape.
  - When `enabled=False`, return a no-op lambda (R7.5).
  - When `enabled=True`: capture previous level, propagate, and handler list; set level to `logging.DEBUG`; set `propagate = False` (D3 default — the G5-A audit fix); attach a stderr `StreamHandler` only if no handler was already attached (R7.3); return a `_restore` closure that undoes every change.
  - The restore closure is idempotent and safe to call from a `finally` block whether or not `enabled` was True.
  - Add `tests/classify_cli/test_debug_flag.py` covering R7.1-R7.8: enabled-but-no-prior-handler attaches one and detaches on restore; enabled-with-prior-handler does not double-attach; enabled sets level to DEBUG and propagate to False; restore returns logger to previous level + propagate state; disabled-flag is a no-op everywhere; test that `loki.baseline`, `loki.extraction`, and `loki.analysis` loggers are NOT modified (R7.6); test that the Forbidden_Leakage_Field_Set audit is not bypassed at DEBUG level (use a manifest with a known signer value and verify it doesn't appear in the captured stderr at DEBUG).
  - Run the four verification gates.
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8_
  - _Design: Internal helpers — `_install_debug_logger`; D3 default; Error handling Layer 1_

- [x] 7. Implement `_build_progress_callback` (R5.1-R5.7)

  - In `loki/classify_helpers.py` implement `_build_progress_callback(*, enabled: bool) -> ProgressCallback | None` per design §Architecture's code shape.
  - When `enabled=False`, return `None` so the library receives no callback (R5.3).
  - When `enabled=True`, return a closure that formats each `ProgressEvent` as `[<index>/<total>] <component_id>` followed by a single newline, written to `sys.stderr` with `flush=True` (R5.4 real-time visibility).
  - R5.6 + R10.2: `component_id` is the deliberate Forbidden_Leakage_Field_Set exception confined to the Progress_Line. Do NOT add any other field from the upstream library's ProgressEvent shape (the dataclass has exactly three fields — `index`, `total`, `component_id` — so this is structurally enforced by the tuple of available fields).
  - R5.7: stderr-write failures (e.g. `BrokenPipeError`) propagate out of the callback; the design Layer 2 catchall maps them to exit 4.
  - R5.8: the callback fires only on successfully-classified components per the upstream library's `pipeline.py:213`-pattern (after `records.append(record)`); per-component error paths use `continue` and skip the progress call. The CLI mirrors this without modification.
  - Add `tests/classify_cli/test_progress.py` covering R5.1-R5.8: enabled emits one line per ProgressEvent invocation; disabled returns None and emits nothing; flush is called (mock `sys.stderr.flush`); BrokenPipeError on the underlying write propagates; the per-component-error path (using a manifest where the rule evaluation crashes for one component) emits exactly N-1 progress lines for N input components, where N-1 is the count of successfully-classified records.
  - Run the four verification gates.
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8_
  - _Design: Internal helpers — `_build_progress_callback`_

- [x] 8. Implement `_serialize_result` (R3.1-R3.7)

  - In `loki/classify_helpers.py` implement `_serialize_result(result: ClassificationResult) -> str` per design §Architecture's code shape.
  - Construct the payload as `{"records": [...], "errors": [...]}` with exact `["records", "errors"]` key ordering (R3.5).
  - Each `ClassificationRecord` is serialized via `record.model_dump(mode="json")`; same for each `ClassificationError`. The mode-json call handles UUID, datetime, enum, and computed-field fields without Pydantic strict-mode round-trip surprises (mirrors the upstream library's strict-mode round-trip pattern documented in `loki/HANDOFF.md`).
  - Output is `json.dumps(payload, indent=2) + "\n"` so the stream ends with exactly one trailing newline (R3.4).
  - Add `tests/classify_cli/test_stdout_shape.py` covering R3.1-R3.5, R3.7, and R3.8 (R5.6 dual-record visibility): empty result → `{"records": [], "errors": []}\n`; populated result preserves library-side ordering of records and errors; key order is exactly `["records", "errors"]` regardless of dataclass field order; deterministic JSON serialization (two calls on the same input produce identical strings); R5.6 dual-record case includes both record and error for the same component_id without collapse; serialization failure (mock json.dumps to raise) is caught at the handler level (test deferred to task 13's handler-integration tests, not this helper test).
  - Run the four verification gates.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.7, 3.8_
  - _Design: Internal helpers — `_serialize_result`_

- [x] 9. Implement `_format_summary_line` (R4.2; G2-B drops `<R>`)

  - In `loki/classify_helpers.py` implement `_format_summary_line(result: ClassificationResult, *, duration_seconds: float) -> str` per design §Architecture's code shape.
  - Format: `classify: <N> records (<K> need_review), <E> errors, duration=<S>s` (no trailing newline; the caller appends via `print(..., file=sys.stderr)`).
  - `<N>` = `len(result.records)`. `<K>` = `sum(1 for r in result.records if r.needs_review)`. `<E>` = `len(result.errors)`. `<S>` = `f"{duration_seconds:.4f}"` (four decimal places per R4.2).
  - R4.3 deferral: do NOT include `rules_loaded=<R>`. The library exposes the rule count only on the internal `ClassificationPipeline._rules` attribute (private per upstream R12.4). G2-B records this as v1's deliberate choice; a future revision adds the field once the public surface carries it.
  - R4.7 no-leakage: only integer counts and a duration appear in the output. No field from the Forbidden_Leakage_Field_Set is interpolated.
  - R4.4 (K renders as N): the parenthesized `(<K> need_review)` segment is emitted verbatim regardless of K's value; no conditional formatting.
  - Add `tests/classify_cli/test_stderr_summary.py` covering R4.1-R4.7 + P57: format string for empty result; format for populated result with mixed needs_review counts; format when K equals N (every record needs review); format when K is zero; deterministic serialization.
  - Run the four verification gates.
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.6, 4.7_
  - _Design: Internal helpers — `_format_summary_line`; G2-B applied_

- [x] 10. Wire the `classify` subcommand into `loki/cli.py` argparse dispatcher (R1.1, R12)

  - Edit `loki/cli.py` to add a new `_add_classify_subcommand(sub)` function alongside `_add_baseline_subcommands(sub)`. Mirror the existing baseline subparser's structure: `sub.add_parser("classify", help=..., description=...)` followed by the five flag registrations + the positional argument.
  - Positional argument: `manifest` (type=str, no Path conversion — the literal `-` would not survive Path()).
  - Flags: `--rules-path` (type=Path, required=True, metavar="DIR"); `--taxonomy-version` (type=str, default="1.0.0", metavar="VERSION"); `--progress` (action="store_true"); `--debug` (action="store_true"); `--summary-only` (action="store_true").
  - Each flag has a non-empty `help=...` string per R12.1. The positional `manifest` has a non-empty help string naming both the file-path mode and the `-` stdin mode (R12.2). The subparser sets `prog` such that `loki classify --help` shows the subcommand by its full invocation form (R12.3 — argparse default `parent_prog + " " + subparser_name` is `"loki classify"` and satisfies the contract). The subparser's `description=` summarizes the input contract, the stdout JSON shape, and the stderr counts line (R12.4).
  - Wire the handler with `classify_parser.set_defaults(handler=_handle_classify)`. The handler is implemented in task 13; for now, set up an entry-point stub `def _handle_classify(args: argparse.Namespace) -> int: raise NotImplementedError("classify handler implemented in task 13")` so the parser registration tests can run without invoking the handler.
  - Call `_add_classify_subcommand(sub)` from `build_parser()` after the existing `_add_baseline_subcommands(sub)` call.
  - Add `tests/classify_cli/test_help_text.py` covering R12.1-R12.5: every flag has non-empty help; positional `manifest` has non-empty help naming both modes; `loki classify --help` invocation succeeds with exit 0; `description=` is present and non-empty; no flag outside the spec's set is advertised (assertion against the parsed help output).
  - Add `tests/classify_cli/test_argparse.py` covering: argparse rejects missing `--rules-path` with exit 2 (P54-relevant); argparse accepts the four-flag baseline; argparse rejects multiple positional arguments (R1.10).
  - Run the four verification gates.
  - _Requirements: 1.1, 1.10, 2.1, 2.2, 2.4, 12.1, 12.2, 12.3, 12.4, 12.5_
  - _Design: Architecture — Subcommand registration_

- [x] 11. Implement the `_handle_classify` function shell (R1, R2, R3, R6, R7, R8 wiring)

  - Edit `loki/cli.py` to replace the task 10 stub of `_handle_classify` with the linear lifecycle per design §Architecture: lazy imports of all classify_helpers + classification + models; Step 1 manifest ingestion via `_load_manifest`; Step 2 ClassificationConfig construction (taxonomy_version=args.taxonomy_version, confidence_threshold=0.6 pinned, rules_path=str(args.rules_path)); Step 3 SIGINT handler installation; Step 4 debug logger setup; Step 5 library invocation with try/except chain (config error → exit 6; rule error → exit 5; pipeline error → exit 4; unexpected → exit 4) inside a `try` block; the `finally` block restores debug-logger and SIGINT handlers regardless of path; Step 9 stdout serialization (gated on `not args.summary_only`); Step 10 stderr summary line (unconditional on success or partial-cancellation path, skipped on error paths via the early returns in the except block); Step 11 exit code resolution (130 if cancel_flag.value, else 0).
  - The library invocation's `try` block uses ordered except clauses: most-specific first (ClassificationConfigError, ClassificationRuleError) before catchall (ClassificationPipelineError) before unexpected (Exception). Each except prints a stderr message of the documented form and returns the appropriate exit code from `_CLASSIFY_EXIT_CODES`.
  - The finally block runs both restores even if an except clause returned; Python's `finally` guarantees this.
  - Add `tests/classify_cli/test_exit_codes.py` covering R8.1-R8.7 and P54: every exit code path resolves to one of `{0, 2, 3, 4, 5, 6, 130}`; the stderr message format matches the spec for each typed-error class; the typed-error message line is emitted on whole-run failures and the summary line is NOT emitted (R4.5); the summary line IS emitted on success paths (R4.1) and partial-cancellation paths (task 12 covers this further); the catchall `Exception` path uses the `unexpected error: <type>: <message>` format (R8.6).
  - Run the four verification gates.
  - _Requirements: 1.9, 1.11, 2.6, 3.6, 6.3, 6.6, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_
  - _Design: Architecture — Internal handler `_handle_classify`; Exit-code resolution; D5 default_

- [x] 12. Add the deterministic in-process cancellation contract test (P55 + R6 + R7)

  - Add `tests/classify_cli/test_cancellation.py` with a parameterized deterministic test for P55 (Cancel_Flag-driven cancellation contract). For cancellation indices in `[1, total]` over a small synthetic manifest (e.g. 5 components), pass a synthetic `CancellationToken` callback that returns `True` at the configured iteration. Assert: (a) `ClassificationResult.errors` ends with exactly one Cancellation_Marker whose `error_message == "classification cancelled by caller"` and `component_id is None`; (b) the Stdout_Result still parses as valid JSON with exactly the keys `["records", "errors"]`; (c) the handler-level exit-code resolution returns 130 when `cancel_flag.value` is True after the library returns.
  - The test invokes the CLI in-process via `loki.cli.main(["classify", str(manifest_path), "--rules-path", str(rules_path)])` plus a `monkeypatch` injection of `classify_components` that respects the synthetic CancellationToken (or a direct `classify_components` call inside the test that uses the same library path).
  - Pinned Q2 (test class organization): use module-level test functions for this deterministic test; the parameterization is via `@pytest.mark.parametrize("cancel_at_index", range(1, 6))`. No class wrapping needed.
  - Add `tests/classify_cli/test_summary_only_partial_cancellation.py` (or add to test_cancellation.py): when `--summary-only` is set AND cancellation is requested, verify stdout has zero bytes, stderr has the summary line, and exit is 130.
  - Run the four verification gates.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 13.3_
  - _Design: Correctness Properties — Property 55; Open questions Q2_

- [x] 13. Add the SIGINT end-to-end subprocess test (R6 + Q2)

  - Add `tests/classify_cli/test_sigint_e2e.py` with a single example-based test that uses `subprocess.Popen` to run `.venv/bin/python -m loki classify <manifest> --rules-path <rules_dir>` (or the equivalent module-form invocation), waits for the process to start (a deterministic wait condition: poll for the first line of stderr or for a specific stdout/stderr signature, using `subprocess.Popen.stderr.readline()` with a timeout), then calls `process.send_signal(signal.SIGINT)`, then waits for the process to exit (via `process.wait(timeout=10)`), then asserts: exit code is 130; stdout is valid JSON or empty (depending on cancellation timing); stderr contains the summary line.
  - This is the only subprocess-based test in the suite; everywhere else uses in-process invocation via `loki.cli.main(...)`. Q2 (test class organization) is pinned by using a single module-level test function; no class wrapping.
  - The test is potentially flaky on heavily-loaded CI environments; mark with `@pytest.mark.timeout(15)` and document the deterministic-wait pattern in the test docstring.
  - Run the four verification gates.
  - _Requirements: 6.1, 6.2, 6.3, 6.4_
  - _Design: Correctness Properties — Property 55 (subprocess-based companion test); Open questions Q2_

- [x] 14. Add P53 stdin-or-file equivalence Hypothesis test

  - Add `tests/classify_cli/test_stdin_equivalence.py` with a Hypothesis property test for P53. Generate a valid `ExtractionManifest` (mirror the strategy from `tests/conftest.py` for ExtractionManifest if it exists; otherwise build a small bespoke strategy). For each generated manifest, write its JSON to a temp file; run `loki.cli.main(["classify", str(path), "--rules-path", str(rules_dir)])` capturing stdout; run `loki.cli.main(["classify", "-", "--rules-path", str(rules_dir)])` with `monkeypatch.setattr(sys, 'stdin', io.StringIO(json_text))` capturing stdout; assert the two stdout strings are equal after stripping the per-record `timestamp` field.
  - Use `max_examples=25` per the project's full-pipeline Hypothesis convention. Suppress `HealthCheck.too_slow` and `HealthCheck.function_scoped_fixture`.
  - The "strip timestamp" helper is a small JSON-walking function: load both stdout strings via `json.loads`, walk `records[*]` setting `timestamp` to a fixed sentinel like `"<TS>"`, re-serialize, compare. Place the helper in `tests/classify_cli/_helpers.py` (underscore-prefixed module name; pytest does not collect it as tests).
  - Run the four verification gates.
  - _Requirements: 9.1, 9.2, 13.1_
  - _Design: Correctness Properties — Property 53_

- [x] 15. Add P56 `--summary-only` Hypothesis test

  - Add `tests/classify_cli/test_summary_only.py` with a Hypothesis property test for P56. Generate a valid `ExtractionManifest` parameterized over record count (including the empty manifest). For each generated manifest, run `loki.cli.main(["classify", str(path), "--rules-path", str(rules_dir), "--summary-only"])` capturing stdout/stderr. Assert: stdout is exactly zero bytes; stderr contains exactly one summary line of the documented format; exit code matches the same invocation without `--summary-only` (run twice, compare).
  - Use `max_examples=50` per the project's in-memory-fast Hypothesis convention.
  - Run the four verification gates.
  - _Requirements: 3.6, 13.4_
  - _Design: Correctness Properties — Property 56_

- [x] 16. Add P57 Stderr_Summary_Line emission discipline test

  - Add `tests/classify_cli/test_stderr_summary_emission.py` (separate from `test_stderr_summary.py` from task 9, which covered the format string only) with a four-case parameterized test for P57. For each of: (a) successful run, (b) partially-cancelled run (cancellation at index 2 of 5), (c) per-component-error run (manifest with one component whose rule evaluation crashes), (d) whole-run failure (e.g. invalid `--taxonomy-version` triggering ClassificationConfigError) → assert: cases (a)-(c) emit exactly one summary line on stderr; case (d) does not emit a summary line at all (only the typed-error message).
  - Verify each case's exit code matches Requirement 4.5: (a) → 0, (b) → 130, (c) → 0 (per-component errors don't change the exit code; R6.6), (d) → 6.
  - Run the four verification gates.
  - _Requirements: 4.1, 4.5, 4.6, 13.5_
  - _Design: Correctness Properties — Property 57_

- [x] 17. Add the static side-channels AST audit (R10.5 indirect)

  - Add `tests/classify_cli/test_no_side_channels.py` with a static AST audit that walks `loki/classify_helpers.py`'s and (optionally) the `_handle_classify` function's AST, asserting: no `import os.environ`, no `random`, no `secrets`, no `socket`, no `urllib`, no `requests`, no `httpx`. The CLI uses `time.monotonic()` for the duration measurement (R4.2's `<S>`); the audit allows `time.monotonic()` but rejects `time.time()` and `datetime.now()` calls inside the helpers.
  - Mirror the pattern from `tests/analysis/test_no_side_channels.py` exactly; the AST-walking machinery is identical, only the module-of-interest changes.
  - Run the four verification gates.
  - _Requirements: 9.5_
  - _Design: Determinism contract; Correctness Properties — implicit (the static audit is the proof for R9.5)_

- [x] 18. Add the static no-leakage AST audit (P58 part 1)

  - Add `tests/classify_cli/test_no_leakage.py` with a static AST audit (one of the two paired audits) that walks `loki/classify_helpers.py`'s AST, asserting that no f-string interpolation or `str.format(...)` call on a stderr-bound write (i.e. inside `print(..., file=sys.stderr)`, `sys.stderr.write(...)`, or `logging.StreamHandler(sys.stderr)` formatter strings) interpolates any value drawn from the Forbidden_Leakage_Field_Set: `ClassificationRecord.component_id`, `ExtractedComponent.component_id`, `SignatureInfo.signer`, `BaselineRecord.source_image_hash`, `AxisClassification.evidence`.
  - Whitelist exception: the Progress_Line emitter in `_build_progress_callback` MAY interpolate `event.component_id` per R10.2. The audit recognizes this exception by checking the surrounding function name.
  - Mirror the pattern from `tests/classification/test_no_log_leakage.py` exactly; the AST-walking machinery is identical, only the module-of-interest and the field set change.
  - Pinned Q2 (test class organization): use a single class `TestNoLeakageStaticAudit` to group the audit and its sub-assertions; the dynamic audit (task 19) is in a separate class `TestNoLeakageDynamicAudit` in the same file.
  - Run the four verification gates.
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 13.6_
  - _Design: No-leakage discipline; Correctness Properties — Property 58 (part 1); Open questions Q2_

- [x] 19. Add the dynamic no-leakage stderr-capture audit (P58 part 2)

  - Add to `tests/classify_cli/test_no_leakage.py` (same file, separate test class `TestNoLeakageDynamicAudit`) a behavioral test that runs `loki.cli.main(["classify", ...])` end-to-end against a manifest with components carrying known-forbidden values (e.g. a synthetic `signature_info.signer = "evil"`, a synthetic `source_image_hash = "deadbeefdeadbeef..."`, an `AxisClassification.evidence = "EVIDENCE_TOKEN"`). Capture stderr via `capsys`. Assert that "evil", the source_image_hash literal, and "EVIDENCE_TOKEN" do NOT appear anywhere in the captured stderr.
  - Run the same test with `--debug` enabled to verify R7.7: the DEBUG-attached handler does NOT bypass the audit; even at DEBUG level, no Forbidden_Leakage_Field_Set value appears in stderr.
  - Run the same test with `--progress` enabled and assert: the only `component_id` substring on stderr originates from a Progress_Line; "evil" and the other forbidden values still don't appear.
  - Run the four verification gates.
  - _Requirements: 7.7, 10.1, 10.2, 10.3, 10.4, 10.5, 13.6_
  - _Design: No-leakage discipline; Correctness Properties — Property 58 (part 2)_

- [x] 20. Add the determinism + R5.6 dual-record passthrough test

  - Add `tests/classify_cli/test_determinism.py` covering R9.1-R9.6: same manifest contents + same rules dir + same taxonomy version produce byte-equal stdout (after stripping per-record timestamp); the file-vs-stdin paths produce byte-equal stdout (already covered by P53 in task 14, but a non-Hypothesis example test pins this independently); environment-derived values (run start time, hostname, cwd, env vars) do not appear in stdout (assert via stderr-capture); R5.6 dual-record case (using a manifest with one component whose `raw_path` is None) emits both a `ClassificationRecord` and a `ClassificationError` for the same component_id without collapse; the Stdout_Result deserializes to a dict with exactly the keys `["records", "errors"]` (R9.6).
  - The R9.5 environmental-side-channels assertion runs the CLI with `monkeypatch.setenv("LOKI_TEST_ENV_VAR", "leaked-value")` and asserts "leaked-value" doesn't appear in stdout.
  - Run the four verification gates.
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_
  - _Design: Determinism contract_

- [x] 21. Add the slow-marker performance test (R11.1)

  - Add `tests/classify_cli/test_performance.py` with a single `@pytest.mark.slow` test for R11.1's wrapper-only timing budget. Build a 256-component synthetic manifest and a 256-rule synthetic rules dir. Time each wrapper step explicitly per the design §Performance plan pseudocode: argparse parsing, manifest read + JSON decode + Pydantic validation (via `_load_manifest`), Stdout_Result JSON serialization (via `_serialize_result`). Sum the three durations as `cli_overhead`. Assert `cli_overhead < 0.200` seconds.
  - Do NOT subtract the library's internally-reported duration; the wrapper-only timing measurement is the contract per R11.1 post-HARDEN. Time each wrapper step in isolation using `time.monotonic()` brackets.
  - Mark the slow performance suite registration: confirm the existing `pyproject.toml` `slow` marker is already registered; the test inherits via `@pytest.mark.slow`.
  - R11.3's working-set bound (≤64 MiB) is SHOULD-level per HARDEN; do NOT add a `tracemalloc`-based test in v1. A future revision MAY add enforcement.
  - Run the four verification gates including `pytest -m slow` to confirm the slow test passes.
  - _Requirements: 11.1, 11.2, 11.4_
  - _Design: Performance plan_

- [x] 22. Update `loki/cli.py` to call `_add_classify_subcommand` and verify the integrated subcommand

  - Confirm that `build_parser()` calls `_add_classify_subcommand(sub)` (added in task 10).
  - Add a smoke test at `tests/classify_cli/test_smoke.py` that runs `.venv/bin/python -m loki classify --help` (via `loki.cli.main(["classify", "--help"])`) and asserts exit code is 0 (argparse's `--help` calls `sys.exit(0)` after printing).
  - Add a second smoke test that runs the full pipeline: build a 5-component manifest, build a 4-rule rules dir, invoke `loki.cli.main(["classify", str(manifest_path), "--rules-path", str(rules_dir)])`, capture stdout/stderr, assert exit 0; stdout parses as JSON with the expected `["records", "errors"]` keys; stderr contains the summary line; record count matches the manifest's component count (assuming no per-component errors).
  - Run the four verification gates and confirm test count rises by approximately 60-80 from the 1211 baseline. Source file count rises to approximately 240 (1211 baseline + 220 from task 2 + ~15 new test files + 5 new module-level adds).
  - _Requirements: 1.1, 1.9, 1.11, 12.1_
  - _Design: Architecture — Subcommand registration_

- [x] 23. Update `README.md` and `STATE.md`

  - Add a `## Classification CLI` section to `loki/README.md` between the existing `## Classification pipeline` section and `## Analysis engine`. Document: the `loki classify` subcommand syntax (`loki classify <manifest|->-` plus the five flags); the stdout JSON shape; the stderr summary line format; the exit-code taxonomy; the cooperative-cancellation pattern; the `--debug` and `--summary-only` flags' purposes; the R5.6 dual-record contract from upstream classification; the design's seven D-defaults at a high level (e.g. "the helpers live in `loki/classify_helpers.py` for module clarity"); the test-suite location at `tests/classify_cli/`.
  - Update `loki/STATE.md`: change the maturity line from "Five IMPLEMENTED + APPROVED subsystems" to "Six IMPLEMENTED + APPROVED subsystems" once the spec is APPROVED (this happens at task 25's final-gate ratification, not here); for now, add a note that classification-cli is IMPLEMENTED but spec-status remains DRAFT until task 25.
  - Update verification-gates count in STATE.md: the new pytest baseline is approximately 1271-1291 (1211 + ~60-80 new); mypy --strict source-file count rises to approximately 240.
  - Run the four verification gates.
  - _Requirements: documentation hygiene; not directly mapped_
  - _Design: not directly mapped_

- [x] 24. Update `loom-loki.md` with the v0.5.0 → v0.6.0 implementation BIND

  - Edit `loom-loki.md`: bump version from 0.5.0 to 0.6.0; add a new evolution-log entry above the v0.5.0 entry describing the implementation work (round-by-round wave summary; final pytest count; the seven D-defaults baked in; any deviations from the design surfaced during implementation).
  - In the §2 subsystem registry, change the `classify-cli` entry's `lifecycle_stage` from `"PROPOSED"` to `"IMPLEMENTED"` and `spec_status` from `"DRAFT"` to `"APPROVED"`.
  - In §3 dependency graph, change the three `classify-cli` edges' `established_by` from `"v0.5.0 (design BIND)"` to `"v0.6.0 (Wave N implementation BIND)"` (replacing N with the appropriate wave number) and `last_verified` to the implementation date.
  - In §5 open threads, change OT-LK-003 status from "OPEN — requirements HARDEN, design BIND, tasks not yet BIND'd" to "CLOSED — implementation v1.0.0 ships at IMPLEMENTED + APPROVED" (mirroring the OT-LK-001 close pattern). Update the entry's notes to summarize the ship: number of source lines actually added; final test count; final mypy --strict file count.
  - Run diagnostics on `loom-loki.md`.
  - _Requirements: documentation hygiene_
  - _Design: not directly mapped_

- [x] 25. Final verification gate

  - Run all four verification gates plus the slow-marker performance suite:
    ```bash
    .venv/bin/python -m pytest -q
    .venv/bin/python -m pytest -m slow
    .venv/bin/python -m mypy --strict loki tests scripts
    .venv/bin/python -m ruff check
    .venv/bin/python -m ruff format --check
    ```
  - Confirm: pytest baseline rises from 1211 to approximately 1271-1291 (the new tests plus the existing baseline; CLI subsystem adds approximately 60-80 tests); mypy --strict clean across approximately 240 source files; ruff check + format clean repo-wide; slow-marker performance test passes (R11.1 budget validated under 200ms).
  - Verify the offscreen GUI smoke remains green (the CLI does not import PyQt6; the smoke test should be unaffected): `QT_QPA_PLATFORM=offscreen .venv/bin/python -c "import sys; sys.argv = ['smoke']; exec(open('scripts/smoke_gui.py').read())"`.
  - Confirm: `from loki.classify_helpers import _load_manifest, _serialize_result, _CLASSIFY_EXIT_CODES` works (the helpers module is private but importable for internal testing; the CLI dispatcher uses it via lazy import in `_handle_classify`).
  - Confirm: `loki classify --help` emits the documented help text (R12.1-R12.5).
  - Confirm: an end-to-end smoke run on a real `ExtractionManifest` (e.g. one produced by `loki extract foo.rom --output-dir /tmp/out > /tmp/m.json`) plus a real rules dir produces a valid JSON result on stdout, the summary line on stderr, and exit 0.
  - Tick this task off after every gate is green. The classification-cli subsystem is then APPROVED + IMPLEMENTED.
  - _Requirements: all (final-gate ratification)_
  - _Design: not directly mapped — final ratification step_


## Task Dependency Graph

The dependency graph organizes tasks into waves. All tasks in a wave can be executed in parallel; each wave waits for the previous one.

```json
{
  "waves": [
    {
      "name": "wave-1-scaffold",
      "tasks": ["1", "2"]
    },
    {
      "name": "wave-2-helpers",
      "tasks": ["3", "4", "5", "6", "7", "8", "9"]
    },
    {
      "name": "wave-3-handler-and-subcommand",
      "tasks": ["10", "11"]
    },
    {
      "name": "wave-4-cancellation-tests",
      "tasks": ["12", "13"]
    },
    {
      "name": "wave-5-properties-and-audits",
      "tasks": ["14", "15", "16", "17", "18", "19", "20", "21"]
    },
    {
      "name": "wave-6-integration-and-docs",
      "tasks": ["22", "23", "24"]
    },
    {
      "name": "wave-7-final-gate",
      "tasks": ["25"]
    }
  ]
}
```

Suggested implementation cadence aligned to the waves:

- **Day 1 — Waves 1-2.** Test-tree scaffold, helpers module skeleton, every helper function (cancel flag, manifest loader, signal handler installer, debug logger lifecycle, progress callback, JSON serializer, summary-line formatter). Pure helper-function work; each is small enough to land in one focused chunk. Smallest meaningful change first.
- **Day 2 — Wave 3.** Subcommand registration on the existing `loki/cli.py` argparse dispatcher; `_handle_classify` handler shell with the linear lifecycle. The CLI becomes invokable end-to-end at the end of this wave.
- **Day 3 — Wave 4.** Cancellation contract tests: P55's deterministic in-process test plus the SIGINT end-to-end subprocess test. The cancellation path is the trickiest behavior in the subsystem; isolating it to its own wave keeps the work auditable.
- **Day 4 — Wave 5.** Cross-cutting tests: P53 stdin-or-file equivalence, P56 `--summary-only` zero-byte stdout, P57 emission discipline, side-channels AST audit, paired no-leakage audits (static + dynamic), determinism + R5.6 dual-record passthrough, performance slow-marker. Tasks within this wave are independent and can be done by separate sessions in parallel.
- **Day 5 — Wave 6.** Integration smoke (re-confirms `_add_classify_subcommand` is wired and the help text is correct), README + STATE updates, loom-loki harness bump from v0.5.0 to v0.6.0.
- **Day 6 — Wave 7.** Final verification gate. Confirm test count is in the 1271-1291 range; mypy clean across approximately 240 source files; ruff clean; slow-marker performance test green; offscreen GUI smoke unaffected.

The cadence is intentionally compressed relative to analysis-engine's six-day plan because the subsystem has narrower scope (no new model layer, no new public Python API, library API consumed unchanged). Five days for waves 1-6 plus one day for the final gate is realistic for a single focused implementer.

## Notes

- **Stick to the design's Module layout exactly.** The new helpers go into `loki/classify_helpers.py` only; do not split across multiple modules. The single-leading-underscore privacy convention (D6 default) is structural, not just stylistic — it prevents future code from importing the helpers as a public API.
- **The seven design defaults D1-D7 are all revertable cheaply if a future revision wants different behavior.** D1 (helpers in classify_helpers.py vs. inline in cli.py) ripples through tasks 2 and 11. D2 (`_CancelFlag` is a `@dataclass`) ripples through task 3. D3 (`propagate = False` on `--debug`) ripples through task 6. D4 (TTY guard fires first) ripples through task 4. D5 (exit code 4 catches both pipeline catchall and unexpected `Exception`) ripples through task 11. D6 (helpers are module-private) ripples through tasks 2 and 22. D7 (integer-on-failure pattern in `_load_manifest`) ripples through tasks 4 and 11. None ripple beyond two or three tasks. If any default needs to change mid-implementation, raise it as a deviation, update design.md, and re-run the affected tasks.
- **The R5.6 dual-record contract from upstream classification is the single trickiest behavior the CLI must preserve.** Tasks 8 (serialization) and 20 (determinism passthrough) both pin the no-collapse contract. Whenever you touch `_serialize_result` or the output-shape tests, re-run `tests/classify_cli/test_stdout_shape.py` together with `tests/classify_cli/test_determinism.py` — not just individually.
- **The Forbidden_Leakage_Field_Set audit (tasks 18 + 19) is the trickiest test to keep correct.** The static AST audit only catches *direct* attribute accesses inside stderr-bound writes; if someone formats a forbidden value into a local variable and then writes the variable, the static audit misses it. The dynamic stderr-capture audit catches that case. Run both as a pair; failures in either should block a checkpoint.
- **The `slow` marker is already registered in `pyproject.toml`** and `addopts = "-ra --strict-markers -m 'not slow'"` keeps the performance test off the default `pytest -q` run. Don't change that; the budget in R11.1 is wrapper-only timing and is sensitive to CI noise.
- **The CLI overhead measurement is wrapper-only per R11.1 (post-HARDEN).** Time argparse parsing + manifest read + JSON decode + Pydantic validation + Stdout_Result JSON serialization + stderr line emission as separate steps; do NOT subtract the library's internally-reported duration. The library's duration reporting is internal and may drift; the CLI's contract is independent.
- **The `--debug` flag's `propagate = False` (G5-A from TENSION pass) is a deliberate and explicit choice to silence externally-attached parent loggers for the duration of the run.** This is well-bounded (one CLI invocation) and avoids the double-logging trap that would otherwise occur when root has a DEBUG-capable handler. Reverting requires removing one line from `_install_debug_logger`'s setup AND removing one line from its restore closure; ensure both are removed atomically.
- **The seven judgment calls baked into this task list (D1-D7) and the three open questions Q1-Q3 from design.md are recorded in the design's Deferred decisions and Open questions sections.** Q1 (test fixture sharing — pinned by task 1's bespoke fixtures), Q2 (test class organization — pinned by task 12's module-level functions and tasks 18/19's class-grouped audits), Q3 (`--no-tty-guard` flag — pinned by NOT being implemented in v1; deferred to a future spec amendment if any operator requests it).
- **`filterwarnings = ["error"]` pytest config will surface any `DeprecationWarning` emitted during the CLI run.** PyYAML, Pydantic, and click occasionally emit these on minor upgrades; if a warning fires, follow the extraction-pipeline's pattern: either upgrade the pin or add a narrow `filterwarnings("ignore", ...)` in `tests/classify_cli/conftest.py` with a documented rationale.
- **v1 ships exactly the library API plus this CLI wrapper.** `loki classify rules-check`, `loki classify show`, `--from-firmware`, `--output-file`, `--confidence-threshold`, `LokiConfig.from_yaml(...)` fallback, YAML auto-detect, JSONL streaming output, GUI integration, and `ExtractionManifest` schema migration are all out of scope and have their own (future) specs or are explicitly deferred (OT-LK-006 tracks the manifest schema migration). Don't pre-emptively add hooks, fallback paths, or alternate-format support.
- **Property numbering picks up at P53 per project-wide convention** (see `loki/HANDOFF.md` carry-forward constraints). The next subsystem to ship a Tier 3 spec triple picks up at P59.
- **Cross-subsystem property referencing is fine.** Properties P53-P58 reference upstream classification's R1.9 (cancellation marker contract), R5.6 (dual-record), R12.1 (progress callback contract), and R13.5 (Forbidden_Leakage_Field_Set); the CLI property tests do not need to re-validate those upstream invariants.
- **The 1211-test pre-implementation baseline is the floor.** A passing CLI implementation should add approximately 60-80 tests (most are small example-based; some are Hypothesis property tests with `max_examples=25` or `max_examples=50`; one slow-marker performance test). Tests that fail or are skipped are not part of the count.
