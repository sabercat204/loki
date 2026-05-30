# Implementation Plan

## Overview

This is the executable task list for the **baseline-persistence**
spec. Tasks are ordered so that each one builds on previous tasks
and leaves the repo in a verifiable state (every checkpoint passes
`pytest`, `mypy --strict`, `ruff check`, and `ruff format --check`).

Each task lists the exact files it touches, the test surface it adds,
and the design / requirement references it implements. Sub-bullets
under each task are checklist items the implementer ticks off as
they go; they are not separate tasks.

Honest scope reminder: this plan covers persistence only.
Comparison, classification, and live extraction wiring are
explicitly out of scope and have their own (future) specs.

## Pre-flight checklist

Before starting, confirm the repo is healthy:

```bash
.venv/bin/pytest -q
.venv/bin/mypy loki tests
.venv/bin/ruff check loki tests
.venv/bin/ruff format --check loki tests
```

All four must be green. The baseline-persistence work assumes a
clean baseline; the foundations from the extraction-pipeline work
should be intact.

## Tasks

- [x] 1. Scaffold the `loki/baseline/` package skeleton

  - Create `loki/baseline/__init__.py`, `errors.py`, `schema.py`,
    `naming.py`, `envelope.py`, `concurrency.py`, `quarantine.py`,
    `store.py` as empty modules with docstrings + `__all__: list[str] = []`.
  - Create `tests/baseline/__init__.py` and an empty
    `tests/baseline/conftest.py` so pytest can collect from the
    new tree.
  - Verify the empty subsystem imports cleanly:
    `.venv/bin/python -c "import loki.baseline"`.
  - _Requirements: none — pure scaffolding_
  - _Design: Components and Interfaces — Module layout_

- [x] 2. Implement the typed exception hierarchy

  - In `loki/baseline/errors.py` define `BaselineStoreError`,
    `BaselineConcurrentModificationError` (carrying `path`,
    `recorded`, `observed`), `BaselineAlreadyExistsError` (`path`),
    `BaselineSerializationError` (`message` + optional
    `cause: BaseException | None`), `BaselineStorageUnwritableError`
    (`path`, `errno`).
  - Each is a normal `Exception` subclass with typed `__init__`.
  - Add `tests/baseline/test_exceptions.py` covering: every class
    is constructible with the documented kwargs; subclasses
    inherit from `BaselineStoreError`; `str()` formats include
    the path and the relevant fields.
  - Re-export every public exception from
    `loki.baseline.__init__`.
  - _Requirements: 5.2, 5.3, 8.1, 8.6, 8.7_
  - _Design: Components and Interfaces — Exception hierarchy_

- [x] 3. Implement the Schema_Version constant module

  - In `loki/baseline/schema.py` define `SCHEMA_VERSION: str = "1.0.0"`
    and `SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({SCHEMA_VERSION})`.
  - Add a regex check (`^\d+\.\d+\.\d+$`) wrapped in a unit test.
  - Document in the module docstring that v1 supports exactly one
    Schema_Version (R4.2).
  - Re-export `SCHEMA_VERSION` and `SUPPORTED_SCHEMA_VERSIONS`
    from `loki.baseline.__init__`.
  - Add `tests/baseline/test_schema_version.py` covering: the
    constant is in semver shape; `SCHEMA_VERSION` is a member of
    `SUPPORTED_SCHEMA_VERSIONS`.
  - _Requirements: 4.1, 4.2, 4.6_
  - _Design: Components and Interfaces — Module layout
    (`schema.py`)_

- [x] 4. Implement filename slugification + collision handling

  - In `loki/baseline/naming.py` implement `slug(value)`,
    `filename_for(record)`, `unique_filename_for(record, taken)`
    exactly as specified in the design's "Naming and
    slugification" section.
  - Add `tests/baseline/test_naming.py` covering: `slug()`
    lower-cases, replaces `[^a-z0-9._-]` with `_`, collapses
    runs, strips leading/trailing `_`; `filename_for()`
    produces the canonical form; `unique_filename_for()`
    appends the 8-hex `baseline_id` prefix on collision; both
    output filenames match `[a-z0-9._-]+\.yaml`.
  - Add Hypothesis property tests for Properties 28 + 29 (slug
    idempotence; unique-filename produces distinct outputs on
    collision).
  - _Requirements: 1.2, 1.3_
  - _Design: Naming and slugification; Property 28, Property 29_

- [x] 5. Implement the QuarantineSet container

  - In `loki/baseline/quarantine.py` implement `QuarantineEntry`
    (frozen dataclass with `path`, `reason`, `raw`) and
    `QuarantineSet` (append-only container with `add()`,
    iteration, `__len__`).
  - Add `tests/baseline/test_quarantine.py` covering: entries
    accumulate in insertion order; `__len__` matches the count;
    `__iter__` yields in insertion order; `raw` preserves the
    original bytes verbatim.
  - Re-export both from `loki.baseline.__init__`.
  - _Requirements: 2.1, 8.2, 8.3, 8.4, 8.5_
  - _Design: Components and Interfaces — QuarantineSet_

- [x] 6. Implement the file-snapshot helpers

  - In `loki/baseline/concurrency.py` implement `FileSnapshot`
    (frozen dataclass), `snapshot(path)`, and
    `check_unchanged(snap)`.
  - Use `os.stat` for `st_mtime_ns` and `st_size`; raise
    `BaselineConcurrentModificationError` from `check_unchanged`
    on mismatch (R5.2).
  - Add `tests/baseline/test_concurrency.py` covering: snapshot
    captures the right fields; `check_unchanged` is a no-op
    when the file is unchanged; `check_unchanged` raises with
    the recorded vs observed values when the file has been
    rewritten; `check_unchanged` raises when the file has been
    deleted.
  - _Requirements: 5.1, 5.2_
  - _Design: Concurrency snapshot; Property 30_

- [x] 7. Implement the YAML envelope module

  - In `loki/baseline/envelope.py` define the `Envelope` frozen
    dataclass (`schema_version`, `written_at`,
    `written_by_extractor_version`, `baseline`),
    `_REQUIRED_KEYS`, the `serialize(record, *, written_at)`
    function, and the `deserialize(payload, *, path)` function.
  - `serialize` builds the dict envelope, dumps via
    `yaml.safe_dump(sort_keys=True, default_flow_style=False,
    allow_unicode=True)` and returns UTF-8 bytes ending in `\n`.
  - `deserialize` runs `yaml.safe_load`, validates the four
    required envelope keys are present, parses `written_at` as
    a `datetime`, and returns the `Envelope` instance.
  - Define a private `EnvelopeMalformedError(Exception)` for
    bulk-load callers (the store) to catch and convert to
    quarantine entries; for `load_one` it bubbles out as
    `BaselineSerializationError`.
  - Add `tests/baseline/test_envelope.py` covering: serialize
    produces deterministic bytes (sort_keys=True); the
    serialized bytes round-trip through `yaml.safe_load`;
    `deserialize` rejects missing keys; `deserialize` rejects
    a non-string `schema_version`; UTF-8 with trailing newline.
  - _Requirements: 1.7, 3.4, 3.5, 3.6, 3.7, 8.3_
  - _Design: Envelope schema; Property 25_

- [x] 8. Author the synthetic baseline fixture

  - Create `tests/baseline/fixtures/__init__.py` and
    `tests/baseline/fixtures/synthetic_baseline.py` exporting
    `build(*, vendor="INTEL", model="DEMO-X1", firmware_version="1.0",
    classification_count=3) -> BaselineRecord`.
  - The builder uses `uuid.uuid5` seeds for every UUID so the
    resulting record is byte-identical across runs (mirrors the
    extraction-pipeline fixture pattern).
  - Wire it into `tests/baseline/conftest.py` as a fixture
    `synthetic_baseline` returning a default-shape record.
  - Add `tests/baseline/test_fixtures.py` smoke-checking the
    builder produces a Pydantic-validated `BaselineRecord` with
    the requested classification count; same inputs produce the
    same `baseline_id`.
  - _Requirements: 9.2, 9.3, 9.4 (fixture inputs to the
    determinism property tests)_
  - _Design: Testing Strategy — Synthetic fixture_

- [x] 9. Implement the BaselineStore: constructor + storage_path
       handling

  - In `loki/baseline/store.py` implement `BaselineStore.__init__`
    accepting a `BaselineConfig`, resolving
    `config.storage_path`, creating the directory with mode
    `0o755` if missing (R1.6), and storing the resolved path
    plus the loaded SCHEMA_VERSION.
  - Add `LoadResult` frozen dataclass.
  - Add `BaselineStore.storage_path` and `schema_version`
    properties.
  - Initialize `self._snapshots: dict[uuid.UUID, FileSnapshot]
    = {}` in the constructor.
  - Add `tests/baseline/test_store_basics.py` covering: missing
    directory is created; existing directory is reused;
    unwritable directory raises
    `BaselineStorageUnwritableError`.
  - _Requirements: 1.5, 1.6, 8.7_
  - _Design: Components and Interfaces — `BaselineStore`_

- [x] 10. Implement `BaselineStore.load`: Discovery_Scan +
        sequential validation

   - Implement `load()` per the design's "Load flow" section:
     stat directory, scan for `*.yaml` files at depth 1, sort
     lexicographically, iterate.
   - Per file: stat (skip > 16 MiB → quarantine), read, parse
     via `envelope.deserialize`, check schema_version against
     `SUPPORTED_SCHEMA_VERSIONS`, run
     `BaselineRecord.model_validate(envelope.baseline,
     strict=False)`, detect duplicate baseline_id, snapshot
     each successfully loaded file, append to registry.
   - Catch `yaml.YAMLError` → `"malformed yaml: {message}"`
     quarantine reason; catch missing keys → `"missing required
     envelope key: {key}"`; catch unsupported schema_version →
     `"unsupported schema_version: {value}"`; catch
     `pydantic.ValidationError` → `"validation failed:
     {summary}"`; catch invalid UUID → `"invalid baseline_id"`.
   - Return `LoadResult(registry, quarantine, duration_ms)`
     where `duration_ms` is the wall-clock duration of the
     scan.
   - Add `tests/baseline/test_store_load.py` covering: empty
     directory returns empty result; one good file loads;
     malformed YAML quarantines with the right reason; missing
     envelope keys quarantines; schema-version mismatch
     quarantines; oversized file quarantines; duplicate
     baseline_id places the second occurrence in quarantine
     with `"duplicate baseline_id"` reason; the registry
     order is lexicographic-by-filename.
   - _Requirements: 1.4, 1.6, 2.1-2.7, 4.3, 4.4, 8.2-8.5,
     9.7, 10.1, 10.2, 10.3_
   - _Design: Architecture — Load flow_

- [x] 11. Implement `BaselineStore.save`: Atomic_Write +
        concurrency check

   - Implement `save(record, *, force=False)` per the design's
     "Save flow" section.
   - Round-trip validation first: `model_validate(record.model_dump(mode="json"))`
     → `BaselineSerializationError` on failure.
   - Compute Baseline_Filename via `naming.filename_for`;
     resolve to `dest = storage_path / canonical`. If
     `force=False` and `record.baseline_id` is in
     `self._snapshots`, use the snapshot's path instead. If
     `force=False` and dest already exists but isn't in
     snapshots, raise `BaselineAlreadyExistsError`.
   - Build envelope bytes via `envelope.serialize(record,
     written_at=datetime.now(tz=UTC))`. Reject if length > 16 MiB
     → `BaselineSerializationError`.
   - Atomic_Write: temp file with monotonic-counter suffix,
     `fd.write(bytes)`, `fd.flush()`, `os.fsync(fd.fileno())`.
     If `force=False` and snapshot exists,
     `concurrency.check_unchanged` against the snapshot before
     `os.replace`.
   - On any exception before `os.replace`: `tmp.unlink(missing_ok=True)`.
   - After successful replace, re-snapshot dest and store in
     `self._snapshots[record.baseline_id]`.
   - Log success per R10.4.
   - Add `tests/baseline/test_store_save.py` covering: happy
     path writes a valid Baseline_File and returns the path;
     two saves of the same record produce byte-identical files
     except for the `written_at` timestamp; oversized payload
     raises `BaselineSerializationError` and writes nothing;
     `force=False` + existing file raises
     `BaselineAlreadyExistsError`; failed serialization (force
     a write error mid-flight) leaves the destination
     unchanged; `force=True` overwrites without the snapshot
     check.
   - _Requirements: 3.1-3.9, 5.1-5.4, 8.6, 9.3, 9.8, 10.4_
   - _Design: Architecture — Save flow; Properties 25, 27, 30_

- [x] 12. Implement `BaselineStore.load_one` and `BaselineStore.delete`

   - `load_one(path)` runs the same per-file path as the load
     flow but raises `BaselineSerializationError` on any
     failure rather than quarantining.
   - `delete(baseline_id)` looks up the snapshot path, removes
     the file, removes the snapshot entry, and returns the
     removed path. Missing baseline_id raises a
     `BaselineStoreError` subclass; missing file at the
     expected path also raises (since the user asked for that
     specific id).
   - Add `tests/baseline/test_store_singletons.py` covering:
     `load_one` happy path; `load_one` raises typed errors on
     each failure mode; `delete` removes the file and clears
     the snapshot; `delete` raises on unknown baseline_id;
     `delete` followed by `save` of the same record works
     (re-creates the file).
   - _Requirements: 6.6, 7.4 (load_one); R6.8 (delete)_
   - _Design: Architecture — Single-file load_

- [x] 13. Round out the typed-error tests + concurrency check

   - Add `tests/baseline/test_store_concurrency.py` covering:
     two `BaselineStore` instances against the same directory;
     each loads the same baseline; one saves; the other tries
     to save → `BaselineConcurrentModificationError`; with
     `force=True` the second save succeeds.
   - Add `tests/baseline/test_store_errors.py` collecting the
     edge cases that didn't fit in the per-feature test files:
     unwritable storage path (read-only filesystem mock),
     malformed UTF-8 input, empty file, file with only whitespace.
   - _Requirements: 5.2, 8.7_
   - _Design: Architecture — Save flow; Property 30_

- [x] 14. Add the Hypothesis property-based test suite

   - Author `tests/baseline/test_determinism.py` covering
     Properties 24 + 25 + 26 (save → load round-trip; two saves
     produce byte-identical files modulo `written_at`; load →
     save → load preserves the baseline payload).
   - Author `tests/baseline/test_manifest_invariants.py`
     covering Property 23 (every loaded record passes Pydantic
     re-validation).
   - Strategy generators live in `tests/baseline/conftest.py`,
     building on `synthetic_baseline.build()` with parameterized
     classification count and vendor/model/version triples.
   - Use `strict=False` in `model_validate` calls following the
     extraction-pipeline pattern (datetime strings need to coerce).
   - _Requirements: 9.2, 9.3, 9.4_
   - _Design: Correctness Properties — Properties 23, 24, 25, 26_

- [x] 15. Add the static side-channel audit test

   - Add `tests/baseline/test_no_side_channels.py` mirroring
     `tests/extraction/test_no_side_channels.py`. Walks
     `loki.baseline.__path__`, parses each `.py` with `ast`,
     fails on any forbidden import (`os.environ`, `random`,
     `secrets`, `socket`, `urllib`, `requests`, `httpx`) and
     on `time.time()`/`time.monotonic()` calls outside the
     timing helpers.
   - The persistence subsystem doesn't have a `timing.py`
     analogue; clock access is allowed in `store.py` only
     (specifically the `datetime.now(tz=UTC)` call for
     `written_at`). Encode that exception in the test.
   - _Requirements: 9.5, 9.6_
   - _Design: Property 32_

- [x] 16. Add the no-leakage logging audit

   - Add `tests/baseline/test_log_no_leakage.py` mirroring the
     extraction equivalent: capture every record on
     `loki.baseline` during a curated load + save and assert
     no record's formatted message contains the test fixture's
     `source_image_hash`, any classification record's
     `raw_hash`, or the `notes` string.
   - The handler runs during pipeline init, save, and shutdown
     to cover the "at any time" clause from R10.5.
   - _Requirements: 10.5_
   - _Design: Logging strategy_

- [x] 17. Add the golden-file regression test

   - Build a deterministic baseline via
     `synthetic_baseline.build(...)` with fixed parameters,
     save it to a temp dir, copy the resulting Baseline_File
     to `tests/baseline/fixtures/golden/canonical_v1.yaml`.
   - Save the expected re-loaded payload (timestamp-stripped)
     to `tests/baseline/fixtures/golden/canonical_v1.json`.
   - Add `tests/baseline/test_golden.py` that re-loads the
     golden YAML, strips volatile fields, and compares against
     the JSON snapshot.
   - Document regeneration procedure in
     `tests/baseline/fixtures/README.md` (mirrors
     `tests/extraction/fixtures/README.md`).
   - _Requirements: 9.2, 9.3_
   - _Design: Testing Strategy — Golden-file regression_

- [x] 18. Add the `loki baseline` CLI subcommands

   - Extend `loki/cli.py` with a `baseline` subcommand group
     containing `list`, `show`, `import`, `export`, `delete`.
   - Each subcommand:
     - Constructs a `BaselineStore` from a fallback
       `BaselineConfig` (storage path from `--storage-path`
       flag, defaulting to a sensible local path).
     - Translates typed errors to clean stderr messages with
       non-zero exit codes (mirrors `loki extract`'s
       error-handling approach: 2 for missing baseline_id, 3
       for serialization, 4 for concurrent modification, etc.).
     - For `delete`, supports `--yes` to skip confirmation.
   - Add `tests/test_cli_baseline.py` covering happy + error
     paths for each subcommand. Use an isolated `tmp_path`
     storage directory; do NOT touch the user's real
     baseline directory.
   - _Requirements: 6.1-6.10_
   - _Design: CLI surface_

- [x] 19. Wire the GUI integration

   - Create `loki/gui/actions/open_baseline.py` and
     `save_baseline.py` action modules.
   - Extend `loki/gui/main_window.py`:
     - Construct a `BaselineStore` in `__init__` from a
       fallback `BaselineConfig` (deferred config-file loading
       to a future spec; v1 uses an in-app default storage
       path, e.g. `~/.local/share/loki/baselines`).
     - On startup, run `store.load()` synchronously and
       populate the **Baselines** navigation group with
       `add_baseline()` for each loaded record.
     - If `quarantine` is non-empty, show a
       `QMessageBox.information` listing the count.
     - Wire **View → Open Baseline Registry…** to a file
       picker rooted at `store.storage_path`.
     - Wire **View → Save Baseline…** to call
       `store.save(record)` against the active `BaselineView`
       tab; on `BaselineAlreadyExistsError` prompt to
       overwrite (`force=True`); on
       `BaselineConcurrentModificationError` show an error.
   - Add `tests/gui/test_baseline_actions.py` covering: load
     on startup populates the navigation pane; quarantine
     count is shown; Open menu loads a single baseline
     without persisting it; Save menu writes a baseline and
     adds it to the navigation pane; overwrite confirmation
     dialog; concurrent modification error dialog.
   - _Requirements: 7.1-7.9_
   - _Design: GUI integration_

- [x] 20. Add a performance smoke test

   - Add `tests/baseline/test_performance.py` (marked `slow`,
     skipped on CI by default) that builds 1024 synthetic
     baselines × 256 classifications, saves them all, and
     loads the directory. Assert load duration < 5 s on the
     reference dev laptop (R9.1) and that the loaded registry
     has 1024 entries.
   - _Requirements: 9.1_
   - _Design: Architecture — Load flow_

- [x] 21. README and Status table updates

   - Update the **Status** table in `README.md` to mark the
     baseline-persistence subsystem `DONE — .kiro/specs/baseline-persistence/`
     and `DONE` on implementation.
   - Add a `## Baseline persistence (GLEIPNIR)` section between
     the Extraction pipeline and Development sections,
     describing the on-disk layout, the `loki baseline`
     subcommands, and the GUI integration.
   - Update the **Repository layout** tree to include
     `loki/baseline/` and `tests/baseline/`.
   - Update **Verification at the current checkpoint** with
     the new test count after running the full suite.
   - Update **Next moves** to remove "Baseline persistence" and
     surface the next priority (likely classification or
     decompression).
   - _Requirements: none — pure documentation_
   - _Design: none — pure documentation_

- [x] 22. Final verification gate

   - Run the four checks and confirm green:
     ```bash
     .venv/bin/pytest -q
     .venv/bin/mypy loki tests
     .venv/bin/ruff check loki tests
     .venv/bin/ruff format --check loki tests
     ```
   - Run the slow performance test once locally:
     `.venv/bin/pytest -m slow tests/baseline/test_performance.py`.
   - Run the offscreen GUI smoke check to confirm baseline load
     on startup doesn't break:
     `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`.
   - Document the final test counts in the README (mirroring
     the model + extraction style).
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
      "tasks": ["2", "3", "4", "5", "6", "8"]
    },
    {
      "name": "wave-3-envelope",
      "tasks": ["7"]
    },
    {
      "name": "wave-4-store-core",
      "tasks": ["9"]
    },
    {
      "name": "wave-5-load-and-save",
      "tasks": ["10", "11"]
    },
    {
      "name": "wave-6-store-extras",
      "tasks": ["12", "13"]
    },
    {
      "name": "wave-7-cross-cutting",
      "tasks": ["14", "15", "16", "17", "20"]
    },
    {
      "name": "wave-8-surfaces",
      "tasks": ["18", "19"]
    },
    {
      "name": "wave-9-docs-and-gate",
      "tasks": ["21", "22"]
    }
  ]
}
```

Suggested implementation cadence aligned to the waves:

- **Day 1 — Waves 1–3.** Skeleton, foundations (errors, schema,
  naming, quarantine, concurrency, fixture), envelope. Pure
  utilities, no integration yet.
- **Day 2 — Waves 4–6.** Store constructor, the load + save
  flows, single-file helpers, concurrency tests. The bulk of
  the persistence layer lands here.
- **Day 3 — Waves 7–8.** Cross-cutting tests (PBT, no-side-
  channels, no-leakage, golden file, performance smoke), then
  CLI + GUI integration.
- **Day 4 — Wave 9.** Documentation refresh and final
  verification gate.

Tasks within each wave are independent and can be tackled by
separate sessions if desired. Wave 7 in particular has five
parallel-friendly tasks.

## Notes

- Stick to the design's Module layout exactly. If a new
  responsibility doesn't fit any of the listed modules, raise it
  as an open question rather than inventing a new module on the
  fly.
- The determinism contract (Properties 23–32) is the hardest
  thing to keep correct over time. Whenever you touch
  `naming.py`, `envelope.py`, or `store.py`, re-run
  `tests/baseline/test_determinism.py` and
  `tests/baseline/test_manifest_invariants.py` *together*.
- The CLI's `--storage-path` flag is the test-friendly escape
  hatch. Tests should never touch the user's real baseline
  directory; always pass `--storage-path` pointing at
  `tmp_path`.
- The GUI integration in task 19 runs the load synchronously on
  the main thread (deferred decision §2 in the design). If the
  5-second budget proves disruptive in practice, a future task
  will add a `BaselineLoadWorker` mirroring the
  `ExtractionWorker` from the extraction GUI work.
- v1 ships exactly one Schema_Version. The migration tool is
  out of scope (deferred decision §1). Document this in the
  README's "Next moves" so future maintainers know.
