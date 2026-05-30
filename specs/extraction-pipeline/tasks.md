# Implementation Plan

## Overview

This is the executable task list for the **extraction-pipeline** spec.
Tasks are ordered so that each one builds on previous tasks and leaves
the repo in a verifiable state (every checkpoint passes
`pytest`, `mypy --strict`, `ruff check`, and `ruff format --check`).

Each task lists the exact files it touches, the test surface it adds,
and the design / requirement references it implements. Sub-bullets
under each task are checklist items the implementer ticks off as they
go; they are not separate tasks.

Honest scope reminder: this plan covers extraction only. Classification
of components, baseline comparison, and analysis are explicitly out of
scope and have their own (future) specs.

## Pre-flight checklist

Before starting, confirm the model layer is healthy and the GUI
scaffold still passes:

```bash
.venv/bin/pytest -q
.venv/bin/mypy loki tests
.venv/bin/ruff check loki tests
.venv/bin/ruff format --check loki tests
```

All four must be green. If they are not, fix that first — the
extraction work assumes a clean baseline.

## Tasks

- [x] 1. Add `uefi_firmware` runtime dependency and verify imports

  - Update `pyproject.toml` `[project.dependencies]` to add
    `uefi_firmware>=1.10`.
  - Run `.venv/bin/pip install -e ".[dev]"` and verify
    `.venv/bin/python -c "import uefi_firmware; print(uefi_firmware.__version__)"`
    prints a version string.
  - Confirm `.venv/bin/pytest -q` is still green afterward.
  - _Requirements: 4.2_
  - _Design: Components and Interfaces — Tool wrapper boundary_

- [x] 2. Scaffold the `loki/extraction/` package skeleton

  - Create the empty package layout exactly as documented in the
    design's Module layout: `loki/extraction/__init__.py`,
    `api.py`, `config.py`, `detection.py`, `manifest.py`, `ids.py`,
    `errors.py`, `streaming.py`, `timing.py`, plus the `tools/`
    and `extractors/` subpackages with stub `__init__.py` files.
  - In each new module write only the docstring and the `__all__`
    list. No logic yet.
  - Add `tests/extraction/__init__.py` and an empty
    `tests/extraction/conftest.py` so pytest can collect from the
    new tree.
  - Verify the empty subsystem still imports cleanly:
    `.venv/bin/python -c "import loki.extraction"`.
  - _Requirements: 9.1, 9.5_
  - _Design: Components and Interfaces — Module layout_

- [x] 3. Implement the typed exception hierarchy

  - In `loki/extraction/errors.py` define
    `ExtractionPipelineError`, `InvalidInputError`,
    `ManifestConstructionError`, `ToolWrapperError` (with
    `tool_name`, `status`, `exit_status`, `stderr_excerpt` fields),
    `ToolTimedOutError` (carrying `timeout_seconds`), and
    `ToolFailedError`.
  - Each class is a normal Python `Exception` subclass with typed
    `__init__` (no Pydantic — these are control-flow exceptions,
    not data models).
  - Add `tests/extraction/test_exceptions.py` covering: every class
    is constructible with the documented kwargs; `ToolTimedOutError`
    and `ToolFailedError` are subclasses of `ToolWrapperError`;
    `ToolWrapperError` is a subclass of `ExtractionPipelineError`.
  - Re-export every public exception from `loki.extraction.__init__`.
  - _Requirements: 1.3, 1.4, 4.7, 4.8, 4.9, 6.6_
  - _Design: Components and Interfaces — Exception hierarchy;
    Error Handling_

- [x] 4. Implement deterministic ID derivation

  - In `loki/extraction/ids.py` implement `derive_component_id`
    and `derive_error_component_id` exactly as specified in the
    Determinism contract. Use `loki.models.LOKI_NAMESPACE`.
  - Add `tests/extraction/test_ids.py` covering: same inputs
    produce the same UUID; different inputs produce different
    UUIDs; the offset is rendered as `0x{n:x}` (so `5` and `0x5`
    produce the same ID); both functions accept and validate
    64-character lowercase hex hashes.
  - _Requirements: 7.2, 7.3_
  - _Design: Correctness Properties — Determinism contract —
    implementation; Properties 19, 20_

- [x] 5. Implement the streaming hash and slice utilities

  - In `loki/extraction/streaming.py` implement `StreamingHasher`
    with `CHUNK_SIZE = 1 << 20`, `PEEK_SIZE = 1 << 16`, the
    `hash_file()` method returning `(hash_hex, file_size,
    peek_bytes)`, and the module-level
    `streaming_sha256_slice(path, offset, size)` function.
  - Both functions must read in 1 MiB chunks; verify by calling
    them on a 4 MiB synthetic file under `tmp_path` and asserting
    `peak_resident_increase < 4 MiB` (use `tracemalloc` snapshot
    diff in the test).
  - Add `tests/extraction/test_streaming.py` covering: full-file
    hash matches `hashlib.sha256(file.read_bytes()).hexdigest()`;
    slice hash matches `hashlib.sha256(file.read_bytes()[offset:offset+size]).hexdigest()`;
    peek returns at most `PEEK_SIZE` bytes; the
    chunked-memory invariant above.
  - _Requirements: 1.7, 8.2, 8.3_
  - _Design: Components and Interfaces — Streaming hash and slice
    utilities_

- [x] 6. Implement the timing helper

  - In `loki/extraction/timing.py` implement a `Stopwatch`
    context manager (`time.monotonic`-based) and a
    `global_timeout_budget(timeout_per_component, expected_components)`
    helper that returns `10 * timeout_per_component *
    max(expected_components, 1)` seconds.
  - Provide a `check_global_budget(stopwatch, budget)` predicate.
  - Add `tests/extraction/test_timing.py` covering both helpers.
    Use `time.monotonic` directly in tests, no real sleeping.
  - _Requirements: 5.9, 8.4_
  - _Design: Components and Interfaces — Pipeline flow_

- [x] 7. Implement format detection

  - In `loki/extraction/detection.py` define the `FormatKind`
    StrEnum, the `DetectedFormat` frozen dataclass, the
    `_KNOWN_CAPSULE_GUIDS` frozenset (initial three from the
    design), and the `detect_formats(buf, file_size)` function.
  - Each format detection (Intel IFD, UEFI PI volume,
    UEFI capsule, PCI option ROM, Intel microcode) is a small
    pure-Python helper. They run independently and return their
    matches; the dispatcher composes them with outer-first
    ordering (R2.7).
  - Add `tests/extraction/test_format_detection.py` with hand-
    crafted byte buffers exercising each signature, including
    nested wrappers (an IFD whose BIOS region has a UEFI volume),
    empty buffers, and buffers shorter than 64 KiB.
  - When nothing is recognized, return
    `[DetectedFormat(FormatKind.UNKNOWN, 0, file_size)]` (R2.8).
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.10_
  - _Design: Components and Interfaces — Format detection_

- [x] 8. Implement the tool wrapper base layer

  - In `loki/extraction/tools/base.py` define the `ToolStatus`
    StrEnum, the `ToolWrapper` `Protocol` with the `name`,
    `required`, `probe()`, and `shutdown()` members, and the
    `SubprocessToolWrapper` ABC with the centralized
    `run_subprocess(argv, *, timeout_seconds, scratch_dir)` method
    that enforces `shell=False`, `cwd=scratch_dir`, raises
    `ToolTimedOutError` on `subprocess.TimeoutExpired` and
    `ToolFailedError` on non-zero exit.
  - Add the module-level `_redact(stderr_bytes)` helper per the
    design (≤512 bytes, strip controls, mask scratch paths, mask
    32/64-char hex runs).
  - Add `tests/extraction/test_tool_base.py` covering all three
    subprocess outcomes (success, timeout, failed) by mocking
    `subprocess.run`, plus a test that the
    timeout-then-non-zero case (R4.9) still raises
    `ToolTimedOutError` because `subprocess.TimeoutExpired` is
    raised first (this is stdlib behavior; the test pins it).
  - _Requirements: 4.1, 4.6, 4.7, 4.8, 4.9, 4.10_
  - _Design: Components and Interfaces — Tool wrapper boundary;
    TIMED_OUT vs FAILED precedence; Stderr redaction; Tool I/O
    sandbox_

- [x] 9. Implement the `uefi_firmware` (required) wrapper

  - In `loki/extraction/tools/uefi_firmware.py` implement
    `UefiFirmwareWrapper` with `required = True`. `probe()`
    attempts `import uefi_firmware`, returns `AVAILABLE` on
    success and raises `ExtractionPipelineError` on failure (the
    pipeline cannot run without it). Capture and expose the
    library version via a `version` property.
  - Add `tests/extraction/test_tool_uefi_firmware.py` covering:
    successful probe records the version string; simulated
    `ImportError` raises `ExtractionPipelineError`.
  - _Requirements: 4.2_
  - _Design: Components and Interfaces — Tool wrapper boundary
    (`UefiFirmwareWrapper`)_

- [x] 10. Implement the `UEFITool` and `chipsec` (optional) wrappers

  - In `loki/extraction/tools/uefitool.py` implement
    `UefitoolWrapper(SubprocessToolWrapper)` with
    `required = False`, `probe()` returning `AVAILABLE` if
    `shutil.which("UEFIExtract")` is non-None else `MISSING`.
  - In `loki/extraction/tools/chipsec.py` implement the
    analogous `ChipsecWrapper`.
  - Both wrappers' `probe()` may also capture a version string
    via `--version` if cheap; on failure, fall back to
    `DEGRADED`.
  - Add tests in
    `tests/extraction/test_tool_optional_wrappers.py` covering
    both probe outcomes for each wrapper, mocking
    `shutil.which` and `subprocess.run`.
  - _Requirements: 4.3, 4.4, 4.5_
  - _Design: Components and Interfaces — Tool wrapper boundary
    (optional wrappers)_

- [x] 11. Implement the `ManifestBuilder`

  - In `loki/extraction/manifest.py` implement `ManifestBuilder`
    with `__init__(*, source_image, extractor_version,
    started_at)`, `add_component(carved, *, raw_path)`,
    `record_error(*, error_kind, message, offset,
    component_id=None)`, and `finalize() -> ExtractionManifest`.
  - `add_component` derives `component_id` via `ids.py`,
    computes `raw_hash` via `streaming_sha256_slice`, applies
    the `max_component_size` policy (skip + record error per
    R3.14), and constructs `ExtractedComponent`. Stores the
    list of components and the list of errors in insertion
    order.
  - `record_error` derives a stable `component_id` via
    `derive_error_component_id` when `offset is not None and
    component_id is None`; otherwise leaves `component_id`
    unchanged. Sets `timestamp = datetime.now(tz=UTC)`.
  - `finalize` sorts components by `int(offset, 16)`, asserts
    `component_id` uniqueness (raises
    `ManifestConstructionError` on duplicates), constructs
    `ExtractionManifest`, and converts any
    `pydantic.ValidationError` into
    `ManifestConstructionError`.
  - Add `tests/extraction/test_manifest_builder.py` covering:
    happy path with mixed components and errors; oversized
    components are skipped and produce one error;
    duplicate `component_id` raises
    `ManifestConstructionError`; `finalize` sorts components by
    offset; whole-file errors (offset=None) leave
    `component_id` as None.
  - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.14, 5.2, 5.4, 5.5, 5.6,
    6.1, 6.2, 6.3, 6.5, 6.6_
  - _Design: Components and Interfaces — ManifestBuilder; Data
    Models_

- [x] 12. Implement the extractor base + dispatch

  - In `loki/extraction/extractors/base.py` define the
    `Extractor` `Protocol`, the `CarvedComponent` frozen
    dataclass, and the `ExtractorContext` dataclass (carrying
    `binary_path`, `pipeline_config`, `tools`, and the
    `ManifestBuilder`).
  - Define a `dispatch_for(kind)` helper returning the
    `Extractor` instance for a given `FormatKind`.
  - For tasks 13–17 each new extractor registers itself via
    `dispatch_for`; until then `dispatch_for` raises
    `NotImplementedError`.
  - Add `tests/extraction/test_extractor_base.py` covering the
    dispatcher's lookup behavior with a stub extractor
    registered.
  - _Requirements: 2.9_
  - _Design: Components and Interfaces — Extractor architecture_

- [x] 13. Implement the UEFI PI volume + raw FFS extractors

  - In `loki/extraction/extractors/uefi_volume.py` implement the
    UEFI PI volume Extractor, walking
    `EFI_FIRMWARE_VOLUME_HEADER`, iterating FFS files,
    decomposing sections, decompressing Tiano and LZMA via the
    `uefi_firmware` library, and emitting one `CarvedComponent`
    per FFS file. Handle compressed-section recovery per R5.8 by
    emitting the outer compressed `CarvedComponent` even when
    decompression fails (and recording an `ExtractionError`).
  - In `loki/extraction/extractors/ffs.py` implement the raw FFS
    Extractor by re-using the section walker from
    `uefi_volume.py`.
  - Add `tests/extraction/test_extractor_uefi_volume.py` and
    `tests/extraction/test_extractor_ffs.py`. Use the synthetic
    fixture from task 18 once it lands; in the meantime use a
    minimal hand-crafted FV header byte buffer.
  - _Requirements: 3.1, 3.6, 3.7, 3.8, 3.10, 3.11, 5.7, 5.8_
  - _Design: Components and Interfaces — Extractor architecture
    (`uefi_volume.py`, `ffs.py`)_

- [x] 14. Implement the Intel IFD extractor

  - In `loki/extraction/extractors/ifd.py` implement the IFD
    Extractor: parse the descriptor, emit one `CarvedComponent`
    per region (BIOS, ME, GbE, Platform Data, EC, …), then
    recurse the format detection + extraction over the BIOS
    region's bytes (without re-hashing the full file —
    sub-components reuse the parent file's binary path with
    sliced offsets).
  - Sub-components emit absolute offsets into the original
    binary (R3.6). Verify with a synthetic IFD fixture once
    task 18 lands.
  - Add `tests/extraction/test_extractor_ifd.py` covering the
    region split and the BIOS recursion (mock the inner
    extractor).
  - _Requirements: 3.2, 3.6, 3.7, 3.8, 3.9_
  - _Design: Components and Interfaces — Extractor architecture
    (`ifd.py`)_

- [x] 15. Implement the UEFI capsule extractor

  - In `loki/extraction/extractors/capsule.py` implement the
    capsule Extractor: parse `EFI_CAPSULE_HEADER`, emit one
    `CarvedComponent` for the capsule body, then recurse format
    detection + extraction on the body for embedded UEFI PI
    volumes.
  - Add `tests/extraction/test_extractor_capsule.py`.
  - _Requirements: 3.3, 3.6, 3.7, 3.8, 3.9_
  - _Design: Components and Interfaces — Extractor architecture
    (`capsule.py`)_

- [x] 16. Implement the PCI option ROM extractor

  - In `loki/extraction/extractors/option_rom.py` implement the
    multi-image option ROM Extractor: walk chained PCI Data
    Structures, emit one `CarvedComponent` per code image, set
    `component_type_hint` from the PCI DS `code_type` field
    (legacy x86 = `"PCI_LEGACY_X86"`, EFI = `"PCI_EFI"`,
    Open Firmware = `"PCI_OPENFIRMWARE"`).
  - Add `tests/extraction/test_extractor_option_rom.py` with a
    synthetic two-image option ROM.
  - _Requirements: 3.4, 3.6, 3.7, 3.8, 3.9_
  - _Design: Components and Interfaces — Extractor architecture
    (`option_rom.py`)_

- [x] 17. Implement the Intel microcode extractor

  - In `loki/extraction/extractors/microcode.py` implement the
    microcode Extractor: walk concatenated microcode update
    blobs, emit one `CarvedComponent` per blob with
    `component_type_hint = "INTEL_MICROCODE"` and
    `name = f"CPUID={cpuid:08x} REV={revision:08x}"`.
  - Add `tests/extraction/test_extractor_microcode.py` with a
    synthetic two-blob fixture.
  - _Requirements: 3.5, 3.6, 3.7, 3.8, 3.9_
  - _Design: Components and Interfaces — Extractor architecture
    (`microcode.py`)_

- [x] 18. Author synthetic binary fixtures

  - Create `tests/extraction/fixtures/__init__.py`,
    `tests/extraction/fixtures/synthetic_uefi_volume.py`,
    `tests/extraction/fixtures/synthetic_option_rom.py`, and
    `tests/extraction/fixtures/synthetic_microcode.py`.
  - Each builder is a pure function `build(tmp_path) -> Path`
    that writes a tiny but valid binary and returns the path.
    Builders construct headers from `struct` byte strings; no
    third-party tools are needed at fixture-build time.
  - Wire them into `tests/extraction/conftest.py` as fixtures
    `synthetic_uefi_volume_path`, `synthetic_option_rom_path`,
    `synthetic_microcode_path`.
  - Add `tests/extraction/fixtures/README.md` documenting how a
    real-world binary can be substituted locally without
    committing it (per Testing Strategy — What's deliberately
    not tested).
  - Update tasks 13–17's tests to use the fixtures.
  - _Requirements: 7.5_
  - _Design: Testing Strategy — Unit tests; What's deliberately
    not tested_

- [x] 19. Implement the public `extract_firmware` entry point

  - In `loki/extraction/api.py` implement `extract_firmware`,
    `PipelineConfig`, `ExtractionResult`, and `ProgressEvent`
    exactly as documented in the Components and Interfaces /
    Data Models sections.
  - Pipeline flow per the design:
    1. Resolve and validate path; raise `InvalidInputError`
       on missing, non-regular-file, or zero-size inputs.
    2. Build `PipelineConfig` from the caller's
       `ExtractionConfig`.
    3. Probe required + optional tools, build
       `tools_available` map; required tool absence raises
       `ExtractionPipelineError`; optional tool absence emits
       informational `ExtractionError` records.
    4. `StreamingHasher.hash_file()` → build `FirmwareImage`.
    5. `detect_formats()` over peek bytes.
    6. For each detected format (outermost first), dispatch to
       the corresponding `Extractor`; convert each
       `CarvedComponent` via `ManifestBuilder.add_component`;
       call `cancel()` between components; emit progress
       events.
    7. Apply the global timeout budget per R5.9.
    8. `ManifestBuilder.finalize()` → return
       `ExtractionResult`.
  - Re-export `extract_firmware`, `ExtractionResult`,
    `PipelineConfig`, and the public exceptions from
    `loki.extraction.__init__`.
  - Add `tests/extraction/test_api_contract.py` covering: the
    exact public signature; `InvalidInputError` for missing /
    non-regular / empty paths; the cancellation token short-
    circuits between components and yields a partial manifest;
    the progress callback is invoked with the documented
    phases and runs on the calling thread.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9,
    1.10, 5.1, 5.9, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_
  - _Design: Components and Interfaces — Module layout; Entry
    point signature; Pipeline flow; Logging strategy_

- [x] 20. Wire structured logging

  - Throughout `loki.extraction.*`, obtain loggers via
    `logging.getLogger(f"loki.extraction.{__name__}")`.
  - Emit the four documented INFO / WARNING / ERROR records
    (run-start, format-detected, error-mirror, run-finished)
    per the Logging strategy section.
  - Add `tests/extraction/test_log_no_leakage.py` per the
    Testing Strategy. Use a captured-handler fixture in
    `tests/extraction/conftest.py` that records every
    `LogRecord` emitted on `loki.extraction` during a curated
    extraction (synthetic UEFI volume from task 18). Assert
    that no record's formatted `message` contains substrings
    of the input file beyond the leading 16 hex chars, no UI
    section names from the manifest, no decompressed payloads,
    and that the same checks pass during pipeline import,
    probe, finalize, and shutdown — covering R10.5's "at any
    time" clause.
  - _Requirements: 9.6, 10.1, 10.2, 10.3, 10.4, 10.5_
  - _Design: Logging strategy_

- [x] 21. Add the static side-channel audit test

  - Add `tests/extraction/test_no_side_channels.py` that walks
    `loki.extraction.__path__`, parses each `.py` with `ast`,
    and fails on any `Import` / `ImportFrom` of `os.environ`,
    `random`, `secrets`, `socket`, `urllib`, `requests`,
    `httpx`, or any direct `time.time()` /
    `datetime.now(...)` call outside `loki/extraction/timing.py`
    (which is the single permitted clock-using module).
  - The test runs once; failures pinpoint the file and line of
    the offending import / call.
  - _Requirements: 7.5_
  - _Design: Correctness Properties — Property 22; No side
    channels_

- [x] 22. Add the Hypothesis property-based test suite

  - Author `tests/extraction/test_determinism.py` covering
    Properties 18–21:
    - Property 18: same input + same config produces equal
      manifests under `model_dump()` after stripping
      timestamps. Strategy: the synthetic-binary fixtures from
      task 18 with parameterized component counts.
    - Property 19: emitted `component_id` equals
      `derive_component_id(...)` for every component.
    - Property 20: emitted error `component_id` equals
      `derive_error_component_id(...)` for every per-
      component error.
    - Property 21: every written output filename equals
      `f"0x{offset:x}-{raw_hash}.bin"`.
  - Author `tests/extraction/test_manifest_invariants.py`
    covering Properties 12–17:
    - Property 12: every returned `ExtractionResult.manifest`
      passes Pydantic validation. (Re-construct via
      `ExtractionManifest.model_validate(manifest.model_dump(mode="json"))`.)
    - Property 13: `total_components == len(components)`.
    - Property 14: `component_id` uniqueness.
    - Property 15: components ordered by ascending integer
      offset.
    - Property 16: JSON round-trip.
    - Property 17: YAML round-trip.
  - Strategy generators live in
    `tests/extraction/conftest.py`, building on the synthetic-
    binary fixtures and parameterizing component count, error
    injection, and oversize-component injection.
  - _Requirements: 6.1, 6.2, 6.3, 6.5, 6.7, 7.1, 7.2, 7.3, 7.4,
    7.6_
  - _Design: Correctness Properties — Properties 12–22;
    Testing Strategy — Property-based tests_

- [x] 23. Add a golden-file regression test

  - Generate a tiny (~32 KiB) UEFI PI volume binary from
    `tests/extraction/fixtures/synthetic_uefi_volume.py`,
    commit it under
    `tests/extraction/fixtures/golden/uefi_volume_v1.bin`,
    and commit its expected manifest snapshot at
    `tests/extraction/fixtures/golden/uefi_volume_v1.json`.
  - Snapshot is `manifest.model_dump(mode="json")` with
    timestamp fields nulled out.
  - Add `tests/extraction/test_golden.py` that runs
    `extract_firmware` on the golden binary and compares the
    timestamp-stripped JSON dump against the committed snapshot.
  - Document in `tests/extraction/fixtures/README.md` how to
    regenerate the snapshot when the manifest shape changes
    (intentional rev: bump the fixture filename to `_v2.bin`,
    don't overwrite history).
  - _Requirements: 6.7_
  - _Design: Testing Strategy — Golden-file tests_

- [x] 24. Add the performance smoke test

  - Add `tests/extraction/test_performance.py` (skipped on CI by
    default via a `@pytest.mark.slow` marker, runnable locally
    with `pytest -m slow`) that builds a 64 MiB synthetic UEFI
    volume from the fixture builder, runs `extract_firmware`,
    and asserts:
    - `tracemalloc` peak resident increase ≤
      `4 × max_component_size + 128 MiB`.
    - Wall-clock duration ≤ a generous bound (e.g. 60 s on the
      reference dev laptop).
  - Add `slow` to `tool.pytest.ini_options.markers` in
    `pyproject.toml` so the marker is recognized.
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  - _Design: Components and Interfaces — Streaming hash and
    slice utilities (memory budget paragraph)_

- [x] 25. Update `loki/cli.py` with the `loki extract` subcommand

  - Add an `extract` subcommand to `loki/cli.py` that takes a
    positional `path` argument and optional `--output-dir`,
    `--max-component-size`, `--timeout-per-component` flags
    mapping to `ExtractionConfig`. Defaults come from a
    minimal in-CLI fallback `ExtractionConfig`; loading from a
    YAML file is a future task.
  - On success, the subcommand prints
    `manifest.model_dump_json(indent=2)` to stdout and
    `tools_available` + `duration_seconds` to stderr.
  - `InvalidInputError` and `ManifestConstructionError` are
    caught and translated to non-zero exit codes with a clean
    one-line message on stderr (no Python traceback).
  - Add `tests/test_cli_extract.py` covering: happy path on the
    golden fixture binary; missing path produces exit code != 0
    and a clean error message; `--help` for the subcommand.
  - This task does NOT introduce a separate CLI spec — the
    extraction CLI surface is part of the extraction subsystem;
    a future CLI spec will cover non-extraction subcommands.
  - _Requirements: 9.1, 9.7_
  - _Design: Overview — pipeline consumers; Components and
    Interfaces — Module layout (CLI uses public entry point)_

- [x] 26. Wire the GUI's extraction tab to real extraction

  - In `loki/gui/views/extraction_view.py`, replace the
    placeholder with a read-only widget that takes an
    `ExtractionManifest` and renders: source-image header,
    component table (offset, size, hash short prefix, name,
    GUID), and an errors panel. Keep the placeholder as the
    initial state of the widget until a manifest is set.
  - In `loki/gui/main_window.py`, add a `View →
    Extract Firmware Components…` menu action that runs
    `extract_firmware` synchronously on the currently selected
    `FirmwareImage` (looking up the file path from the
    `FirmwareImageView` instance). The action blocks the UI;
    that's acceptable for v1 per R8.5.
  - On success, push the manifest into a new
    `ExtractionView` tab labeled with the source file basename.
  - On `InvalidInputError` or `ManifestConstructionError`,
    show the error in a `QMessageBox` and do not open a tab.
  - Update `tests/gui/test_main_window.py` (or add a new
    `tests/gui/test_extraction_view.py`) covering: menu action
    becomes enabled when an image is selected; running
    extraction on the golden fixture from task 23 produces an
    `ExtractionView` tab; an invalid path produces the
    expected `QMessageBox`.
  - _Requirements: 9.5_ (the GUI imports from `loki.extraction`,
    not the other way around)
  - _Design: Overview — pipeline consumers_

- [x] 27. README and HANDOFF updates

  - Update the **Status** table in `README.md` to mark the
    extraction pipeline `DONE — specs/extraction-pipeline/`
    on the spec column and `DONE` (or partial) on the
    implementation column, with a link to the new
    `loki.extraction` module.
  - Add an `## Extraction pipeline` section between the GUI
    section and the Development section, describing the public
    entry point, the `loki extract` CLI subcommand, the
    `View → Extract Firmware Components…` GUI action, and the
    determinism contract caveats from the design's Open
    questions section.
  - Update the **Repository layout** tree to include
    `loki/extraction/` and `tests/extraction/`.
  - Update **Verification at the current checkpoint** with the
    new test count and source file count after running
    `pytest`, `mypy`, and `ruff`.
  - Update **Next moves** to remove "Extraction pipeline" and
    surface the next priority (likely "Baseline persistence"
    or "Classification pipeline").
  - Move `HANDOFF.md` to `HANDOFF.archive.md` (or delete it,
    user's call); the build it described is now landed.
  - _Requirements: none — pure documentation_
  - _Design: Overview; Goals and non-goals_

- [x] 28. Final verification gate

  - Run all four checks and confirm they're green:
    ```bash
    .venv/bin/pytest -q
    .venv/bin/mypy loki tests
    .venv/bin/ruff check loki tests
    .venv/bin/ruff format --check loki tests
    ```
  - Run the slow performance test once locally:
    `.venv/bin/pytest -m slow tests/extraction/test_performance.py`.
  - Run the offscreen GUI smoke check:
    `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`.
  - Document the final test counts in the README (mirroring
    the model layer's "70 tests pass" style).
  - _Requirements: all_
  - _Design: all_

## Task Dependency Graph

The dependency graph organizes tasks into waves. All tasks in a wave
can be executed in parallel; each wave waits for the previous one.

```json
{
  "waves": [
    {
      "name": "wave-1-dependency",
      "tasks": ["1"]
    },
    {
      "name": "wave-2-skeleton",
      "tasks": ["2"]
    },
    {
      "name": "wave-3-foundations",
      "tasks": ["3", "4", "5", "6", "7", "18"]
    },
    {
      "name": "wave-4-tool-boundary",
      "tasks": ["8"]
    },
    {
      "name": "wave-5-tools-and-builder",
      "tasks": ["9", "10", "11", "12"]
    },
    {
      "name": "wave-6-extractors",
      "tasks": ["13", "14", "15", "16", "17"]
    },
    {
      "name": "wave-7-public-entry-point",
      "tasks": ["19"]
    },
    {
      "name": "wave-8-cross-cutting",
      "tasks": ["20", "21", "22", "23", "24"]
    },
    {
      "name": "wave-9-surfaces",
      "tasks": ["25", "26"]
    },
    {
      "name": "wave-10-docs-and-gate",
      "tasks": ["27", "28"]
    }
  ]
}
```

Suggested implementation cadence aligned to the waves:

- **Day 1 — Waves 1–3.** Dependency, scaffold, and pure-utility
  modules (`errors`, `ids`, `streaming`, `timing`, `detection`,
  synthetic fixtures). Repo gains typed scaffolding and pure
  utilities, no integration yet.
- **Day 2 — Waves 4–5.** Tool boundary plus the manifest builder
  and extractor base. Detection and the entire tool boundary
  finished.
- **Day 3 — Wave 6.** Extractors. Tasks 16 and 17 have no
  inter-task dependencies inside the wave and can be done by
  separate sessions in parallel.
- **Day 4 — Waves 7–8.** Public entry point and the cross-cutting
  test layer (logging hygiene, no-side-channels audit, PBT,
  golden file, performance smoke).
- **Day 5 — Waves 9–10.** CLI and GUI surfaces, then the
  documentation refresh and final verification gate.

## Notes

- Stick to the design's Module layout exactly. If a new
  responsibility doesn't fit any of the listed modules, raise it as
  an open question rather than inventing a new module on the fly —
  that's a sign the design needs an update first.
- The determinism contract (Properties 18–22) is the single
  hardest thing to keep correct over time. Whenever you touch
  `ids.py`, `streaming.py`, `manifest.py`, or any extractor's
  output ordering, re-run `tests/extraction/test_determinism.py`
  and `tests/extraction/test_manifest_invariants.py` *together* —
  not just individually.
- The required `uefi_firmware` library has known quirks
  (deprecated `print_tree` etc.) that may surface as
  `DeprecationWarning`s. The project's `filterwarnings = ["error"]`
  pytest config will fail on those. Either upgrade the pin or
  add a narrow `filterwarnings("ignore", category=DeprecationWarning,
  module="uefi_firmware.*")` in `tests/extraction/conftest.py` —
  document whichever choice in the conftest comment.
- Tasks 13–17 each contain enough stand-alone work to be a half-
  day session. Resist the temptation to merge them; small commits
  with green tests are easier to review than one extractor megacommit.
