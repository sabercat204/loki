# Requirements Document

## Introduction

Baseline Persistence (codenamed GLEIPNIR) is the LOKI subsystem that
moves `BaselineRecord` and `BaselineRegistry` instances between memory
and a YAML directory layout on disk. It is the bridge that lets the
GUI's Baselines navigation group, the `loki baseline` CLI subcommands,
and downstream comparison code load real, curated baselines instead of
the synthetic data the GUI currently surfaces.

This spec covers persistence only:

- The on-disk file layout, file naming, and schema versioning of
  baseline files.
- Loading: discovery, schema-version checks, validation, and
  registry construction at startup.
- Saving: atomic writes, schema-version tagging, and deterministic
  file output.
- Concurrency: behaviour when two LOKI processes touch the same
  baseline directory.
- The `loki baseline` CLI surface (`list`, `show`, `import`,
  `export`, `delete`).
- GUI integration (the **Baselines** navigation group, **View →
  Open Baseline Registry**, **View → Save Baseline**, automatic
  load on startup).
- Error semantics: malformed YAML, schema-version mismatch, missing
  required fields, unparseable UUIDs, etc.
- Determinism, round-trip, performance bounds, and observability.

It does **not** cover:

- The `BaselineComparison` subsystem (deviation scoring,
  `DeviationRecord` generation). That's downstream and out of scope.
- The classification pipeline that produces the
  `ClassificationRecord` instances inside
  `BaselineRecord.component_manifest`. That's a separate, not-yet-
  specced subsystem.
- Wiring baselines to live extraction runs. The extraction pipeline
  is in scope only insofar as a saved baseline references its source
  firmware via `source_image_hash`; a `BaselineRecord` can be
  imported from an `ExtractionManifest` plus a (yet-to-be-built)
  classification step, but this spec does not orchestrate that.
- Defining new configuration. `BaselineConfig.storage_path` and
  `BaselineConfig.auto_match` already exist in
  `loki/models/config.py`; the persistence layer reads them but
  does not extend them.

The shape and quality bar mirror `extraction-pipeline/requirements.md`
but the surface is genuinely smaller, because the model layer
(`loki/models/baseline.py`) already defines what a baseline *is*. This
spec only defines storage, retrieval, and lifecycle.

## Glossary

- **Baseline_Store**: The subsystem specified by this document. The
  single object responsible for reading and writing
  `BaselineRecord` instances and `BaselineRegistry` instances to
  and from a directory on disk.
- **Storage_Directory**: The directory referred to by
  `BaselineConfig.storage_path`. The Baseline_Store owns this
  directory's contents but does not delete files it did not create.
- **Baseline_File**: A single YAML file under the Storage_Directory
  that contains exactly one serialized `BaselineRecord` plus a
  Baseline_Store envelope (schema_version, written_at,
  written_by_extractor_version). One file per baseline.
- **Baseline_Filename**: The name of a Baseline_File, of the form
  `{slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml`,
  where `slug()` produces a `[a-z0-9._-]+` string from a free-form
  `BaselineRecord` field.
- **Schema_Version**: The on-disk file-format version of a
  Baseline_File, distinct from the per-baseline semantic version
  carried by `BaselineRecord.baseline_version`. Schema_Version is
  set by the Baseline_Store; `baseline_version` is set by the
  user.
- **Atomic_Write**: A write whose visible result on disk is either
  the new file fully present or the previous file unchanged. The
  Baseline_Store implements Atomic_Write by serializing to a
  sibling temp file under the Storage_Directory, calling `fsync`,
  and renaming over the destination.
- **Discovery_Scan**: The startup-time operation that enumerates
  every `*.yaml` file directly inside the Storage_Directory and
  attempts to load each into a `BaselineRecord`.
- **Quarantine_Set**: The list of Baseline_Files that
  Discovery_Scan found but rejected (malformed YAML, schema
  mismatch, validation failure). Quarantined files are reported
  to the caller but never deleted.
- **Baseline_Identifier**: For logging and CLI output, the tuple
  `(baseline_id, vendor, model, firmware_version)`. The
  Baseline_Store identifies baselines by this tuple in messages
  and never logs `component_manifest` contents.
- **Out_Of_Scope_Operation**: Anything beyond persistence and
  lifecycle — comparison, classification, deviation scoring,
  multi-host synchronization. Explicitly deferred.

## Requirements

### Requirement 1: Storage layout and file naming

**User Story:** As a baseline curator, I want one human-readable
YAML file per baseline so that I can review individual baselines in
git diffs and edit one without touching the rest.

#### Acceptance Criteria

1. THE Baseline_Store SHALL store each `BaselineRecord` in its own
   Baseline_File directly inside the Storage_Directory, with no
   subdirectories.
2. THE Baseline_Store SHALL name each Baseline_File using the
   Baseline_Filename format
   `{slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml`,
   where `slug()` lower-cases the input, replaces every character
   outside `[a-z0-9._-]` with `_`, and collapses consecutive `_`
   into a single `_`.
3. WHEN two `BaselineRecord` instances would produce the same
   Baseline_Filename after slugification, THE Baseline_Store SHALL
   append `-{first 8 hex chars of baseline_id}` to the second file
   so that filenames remain unique without losing the canonical
   form for the first.
4. THE Baseline_Store SHALL attempt to deserialize every file
   under the Storage_Directory whose name ends in `.yaml` (the
   "Discovery_Scan target set"); THE Baseline_Store SHALL treat
   every other file under the Storage_Directory as foreign, SHALL
   ignore it during Discovery_Scan, and SHALL never delete or
   modify it.
5. THE Baseline_Store SHALL NOT create, read, or write any file
   outside the Storage_Directory during normal operation.
6. WHEN the Storage_Directory does not exist at the time the
   Baseline_Store is constructed, THE Baseline_Store SHALL create
   the directory with mode `0o755` before performing any read or
   write.
7. THE Baseline_Store SHALL store every Baseline_File on disk in
   UTF-8 with a trailing newline.

### Requirement 2: Loading — Discovery_Scan and validation

**User Story:** As a GUI user or CLI user, I want the Baseline_Store
to load every baseline in the Storage_Directory at startup and
report which files it could not load, so that one bad file never
hides the rest.

#### Acceptance Criteria

1. THE Baseline_Store SHALL expose a single load entry point that
   accepts a `BaselineConfig` and returns a `BaselineRegistry`
   together with a Quarantine_Set.
2. WHEN the load entry point is called, THE Baseline_Store SHALL
   perform a Discovery_Scan over the Storage_Directory and SHALL
   attempt to deserialize every `*.yaml` file directly inside it.
3. THE Baseline_Store SHALL deserialize each Baseline_File by
   parsing it with `yaml.safe_load`, extracting the embedded
   `BaselineRecord` payload from the Baseline_Store envelope, and
   constructing a `BaselineRecord` via Pydantic strict validation.
4. THE Baseline_Store SHALL include in the returned
   `BaselineRegistry` exactly those `BaselineRecord` instances for
   which deserialization, schema-version check, and Pydantic
   validation all succeeded.
5. IF the Storage_Directory does not exist at load time and cannot
   be created (per Requirement 1.6), THEN THE Baseline_Store SHALL
   raise a typed error that names the offending path and SHALL NOT
   return a partial `BaselineRegistry`.
6. WHEN the Storage_Directory exists but is empty, THE
   Baseline_Store SHALL return a `BaselineRegistry` with
   `baselines == []` and an empty Quarantine_Set.
7. WHEN two successfully loaded `BaselineRecord` instances share
   the same `baseline_id`, THE Baseline_Store SHALL include only
   the first one encountered in lexicographic Baseline_Filename
   order in the returned `BaselineRegistry` and SHALL place the
   later one in the Quarantine_Set with reason
   `"duplicate baseline_id"`.
8. WHERE the caller passes an optional progress callback to the
   load entry point (a callable accepting a structured
   `LoadProgressEvent` carrying the file path being processed,
   the 1-based file index, and the total candidate count), THE
   Baseline_Store SHALL invoke the callback exactly once before
   parsing each Baseline_File, on the calling thread, and SHALL
   NOT invoke the callback for files filtered out by the
   Discovery_Scan's extension check (Requirement 1.4).
9. WHERE the caller passes an optional cancellation token to the
   load entry point (a callable returning `bool`), THE
   Baseline_Store SHALL check the token between Baseline_Files
   in the Discovery_Scan loop and, when the token returns
   `True`, SHALL stop further parsing, SHALL emit no further
   progress callbacks, and SHALL return a `LoadResult` whose
   `BaselineRegistry` contains only the records parsed before
   cancellation and whose `QuarantineSet` contains only entries
   recorded before cancellation.
10. THE optional progress and cancellation callbacks from
    acceptance criteria 2.8 and 2.9 SHALL NOT, when omitted,
    change the `LoadResult` produced by the load entry point;
    a load with `progress=None` and `cancel=None` SHALL produce
    a `LoadResult` byte-equal under `model_dump(mode="json")` to
    a load with stub callbacks that record events but do not
    request cancellation.

### Requirement 3: Saving — Atomic_Write and schema tagging

**User Story:** As a baseline curator, I want saves to be atomic
and tagged with the file format version, so that a crash mid-write
never corrupts an existing baseline and so that future tooling can
recognize older files.

#### Acceptance Criteria

1. THE Baseline_Store SHALL expose a save entry point that accepts
   a single `BaselineRecord` and writes it to its computed
   Baseline_Filename inside the Storage_Directory using
   Atomic_Write.
2. THE Baseline_Store SHALL implement Atomic_Write by serializing
   the payload to a sibling temp file
   `{Baseline_Filename}.{8 hex chars}.tmp` in the same
   Storage_Directory, calling `os.fsync` on its file descriptor,
   and then `os.replace`-ing the temp file over the destination.
3. WHEN Atomic_Write fails before the `os.replace` step, THE
   Baseline_Store SHALL remove the temp file and SHALL leave any
   existing destination file untouched.
4. THE Baseline_Store SHALL embed the Baseline_Store envelope at
   the top level of every written Baseline_File with the keys
   `schema_version` (string), `written_at` (UTC ISO-8601
   timestamp), and `written_by_extractor_version` (string) and
   the key `baseline` containing the serialized `BaselineRecord`.
5. THE Baseline_Store SHALL set `schema_version` on every written
   Baseline_File to the Baseline_Store's current Schema_Version
   string in `^\d+\.\d+\.\d+$` form.
6. THE Baseline_Store SHALL serialize the `BaselineRecord` payload
   via `BaselineRecord.model_dump(mode="json")` so that
   `datetime`, `UUID`, and Pydantic-validated string fields
   round-trip through `yaml.safe_load`.
7. THE Baseline_Store SHALL emit YAML using `yaml.safe_dump` with
   `sort_keys=True`, `default_flow_style=False`, and
   `allow_unicode=True`, so that two saves of the same
   `BaselineRecord` produce byte-identical files.
8. WHEN the save entry point is called with a `BaselineRecord`
   whose `component_manifest` contains records that fail
   Pydantic strict validation on round-trip, THE Baseline_Store
   SHALL raise a typed error before writing anything to disk.
9. THE Baseline_Store SHALL perform the save entry point's
   complete sequence — round-trip validation (acceptance
   criterion 3.8), envelope construction (acceptance criterion
   3.4), Schema_Version tagging (acceptance criterion 3.5),
   YAML serialization (acceptance criteria 3.6 and 3.7), and
   Atomic_Write (acceptance criteria 3.1 through 3.3) — as a
   single transaction; the Baseline_Store SHALL NOT expose any
   partial-save mode that omits any of these steps.

### Requirement 4: Schema versioning and migration

**User Story:** As a future maintainer, I want the on-disk file
format to carry an explicit Schema_Version distinct from
`baseline_version`, so that I can evolve the format without
silently breaking older Baseline_Files.

#### Acceptance Criteria

1. THE Baseline_Store SHALL define exactly one current
   Schema_Version string, in `^\d+\.\d+\.\d+$` form, and SHALL
   write that string into every saved Baseline_File per
   Requirement 3.5.
2. THE Baseline_Store SHALL define exactly one set of supported
   Schema_Version strings (the current version plus any explicitly
   migratable older versions). v1 of this subsystem SHALL list
   exactly one supported Schema_Version: the current one.
3. WHEN a loaded Baseline_File's `schema_version` matches the
   current Schema_Version, THE Baseline_Store SHALL deserialize
   the embedded baseline payload directly.
4. IF a loaded Baseline_File's `schema_version` is missing, is not
   a string, or does not match the current Schema_Version, THEN
   THE Baseline_Store SHALL place the file in the Quarantine_Set
   with reason `"unsupported schema_version: {value}"` and SHALL
   NOT attempt to deserialize the embedded payload.
5. THE Baseline_Store SHALL never modify a Baseline_File on disk
   solely as a side effect of loading it (no auto-upgrade in v1);
   migrations SHALL be performed only by an explicit operation
   covered in a future spec.
6. THE Baseline_Store SHALL document the current Schema_Version
   string in `loki/baseline/schema.py` as a module-level constant
   so that tests and CLI subcommands import the same value.

### Requirement 5: Concurrency and external mutation

**User Story:** As a user running two LOKI processes against the
same Storage_Directory, I want the Baseline_Store to refuse to
silently overwrite changes made by another process, so that I lose
no work and never see merged-but-corrupt YAML.

#### Acceptance Criteria

1. THE Baseline_Store SHALL detect external mutation of a
   destination Baseline_File by recording the file's `st_mtime_ns`
   and `st_size` at load time and re-checking them immediately
   before performing the `os.replace` step of Atomic_Write.
2. IF the destination Baseline_File's `st_mtime_ns` or `st_size`
   has changed since the in-memory `BaselineRecord` was loaded,
   THEN THE Baseline_Store SHALL raise a typed
   `BaselineConcurrentModificationError` that carries the path,
   the recorded `(mtime_ns, size)`, and the observed
   `(mtime_ns, size)`, and SHALL NOT perform the replace.
3. WHEN the save entry point is called for a `BaselineRecord` that
   the Baseline_Store has not previously loaded from disk, THE
   Baseline_Store SHALL treat the file as new and SHALL refuse
   to overwrite an existing Baseline_File at the same path,
   raising a typed
   `BaselineAlreadyExistsError` that carries the path.
4. WHERE the caller wishes to overwrite an existing Baseline_File
   without having loaded it first, THE Baseline_Store SHALL
   accept a `force=True` argument on the save entry point that
   skips the existence check from acceptance criterion 5.3 and
   the mtime check from acceptance criterion 5.2.
5. THE Baseline_Store SHALL NOT, in v1, acquire any inter-process
   lock file or POSIX advisory lock; concurrency safety is
   provided by Atomic_Write plus the mtime/size check in
   acceptance criteria 5.1 and 5.2 (last-writer-wins is rejected
   when detected; not avoided by mutual exclusion).
6. THE Baseline_Store SHALL document its concurrency contract in
   `loki/baseline/__init__.py`: single-host, multi-process safe
   for non-overlapping baselines, and explicit-error on
   overlapping concurrent writes.

### Requirement 6: CLI surface (`loki baseline ...`)

**User Story:** As a CLI user, I want `loki baseline list`,
`loki baseline show`, `loki baseline import`, `loki baseline
export`, and `loki baseline delete` so that I can curate
baselines from the shell without launching the GUI.

#### Acceptance Criteria

1. THE Baseline_Store SHALL be invoked from the CLI through a
   single `loki baseline` subcommand group with exactly five v1
   subcommands: `list`, `show`, `import`, `export`, `delete`.
2. WHEN `loki baseline list` is invoked, THE CLI SHALL load the
   Storage_Directory via the load entry point and SHALL print
   one line per baseline with columns `baseline_id`, `vendor`,
   `model`, `firmware_version`, `baseline_version`,
   `created_timestamp`, ordered by `(vendor, model,
   firmware_version)`.
3. WHEN `loki baseline list` is invoked and one or more files
   fall into the Quarantine_Set, THE CLI SHALL print a trailing
   `quarantined: N` summary line to stderr and SHALL exit with
   status `0` if at least one baseline loaded successfully and
   the Quarantine_Set is non-empty.
4. WHEN `loki baseline show {baseline_id}` is invoked, THE CLI
   SHALL print the matching baseline as JSON via
   `BaselineRecord.model_dump_json(indent=2)` to stdout and
   SHALL exit `0`.
5. IF `loki baseline show` is invoked with a `baseline_id` that
   does not match any loaded baseline, THEN THE CLI SHALL exit
   with status `2` and SHALL print
   `baseline not found: {baseline_id}` to stderr.
6. WHEN `loki baseline import {path}` is invoked with a path to
   a YAML file, THE CLI SHALL load that single file via the
   Baseline_Store's single-file deserializer, SHALL save it into
   the Storage_Directory via the save entry point, and SHALL
   print the resulting Baseline_Filename to stdout.
7. WHEN `loki baseline export {baseline_id} {dest}` is invoked,
   THE CLI SHALL look up the matching `BaselineRecord` in the
   loaded `BaselineRegistry`, SHALL write a Baseline_File to
   `{dest}` using the same envelope and Atomic_Write contract
   as the save entry point, and SHALL exit `0`.
8. WHEN `loki baseline delete {baseline_id}` is invoked, THE
   CLI SHALL look up the matching `BaselineRecord`, SHALL prompt
   the user for confirmation `Delete {baseline_id}? [y/N]`, and
   SHALL remove the corresponding Baseline_File on `y` and SHALL
   exit `0` without removing anything on any other input.
9. WHERE the caller passes `--yes` to `loki baseline delete`,
   THE CLI SHALL skip the confirmation prompt and SHALL proceed
   with deletion.
10. THE CLI SHALL log activity through Python's standard
    `logging` module under the logger name `loki.baseline`.

### Requirement 7: GUI integration

**User Story:** As a GUI user, I want the Baselines navigation
group to show real baselines loaded from disk on startup, and I
want menu actions to open and save baseline files, so that the
GUI surfaces persisted state instead of demo data.

#### Acceptance Criteria

1. WHEN the GUI's main window is constructed, THE GUI SHALL
   invoke the Baseline_Store's load entry point with the
   `BaselineConfig` from the active `LokiConfig` and SHALL
   populate the **Baselines** navigation group with one entry
   per successfully loaded `BaselineRecord`.
2. WHILE the GUI is loading the Storage_Directory at startup,
   THE GUI SHALL display the status-bar message
   `Loading baselines from {storage_path}…` and SHALL NOT
   block menu input on a Storage_Directory of up to 1024
   baselines (Requirement 9.1's bound).
3. WHERE the load entry point returns a non-empty
   Quarantine_Set at startup, THE GUI SHALL show a
   non-blocking notification listing the count of quarantined
   files and SHALL log the per-file reasons under the logger
   `loki.gui.baselines`.
4. THE GUI SHALL expose **View → Open Baseline Registry…** that
   opens a file-system picker rooted at the current
   Storage_Directory, lets the user pick one Baseline_File, and
   loads it via the Baseline_Store's single-file deserializer
   without modifying the Storage_Directory.
5. THE GUI SHALL expose **View → Save Baseline…** that, when a
   `BaselineRecord` is the active selection in the workspace,
   invokes the Baseline_Store's save entry point and adds (or
   refreshes) the corresponding **Baselines** navigation entry.
6. WHERE the save attempt raises
   `BaselineAlreadyExistsError`, THE GUI SHALL show a
   confirmation dialog `Overwrite existing baseline at {path}?`
   and SHALL retry with `force=True` on confirmation.
7. WHERE the save attempt raises
   `BaselineConcurrentModificationError`, THE GUI SHALL show
   an error dialog naming the path and SHALL NOT retry
   automatically.
8. THE GUI SHALL never display the contents of
   `BaselineRecord.component_manifest` in the navigation pane;
   the navigation entry label SHALL be
   `{vendor} {model} {firmware_version}`.
9. THE GUI's existing demo-data builder SHALL continue to work
   without writing any Baseline_File to the Storage_Directory;
   demo-loaded baselines SHALL appear in the **Baselines**
   group with the `(demo)` suffix already used elsewhere in the
   GUI.
10. WHILE the `BaselineLoadWorker` is running, THE GUI SHALL
    update the status bar with a per-file progress message of
    the form
    `Loading baselines… {index}/{total} ({basename})` driven by
    the optional progress callback contracted in Requirement
    2.8; the message SHALL update on the main thread via a Qt
    signal emitted by the worker.
11. THE GUI SHALL expose a cancellation affordance for the
    background baseline load that, when activated, SHALL set
    the cancellation token contracted in Requirement 2.9 to
    `True` and cause the worker to return the partial
    `LoadResult` accumulated up to the cancellation point; the
    GUI SHALL surface the partial result in the **Baselines**
    navigation group with no error dialog and SHALL log the
    cancellation under the `loki.gui.baselines` logger.

### Requirement 8: Error handling and typed exceptions

**User Story:** As a caller of the Baseline_Store (CLI, GUI,
tests), I want every failure mode mapped to a specific typed
exception so that I can render the right error and recover where
recovery is possible.

#### Acceptance Criteria

1. THE Baseline_Store SHALL expose a typed exception hierarchy
   rooted at `BaselineStoreError` (subclass of `Exception`) and
   SHALL raise only subclasses of `BaselineStoreError` from its
   public entry points.
2. IF a Baseline_File cannot be parsed by `yaml.safe_load`, THEN
   the file SHALL be placed in the Quarantine_Set with reason
   `"malformed yaml: {message}"` and the load entry point SHALL
   NOT raise.
3. IF a parsed Baseline_File is missing the top-level
   `schema_version`, `written_at`, `written_by_extractor_version`,
   or `baseline` key, THEN the file SHALL be placed in the
   Quarantine_Set with reason
   `"missing required envelope key: {key}"` and the load entry
   point SHALL NOT raise.
4. IF a parsed Baseline_File's embedded baseline payload fails
   Pydantic strict validation, THEN the file SHALL be placed in
   the Quarantine_Set with reason
   `"validation failed: {pydantic error summary}"` and the load
   entry point SHALL NOT raise.
5. IF a Baseline_File contains a `baseline_id` that is not a
   valid UUID string, THEN the file SHALL be placed in the
   Quarantine_Set with reason `"invalid baseline_id"` (this is a
   subset of acceptance criterion 8.4 surfaced as a distinct
   reason).
6. WHEN the save entry point is called with a `BaselineRecord`
   that fails its own Pydantic validators in round-trip, THE
   Baseline_Store SHALL raise
   `BaselineSerializationError` and SHALL NOT write any file.
7. WHEN the save entry point is called with a destination
   directory that exists but is not writable by the current
   process, THE Baseline_Store SHALL raise
   `BaselineStorageUnwritableError` carrying the path and the
   underlying `OSError` errno.
8. THE Baseline_Store SHALL surface
   `BaselineConcurrentModificationError` and
   `BaselineAlreadyExistsError` as defined in Requirement 5.

### Requirement 9: Determinism, round-trip, and performance

**User Story:** As a tester and as the property-based test suite,
I want save → load → save to be deterministic and to round-trip
losslessly, and I want load times bounded for realistic
Storage_Directory sizes, so that property tests can pin the
contract and the GUI stays responsive.

#### Acceptance Criteria

1. THE Baseline_Store SHALL keep load wall time under 30 seconds
   for a Storage_Directory containing up to 128 Baseline_Files
   each holding up to 256 `ClassificationRecord` entries, and
   under 180 seconds for up to 1024 Baseline_Files of the same
   shape, on a 2024-class developer laptop with a local SSD.
   PyYAML's parser dominates load cost at scale; a future
   `baseline-load-perf` spec may revisit these budgets if
   startup latency proves disruptive in practice.
2. WHEN the Baseline_Store saves a `BaselineRecord` and
   immediately re-loads the resulting Baseline_File, THE
   Baseline_Store SHALL return a `BaselineRecord` equal under
   `model_dump(mode="json")` to the input.
3. WHEN the Baseline_Store saves the same `BaselineRecord`
   twice via the save entry point with no other changes to the
   Storage_Directory, THE Baseline_Store SHALL produce
   byte-identical Baseline_File contents (modulo the
   `written_at` envelope field).
4. WHEN the Baseline_Store loads a `BaselineRegistry` and
   immediately writes every `BaselineRecord` back via the save
   entry point, THE Baseline_Store SHALL produce
   Baseline_Files whose `baseline` payload subtree is equal
   under `yaml.safe_load` to the original loaded payload
   subtree (Schema_Version envelope fields excluded from the
   equality check).
5. THE Baseline_Store SHALL NOT depend on the system clock for
   any decision affecting Baseline_File contents other than
   populating the envelope's `written_at` field.
6. THE Baseline_Store SHALL NOT consult environment variables,
   the random number generator, or any network resource during
   load, save, or Discovery_Scan.
7. THE Baseline_Store SHALL NOT load a `BaselineRecord` whose
   serialized YAML form exceeds 16 MiB and SHALL place such
   files in the Quarantine_Set with reason
   `"file exceeds 16 MiB size limit"`.
8. THE Baseline_Store SHALL NOT save a `BaselineRecord` whose
   serialized YAML form would exceed 16 MiB and SHALL raise
   `BaselineSerializationError` before writing.

### Requirement 10: Observability and diagnostics

**User Story:** As a developer debugging a failed load on a real
Storage_Directory, I want enough structured logging to identify
which file failed and why, without leaking the contents of any
loaded baseline.

#### Acceptance Criteria

1. WHEN the load entry point is called, THE Baseline_Store SHALL
   log an INFO record naming the Storage_Directory path and the
   number of `*.yaml` files Discovery_Scan found before
   deserialization.
2. WHEN the load entry point completes, THE Baseline_Store SHALL
   log an INFO record summarizing the count of successfully
   loaded baselines, the count in the Quarantine_Set, and the
   wall-clock duration in milliseconds.
3. WHEN the Baseline_Store places a Baseline_File in the
   Quarantine_Set, THE Baseline_Store SHALL log a WARNING record
   carrying the file path and the quarantine reason string.
4. WHEN the save entry point completes successfully, THE
   Baseline_Store SHALL log an INFO record carrying the
   Baseline_Identifier and the destination Baseline_Filename,
   and SHALL NOT log any byte of the serialized payload.
5. THE Baseline_Store SHALL NOT, at any time, log the contents
   of `BaselineRecord.component_manifest`, the
   `source_image_hash`, `notes`, or any embedded
   `ClassificationRecord` field beyond the
   Baseline_Identifier permitted by acceptance criterion 10.4;
   inspection of Baseline_File contents for debugging SHALL be
   performed via the `loki baseline show` CLI subcommand or
   direct file reading, not via log records.
6. THE Baseline_Store SHALL log all activity under the logger
   name `loki.baseline` so that GUI and CLI consumers can
   attach their own handlers without monkey-patching.
