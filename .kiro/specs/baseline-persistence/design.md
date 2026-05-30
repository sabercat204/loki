# Design Document — Baseline Persistence (GLEIPNIR)

## Overview

The Baseline Persistence subsystem is the bridge that moves
`BaselineRecord` and `BaselineRegistry` instances between memory and
a YAML directory layout on disk. It is the smallest of LOKI's
subsystems by surface area: the model layer already defines what a
baseline *is*, and this spec only defines storage, retrieval, and
lifecycle.

The subsystem is **synchronous**, **single-process-friendly**,
**deterministic** (byte-identical output for the same input modulo
one explicit timestamp field), and **honest** about what it cannot
do — concurrent overlapping writes get a typed error rather than
silent merge, schema version mismatches quarantine the file rather
than auto-upgrade, and malformed YAML never crashes the whole load.

The shape mirrors the extraction-pipeline design but is roughly half
the size. Each non-trivial design choice cites the acceptance criteria
it satisfies (e.g. `R3.7` = Requirement 3 acceptance criterion 7).

## Goals and non-goals

### Goals

- Deliver a stable, typed `BaselineStore` importable as
  `from loki.baseline import BaselineStore`.
- Round-trip every `BaselineRecord` through YAML losslessly
  (R9.2-R9.4).
- Bound load time to under 5 seconds for 1024 baselines × 256
  classifications on a local SSD (R9.1).
- Surface concurrent external mutation as a typed error, never as
  silent overwrite (R5).
- Keep the subsystem completely independent of `loki.gui`
  (parallel constraint to `loki.extraction`'s R9.5).

### Non-goals (explicit)

- **Comparison.** No deviation scoring or `DeviationRecord`
  generation. That's a downstream subsystem.
- **Classification.** No production of `ClassificationRecord`
  instances inside `BaselineRecord.component_manifest`.
- **Live extraction wiring.** The extraction pipeline produces
  `ExtractionManifest`s; turning those into baselines requires
  classification first. Out of scope.
- **Inter-process locking.** No lock files or POSIX advisory
  locks (R5.5). Concurrency safety is via mtime/size check +
  atomic replace; lost races raise typed errors.
- **Schema migration.** Schema_Version mismatches quarantine the
  file (R4.4); a future spec will define the migration tool.
- **Multi-host synchronization.** Single-host only.

## Constraints carried forward

- Python 3.11+ (3.12 baseline). All new code must satisfy
  `mypy --strict`, `ruff check`, and `ruff format`.
- Pydantic v2 strict mode for every model already in `loki.models`;
  the persistence layer constructs `BaselineRecord` and
  `BaselineRegistry` directly so their validators run before the
  values escape (R2.3, R3.8).
- `loki.baseline` must not import from `loki.gui` (parallel to
  `loki.extraction`'s no-PyQt6 constraint).
- Logging via the stdlib `logging` module under the logger name
  `loki.baseline` (R10.6).
- No content leakage in logs at any time (R10.5).

## Components and Interfaces

### Module layout

```
loki/baseline/
├── __init__.py           # re-exports the public surface; concurrency contract docstring
├── store.py              # BaselineStore: load/save/delete entry points
├── envelope.py           # YAML envelope schema + (de)serialization
├── naming.py             # slug() + Baseline_Filename computation + uniqueness handling
├── schema.py             # SCHEMA_VERSION constant + supported-version set
├── errors.py             # typed exception hierarchy
├── quarantine.py         # QuarantineEntry + QuarantineSet dataclasses
└── concurrency.py        # mtime/size snapshot + check helpers
```

`loki/baseline/__init__.py` re-exports exactly:

```python
from loki.baseline.errors import (
    BaselineAlreadyExistsError,
    BaselineConcurrentModificationError,
    BaselineSerializationError,
    BaselineStorageUnwritableError,
    BaselineStoreError,
)
from loki.baseline.quarantine import QuarantineEntry, QuarantineSet
from loki.baseline.schema import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS
from loki.baseline.store import (
    BaselineStore,
    CancellationToken,
    LoadProgressCallback,
    LoadProgressEvent,
    LoadResult,
)
```

The `__init__.py` module docstring documents the concurrency
contract per R5.6 ("single-host, multi-process safe for
non-overlapping baselines; explicit-error on overlapping concurrent
writes").

### Public API surface

#### `BaselineStore` (R2.1, R3.1, R5)

```python
# loki/baseline/store.py
@dataclass(frozen=True)
class LoadResult:
    """Tuple-shaped return for ``BaselineStore.load`` (R2.1)."""
    registry: BaselineRegistry
    quarantine: QuarantineSet
    duration_ms: float


@dataclass(frozen=True)
class LoadProgressEvent:
    """Structured progress event for the optional ``progress`` callback (R2.8).

    Emitted exactly once before each Baseline_File is parsed.
    Files filtered out by the Discovery_Scan extension check
    (R1.4) are not reported.
    """
    path: Path                # absolute path to the file being parsed
    index: int                # 1-based position in the candidate list
    total: int                # candidate count returned by Discovery_Scan


# Type aliases used by the load entry point's optional callback parameters.
LoadProgressCallback = Callable[[LoadProgressEvent], None]
CancellationToken = Callable[[], bool]


class BaselineStore:
    """Move ``BaselineRecord`` instances between memory and disk.

    Constructor accepts the caller's ``BaselineConfig`` and resolves
    the storage path immediately. The directory is created with mode
    ``0o755`` if missing (R1.6).
    """

    def __init__(self, config: BaselineConfig) -> None: ...

    @property
    def storage_path(self) -> Path: ...

    @property
    def schema_version(self) -> str: ...

    def load(
        self,
        *,
        progress: LoadProgressCallback | None = None,
        cancel: CancellationToken | None = None,
    ) -> LoadResult:
        """Run Discovery_Scan + validate every Baseline_File.

        R2.1-R2.10. Raises only typed
        :class:`BaselineStoreError` subclasses.

        Optional ``progress`` and ``cancel`` callbacks (R2.8 / R2.9)
        let GUI callers surface per-file progress in the status
        bar and cancel a long load between files. When omitted,
        the load behaves exactly as the no-callback path
        (R2.10's no-observable-difference contract).
        """

    def save(
        self,
        record: BaselineRecord,
        *,
        force: bool = False,
    ) -> Path:
        """Atomic_Write ``record`` to its computed Baseline_Filename.

        Returns the absolute destination path. R3, R5.3-R5.4.
        Raises :class:`BaselineAlreadyExistsError` if a file exists
        and ``force`` is False; raises
        :class:`BaselineConcurrentModificationError` if the
        destination's mtime/size moved since load.
        """

    def delete(self, baseline_id: uuid.UUID) -> Path:
        """Remove the Baseline_File matching ``baseline_id``.

        Returns the path that was removed. CLI ``delete`` and GUI
        future trash actions call this. Raises
        :class:`BaselineStoreError` subclass on missing file or
        permission errors.
        """

    def load_one(self, path: Path) -> BaselineRecord:
        """Load a single Baseline_File without touching the registry.

        Used by `loki baseline import` and the GUI's "Open Baseline
        Registry…" file picker (R6.6, R7.4). Returns a validated
        :class:`BaselineRecord`; raises typed errors on failure
        rather than quarantining (single-file load isn't a bulk
        scan, so the caller wants a hard error not a soft one).
        """
```

`save` records the destination's pre-write `(mtime_ns, size)` via
:mod:`loki.baseline.concurrency` immediately before `os.replace`,
re-checks against the snapshot recorded at load time, and raises
`BaselineConcurrentModificationError` on mismatch (R5.1-R5.2).

#### Exception hierarchy (R8)

```
BaselineStoreError                      # all errors raised by this subsystem
├── BaselineConcurrentModificationError # R5.2
├── BaselineAlreadyExistsError          # R5.3
├── BaselineSerializationError          # R3.8 / R8.6 / R9.8
└── BaselineStorageUnwritableError      # R8.7
```

`BaselineConcurrentModificationError` carries `path: Path`,
`recorded: tuple[int, int]`, and `observed: tuple[int, int]`.
`BaselineAlreadyExistsError` carries `path: Path`.
`BaselineSerializationError` carries the underlying
`pydantic.ValidationError` or size-limit message.
`BaselineStorageUnwritableError` carries `path: Path` and `errno: int`.

### Naming and slugification (R1.2, R1.3)

```python
# loki/baseline/naming.py
_SLUG_VALID = re.compile(r"[a-z0-9._-]+")
_SLUG_INVALID_RUN = re.compile(r"[^a-z0-9._-]+")
_UNDERSCORE_RUN = re.compile(r"_+")


def slug(value: str) -> str:
    """Lowercase, replace [^a-z0-9._-] with _, collapse __+ to _."""
    lowered = value.lower()
    replaced = _SLUG_INVALID_RUN.sub("_", lowered)
    collapsed = _UNDERSCORE_RUN.sub("_", replaced)
    # Strip leading/trailing underscores so "v1.42" -> "v1.42" and
    # "/etc/passwd" -> "etc_passwd" rather than "_etc_passwd_".
    return collapsed.strip("_")


def filename_for(record: BaselineRecord) -> str:
    """Compute the canonical Baseline_Filename for ``record``.

    Returns the form
    ``{slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml``.
    Suffixes ``-{first 8 hex chars of baseline_id}`` are NOT applied
    here; that's the collision-resolution path in
    :func:`unique_filename_for`, which the store calls when it
    detects a collision against an already-saved file.
    """


def unique_filename_for(
    record: BaselineRecord, taken: set[str]
) -> str:
    """Return a Baseline_Filename guaranteed not to collide with ``taken``.

    R1.3. If the canonical name (from :func:`filename_for`) is
    already in ``taken``, append ``-{first 8 hex chars of
    baseline_id}`` before the ``.yaml`` extension.
    """
```

### Envelope schema (R3.4-R3.7)

```yaml
# Baseline_File — example
schema_version: "1.0.0"
written_at: "2026-05-23T15:42:00.123456Z"
written_by_extractor_version: "0.1.0"
baseline:
  baseline_id: "550e8400-e29b-41d4-a716-446655440000"
  name: "DEMO-X1-G11 v1.42 reference"
  vendor: "INTEL"
  model: "DEMO-X1-G11"
  firmware_version: "1.42"
  created_timestamp: "2026-05-23T14:30:00Z"
  notes: null
  component_manifest: [...]   # array of ClassificationRecord
  source_image_hash: "..."
  baseline_version: "1.0.0"
```

The four envelope keys are sorted (`baseline`, `schema_version`,
`written_at`, `written_by_extractor_version`) by `yaml.safe_dump`'s
`sort_keys=True` (R3.7). The `baseline` payload is exactly
`record.model_dump(mode="json")` — datetimes as ISO strings,
UUIDs as strings.

```python
# loki/baseline/envelope.py
@dataclass(frozen=True)
class Envelope:
    """Parsed Baseline_File envelope (R3.4)."""
    schema_version: str
    written_at: datetime
    written_by_extractor_version: str
    baseline: dict[str, object]   # raw model_dump payload


_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"schema_version", "written_at", "written_by_extractor_version", "baseline"}
)


def serialize(record: BaselineRecord, *, written_at: datetime) -> bytes:
    """R3.4-R3.7: build the envelope and emit deterministic YAML bytes.

    Returns UTF-8 bytes ending in ``\\n`` (R1.7) suitable for
    Atomic_Write.
    """


def deserialize(payload: bytes, *, path: Path) -> Envelope:
    """Parse + validate the envelope shape only.

    Raises :class:`EnvelopeMalformedError` on missing keys, bad
    schema_version type, etc. The :class:`BaselineStore.load`
    method catches these and converts to QuarantineEntry instances
    (R8.2-R8.3); :class:`BaselineStore.load_one` lets them
    propagate as :class:`BaselineSerializationError`.
    """
```

### Concurrency snapshot (R5.1-R5.2)

```python
# loki/baseline/concurrency.py
@dataclass(frozen=True)
class FileSnapshot:
    """Captured ``(mtime_ns, size)`` for a Baseline_File at load time."""
    path: Path
    mtime_ns: int
    size: int


def snapshot(path: Path) -> FileSnapshot:
    """Capture ``stat()``'s ``st_mtime_ns`` and ``st_size``."""


def check_unchanged(snap: FileSnapshot) -> None:
    """Raise BaselineConcurrentModificationError if the file moved.

    Called by :meth:`BaselineStore.save` immediately before
    ``os.replace``. R5.2.
    """
```

The `BaselineStore` keeps a `dict[uuid.UUID, FileSnapshot]` that
maps `baseline_id` to the snapshot recorded at load time. Save with
`force=False` (the default) requires this snapshot to exist (R5.3:
"a `BaselineRecord` that the Baseline_Store has not previously
loaded from disk … treat the file as new and refuse to overwrite").

### QuarantineSet (R2.1, R8.2-R8.5)

```python
# loki/baseline/quarantine.py
@dataclass(frozen=True)
class QuarantineEntry:
    path: Path
    reason: str         # human-readable; must match R8 message strings
    raw: bytes | None   # original file bytes, retained for forensic display


class QuarantineSet:
    """Append-only container of QuarantineEntry records."""

    def __init__(self) -> None: ...
    def add(self, entry: QuarantineEntry) -> None: ...
    def __iter__(self) -> Iterator[QuarantineEntry]: ...
    def __len__(self) -> int: ...
```

`raw` is kept so the GUI's quarantine notification can offer a
"View raw" affordance in a future spec without re-reading the
file (avoiding TOCTOU between the load-time scan and the
notification dialog).

## Data Models

This subsystem introduces no new Pydantic models. It re-uses the
model-layer types unchanged:

| Type                  | Used as                                                |
|-----------------------|--------------------------------------------------------|
| `BaselineRecord`      | the record that gets serialized                        |
| `BaselineRegistry`    | the result of :meth:`BaselineStore.load`               |
| `ClassificationRecord` | child of `BaselineRecord.component_manifest`          |
| `BaselineConfig`      | constructor input                                      |

It introduces three internal frozen dataclasses (purely
in-process; not persisted):

- `LoadResult` — bundle of registry + quarantine + duration
- `LoadProgressEvent` — per-file progress event for the
  optional ``progress`` callback (R2.8)
- `Envelope` — parsed envelope shape
- `FileSnapshot` — captured `(mtime_ns, size)`
- `QuarantineEntry` — one quarantine row

It also introduces two type aliases on the load entry point's
optional callback parameters:

- `LoadProgressCallback = Callable[[LoadProgressEvent], None]`
- `CancellationToken = Callable[[], bool]`

These don't ship in `loki.models` because they're not part of the
long-term data contract that other subsystems consume.

## Error Handling

This section consolidates the error story already touched on in
"Components and Interfaces."

### What gets raised

Five exception classes leave the subsystem boundary:

- `BaselineStoreError` — root parent.
- `BaselineConcurrentModificationError` — destination's
  `(mtime_ns, size)` moved since load (R5.2).
- `BaselineAlreadyExistsError` — save without prior load and the
  file exists, with `force=False` (R5.3).
- `BaselineSerializationError` — save-side validation failure
  (R3.8) or size-limit exceeded (R9.8).
- `BaselineStorageUnwritableError` — destination directory exists
  but isn't writable (R8.7).

### What gets quarantined (not raised)

Per R2.4 and R8.2-R8.5, load-side failures populate the
`QuarantineSet`:

| Reason string                                   | Cause                                     |
|-------------------------------------------------|-------------------------------------------|
| `malformed yaml: {message}`                     | `yaml.YAMLError` from `safe_load`         |
| `missing required envelope key: {key}`          | one of the four envelope keys absent      |
| `unsupported schema_version: {value}`           | `schema_version` ≠ current Schema_Version |
| `validation failed: {pydantic error summary}`   | `pydantic.ValidationError` on the payload |
| `invalid baseline_id`                           | the payload's `baseline_id` isn't a UUID  |
| `duplicate baseline_id`                         | second file with the same baseline_id     |
| `file exceeds 16 MiB size limit`                | file size > 16 MiB                        |

### Pre/post-condition contract

| Condition                                      | Behavior                                                           |
|------------------------------------------------|--------------------------------------------------------------------|
| Storage_Directory missing, can be created      | Create with mode 0o755 (R1.6)                                      |
| Storage_Directory missing, can't be created    | Raise `BaselineStorageUnwritableError` (R2.5)                      |
| Storage_Directory empty                        | Return `LoadResult(empty registry, empty quarantine)` (R2.6)       |
| File too large                                 | Quarantine, don't read into memory (R9.7)                          |
| Save with `force=False`, file exists           | Raise `BaselineAlreadyExistsError` (R5.3)                          |
| Save with `force=True`, mtime moved            | Skip mtime check; replace (R5.4)                                   |
| Save with `force=False`, mtime moved           | Raise `BaselineConcurrentModificationError` (R5.2)                 |
| Save with payload > 16 MiB                     | Raise `BaselineSerializationError` before any disk write (R9.8)    |
| Round-trip validation fails on save            | Raise `BaselineSerializationError`, write nothing (R3.8)           |

## Architecture

### Load flow (`BaselineStore.load`)

Satisfies R2 and R10.1-R10.2.

```
BaselineStore.load()
  │
  ├── 1. Resolve and stat Storage_Directory                       (R1.6)
  │   └── on missing / unwritable: BaselineStorageUnwritableError
  │
  ├── 2. logger.info("baseline load starting path=... candidates=N")
  │
  ├── 3. Discovery_Scan: list `*.yaml` files at depth 1            (R1.4)
  │
  ├── 4. For each candidate, in lexicographic Baseline_Filename order:
  │     a. cancel() check; on True → break the loop                 (R2.9)
  │     b. progress() callback with LoadProgressEvent                (R2.8)
  │     c. stat; if size > 16 MiB → quarantine, continue            (R9.7)
  │     d. read; if read fails → quarantine                         (R8.2)
  │     e. yaml.safe_load; on YAMLError → quarantine                (R8.2)
  │     f. envelope.deserialize; on missing key → quarantine        (R8.3)
  │     g. envelope.schema_version not in SUPPORTED_SCHEMA_VERSIONS
  │        → quarantine                                              (R4.4)
  │     h. BaselineRecord.model_validate(envelope.baseline,
  │        strict=False)
  │        on ValidationError → quarantine                          (R8.4-R8.5)
  │     i. duplicate baseline_id check vs the in-flight registry    (R2.7)
  │        → quarantine the *second* occurrence
  │     j. snapshot = concurrency.snapshot(candidate)
  │     k. registry.baselines.append(record)
  │        self._snapshots[record.baseline_id] = snapshot
  │
  ├── 5. logger.info("baseline load finished loaded=N
  │     quarantined=M duration=Xms")                                 (R10.2)
  │
  └── 6. Return LoadResult(registry, quarantine, duration_ms)
```

The scan is sequential — the 1024 × 256 budget (R9.1) is comfortably
met by sequential I/O on a local SSD (each file is < 1 MiB; the
total is < 1 GiB; sequential read of that volume is ~1 second; the
remaining 4 seconds covers Pydantic strict validation of 256K
records). A future spec could parallelize the Pydantic step, but
the contract doesn't require it.

### Save flow (`BaselineStore.save`)

Satisfies R3, R5.

```
BaselineStore.save(record, *, force=False)
  │
  ├── 1. Round-trip validation:
  │     - record.model_dump(mode="json") + BaselineRecord.model_validate
  │     - on ValidationError: raise BaselineSerializationError       (R3.8)
  │
  ├── 2. Compute Baseline_Filename:
  │     - canonical = naming.filename_for(record)
  │     - if force: dest = canonical
  │     - else if baseline_id known to self._snapshots:
  │         dest = path-of-snapshot                                   (R5.1)
  │     - else if canonical exists:
  │         raise BaselineAlreadyExistsError                          (R5.3)
  │     - else: dest = canonical
  │
  ├── 3. Build envelope:
  │     - written_at = datetime.now(tz=UTC)
  │     - bytes = envelope.serialize(record, written_at=...)          (R3.4-R3.7)
  │     - if len(bytes) > 16 MiB: raise BaselineSerializationError    (R9.8)
  │
  ├── 4. Atomic_Write:
  │     - tmp = dest.parent / f"{dest.name}.{secrets-not-needed}.tmp"
  │       NOTE: filename uses 8 hex chars from a deterministic
  │       counter or process-time hash, NOT the random module
  │       (R9.6 forbids the random module). The counter is monotonic
  │       within one process and reset across processes; collisions
  │       are impossible because each save holds exclusive ownership
  │       of its destination path.
  │     - fd = open(tmp, "wb"); fd.write(bytes); fd.flush();
  │       os.fsync(fd.fileno()); fd.close()
  │     - if force is False and dest exists:
  │         concurrency.check_unchanged(self._snapshots[id])          (R5.2)
  │     - os.replace(tmp, dest)                                       (R3.2)
  │     - on any exception before replace: tmp.unlink(missing_ok=True) (R3.3)
  │
  ├── 5. Re-snapshot dest and store in self._snapshots[record.baseline_id]
  │
  └── 6. logger.info("baseline save id=... vendor=... ... path=...")  (R10.4)
       Returns dest.
```

R9.6 forbids the random module, so the temp filename suffix uses a
monotonic process-local counter (`itertools.count`) plus the
process pid, which is deterministic-per-process and collision-free
because each save owns its destination.

### Single-file load (`BaselineStore.load_one`)

Satisfies R6.6, R7.4. Re-uses the load flow's per-file path
(steps 4a-4f) but raises typed errors instead of quarantining,
because the caller asked specifically for that file. Used by:

- `loki baseline import {path}` — load → save into Storage_Directory
- GUI's `View → Open Baseline Registry…` — load one selected file
  into memory without touching the Storage_Directory

### CLI surface (`loki baseline ...`)

Satisfies R6 in full. Adds five subparsers under a `baseline`
subcommand group in `loki/cli.py`, mirroring the existing
`loki extract` pattern.

```
loki baseline list
  -> BaselineStore(config).load()
  -> Print one row per registry.baselines, sorted (vendor, model, firmware_version).
  -> If quarantine non-empty: print "quarantined: N" to stderr; exit 0.

loki baseline show {baseline_id}
  -> BaselineStore(config).load()
  -> registry.get_by_id(...) -> model_dump_json(indent=2) -> stdout
  -> Exit 0; missing id -> exit 2 + "baseline not found: {id}" to stderr.

loki baseline import {path}
  -> BaselineStore(config).load_one(path) -> save() -> stdout: filename
  -> Errors: typed -> exit 3-5 (matching extraction's error taxonomy).

loki baseline export {baseline_id} {dest}
  -> load() -> get_by_id() -> serialize via envelope.serialize -> dest

loki baseline delete {baseline_id} [--yes]
  -> load() -> prompt unless --yes -> store.delete(id)
```

All five subcommands take a `--storage-path` flag for ad-hoc
testing; absent that, they read `LokiConfig` from the standard
config path (deferred to a future config-loading spec; v1 uses an
in-CLI fallback `BaselineConfig`).

### GUI integration

Satisfies R7. Three integration points in `loki/gui/main_window.py`
plus a new GUI action module:

```
loki/gui/actions/
├── open_baseline.py    # File-system picker + load_one
├── save_baseline.py    # Save current selection via store.save
└── ...
```

`MainWindow.__init__` is extended to:

1. Construct a `BaselineStore` from the active `LokiConfig`.
2. Show "Loading baselines from {path}…" in the status bar.
3. Run `store.load()` on the *main* thread (the load is bounded
   by R9.1's 5-second budget; backgrounding it is a future
   enhancement). For Storage_Directories larger than the v1
   1024 baseline cap a future spec will introduce a worker.
4. Populate the **Baselines** navigation group with one entry
   per loaded `BaselineRecord`. Demo-data baselines remain
   suffixed `(demo)` (R7.9).
5. If `quarantine` is non-empty, show a `QMessageBox.information`
   listing the count and log each entry under
   `loki.gui.baselines` (R7.3).

`View → Open Baseline Registry…` opens a `QFileDialog` rooted at
`store.storage_path`, loads via `store.load_one`, and treats the
result like demo data — *not* persisted (R7.4: "without modifying
the Storage_Directory").

`View → Save Baseline…` is enabled only when a `BaselineView` is
the active workspace tab. Clicking invokes `store.save(record)`;
on `BaselineAlreadyExistsError`, prompt to overwrite (`force=True`);
on `BaselineConcurrentModificationError`, show an error and stop
(R7.6-R7.7).

## Correctness Properties

This section enumerates the invariants the persistence subsystem
guarantees. Numbering continues from extraction-pipeline's 12-22, so
the model layer owns 1-11, extraction owns 12-22, and persistence
starts at 23.

### Property 23: Loaded BaselineRegistry is Pydantic-validated on return

For every input that survives Discovery_Scan, the
`BaselineRegistry` returned by `BaselineStore.load` contains only
`BaselineRecord` instances that passed Pydantic v2 strict
validation. Any caller can use the registry without re-validating.

**Validates: Requirements 2.4, 8.4**

### Property 24: Save → load round-trips losslessly

For every `BaselineRecord` `r` and every fresh `BaselineStore`
`s`, `s.load_one(s.save(r))` returns a record `r'` such that
`r.model_dump(mode="json") == r'.model_dump(mode="json")`.

**Validates: Requirements 9.2**

### Property 25: Two saves produce byte-identical files modulo `written_at`

Saving the same `BaselineRecord` twice via `store.save` produces
Baseline_File contents that are identical except for the
`written_at` envelope field. Achieved by `yaml.safe_dump` with
`sort_keys=True` and `model_dump(mode="json")` for the payload.

**Validates: Requirements 3.7, 9.3**

### Property 26: Load → save → load preserves the baseline payload

Loading a `BaselineRegistry` and saving every `BaselineRecord`
back via the save entry point produces files whose `baseline`
subtree (under `yaml.safe_load`) equals the original loaded
payload subtree. Envelope fields (`schema_version`, `written_at`,
`written_by_extractor_version`) are excluded from the equality
check.

**Validates: Requirements 9.4**

### Property 27: Atomic_Write never corrupts the destination file

For every save operation that fails before `os.replace`, the
existing destination Baseline_File (if any) is byte-identical to
its pre-save content. Verified by injecting a write failure mid-
serialization and asserting the destination is unchanged.

**Validates: Requirements 3.2, 3.3**

### Property 28: Filename slugification is idempotent

For every `BaselineRecord`, `slug(slug(value)) == slug(value)`,
and the resulting Baseline_Filename matches `[a-z0-9._-]+\\.yaml`.

**Validates: Requirements 1.2**

### Property 29: Filename uniqueness is preserved under collision

For every pair of `BaselineRecord` instances with distinct
`baseline_id` but colliding canonical filenames,
`unique_filename_for` produces two distinct filenames, both
matching `[a-z0-9._-]+\\.yaml`.

**Validates: Requirements 1.3**

### Property 30: Concurrent modification is detected, not silently overwritten

For every save operation against a destination whose
`(mtime_ns, size)` has changed since `BaselineStore.load` recorded
its snapshot, `BaselineConcurrentModificationError` is raised
*and* the destination file is unchanged.

**Validates: Requirements 5.2**

### Property 31: Quarantined files are never modified

For every Baseline_File placed in the `QuarantineSet` during
`BaselineStore.load`, the file's `(mtime_ns, size)` after the
load is identical to its `(mtime_ns, size)` before the load.

**Validates: Requirements 1.4, 4.5**

### Property 32: No environmental side channels

`loki.baseline` does not consult environment variables, the
random number generator, the network, or any clock other than
`datetime.now(tz=UTC)` for the envelope's `written_at` field.
Enforced by an AST audit test (continuing the pattern from
extraction's Property 22) that walks `loki.baseline.__path__`.

**Validates: Requirements 9.5, 9.6**

## Logging strategy

Satisfies R10.

- Logger name: `loki.baseline` (R10.6).
- Loggers in submodules use `logging.getLogger(f"loki.baseline.{modname}")`.
- The subsystem never installs handlers, never sets levels, never
  logs to stdout/stderr directly.
- INFO records:
  - Load start: `"baseline load starting path=%s candidates=%d"` (R10.1)
  - Load end: `"baseline load finished loaded=%d quarantined=%d duration=%.1fms"` (R10.2)
  - Save success: `"baseline save id=%s vendor=%s model=%s firmware_version=%s path=%s"` (R10.4)
- WARNING records:
  - One per quarantined file: `"baseline quarantine path=%s reason=%s"` (R10.3)
- ERROR records:
  - On `BaselineStorageUnwritableError`, `BaselineConcurrentModificationError`,
    and `BaselineAlreadyExistsError` (the typed exceptions that
    leave the subsystem boundary).

R10.5 ("never log component_manifest, source_image_hash, notes")
is enforced by:

- **At source.** No log message in `loki.baseline` references
  `record.component_manifest`, `record.source_image_hash`,
  or `record.notes` directly. Reviewer-checkable.
- **At test.** `tests/baseline/test_log_no_leakage.py` mirrors
  `tests/extraction/test_log_no_leakage.py`: capture every
  emitted record during a curated load + save and assert no
  record's formatted message contains the test fixture's
  `source_image_hash`, any classification record's `raw_hash`,
  or the `notes` string.

## Testing Strategy

Test layout mirrors the existing extraction layout:

```
tests/baseline/
├── __init__.py
├── conftest.py               # fixtures: BaselineConfig, scratch dirs, valid records
├── fixtures/
│   ├── __init__.py
│   ├── synthetic_baseline.py # builds a deterministic BaselineRecord
│   └── golden/
│       ├── canonical_v1.yaml # one committed Baseline_File for golden-file regression
│       └── canonical_v1.json # the expected re-loaded payload
├── test_naming.py            # R1.2-R1.3, Properties 28-29
├── test_envelope.py          # R3.4-R3.7
├── test_store_load.py        # R2, R10.1-R10.2
├── test_store_save.py        # R3, R5.1-R5.4
├── test_store_concurrency.py # R5, Property 30
├── test_store_errors.py      # R8 (typed exceptions + quarantine reasons)
├── test_schema_version.py    # R4
├── test_determinism.py       # Properties 24-26 (Hypothesis)
├── test_manifest_invariants.py # Property 23 (Hypothesis)
├── test_no_side_channels.py  # Property 32 (AST audit)
├── test_log_no_leakage.py    # R10.5 (dynamic capture)
└── test_golden.py            # R3.7 + R9.2 against the committed golden file
```

Plus integration tests that *don't* live under `tests/baseline/`:

```
tests/test_cli_baseline.py   # R6 (5 subcommands × happy/error paths)
tests/gui/test_baseline_actions.py  # R7 (load on startup, Open/Save menu actions)
```

### Synthetic fixture

`tests/baseline/fixtures/synthetic_baseline.py` exports a
`build(*, vendor, model, firmware_version, classification_count)`
function that returns a deterministic `BaselineRecord` with the
requested number of classifications. Component classifications use
fixed `uuid.uuid5` seeds so the resulting record is byte-identical
across runs.

### Golden-file regression

`tests/baseline/fixtures/golden/canonical_v1.yaml` is committed
and regenerated only when the schema or the synthetic builder
changes (mirroring the extraction-pipeline approach). The test
re-saves the canonical record and compares against the committed
file modulo the `written_at` envelope field.

### What's deliberately not tested

- Real-world vendor baselines — no public corpus exists, and
  vendors don't publish their classifications. Future work.
- Network behaviour — the subsystem doesn't have any.
- GUI integration on real Storage_Directories — covered by
  `tests/gui/test_baseline_actions.py` against synthetic
  fixtures.

## Deferred decisions and open questions

Tracked here so future sessions don't re-derive answers.

1. **Schema migration tool.** R4.5 forbids auto-upgrade. A future
   spec (`baseline-schema-migration`) will define an explicit
   `loki baseline migrate` subcommand that reads files of older
   Schema_Versions and writes them at the current version. v1
   defines exactly one Schema_Version (1.0.0) so no migration is
   needed yet.
2. **GUI background loading.** ~~R7.2 says the load must not block
   menu input on up to 1024 baselines. v1 runs the load on the
   main thread; if the 5-second budget proves disruptive in
   practice, a future spec will add a `BaselineLoadWorker` mirror
   of the `ExtractionWorker` from the GUI's extraction wiring.~~
   **Resolved**: `loki/gui/baseline_load_worker.py` ships a
   `QThread` wrapper around `BaselineStore.load`. v1.1 adds the
   optional `progress` and `cancel` callbacks contracted by R2.8
   and R2.9, surfaced in the GUI per R7.10 and R7.11.
3. **Foreign-file cleanup.** R1.4 says the store never deletes
   foreign files. A future spec could add an opt-in
   `loki baseline clean` subcommand that removes `*.yaml.tmp`
   leftovers from interrupted Atomic_Write attempts.
4. **Multi-host synchronization.** Out of scope. If two hosts
   need to share baselines, the user puts the Storage_Directory
   on a shared filesystem; the mtime/size check from R5 detects
   conflicts but does not resolve them. A future spec could
   define an explicit synchronization protocol.
5. **Lock-free vs locked concurrency.** R5.5 explicitly rejects
   lock files. If real-world use shows that the typed-error model
   is too punishing, this decision is the cheapest one to revisit.

## Traceability matrix

| Requirement | Design section(s)                                                       |
|-------------|--------------------------------------------------------------------------|
| R1.1-R1.7   | "Module layout", "Naming and slugification", "Load flow"                 |
| R2.1-R2.10  | "Public API surface — `BaselineStore`", "Load flow"                      |
| R3.1-R3.9   | "Envelope schema", "Save flow"                                           |
| R4.1-R4.6   | "Module layout (`schema.py`)", "Load flow step 4e", "Deferred decisions" |
| R5.1-R5.6   | "Concurrency snapshot", "Save flow", "Public API surface — `BaselineStore`" |
| R6.1-R6.10  | "CLI surface"                                                            |
| R7.1-R7.11  | "GUI integration"                                                        |
| R8.1-R8.8   | "Public API surface — Exception hierarchy", "Error Handling"             |
| R9.1-R9.8   | "Load flow", "Save flow", Properties 24-27, 32                           |
| R10.1-R10.6 | "Logging strategy"                                                       |

Every acceptance criterion has at least one design section it maps
to, and every design section cites at least one acceptance criterion
it satisfies.
