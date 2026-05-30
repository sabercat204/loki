# Design Document — Extraction Pipeline

## Overview

The Extraction Pipeline turns a firmware binary on disk into a validated
`ExtractionManifest`. It is the first subsystem downstream of the model
layer (`loki/models/`) and the source of truth for every later stage.

This design covers the architecture, public API, internal components,
determinism contract, error handling, observability, performance
contract, and testing strategy needed to implement
`requirements.md` end-to-end. Each non-trivial design choice cites the
acceptance criteria it satisfies (e.g. `R4.7` = Requirement 4
acceptance criterion 7).

The pipeline is **synchronous**, **single-threaded**, **deterministic**,
and **honest** about what it cannot do. Container formats it cannot
parse are reported via a single `ExtractionError` describing the input
as an Out-of-Scope format (R2.8) — it never silently produces empty or
fabricated manifests.

## Goals and non-goals

### Goals

- Deliver a stable, typed entry point `extract_firmware(path, config)`
  importable as `from loki.extraction import extract_firmware`.
- Produce a Pydantic-validated `ExtractionManifest` whose components
  are uniquely identified, ordered by offset, and reproducible
  (R6, R7).
- Cover the v1 container set: Intel IFD-described full-flash images,
  UEFI PI firmware volumes, raw FFS blobs, UEFI capsule images, PCI
  option ROMs, and Intel CPU microcode update blobs (R2, R3).
- Bound peak memory and per-component wall time on inputs up to
  512 MiB (R8).
- Stay completely independent of `loki.gui`; remain importable from
  CLI, tests, and headless harnesses (R9.5).

### Non-goals (explicit)

- **Classification.** No mapping from `ExtractedComponent` to the
  four LOKI taxonomic axes (type, vendor, security posture,
  mutability). That's the classification subsystem's job.
- **Baseline comparison or analysis.** Not in this spec.
- **Coreboot CBFS, ARM TF, iBoot, Android boot, vendor-proprietary
  capsules.** Explicitly deferred (R2.10).
- **Async / multi-process extraction.** v1 is synchronous on the
  caller's thread (R8.5).
- **Repair or recovery.** The pipeline reports corruption; it does
  not heal it.

## Constraints carried forward

- Python 3.11+ (3.12 baseline). All new code must satisfy
  `mypy --strict`, `ruff check`, and `ruff format` configured at the
  project level.
- Pydantic v2 strict mode for every model already in `loki.models`;
  this design constructs `ExtractionManifest` directly so its
  validators run before the value escapes (R6.1).
- `loki.extraction` must not import from `loki.gui` (R9.5).
- Logging via the stdlib `logging` module under the logger name
  `loki.extraction` (R9.6, R10).
- No content leakage in logs at any time (R10.5).

## Components and Interfaces

### Module layout

```
loki/extraction/
├── __init__.py           # re-exports the public surface
├── api.py                # extract_firmware() entry point
├── config.py             # PipelineConfig + ExtractionResult dataclasses
├── detection.py          # Format_Detector: identifies container formats
├── manifest.py           # ManifestBuilder: assembles + validates output
├── ids.py                # deterministic component_id derivation (R7.2)
├── errors.py             # typed exception hierarchy
├── tools/
│   ├── __init__.py
│   ├── base.py           # ToolWrapper protocol + base classes
│   ├── uefi_firmware.py  # required wrapper around uefi_firmware-parser
│   ├── uefitool.py       # optional CLI wrapper around UEFITool
│   └── chipsec.py        # optional wrapper around chipsec
├── extractors/
│   ├── __init__.py
│   ├── base.py           # Extractor abstract base + dispatch helper
│   ├── ifd.py            # Intel Flash Descriptor (full-flash) extractor
│   ├── uefi_volume.py    # UEFI PI firmware volume extractor
│   ├── ffs.py            # raw FFS blob extractor
│   ├── capsule.py        # UEFI capsule extractor
│   ├── option_rom.py     # PCI option ROM extractor (multi-image)
│   └── microcode.py      # Intel CPU microcode update extractor
├── streaming.py          # chunked SHA-256, slicing helpers
└── timing.py             # per-component + global timeout helpers
```

`loki/extraction/__init__.py` re-exports exactly:

```python
from loki.extraction.api import extract_firmware, ExtractionResult, PipelineConfig
from loki.extraction.errors import (
    ExtractionPipelineError,
    InvalidInputError,
    ManifestConstructionError,
    ToolWrapperError,
    ToolTimedOutError,
    ToolFailedError,
)
```

### Entry point signature

Satisfies R1, R9.1–9.7.

```python
# loki/extraction/api.py
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from loki.models import ExtractionManifest, ExtractionConfig

ProgressCallback = Callable[["ProgressEvent"], None]
CancellationToken = Callable[[], bool]


@dataclass(frozen=True)
class ProgressEvent:
    """Structured progress event passed to ``progress`` callback (R9.2)."""
    phase: str  # "input-check" | "detect" | "extract" | "manifest"
    component_index: int  # 1-based; 0 before any component started
    components_estimated: int  # detector's running estimate
    message: str  # short human-readable status


@dataclass(frozen=True)
class PipelineConfig:
    """Pipeline-internal configuration extracted from ``ExtractionConfig``.

    Built by ``extract_firmware`` from the caller's ``ExtractionConfig``;
    not constructed by external callers in v1.
    """
    default_output_dir: Path | None
    max_component_size: int
    timeout_per_component: float  # seconds


@dataclass(frozen=True)
class ExtractionResult:
    """Wrapper around the manifest plus diagnostic counters."""
    manifest: ExtractionManifest
    tools_available: dict[str, bool]  # populated per R4.4
    duration_seconds: float           # wall-clock duration


def extract_firmware(
    path: Path,
    config: ExtractionConfig,
    *,
    progress: ProgressCallback | None = None,
    cancel: CancellationToken | None = None,
) -> ExtractionResult:
    """Extract a firmware binary into a validated ``ExtractionManifest``.

    Args:
        path: Filesystem path to the firmware binary.
        config: Caller-supplied ``ExtractionConfig`` (R9.7).
        progress: Optional callback invoked from the calling thread
            (R9.2, R9.3).
        cancel: Optional callable returning True to request graceful
            shutdown (R9.4).

    Returns:
        ``ExtractionResult`` containing a Pydantic-validated
        ``ExtractionManifest``, a tool-availability map, and the
        pipeline duration.

    Raises:
        InvalidInputError: ``path`` is missing, not a regular file,
            or empty (R1.3, R1.4).
        ManifestConstructionError: final ``ExtractionManifest`` failed
            its own validators (R6.6).
    """
```

### Exception hierarchy

Satisfies R1.3, R1.4, R4.7–4.9, R6.6.

```
ExtractionPipelineError                  # all errors raised by this subsystem
├── InvalidInputError                    # R1.3, R1.4
├── ManifestConstructionError            # R6.6
└── ToolWrapperError                     # R4.7-4.9 (carries status)
    ├── ToolTimedOutError                # R4.7, R4.9 (TIMED_OUT precedence)
    └── ToolFailedError                  # R4.8
```

`ToolWrapperError` and its subclasses carry, at minimum:
`tool_name: str`, `status: Literal["TIMED_OUT", "FAILED"]`,
`exit_status: int | None`, `stderr_excerpt: str` (already redacted by
the wrapper). They are the *only* exceptions ToolWrappers raise; the
pipeline catches them and converts to `ExtractionError` records via
`ManifestBuilder.record_error()` rather than letting them bubble out.

`InvalidInputError` and `ManifestConstructionError` *do* bubble out —
those are pre-conditions and post-conditions of the pipeline and must
not be swallowed (R1.3, R6.6).

## Data Models

This subsystem introduces three internal dataclasses (purely
in-process; not persisted, not exposed to GUI/CLI consumers) and
re-uses the model-layer types unchanged.

### Re-used from `loki.models`

| Type | Used as | Source |
|------|---------|--------|
| `FirmwareImage` | `ExtractionManifest.source_image` | `loki.models.firmware` |
| `ExtractedComponent` | every successful carve | `loki.models.firmware` |
| `ExtractionError` | every failure | `loki.models.firmware` |
| `ExtractionManifest` | the pipeline's return value | `loki.models.firmware` |
| `ExtractionConfig` | caller-supplied configuration | `loki.models.config` |
| `LOKI_NAMESPACE` | uuid5 namespace for deterministic IDs | `loki.models.firmware` |

### New internal dataclasses

- **`PipelineConfig`** (frozen, from §Components and Interfaces) —
  pipeline-internal projection of `ExtractionConfig` plus a resolved
  `default_output_dir: Path | None`.
- **`ProgressEvent`** (frozen) — the structured event type passed to
  the optional progress callback (R9.2). Five fields: `phase`,
  `component_index`, `components_estimated`, `message`.
- **`ExtractionResult`** (frozen) — the public return type. Wraps the
  `ExtractionManifest` plus a `tools_available: dict[str, bool]` map
  (R4.4) and the wall-clock `duration_seconds`.
- **`CarvedComponent`** (frozen) — internal extractor output before
  manifest assembly. Six fields: `offset`, `size`,
  `component_type_hint`, `guid`, `name`, `decompressed_payload`.
  Never escapes the subsystem.
- **`DetectedFormat`** (frozen) — output of the format detector.
  Three fields: `kind: FormatKind`, `offset`, `length`.

### New StrEnums

- **`FormatKind`** — five values per §Components and Interfaces
  ("Format detection") plus `UNKNOWN`. Lives in
  `loki.extraction.detection`.
- **`ToolStatus`** — three values: `AVAILABLE`, `MISSING`, `DEGRADED`.
  Lives in `loki.extraction.tools.base`.

These are internal to the extraction subsystem; they don't ship in
`loki.models` because they're not part of the long-term data contract
that other subsystems consume.

## Error Handling

This section consolidates the error-handling story already touched on
in §Components and Interfaces ("Exception hierarchy") and §Components
and Interfaces ("Tool wrapper boundary").

### What gets raised

Three exception classes leave the subsystem boundary:

- `InvalidInputError` — pre-conditions failed (R1.3, R1.4). Path
  missing, not a regular file, or empty. Carries the offending path
  and a human-readable message.
- `ManifestConstructionError` — the final `ExtractionManifest`
  failed Pydantic validation (R6.6). Carries the field path and the
  underlying `pydantic.ValidationError`.
- `ExtractionPipelineError` — generic fallback parent class for the
  two above plus any subsystem-internal failure that escaped expected
  handling. Callers catching this catch every error the pipeline can
  raise.

### What gets caught and converted

Three tool-wrapper exception classes are caught inside the pipeline
and converted into `ExtractionError` records via
`ManifestBuilder.record_error` (R5.2):

- `ToolTimedOutError` (R4.7, R4.9 — TIMED_OUT precedence)
- `ToolFailedError` (R4.8)
- `ToolWrapperError` — the parent class, used when a wrapper raises
  anything ToolWrapper-shaped that isn't one of the two above.

Per-component pure-Python exceptions (e.g. `struct.error` from a
malformed FFS header) are similarly caught and converted (R5.2,
R5.7) — the pipeline never lets a single bad component abort the
whole run.

### What gets logged at error time

Every `ExtractionError` recorded by `ManifestBuilder.record_error` is
also emitted to the `loki.extraction` logger (R10.3). Default level
is `WARNING`; the allowlist `_ERROR_LEVEL_KINDS` (initially
`{"MANIFEST_VALIDATION", "GLOBAL_TIMEOUT"}`) is logged at `ERROR`.

### Pre/post-condition contract

| Condition | Behavior |
|-----------|----------|
| `path` doesn't exist or isn't a regular file | Raise `InvalidInputError`; no manifest produced (R1.3) |
| `path` is empty | Raise `InvalidInputError`; no manifest produced (R1.4) |
| Required tool (`uefi_firmware`) missing at startup | Raise `ExtractionPipelineError` from the probe step |
| Optional tool missing at startup | Manifest emitted with one informational `ExtractionError` per missing tool (R4.5) |
| Per-component extractor raises | Catch, record error, continue (R5.2) |
| Final manifest fails Pydantic validation | Raise `ManifestConstructionError` (R6.6) |
| Caller-supplied `cancel()` returns True | Stop, emit "extraction cancelled by caller" error, return partial manifest (R9.4) |

## Architecture

### Pipeline flow

Satisfies R1, R5, R9.4. One pass, top to bottom; cancellation
checked between components (R9.4).

```
extract_firmware(path, config, progress, cancel)
  │
  ├── 1. Resolve path, statvfs, regular-file + non-empty check  (R1.2-R1.4)
  │   └── on failure: raise InvalidInputError, do not build a manifest
  │
  ├── 2. Probe optional ToolWrappers, build tools_available map  (R4.4)
  │
  ├── 3. StreamingHasher: SHA-256 over the file in 1 MiB chunks  (R1.7, R8.2)
  │   └── build FirmwareImage(file_path, file_hash, file_size)
  │
  ├── 4. FormatDetector: inspect first 64 KiB                   (R2.1)
  │   └── returns ordered list of (FormatKind, offset, length)  (R2.7)
  │
  ├── 5. For each detected format (outermost first):            (R2.7, R3)
  │     a. select Extractor strategy                            (R2.9, R3.1-R3.5)
  │     b. extractor yields a stream of CarvedComponent objects
  │     c. ManifestBuilder converts each carve → ExtractedComponent
  │        - generates deterministic component_id              (R7.2)
  │        - computes raw_hash via streaming slice              (R3.8, R8.3)
  │        - writes raw_path if default_output_dir set          (R3.12)
  │        - applies max_component_size policy                  (R3.14)
  │        - per-component timeout enforced via timing.py       (R5.9, R8.4)
  │     d. on extractor exception: catch, record ExtractionError,
  │        continue with next component                         (R5.2)
  │     e. cancel() check between components                    (R9.4)
  │
  ├── 6. ManifestBuilder.finalize():                             (R6)
  │     - sort components by integer offset                     (R6.5)
  │     - validate component_id uniqueness                      (R6.2)
  │     - construct ExtractionManifest (Pydantic strict)         (R6.1, R6.3)
  │     - on Pydantic ValidationError: raise ManifestConstructionError
  │
  └── 7. Return ExtractionResult(manifest, tools_available, duration)
```

If detection finds no supported formats, step 5 is skipped and step 6
emits a manifest with `components == []` and a single
"out-of-scope" `ExtractionError` (R2.8).

If the global timeout trips
(`elapsed > 10 × timeout_per_component × len(detected_components)`,
R5.9), step 5 stops, step 6 still runs to produce a partial manifest,
and a single global-timeout `ExtractionError` is appended.

### Format detection

Satisfies R2 in full.

```python
# loki/extraction/detection.py
class FormatKind(StrEnum):
    INTEL_IFD       = "INTEL_IFD"
    UEFI_PI_VOLUME  = "UEFI_PI_VOLUME"
    UEFI_CAPSULE    = "UEFI_CAPSULE"
    PCI_OPTION_ROM  = "PCI_OPTION_ROM"
    INTEL_MICROCODE = "INTEL_MICROCODE"
    UNKNOWN         = "UNKNOWN"


@dataclass(frozen=True)
class DetectedFormat:
    kind: FormatKind
    offset: int        # byte offset into the firmware binary
    length: int | None # known length if header carries it; else None


def detect_formats(buf: bytes, file_size: int) -> list[DetectedFormat]:
    """Inspect the first 64 KiB and return formats ordered outermost-first.

    R2.1: at least 64 KiB inspected via StreamingHasher.peek().
    R2.7: when an outer container nests one of the supported formats
          (e.g. IFD whose BIOS region holds UEFI PI volumes), both the
          outer kind (INTEL_IFD) and the inner kind (UEFI_PI_VOLUME)
          appear in the list, outer first.
    R2.8: returns [DetectedFormat(UNKNOWN, 0, file_size)] if nothing
          matches; ManifestBuilder converts that to the standard
          out-of-scope ExtractionError.
    """
```

Detection signatures (R2.2–2.6):

| Format          | Signature & offset                                         |
|-----------------|------------------------------------------------------------|
| INTEL_IFD       | `0x5A A5 F0 0F` at `0x10` of a 4 KiB-aligned descriptor    |
| UEFI_PI_VOLUME  | `_FVH` (`0x5F 0x46 0x56 0x48`) in `EFI_FIRMWARE_VOLUME_HEADER.Signature` |
| UEFI_CAPSULE    | leading `EFI_CAPSULE_HEADER.CapsuleGuid` matches a known UEFI capsule GUID |
| PCI_OPTION_ROM  | `0x55 0xAA` at start, plus self-consistent PCI Data Structure pointer at `+0x18` |
| INTEL_MICROCODE | header_version=`0x1`, loader_revision=`0x1`, valid `total_size` |

The known-capsule-GUID list lives in `detection.py` as a module-level
`frozenset[str]` of canonical lowercase 8-4-4-4-12 UUIDs. Initial set:
`EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID` (`6dcbd5ed-e82d-4c44-bda1-7194199ad92a`),
`EFI_FMP_CAPSULE_ID_GUID` (`3b8c8162-188c-46a4-aec9-be43f1d65697`), plus
the legacy `EFI_CAPSULE_GUID` (`3b6686bd-0d76-4030-b70e-b5519e2fc5a0`).
Tracked under "Open questions" §15: completeness of the GUID list.

### Extractor architecture

Satisfies R3, R5.7, R5.8.

```python
# loki/extraction/extractors/base.py
class Extractor(Protocol):
    """Protocol every per-format extractor implements.

    An Extractor reads from a file-like object positioned at ``offset``
    and yields ``CarvedComponent`` records. It must be re-entrant
    (multiple extractor strategies can run in series) and must never
    seek before ``offset`` or beyond ``offset + length``.
    """

    name: ClassVar[str]   # e.g. "uefi_volume", "intel_ifd"

    def supports(self, kind: FormatKind) -> bool: ...

    def extract(
        self,
        binary_path: Path,
        offset: int,
        length: int | None,
        ctx: ExtractorContext,
    ) -> Iterator[CarvedComponent]: ...


@dataclass(frozen=True)
class CarvedComponent:
    """Single extractor output before manifest assembly.

    The ManifestBuilder converts this into an ExtractedComponent,
    deriving component_id deterministically (R7.2), computing
    raw_hash via streaming slice (R3.8), and applying the
    max_component_size policy (R3.14).
    """
    offset: int                    # absolute byte offset (R3.6)
    size: int                      # exact byte length (R3.7)
    component_type_hint: str | None
    guid: str | None               # canonical lowercase UUID (R3.10)
    name: str | None               # truncated at first NUL (R3.11)
    decompressed_payload: bytes | None  # only set for compressed-section recovery (R5.8)
```

Per-format strategies:

- **`extractors/ifd.py`**: parses the Intel Flash Descriptor, emits one
  `CarvedComponent` per region (BIOS, ME, GbE, Platform Data, EC,
  …) (R3.2). For the BIOS region, recurses by re-running detection +
  extraction inside the BIOS region's bytes — sub-components are still
  emitted with absolute offsets (R3.6).
- **`extractors/uefi_volume.py`**: walks `EFI_FIRMWARE_VOLUME_HEADER`,
  iterates FFS files, decomposes each file into sections, decompresses
  Tiano and LZMA-Custom GUID-defined sections via `UefiFirmwareWrapper`
  (R3.1), records UI section names (R3.11), and emits one
  `CarvedComponent` per FFS file. When a section decompresses
  successfully, the resulting payload is attached to the parent
  `CarvedComponent.decompressed_payload`; the api orchestrator hashes
  that payload once and walks it via
  `loki.extraction.inner_carve.walk_decompressed_sections`,
  appending one `ExtractedComponent` per UEFI PI section it
  finds (PE32, RAW, UI, COMPRESSION, GUID_DEFINED, etc.) through
  `ManifestBuilder.add_inner_component`. Inner components carry a
  synthetic `source_image_id = uuid5(LOKI_NAMESPACE, decompressed_hash)`
  and a `component_id` derived from the
  `(decompressed_hash, inner_offset, inner_raw_hash)` triple, which
  guarantees stability across runs and prevents collisions with
  outer-component IDs (which derive from the source firmware's hash).
  Compressed sections that fail decompression generate an
  `ExtractionError` *and* still emit the outer compressed-section
  component with `raw_hash` covering the on-disk compressed bytes
  (R5.8). Inner-component bytes are written to disk under the
  configured `output_dir` with filename
  `0x{parent_offset:x}-decompressed-0x{inner_offset:x}-{inner_raw_hash}.bin`
  when an output directory is set; otherwise only the manifest entry
  is produced. The walk is one level deep — UEFI PI sections inside
  the decompressed buffer become inner components, but recursive FFS
  or capsule walks of the decompressed payload are out of scope until
  a fixture demands them.
- **`extractors/ffs.py`**: handles raw FFS blobs (no enclosing PI
  volume) by reusing the FFS section walker from `uefi_volume.py`.
- **`extractors/capsule.py`**: parses `EFI_CAPSULE_HEADER`, emits one
  `CarvedComponent` for the capsule body, then recurses with the
  detector on the body for embedded UEFI PI volumes (R3.3).
- **`extractors/option_rom.py`**: walks chained PCI Data Structures,
  emits one `CarvedComponent` per code image, sets
  `component_type_hint` from the PCI DS `code_type` field (legacy x86
  vs UEFI vs OFW) (R3.4).
- **`extractors/microcode.py`**: walks concatenated microcode update
  blobs, sets `component_type_hint = "INTEL_MICROCODE"`, sets
  `name = f"CPUID={cpuid:08x} REV={revision:08x}"` (R3.5).

Each extractor depends on the `uefi_firmware` package via the
required `UefiFirmwareWrapper` (see §8). The microcode and
option-ROM extractors are pure-Python, no third-party tool needed.

### Tool wrapper boundary

Satisfies R4.1–4.10.

All third-party tool access is funneled through `loki.extraction.tools`.
No other module in `loki.extraction` imports `subprocess`, `shutil.which`,
`uefi_firmware`, or `chipsec`.

```python
# loki/extraction/tools/base.py
class ToolStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING   = "MISSING"
    DEGRADED  = "DEGRADED"  # importable but version unknown / probe failed


class ToolWrapper(Protocol):
    name: ClassVar[str]
    required: ClassVar[bool]

    def probe(self) -> ToolStatus: ...
    def shutdown(self) -> None: ...  # idempotent cleanup


class SubprocessToolWrapper(ABC, ToolWrapper):
    """Base for wrappers that spawn external CLI tools (UEFITool, chipsec).

    Enforces R4.6 (argument list, no shell) and R4.7-4.9 (typed
    TIMED_OUT vs FAILED status with TIMED_OUT precedence) by
    centralizing subprocess.run() invocation.
    """

    def run_subprocess(
        self,
        argv: list[str],
        *,
        timeout_seconds: float,
        scratch_dir: Path,
    ) -> subprocess.CompletedProcess[bytes]:
        ...
```

Concrete wrappers:

- **`UefiFirmwareWrapper`** (`tools/uefi_firmware.py`) — `required = True`.
  Wraps the `uefi_firmware` Python package (declared in
  `pyproject.toml` as `uefi_firmware>=1.10`, R4.2). No subprocess.
  Probes by attempting `import uefi_firmware`; if the import fails the
  pipeline cannot proceed and `extract_firmware` raises an
  `ExtractionPipelineError` from the import probe step. (Required-tool
  absence is *not* a recoverable degraded mode; R4.5's fallback only
  applies to optional tools.)
- **`UefitoolWrapper`** (`tools/uefitool.py`) — `required = False`.
  Wraps the `UEFITool` CLI (`UEFIExtract`) when present on `$PATH`.
  Probes via `shutil.which("UEFIExtract")`. If absent, the pipeline
  records one informational `ExtractionError` per missing optional
  tool (R4.5) and falls back to the `uefi_firmware` Python parser.
- **`ChipsecWrapper`** (`tools/chipsec.py`) — `required = False`.
  Wraps the `chipsec_util` CLI when present on `$PATH`. Same probe
  and fallback pattern as `UefitoolWrapper`.

#### TIMED_OUT vs FAILED precedence

Implements R4.7–4.9.

```python
def run_subprocess(self, argv, *, timeout_seconds, scratch_dir):
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout_seconds,
            cwd=scratch_dir,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # R4.7: TIMED_OUT path. Capture stderr collected before timeout.
        raise ToolTimedOutError(
            tool_name=self.name,
            status="TIMED_OUT",
            exit_status=None,
            stderr_excerpt=_redact(exc.stderr or b""),
            timeout_seconds=timeout_seconds,
        ) from exc
    if proc.returncode != 0:
        # R4.8: FAILED path. R4.9 cannot apply — we did not time out.
        raise ToolFailedError(
            tool_name=self.name,
            status="FAILED",
            exit_status=proc.returncode,
            stderr_excerpt=_redact(proc.stderr),
        )
    return proc
```

R4.9 (subprocess both timed out and exited non-zero) is handled by the
Python stdlib semantics: `subprocess.run(timeout=…)` raises
`TimeoutExpired` *before* observing the exit status when the timeout
trips. The `TIMED_OUT` branch above runs and the `FAILED` branch is
never reached, so TIMED_OUT precedence is automatic. The corresponding
`ExtractionError.error_message` is constructed as
`f"{self.name} timed out after {timeout_seconds:.1f}s; stderr: {stderr_excerpt}"`
and explicitly does *not* include any post-timeout exit status.

#### Stderr redaction

The wrapper-level `_redact()` helper enforces R4.7's "redacted excerpt"
phrase and R10.5's no-leakage rule:

- Keeps at most 512 bytes of the raw stderr.
- Strips ASCII control characters except newlines.
- Replaces any byte sequence that decodes as a path under
  `scratch_dir` with the literal string `<scratch>/...`.
- Replaces any 32-character or 64-character hex run with
  `<hash:N>` (where `N` is the original length).

Open question §15: whether to strip embedded GUIDs from stderr too.
Initial decision: leave GUIDs visible because they're useful for
debugging and aren't sensitive. Revisit if a real-world tool's stderr
proves otherwise.

#### Tool I/O sandbox

R4.10 is enforced by passing `cwd=scratch_dir` to every subprocess and
by routing every read / write the tool needs through the wrapper.
`scratch_dir` is created under
`tempfile.mkdtemp(prefix="loki-extract-")`, owned by the pipeline,
deleted in a `finally` block when extraction returns. The
`default_output_dir` from `ExtractionConfig` is the *only* other path
the pipeline writes to.

### Streaming hash and slice utilities

Satisfies R1.7, R3.8, R8.2, R8.3.

```python
# loki/extraction/streaming.py
class StreamingHasher:
    """Compute SHA-256 in 1 MiB chunks, peek at the leading window."""

    CHUNK_SIZE = 1 << 20   # 1 MiB (R8.2)
    PEEK_SIZE  = 1 << 16   # 64 KiB (R2.1)

    def __init__(self, path: Path) -> None: ...

    def hash_file(self) -> tuple[str, int, bytes]:
        """Return (file_hash_hex, file_size, peek_bytes).

        peek_bytes is the first PEEK_SIZE bytes (or the whole file if
        smaller) — passed to FormatDetector and never logged (R10.5).
        """


def streaming_sha256_slice(path: Path, offset: int, size: int) -> str:
    """SHA-256 of [offset, offset+size) read in 1 MiB chunks.

    Used by ManifestBuilder when computing ExtractedComponent.raw_hash
    so the carved bytes never need to be held in memory all at once
    (R8.3).
    """
```

Memory budget per R8.1:

```
peak_resident_memory ≤ 4 × max_component_size + 128 MiB working set
```

The `4 × max_component_size` allowance covers: one component currently
being decompressed, one previous component awaiting raw_hash flushing
to disk, plus headroom for `uefi_firmware`'s internal state. The
128 MiB working set covers the Python interpreter, Pydantic, logging
buffers, and the `uefi_firmware` import.

## Correctness Properties

This section enumerates the invariants the extraction subsystem
guarantees. Each property maps directly to a Hypothesis-backed test
in `tests/extraction/test_determinism.py` or
`tests/extraction/test_manifest_invariants.py` (see Testing Strategy
for the full mapping). Numbering continues from the model layer's
spec (which owns Properties 1–11) so cross-references are unambiguous.

### Property 12: Manifest is Pydantic-validated on return

For every input that survives Requirement 1's input checks,
`extract_firmware` returns an `ExtractionResult` whose `manifest`
field has passed `ExtractionManifest`'s Pydantic v2 strict validators.
Any caller can use the manifest without re-validating.

**Validates: Requirements 6.1**

### Property 13: total_components matches components length

For every returned manifest, `manifest.total_components ==
len(manifest.components)`. The model layer enforces this via its
`_compute_total_components` validator; the property restates it at
the extraction level so a regression in the builder is caught here
too.

**Validates: Requirements 6.3**

### Property 14: component_id is unique within a manifest

For every returned manifest,
`len({c.component_id for c in manifest.components}) ==
len(manifest.components)`. The builder asserts this before
constructing the manifest; if violated, `ManifestConstructionError`
is raised.

**Validates: Requirements 6.2**

### Property 15: components are ordered by ascending offset

For every returned manifest, the integer values of
`int(c.offset, 16)` are non-decreasing across `manifest.components`.
Allows downstream consumers to rely on positional ordering (e.g.
binary search by offset, range queries).

**Validates: Requirements 6.5**

### Property 16: manifest round-trips losslessly through JSON

For every returned manifest `m`,
`ExtractionManifest.model_validate_json(m.model_dump_json()) == m`.
The model layer already covers this for arbitrary instances; the
extraction PBT pins it specifically against pipeline-produced
instances so any extractor-introduced shape drift is caught.

**Validates: Requirements 6.7, 7.6**

### Property 17: manifest round-trips losslessly through YAML

For every returned manifest `m`,
`ExtractionManifest.model_validate(yaml.safe_load(yaml.safe_dump(m.model_dump(mode="json")))) == m`.
Same shape as Property 16 but through the YAML path.

**Validates: Requirements 6.7**

### Property 18: extraction is deterministic modulo timestamps

For every input `(path, config)`, two invocations of
`extract_firmware(path, config)` produce manifests that are equal
under `model_dump()` after stripping
`extraction_timestamp` from the manifest, the
`source_image.extraction_timestamp` from the embedded image, and
every `extraction_errors[i].timestamp`.

**Validates: Requirements 7.1**

### Property 19: component_id is derived deterministically

For every successfully carved component, the emitted `component_id`
equals `uuid5(LOKI_NAMESPACE, f"{source_image.file_hash}:0x{offset:x}:{raw_hash}")`.
Two extractions of the same input yield the same `component_id`
sequence.

**Validates: Requirements 7.2**

### Property 20: error_id is derived deterministically

For every per-component `ExtractionError` (one with non-None
`component_id`), the emitted `component_id` equals
`uuid5(LOKI_NAMESPACE, f"{source_image.file_hash}:0x{offset:x}:err:{error_kind}")`.
Two extractions of the same broken input yield the same error-id
sequence.

**Validates: Requirements 7.3**

### Property 21: output filenames are pure functions of (offset, raw_hash)

When `default_output_dir` is set, every written component's filename
matches `^0x[0-9a-f]+-[0-9a-f]{64}\.bin$` and equals
`f"0x{offset:x}-{raw_hash}.bin"`. The same component bytes at the
same offset always produce the same filename.

**Validates: Requirements 7.4**

### Property 22: no environmental side channels

The extraction subsystem does not consult environment variables, the
random number generator, the network, or the system clock for any
decision that affects manifest contents. Enforced by an AST audit
test (`test_no_side_channels.py`) that walks
`loki.extraction.__path__` and fails on any forbidden import or
attribute access.

**Validates: Requirements 7.5**

### Determinism contract — implementation

#### Deterministic component_id

```python
# loki/extraction/ids.py
import uuid
from loki.models import LOKI_NAMESPACE

def derive_component_id(
    *, source_image_hash: str, offset: int, raw_hash: str
) -> uuid.UUID:
    """R7.2: uuid5(LOKI_NAMESPACE, source_image_hash + ":" + offset + ":" + raw_hash).

    The string format MUST be exactly:
        f"{source_image_hash}:0x{offset:x}:{raw_hash}"

    Both hashes are 64-char lowercase hex (already normalized by
    StreamingHasher and streaming_sha256_slice). The offset is
    rendered with the same `0x{n:x}` format the model uses for
    ExtractedComponent.offset. Anything else risks producing
    different UUIDs for the same content.
    """
    payload = f"{source_image_hash}:0x{offset:x}:{raw_hash}"
    return uuid.uuid5(LOKI_NAMESPACE, payload)


def derive_error_component_id(
    *, source_image_hash: str, offset: int, error_kind: str
) -> uuid.UUID:
    """R7.3: stable identity for per-component errors when the
    component itself wasn't carved (so raw_hash is unavailable).

    Uses error_kind as the placeholder hash so two different
    failures at the same offset don't collide.
    """
    payload = f"{source_image_hash}:0x{offset:x}:err:{error_kind}"
    return uuid.uuid5(LOKI_NAMESPACE, payload)
```

#### Deterministic output filenames

R7.4: each component written to `default_output_dir` is named
`f"{offset_hex}-{raw_hash}.bin"` where `offset_hex = f"0x{offset:x}"`.
The filename is a pure function of position and content; the same
binary always produces the same filenames.

#### No side channels

R7.5 is enforced by the architecture:

- `loki.extraction` does not import `os.environ`, `time` (other than
  through `timing.py` for the wall-clock timestamps explicitly
  permitted by R7.1), `random`, `secrets`, `socket`, `urllib`,
  `requests`, or `httpx`.
- A unit test in `tests/extraction/test_no_side_channels.py` asserts
  this by walking `loki.extraction.__path__` with `ast.parse` and
  failing on any forbidden import.

#### Stable manifest serialization

R6.7, R7.6: the returned `ExtractionManifest` round-trips through both
`model_dump_json` + `model_validate_json` and
`yaml.safe_dump(model_dump(mode="json"))` + `model_validate(yaml.safe_load(...))`.
The model layer's existing PBT for round-trip already covers this; the
extraction PBT (§13.2 invariant E2) restates the property over
extractor-produced manifests specifically.

### ManifestBuilder

Satisfies R5, R6.

```python
# loki/extraction/manifest.py
class ManifestBuilder:
    """Accumulates components and errors, then constructs the manifest."""

    def __init__(self, *, source_image: FirmwareImage,
                 extractor_version: str, started_at: datetime) -> None: ...

    def add_component(self, carved: CarvedComponent,
                      *, raw_path: Path | None) -> None:
        """Append a carved component as ExtractedComponent.

        - Computes raw_hash via streaming_sha256_slice (R3.8)
        - Derives component_id via derive_component_id (R7.2)
        - Validates size > 0 and offset format (delegated to model)
        - Skips + records error if size > max_component_size (R3.14)
        """

    def record_error(self, *, error_kind: str, message: str,
                     offset: int | None,
                     component_id: uuid.UUID | None = None) -> None:
        """Append an ExtractionError. R5.2-5.6.

        - When component_id is None and offset is not None, derive a
          stable component_id via derive_error_component_id (R7.3).
        - When the error is whole-file or whole-region (offset is
          None), leave component_id as None (R5.5).
        - timestamp is set to datetime.now(tz=UTC) at the moment
          record_error is called (R5.6).
        """

    def finalize(self) -> ExtractionManifest:
        """Produce the validated manifest.

        - Sorts self._components by integer offset (R6.5)
        - Asserts component_id uniqueness (R6.2); duplicates raise
          ManifestConstructionError before Pydantic ever sees them
        - Constructs ExtractionManifest(...); on Pydantic
          ValidationError raises ManifestConstructionError naming
          the offending field path (R6.6)
        - Returns the validated manifest (R6.1, R6.3 enforced by
          ExtractionManifest's own validators)
        """
```

## Logging strategy

Satisfies R10.

- Logger name: `loki.extraction` (R9.6, R10).
- All `logging.Logger` instances are obtained via
  `logging.getLogger("loki.extraction.<module-name>")`. The module
  hierarchy gives consumers per-component filtering for free.
- The pipeline never installs handlers, never sets levels on its own
  loggers, and never logs to stdout / stderr directly.
- Run-start log (R10.1):
  `logger.info("extraction starting path=%s size=%d head=%s", path, size, head_hex)`
  where `head_hex` is exactly 16 hex chars (8 bytes lowercase).
- Format-detected log (R10.2): one INFO record per
  `DetectedFormat` containing `kind` and `offset`.
- Error log (R10.3): every `ExtractionError` recorded by
  `ManifestBuilder.record_error` is mirrored to a `logger.warning` (or
  `logger.error` if `error_kind` is in the
  `_ERROR_LEVEL_KINDS` allowlist, e.g. `MANIFEST_VALIDATION`,
  `GLOBAL_TIMEOUT`).
- Run-finished log (R10.4):
  `logger.info("extraction finished duration=%.3fs components=%d errors=%d", ...)`.

R10.5 is enforced two ways:

- **At source.** No log message in `loki.extraction` may include any
  of: raw component bytes, decompressed bytes, embedded strings
  (UI section names are exposed via the manifest; the *log* doesn't
  reproduce them), or any portion of the firmware binary other than
  the leading 8-byte hex preview.
- **At test.** A unit test in
  `tests/extraction/test_log_no_leakage.py` runs a curated extraction
  with a `logging.Handler` capturing every emitted record and asserts
  that no record's formatted message contains any of: substrings of
  the input file beyond the leading 16 hex chars, decompressed
  payloads, or any UI section names from the test fixture's manifest.
  The handler is also active during pipeline init, probe, and
  shutdown — covering R10.5's "at any time" clause.

## Testing Strategy

Test layout mirrors source:

```
tests/extraction/
├── __init__.py
├── conftest.py                     # synthetic-binary fixtures, scratch_dir
├── fixtures/
│   ├── README.md                   # how to obtain real-ish test binaries
│   ├── synthetic_uefi_volume.py    # builds a tiny but valid PI volume
│   ├── synthetic_option_rom.py     # builds a tiny but valid option ROM
│   └── synthetic_microcode.py      # builds a tiny but valid microcode blob
├── test_api_contract.py            # extract_firmware signature, exceptions
├── test_input_handling.py          # R1
├── test_format_detection.py        # R2
├── test_extractors_uefi.py         # R3.1
├── test_extractors_ifd.py          # R3.2
├── test_extractors_capsule.py      # R3.3
├── test_extractors_option_rom.py   # R3.4
├── test_extractors_microcode.py    # R3.5
├── test_tool_wrappers.py           # R4
├── test_failure_modes.py           # R5
├── test_manifest_invariants.py     # R6 (PBT)
├── test_determinism.py             # R7 (PBT)
├── test_performance.py             # R8 (skip-on-CI for slow cases)
├── test_integration_surface.py     # R9
├── test_no_side_channels.py        # R7.5 / static import audit
└── test_log_no_leakage.py          # R10.5 / dynamic capture audit
```

### Unit tests

- One module per extractor, each with at minimum:
  - "happy path on a synthetic binary" (table-driven)
  - "header CRC mismatch produces ExtractionError, doesn't abort"
  - "compressed section that fails decompression still emits the
    outer component" (R5.8 specifically)
- `test_tool_wrappers.py` mocks `subprocess.run` with three
  scenarios: success, `subprocess.TimeoutExpired`, non-zero exit.
  Each scenario asserts the right exception type is raised
  (R4.7-4.9) and the resulting `ExtractionError` carries the
  expected message format.

### Property-based tests (Hypothesis)

Mirrors the model layer's PBT pattern. Each invariant gets at least
one Hypothesis-backed test:

| ID | Invariant | Citation |
|----|-----------|----------|
| E1 | Output is a Pydantic-validated `ExtractionManifest` | R6.1 |
| E2 | `manifest.total_components == len(manifest.components)` | R6.3 |
| E3 | Every `component_id` in the manifest is unique | R6.2 |
| E4 | Components are ordered by ascending integer offset | R6.5 |
| E5 | Manifest round-trips through JSON without data loss | R6.7, R7.6 |
| E6 | Manifest round-trips through YAML without data loss | R6.7 |
| E7 | Same input + same config → identical manifest modulo timestamps | R7.1 |
| E8 | Same input + same config → identical component_id sequence | R7.2 |
| E9 | Same input + same config → identical error_id sequence | R7.3 |
| E10 | Output filenames are pure functions of (offset, raw_hash) | R7.4 |

Strategies live in `tests/extraction/conftest.py`. The synthetic
binary builders in `tests/extraction/fixtures/` are the inputs;
Hypothesis composes binaries from them by varying the count and
order of sub-components.

### Golden-file tests

- One small (~32 KiB) hand-crafted UEFI PI volume binary checked
  in under `tests/extraction/fixtures/golden/`. Asserts the manifest
  it produces matches a checked-in JSON snapshot exactly (modulo
  timestamps). This catches accidental changes to extractor
  output format.
- The golden binary is generated by `synthetic_uefi_volume.py` and
  the script is committed alongside the binary so the binary can be
  regenerated.

### What's deliberately not tested

- Real-world vendor firmware (vendor confidentiality, license terms,
  size). Documented in `tests/extraction/fixtures/README.md` with
  pointers to public corpora analysts can use locally.
- Network behavior — the pipeline doesn't have any.
- GUI integration — covered by the GUI's own test suite when the
  Extraction view stops being a placeholder.

## Deferred decisions and open questions

Tracked here so future sessions don't re-derive answers.

1. **Capsule GUID list completeness.** The initial list in §6 covers
   the GUIDs published in UEFI 2.10 plus the legacy capsule GUID.
   Vendors ship private capsule GUIDs that aren't in the spec. Open
   question: how to handle a capsule whose GUID isn't recognized.
   Initial decision: treat as `UNKNOWN` and emit the standard
   out-of-scope error (R2.8). Revisit when we encounter real-world
   firmware that hits this case.
2. **Stderr GUID redaction.** §8.2 keeps GUIDs visible. Revisit if
   real-world tool stderr proves to leak sensitive content via GUID
   sequences.
3. **`uefi_firmware-parser` version pin.** Initial pin is
   `uefi_firmware>=1.10` (current release as of authoring). The
   wrapper's probe will record the resolved version in
   `tools_available["uefi_firmware"]` for diagnostics. If the
   library's API breaks on a minor release, pin tighter.
4. **Per-component timeout enforcement.** The Python stdlib does not
   provide cooperative cancellation for pure-Python work. The
   per-component timer in `timing.py` enforces wall-clock limits
   for *subprocess* tools (via `subprocess.run(timeout=…)`) and for
   pure-Python extractors via a coarse `time.monotonic()` check at
   each component boundary. Truly hung pure-Python extractors won't
   be killable in v1; the global timeout (R5.9) is the safety net.
5. **Tool wrapper observability beyond ExtractionError.** Whether
   `tools_available` should also surface tool *version* strings.
   Initial decision: yes, when cheap to obtain. Wrapper-specific.

## Traceability matrix

| Requirement | Design section(s) |
|-------------|-------------------|
| R1.1–R1.10  | §4.2, §5, §9 |
| R2.1–R2.10  | §6 |
| R3.1–R3.14  | §7, §11 |
| R4.1–R4.10  | §8, §8.1, §8.2, §8.3 |
| R5.1–R5.9   | §5, §11 (`ManifestBuilder.record_error`), §8.1 |
| R6.1–R6.7   | §11 (`ManifestBuilder.finalize`), §10.4 |
| R7.1–R7.6   | §10 |
| R8.1–R8.5   | §9, §5 (synchronous flow) |
| R9.1–R9.7   | §4.2, §5 (cancel checks), §8 (no PyQt6 imports) |
| R10.1–R10.5 | §12 |

Every acceptance criterion has at least one design section it maps
to, and every design section cites at least one acceptance criterion
it satisfies. Sections that introduce structure not directly required
(e.g. the `tools_available` map in §4.2) are kept minimal and
justified in the surrounding prose.
