# Requirements Document

## Introduction

The Extraction Pipeline is the LOKI subsystem that turns a real firmware
binary on disk into a validated `ExtractionManifest`. It is the first
subsystem downstream of the shared data model layer (`loki/models/`) and
is the source of truth for every later stage: classification,
baselining, and analysis all consume the manifests this pipeline
produces.

This spec covers extraction only. Classification of components into the
four LOKI taxonomic axes (type, vendor, security posture, mutability),
baseline comparison, and analysis are explicitly out of scope and will
be specced separately. The pipeline's job ends when an
`ExtractionManifest` containing zero or more `ExtractedComponent`
records and any `ExtractionError` records has been validated and
returned to the caller.

The pipeline is consumed by:

- The `loki gui` desktop app — the "Extraction" tab in the workspace
  is currently a scaffolded placeholder. This subsystem is what makes
  that tab show real data.
- A future `loki extract` CLI subcommand (separately specced as part
  of the CLI work).
- Tests and demo-data builders in `loki/gui/demo/` once real
  extraction exists alongside synthetic manifests.

The pipeline operates on the firmware container formats commonly seen
on x86 PC and server hardware: UEFI / Platform Initialization (PI)
firmware volumes, Intel Flash Descriptor (IFD)-described full SPI
images, Firmware File System (FFS) blobs, UEFI capsule update
payloads, PCI option ROMs, and Intel CPU microcode update binaries.
Every other format is deferred to a later version.

The pipeline is required to be deterministic given the same input —
the same firmware binary must always produce the same
`ExtractionManifest` (modulo wall-clock timestamps), so that property-
based tests, baselining, and reproducible analysis are all possible.

## Glossary

- **Extraction_Pipeline**: The subsystem specified by this document.
  The single public callable that takes a firmware binary path and
  returns a validated `ExtractionManifest`.
- **Format_Detector**: The internal component of the
  Extraction_Pipeline that inspects binary headers and magic bytes
  to determine which container format(s) a firmware image uses.
- **Extractor**: A single format-specific component-extraction
  strategy (e.g., a UEFI volume extractor, an option ROM extractor).
  The Extraction_Pipeline dispatches to one or more Extractors based
  on Format_Detector output.
- **Tool_Wrapper**: An adapter around a third-party firmware-parsing
  tool (UEFITool, `uefi_firmware-parser`, `chipsec`) that exposes
  the tool's output in terms of the LOKI model contract. Tool_Wrappers
  are the only place in the pipeline that handle subprocesses or
  third-party APIs.
- **Firmware_Binary**: The raw input file on disk. Sizes range from
  a few hundred KB (option ROM) to several hundred MB (full SPI flash
  dump for a server platform).
- **Component**: A discrete unit of firmware that the pipeline can
  identify and split out of a Firmware_Binary — an FFS file, a PE32
  driver inside a DXE volume, an option ROM, a microcode update
  blob, etc. Each Component becomes one `ExtractedComponent` record.
- **Manifest**: An `ExtractionManifest` instance, as defined in
  `loki/models/firmware.py`. The single output of one extraction run.
- **Determinism**: The property that two extraction runs over the
  same Firmware_Binary, with the same Extraction_Pipeline version
  and configuration, produce manifests that are equal except for
  wall-clock timestamp fields and, where applicable, the path
  written to `raw_path`.
- **Streaming_Read**: Reading a Firmware_Binary in bounded-size
  chunks rather than loading the entire file into memory. Required
  for hashing and for any extractor whose output size scales with
  input size.
- **Out_Of_Scope_Format**: Any firmware container format not listed
  in Requirement 2's v1 support table. Examples: ARM Trusted
  Firmware images, Coreboot CBFS, Apple iBoot images, Android boot
  images, vendor-proprietary capsule wrappers without a published
  parser.

## Requirements

### Requirement 1: Input handling and pipeline entry point

**User Story:** As a LOKI consumer (GUI tab, future CLI command, or
test harness), I want a single typed entry point that accepts a path
to a firmware binary and returns a validated `ExtractionManifest`,
so that I can run extraction without knowing which container formats
or third-party tools are involved.

#### Acceptance Criteria

1. THE Extraction_Pipeline SHALL expose exactly one public entry
   point that accepts a `pathlib.Path` to a firmware binary and an
   `ExtractionConfig` instance, and returns an `ExtractionManifest`
   instance.
2. WHEN the entry point is called, THE Extraction_Pipeline SHALL
   validate that the supplied path refers to an existing regular
   file before performing any extraction work.
3. IF the supplied path does not exist or does not refer to a
   regular file, THEN THE Extraction_Pipeline SHALL raise a typed
   exception that carries the offending path and a human-readable
   message, and SHALL NOT produce a partial `ExtractionManifest`.
4. IF the supplied file is empty (zero bytes), THEN THE
   Extraction_Pipeline SHALL raise a typed exception that carries
   the offending path and a human-readable message.
5. WHEN the entry point is called with a Firmware_Binary larger
   than `ExtractionConfig.max_component_size` × 64, THE
   Extraction_Pipeline SHALL refuse to load the file in memory and
   SHALL use Streaming_Read for hashing and component carving.
6. WHEN the entry point completes successfully, THE
   Extraction_Pipeline SHALL return an `ExtractionManifest` whose
   `source_image.file_path` equals the absolute path of the input
   file.
7. WHEN the entry point completes successfully, THE
   Extraction_Pipeline SHALL populate
   `ExtractionManifest.source_image.file_hash` with the
   lower-case 64-character SHA-256 of the input file bytes,
   computed via Streaming_Read.
8. WHEN the entry point completes successfully, THE
   Extraction_Pipeline SHALL populate
   `ExtractionManifest.source_image.file_size` with the byte count
   of the input file.
9. WHEN the entry point completes successfully, THE
   Extraction_Pipeline SHALL populate
   `ExtractionManifest.extractor_version` with the
   Extraction_Pipeline's own semantic version string in
   `^\d+\.\d+\.\d+$` form.
10. WHEN the entry point completes successfully, THE
    Extraction_Pipeline SHALL populate
    `ExtractionManifest.extraction_timestamp` with the UTC wall-clock
    time at which extraction finished.

### Requirement 2: Format detection and v1 supported container set

**User Story:** As a firmware analyst, I want the pipeline to
correctly identify which container format(s) a binary uses before
attempting extraction, so that the right Extractor runs and unknown
formats are reported instead of producing garbage components.

#### Acceptance Criteria

1. WHEN the entry point receives a Firmware_Binary, THE
   Format_Detector SHALL inspect at least the first 64 KiB of the
   binary using Streaming_Read and SHALL identify every supported
   container format whose signature is present.
2. THE Format_Detector SHALL recognize Intel Flash Descriptor
   images by the `0x5A A5 F0 0F` flash valid signature at offset
   `0x10` within a 4 KiB-aligned descriptor region.
3. THE Format_Detector SHALL recognize UEFI Platform Initialization
   firmware volumes by the `_FVH` signature in the
   `EFI_FIRMWARE_VOLUME_HEADER` structure.
4. THE Format_Detector SHALL recognize UEFI capsule images by a
   leading `EFI_CAPSULE_HEADER` whose `CapsuleGuid` matches one of
   the standard UEFI capsule GUIDs published in the UEFI
   specification.
5. THE Format_Detector SHALL recognize PCI option ROM images by
   the `0x55 0xAA` signature at the start of the candidate region
   together with a self-consistent PCI Data Structure pointer.
6. THE Format_Detector SHALL recognize Intel CPU microcode update
   blobs by the microcode update header layout defined in the
   Intel Software Developer's Manual (header version `0x1`,
   loader revision `0x1`, valid total size).
7. WHEN a Firmware_Binary contains a known wrapper around one of
   the formats above (for example, an Intel IFD image whose BIOS
   region contains UEFI PI volumes), THE Format_Detector SHALL
   report all formats recognized at all nesting levels it has
   inspected, ordered outermost-first.
8. IF the Format_Detector cannot recognize any supported format
   in the inspected bytes, THEN THE Extraction_Pipeline SHALL
   produce an `ExtractionManifest` with `components == []` and a
   single `ExtractionError` whose `error_message` identifies the
   binary as an Out_Of_Scope_Format and lists the byte offsets and
   lengths inspected.
9. WHERE the Firmware_Binary is identified as one of the v1
   supported formats listed in this requirement (Intel IFD-described
   image, UEFI PI firmware volume, raw FFS blob, UEFI capsule, PCI
   option ROM, Intel microcode update), THE Extraction_Pipeline
   SHALL dispatch to the corresponding Extractor.
10. THE Extraction_Pipeline SHALL NOT, in v1, attempt extraction of
    Coreboot CBFS images, ARM Trusted Firmware images, Apple
    iBoot/SecureROM images, Android boot images, or vendor-
    proprietary capsule wrappers; these are deferred and SHALL be
    reported per acceptance criterion 2.8.

### Requirement 3: Component extraction for v1 supported formats

**User Story:** As a firmware analyst, I want each recognized
container to be carved into individual components with offsets,
sizes, and content hashes, so that downstream classification and
analysis have a stable, addressable unit of work.

#### Acceptance Criteria

1. WHEN the Extraction_Pipeline dispatches to a UEFI PI volume
   Extractor, THE Extractor SHALL produce one `ExtractedComponent`
   per FFS file inside the volume, including PEI modules, DXE
   drivers, SMM modules, runtime drivers, raw sections, and
   compressed sections that the Extractor can decompress with the
   standard UEFI compression algorithms (Tiano and LZMA).
2. WHEN the Extraction_Pipeline dispatches to an Intel IFD
   Extractor, THE Extractor SHALL emit one `ExtractedComponent`
   per IFD region (BIOS, ME, GbE, Platform Data, EC, and any
   other regions present in the descriptor) and SHALL recurse
   into the BIOS region to extract its inner UEFI PI volumes.
3. WHEN the Extraction_Pipeline dispatches to a UEFI capsule
   Extractor, THE Extractor SHALL emit one `ExtractedComponent`
   for the capsule body and SHALL recurse into any embedded UEFI
   PI volumes the body contains.
4. WHEN the Extraction_Pipeline dispatches to a PCI option ROM
   Extractor, THE Extractor SHALL emit one `ExtractedComponent`
   per code image in the ROM (handling multi-image ROMs with
   chained PCI Data Structures), and SHALL set
   `component_type_hint` to identify each image's code type
   (legacy x86, EFI, etc.).
5. WHEN the Extraction_Pipeline dispatches to a microcode
   Extractor, THE Extractor SHALL emit one `ExtractedComponent`
   per microcode update blob in the file (handling concatenated
   updates), with `component_type_hint` set to identify the blob
   as a microcode update and the GUID/CPUID metadata recorded in
   `name`.
6. THE Extraction_Pipeline SHALL set every emitted
   `ExtractedComponent.offset` to the absolute byte offset of the
   component within the original Firmware_Binary, in
   `^0x[0-9a-fA-F]+$` form.
7. THE Extraction_Pipeline SHALL set every emitted
   `ExtractedComponent.size` to the exact byte length of the
   carved component as it lives in the Firmware_Binary, with
   `size > 0`.
8. THE Extraction_Pipeline SHALL set every emitted
   `ExtractedComponent.raw_hash` to the lower-case 64-character
   SHA-256 of the carved component bytes.
9. THE Extraction_Pipeline SHALL set every emitted
   `ExtractedComponent.source_image_id` equal to
   `ExtractionManifest.source_image.image_id`.
10. WHERE a UEFI FFS file carries a GUID, THE Extraction_Pipeline
    SHALL record that GUID in `ExtractedComponent.guid` in
    canonical lower-case `8-4-4-4-12` UUID form.
11. WHERE a component has an embedded UI section name (UEFI FFS
    `EFI_SECTION_USER_INTERFACE`) or another vendor-supplied
    label, THE Extraction_Pipeline SHALL record that label in
    `ExtractedComponent.name` exactly as it appears in the binary,
    truncating only at the first NUL byte.
12. WHERE the Extraction_Pipeline is configured with a
    `default_output_dir`, THE Extraction_Pipeline SHALL write each
    component's raw bytes to a file under that directory and SHALL
    record the absolute path in `ExtractedComponent.raw_path`.
13. WHERE no `default_output_dir` is configured or the directory is
    not writable, THE Extraction_Pipeline SHALL leave
    `ExtractedComponent.raw_path` set to `None` and SHALL still
    populate every other field of the component.
14. IF a single component's reported size exceeds
    `ExtractionConfig.max_component_size`, THEN THE
    Extraction_Pipeline SHALL skip that component, emit an
    `ExtractionError` referencing the would-be component's offset,
    and continue extraction.

### Requirement 4: Third-party tool integration

**User Story:** As a maintainer, I want the boundary between LOKI's
own code and third-party firmware-parsing tools to be explicit and
enforceable, so that I can swap a tool, mock it in tests, or
gracefully degrade when a tool is missing without scattering
subprocess calls through the codebase.

#### Acceptance Criteria

1. THE Extraction_Pipeline SHALL access every third-party firmware-
   parsing tool (UEFITool, `uefi_firmware-parser`, `chipsec`)
   exclusively through a Tool_Wrapper class.
2. THE Extraction_Pipeline SHALL treat the
   `uefi_firmware-parser` Python library as a required dependency
   and SHALL declare it in `pyproject.toml`.
3. THE Extraction_Pipeline SHALL treat UEFITool and `chipsec` as
   optional dependencies that the Tool_Wrapper resolves at runtime.
4. WHEN the Extraction_Pipeline starts, THE Extraction_Pipeline
   SHALL probe each optional Tool_Wrapper for availability and
   SHALL record which tools are present in pipeline-internal
   diagnostics.
5. IF an optional Tool_Wrapper's underlying tool is absent at
   extraction time, THEN THE Extraction_Pipeline SHALL fall back
   to the required Python-only Extractor for that format and
   SHALL emit one informational `ExtractionError` per missing
   tool, recording the tool name in `error_message`.
6. WHEN a Tool_Wrapper invokes a subprocess, THE Tool_Wrapper
   SHALL pass arguments as an explicit list (never via shell
   interpolation) and SHALL apply the per-component timeout from
   `ExtractionConfig.timeout_per_component`.
7. IF a Tool_Wrapper subprocess times out, THEN THE Tool_Wrapper
   SHALL raise a typed wrapper exception with a `TIMED_OUT`
   status that the Extraction_Pipeline converts into an
   `ExtractionError` whose `error_message` records the tool name,
   the timeout duration in seconds, and a redacted excerpt of
   the tool's stderr captured before the timeout.
8. IF a Tool_Wrapper subprocess exits non-zero without having
   timed out, THEN THE Tool_Wrapper SHALL raise a typed wrapper
   exception with a `FAILED` status that the Extraction_Pipeline
   converts into an `ExtractionError` whose `error_message`
   records the tool name, the exit status, and a redacted
   excerpt of the tool's stderr.
9. WHERE a Tool_Wrapper subprocess both times out and exits
   non-zero (for example, when the tool exits non-zero after
   receiving the termination signal that enforced the timeout),
   THE Tool_Wrapper SHALL report the failure as `TIMED_OUT`,
   suppress the `FAILED` status, and the resulting
   `ExtractionError.error_message` SHALL identify the failure as
   a timeout and SHALL NOT promote the post-timeout exit status
   to a primary failure cause.
10. THE Tool_Wrapper SHALL never write to or read from any
    directory outside the Extraction_Pipeline's scratch directory
    and `ExtractionConfig.default_output_dir`.

### Requirement 5: Failure modes and ExtractionError reporting

**User Story:** As a firmware analyst, I want partial extractions
to succeed where possible and to report exactly which components
failed and why, so that one corrupt FFS file does not cause me to
lose visibility into the rest of the image.

#### Acceptance Criteria

1. THE Extraction_Pipeline SHALL produce an `ExtractionManifest`
   for every input file that survives Requirement 1's input checks,
   regardless of whether any component extraction succeeded.
2. WHEN a per-component extraction step raises an exception, THE
   Extraction_Pipeline SHALL catch that exception, record an
   `ExtractionError`, and continue with the remaining components.
3. THE Extraction_Pipeline SHALL populate every emitted
   `ExtractionError.error_message` with a non-empty,
   human-readable message that names the failure category (for
   example, "FFS header CRC mismatch", "compressed section
   decompression failed", "option ROM PCI Data Structure
   pointer out of range").
4. WHERE an `ExtractionError` corresponds to a specific component
   that the pipeline was attempting to carve, THE
   Extraction_Pipeline SHALL set `ExtractionError.component_id`
   to a freshly generated UUID and SHALL include the byte offset
   of the would-be component in `error_message`.
5. WHERE an `ExtractionError` corresponds to a whole-file or
   whole-region failure (not tied to a single component), THE
   Extraction_Pipeline SHALL leave
   `ExtractionError.component_id` set to `None`.
6. THE Extraction_Pipeline SHALL populate every emitted
   `ExtractionError.timestamp` with the UTC wall-clock time at
   which the error was recorded.
7. WHEN a UEFI PI firmware volume header CRC fails or its
   `FvLength` exceeds the remaining bytes in the Firmware_Binary,
   THE Extraction_Pipeline SHALL skip that volume, emit a single
   `ExtractionError`, and continue scanning for further volumes
   in the binary.
8. WHEN a compressed section cannot be decompressed by any
   Tiano or LZMA decoder available to the pipeline, THE
   Extraction_Pipeline SHALL emit an `ExtractionError` for that
   section and SHALL still emit the section's outer `ExtractedComponent`
   record with `raw_hash` covering the on-disk compressed bytes.
9. IF the Extraction_Pipeline runs for longer than ten times
   `ExtractionConfig.timeout_per_component` × the number of
   detected components, THEN THE Extraction_Pipeline SHALL stop
   further extraction, emit an `ExtractionError` describing the
   global timeout, and return the partial `ExtractionManifest`
   accumulated up to that point.

### Requirement 6: Manifest construction and validation

**User Story:** As a downstream consumer (classifier, GUI,
analysis engine), I want the pipeline's output to be a
`ExtractionManifest` that has already passed every model-layer
invariant, so that I never have to re-validate before using it.

#### Acceptance Criteria

1. THE Extraction_Pipeline SHALL construct its return value by
   instantiating `ExtractionManifest` directly, so that all
   Pydantic v2 strict validators run before the value leaves the
   subsystem.
2. THE Extraction_Pipeline SHALL ensure that every
   `ExtractedComponent` in the returned manifest has a unique
   `component_id`.
3. THE Extraction_Pipeline SHALL ensure that the returned
   manifest's `total_components` equals
   `len(manifest.components)`.
4. THE Extraction_Pipeline SHALL ensure that for every emitted
   `ExtractionError` whose `component_id` is not `None`, that
   `component_id` is also present in
   `[c.component_id for c in manifest.components]` if the
   component was successfully extracted, and is unique among
   error records otherwise.
5. THE Extraction_Pipeline SHALL ensure the components in
   `manifest.components` are ordered by ascending integer value
   of their `offset` field, so that downstream consumers can
   rely on positional ordering.
6. IF construction of the final `ExtractionManifest` fails its
   own Pydantic validation, THEN THE Extraction_Pipeline SHALL
   raise a typed internal exception that names the offending
   field path and SHALL NOT return a partially constructed
   manifest.
7. WHERE final-manifest construction succeeds (acceptance
   criterion 6.6 has not raised), THE Extraction_Pipeline SHALL
   guarantee that the returned `ExtractionManifest` serializes
   losslessly through both JSON
   (`model_dump_json` + `model_validate_json`) and YAML
   (`model_dump` + `yaml.safe_dump` + `yaml.safe_load` +
   `model_validate`); IF construction fails, THEN THE
   Extraction_Pipeline SHALL NOT attempt serialization of any
   intermediate state.

### Requirement 7: Determinism and reproducibility

**User Story:** As a tester and as the property-based test
suite, I want extraction to be deterministic given the same
binary and the same pipeline version, so that round-trip,
idempotence, and equivalence properties can be tested under
Hypothesis.

#### Acceptance Criteria

1. WHEN the Extraction_Pipeline is invoked twice on the same
   Firmware_Binary with the same `ExtractionConfig` and the
   same Extraction_Pipeline version, THE Extraction_Pipeline
   SHALL produce two manifests that are equal under
   `model_dump()` after stripping
   `extraction_timestamp` fields on the manifest and on every
   `ExtractionError`.
2. WHEN the Extraction_Pipeline is invoked twice on the same
   Firmware_Binary with the same `ExtractionConfig`, THE
   Extraction_Pipeline SHALL emit identical sequences of
   `ExtractedComponent` records, including identical
   `component_id` values, where each `component_id` is
   derived as
   `uuid5(LOKI_NAMESPACE, source_image.file_hash + ":" + offset + ":" + raw_hash)`.
3. WHEN the Extraction_Pipeline is invoked twice on the same
   Firmware_Binary with the same `ExtractionConfig`, THE
   Extraction_Pipeline SHALL emit identical sequences of
   `ExtractionError` records, where each error's
   `component_id` (when not `None`) is derived deterministically
   from the same `uuid5` recipe applied to the would-be
   component's offset and a placeholder hash, so that error
   identity is stable across runs.
4. WHEN the Extraction_Pipeline writes raw component bytes to
   `default_output_dir`, THE Extraction_Pipeline SHALL choose
   each output filename as
   `{offset}-{raw_hash}.bin` so that the filename is a pure
   function of the component's content and position.
5. WHEN the Extraction_Pipeline runs, THE Extraction_Pipeline
   SHALL NOT consult environment variables, the system clock
   (other than for the wall-clock timestamp fields permitted by
   acceptance criterion 7.1), the random number generator, or
   any network resource for any decision that affects manifest
   contents.
6. FOR ALL valid Firmware_Binary inputs the pipeline accepts,
   serializing the returned manifest to JSON via
   `model_dump_json()` and deserializing via
   `model_validate_json()` SHALL produce a manifest equal to
   the original (round-trip property).

### Requirement 8: Performance bounds and resource use

**User Story:** As an analyst working with full SPI flash
dumps, I want extraction of a multi-hundred-megabyte image to
complete in bounded memory and bounded time, so that the GUI
stays responsive and CI runs do not exhaust runner resources.

#### Acceptance Criteria

1. WHEN the Extraction_Pipeline processes a Firmware_Binary
   of any size up to 512 MiB, THE Extraction_Pipeline SHALL
   keep peak resident memory attributable to extraction under
   four times `ExtractionConfig.max_component_size` plus a
   fixed 128 MiB working set.
2. WHEN computing `source_image.file_hash`, THE
   Extraction_Pipeline SHALL read the input in chunks of
   1 MiB or less rather than loading the entire file into
   memory.
3. WHEN extracting components, THE Extraction_Pipeline SHALL
   stream component bytes from the input file rather than
   holding the full Firmware_Binary in memory simultaneously
   with all extracted component buffers.
4. WHEN the Extraction_Pipeline processes any single
   component, THE Extraction_Pipeline SHALL enforce a
   per-component wall-clock timeout equal to
   `ExtractionConfig.timeout_per_component` seconds and SHALL
   abort that component per Requirement 5 when the timeout
   trips.
5. THE Extraction_Pipeline SHALL run synchronously on the
   calling thread and SHALL NOT spawn worker threads, asyncio
   tasks, or process pools in v1.

### Requirement 9: Integration surface for the GUI and CLI

**User Story:** As the author of the GUI's "Extraction" tab and
of the future `loki extract` CLI command, I want a stable,
typed integration surface that does not leak third-party tool
specifics, so that I can render progress, errors, and the final
manifest without poking at internal extractor state.

#### Acceptance Criteria

1. THE Extraction_Pipeline SHALL expose its public entry point
   in a stable module path under `loki.extraction` so that GUI
   and CLI code can import it as
   `from loki.extraction import extract_firmware`.
2. THE Extraction_Pipeline SHALL expose a typed progress callback
   parameter on its public entry point that, if supplied, is
   invoked with structured progress events (current phase,
   current component index, total components estimated so far)
   at component-extraction granularity.
3. THE Extraction_Pipeline SHALL guarantee that the progress
   callback, if supplied, is invoked from the calling thread
   only.
4. WHERE the caller passes a cancellation token (a callable
   returning `bool`), THE Extraction_Pipeline SHALL check the
   token between components and, if cancellation is requested,
   SHALL stop further extraction, emit one `ExtractionError`
   with `error_message == "extraction cancelled by caller"`,
   and return the partial `ExtractionManifest` accumulated so
   far.
5. THE Extraction_Pipeline SHALL not depend on any
   `loki.gui` module, so that the CLI and headless test
   harnesses can use the pipeline without importing PyQt6.
6. THE Extraction_Pipeline SHALL log its activity through
   Python's standard `logging` module under the logger name
   `loki.extraction` so that GUI and CLI consumers can attach
   their own handlers without monkey-patching.
7. THE Extraction_Pipeline SHALL accept its `ExtractionConfig`
   from the caller without itself reading any config file, so
   that GUI / CLI / tests retain full control over
   configuration sourcing.

### Requirement 10: Observability and diagnostics

**User Story:** As a developer debugging a failed extraction
on a real-world firmware dump, I want enough structured logging
and diagnostic state to reproduce the failure without relying
on stack traces in the GUI status bar.

#### Acceptance Criteria

1. WHEN the Extraction_Pipeline begins processing a
   Firmware_Binary, THE Extraction_Pipeline SHALL log an INFO
   record naming the file path, file size, and the first
   eight bytes of the file in lower-case hex.
2. WHEN the Format_Detector identifies one or more supported
   formats, THE Extraction_Pipeline SHALL log an INFO record
   listing each format name and the byte offset at which it
   was recognized.
3. WHEN the Extraction_Pipeline emits an `ExtractionError`,
   THE Extraction_Pipeline SHALL also log a WARNING or ERROR
   record (matching the failure severity) carrying the same
   `error_message` and the same `component_id` (or `None`).
4. WHEN the Extraction_Pipeline finishes a run, THE
   Extraction_Pipeline SHALL log an INFO record summarizing
   the wall-clock duration, the number of components emitted,
   and the number of errors recorded.
5. THE Extraction_Pipeline SHALL NOT, at any time (including
   while idle, during initialization, during shutdown, or while
   no Firmware_Binary is being processed), log the raw contents
   of any extracted component, decompressed bytes, embedded
   strings, or any portion of any Firmware_Binary beyond the
   leading hex preview permitted by acceptance criterion 10.1,
   and SHALL NOT log derived metadata that could be used to
   fingerprint or reconstruct the input contents beyond the
   identifiers already present in the returned
   `ExtractionManifest` (file hash, component hashes, offsets,
   sizes, GUIDs, names).
