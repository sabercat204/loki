# LOKI

Firmware analysis platform. Pulls firmware images from disk, extracts
their components, classifies each component along four taxonomic axes
(type, vendor, security posture, mutability), compares against named
baselines, scores deviations, and writes structured analysis reports.

## Status

Six subsystems have shipped: the **shared data model layer** at
`loki/models/`, the **extraction pipeline** at `loki/extraction/`,
the **baseline persistence layer (GLEIPNIR)** at `loki/baseline/`,
the **classification pipeline** at `loki/classification/`, the
**analysis engine** at `loki/analysis/`, and the **feeds subsystem**
at `loki/feeds/`. The fleet engine is still pending its own spec.

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` (Pydantic v2 data models) | DONE — `.kiro/specs/loki-data-models/` | DONE (this README's subject) |
| `loki/gui/` (PyQt6 desktop scaffold) | None — handoff plan | DONE (scope B scaffold; demo data + threaded extraction + threaded baseline load) |
| `loki/cli.py` (top-level CLI dispatcher) | Spec dir empty | `loki gui`, `loki extract`, `loki baseline`, `loki classify`, `loki analyze`, `loki feeds`, `loki fleet` |
| Extraction pipeline | DONE — `.kiro/specs/extraction-pipeline/` | DONE — synthetic v1 covering UEFI PI / Intel IFD / capsule / option ROM / microcode, plus Tiano + LZMA-Custom decompression and inner-component emission |
| Classification pipeline | DONE — `.kiro/specs/classification-pipeline/` | DONE — 25/25 tasks; library API at `from loki.classification import classify_components`, four-axis classifier, R5.6 dual-record contract, full Property 33-42 coverage |
| Baseline management (GLEIPNIR) | DONE — `.kiro/specs/baseline-persistence/` | DONE — YAML-on-disk persistence + CLI + GUI integration with background load |
| Analysis engine | DONE — `.kiro/specs/analysis-engine/` | DONE — 28/28 tasks; library API at `from loki.analysis import analyze_image`, six finding categories, PostureRating six-rule cascade, full Property 43-52 coverage |
| Feeds (NVD, implant rules) | DONE -- `.kiro/specs/feeds/` | DONE -- 28/28 tasks; library API at `from loki.feeds import FeedRegistry`, CVE lookup + implant-rule lookup, `loki feeds refresh/status` CLI, six FULL-context audits, Property P59-P68 coverage |
| Consumer wiring (CVE integration) | DONE -- `.kiro/specs/consumer-wiring/` | DONE -- 10/10 tasks; `classify_components` populates `cve_matches` via feeds; analysis engine surfaces `matched_cve` + `cve_introduced`; `loki classify --feeds-config`; Property P69-P71 coverage |
| Fleet analysis | DONE -- `.kiro/specs/fleet-analysis/` | DONE -- 18/18 tasks; library API at `from loki.fleet import analyze_fleet`, config-driven + dir-scan membership, five aggregation passes, `loki fleet analyze` CLI, Property P72-P76 coverage |

## What the model layer provides

The shared type system imported by every other subsystem. Eight
modules, ~1100 source lines, all Pydantic v2 with strict validation
on construction and lossless JSON / YAML round-trip:- **`enums.py`** — 14 `StrEnum` types covering component types,
  vendors, security/mutability axes, severity levels, posture
  ratings, output formats, log levels.
- **`firmware.py`** — `FirmwareImage` (with deterministic
  `image_id` derived from `file_hash` via `uuid5`),
  `ExtractedComponent`, `ExtractionError`, `ExtractionManifest`.
- **`classification.py`** — `AxisClassification`, `SignatureInfo`,
  `OverrideRecord`, `ClassificationRecord` (with auto-computed
  `composite_confidence` and `needs_review` flag).
- **`baseline.py`** — `BaselineRecord`, `BaselineRegistry` (with
  three lookup methods), `DeviationRecord`, `BaselineComparison`
  (with auto-computed summary counts by `DeltaType`).
- **`analysis.py`** — `DeviationScore`, `FindingEvidence`,
  `FindingRecord`, `ActionRecord`.
- **`reports.py`** — `ReportSummary`, `ImageAnalysisReport`
  (with auto-computed severity distribution),
  `FleetAnalysisReport`.
- **`config.py`** — Seven config sub-models plus a root
  `LokiConfig` with `from_yaml(path)` classmethod.

## Extraction pipeline

The extraction subsystem turns a firmware binary on disk into a
validated `ExtractionManifest` containing zero or more
`ExtractedComponent` records and any `ExtractionError`s that occurred
during processing. v1 covers Intel Flash Descriptor (full-flash)
images, UEFI PI firmware volumes, raw FFS blobs, UEFI capsules, PCI
option ROMs, and Intel CPU microcode update blobs. Coreboot CBFS,
ARM Trusted Firmware, Apple iBoot, Android boot, and vendor-private
capsule wrappers are explicitly deferred.

```python
from pathlib import Path
from loki.extraction import extract_firmware
from loki.models import ExtractionConfig

config = ExtractionConfig(
    default_output_dir="/tmp/loki-out",
    max_component_size=50_000_000,
    timeout_per_component=60,
)
result = extract_firmware(Path("/firmware/laptop-bios.rom"), config)
print(result.manifest.total_components, "components")
print(result.tools_available)  # {'uefi_firmware': True, 'uefitool': False, ...}
```

The pipeline is deterministic: same binary plus same config produces
the same manifest minus timestamp fields, and component IDs are
derived as
`uuid5(LOKI_NAMESPACE, f"{file_hash}:0x{offset:x}:{raw_hash}")` so
the same component carries the same ID across runs and across hosts.
Property tests (Hypothesis) pin the eleven invariants that make the
contract usable downstream — round-trip, ordering, uniqueness,
determinism, output-filename purity, and absence of environmental
side channels.

The CLI exposes the same surface:

```bash
.venv/bin/loki extract /firmware/laptop-bios.rom \
  --output-dir /tmp/loki-out \
  --max-component-size 50000000 \
  --timeout-per-component 60 \
  --progress
```

The manifest goes to stdout as JSON; diagnostic counters
(`tools_available`, `duration_seconds`, component / error counts)
go to stderr. The optional `--progress` flag streams one
`ProgressEvent` per line to stderr in the form
`[phase] index/estimated message`; the manifest JSON on stdout is
unchanged regardless, so callers piping into `jq` aren't affected.

The pipeline goes one level deep into compressed UEFI sections.
When `uefi_firmware`'s Tiano or LZMA-Custom GUID-defined decoder
successfully decompresses a section, the resulting payload is
walked for inner UEFI PI sections (PE32, RAW, UI, COMPRESSION,
GUID_DEFINED, etc.) and each inner section becomes its own
`ExtractedComponent` carrying a synthetic
`source_image_id = uuid5(LOKI_NAMESPACE, decompressed_hash)` and a
deterministic `component_id` derived from
`(decompressed_hash, inner_offset, inner_raw_hash)`. When
`--output-dir` is set, inner-component bytes write to disk under
`0x{parent_offset:x}-decompressed-0x{inner_offset:x}-{inner_raw_hash}.bin`.
Compressed sections that fail decompression still emit the outer
component with `raw_hash` over the on-disk compressed bytes
(R5.8) and surface a typed error in the manifest.

The GUI's "Extraction" tab is now backed by the real subsystem.
Open a firmware image via **File → Open Firmware Image…**, then run
**View → Extract Firmware Components…** (Ctrl+E) to extract on a
background `QThread`; the status bar shows live phase / component
progress while the worker runs.

## Baseline persistence (GLEIPNIR)

Persists `BaselineRecord` and `BaselineRegistry` instances to a YAML
directory layout on disk. One human-readable YAML file per baseline,
named `{slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml`,
all directly inside the configured Storage_Directory. No
subdirectories, no lock files, no auto-upgrade across schema
versions.

The `BaselineStore` API is small. Constructor takes a
`BaselineConfig`; load + save + delete + load_one + export are the
five entry points:

```python
from pathlib import Path
from loki.baseline import BaselineStore
from loki.models import BaselineConfig

store = BaselineStore(BaselineConfig(
    storage_path=str(Path.home() / ".local/share/loki/baselines"),
    auto_match=False,
))
result = store.load()                     # registry + quarantine + duration_ms
print(len(result.registry.baselines), "baselines loaded")
print(len(result.quarantine), "files quarantined")

# Save a record (atomic write, mtime/size concurrency check)
record = result.registry.baselines[0]
store.save(record)                        # raises typed errors on conflict

# Single-file load (typed errors instead of quarantining)
loaded = store.load_one(Path("/some/exported/baseline.yaml"))

# Export to an arbitrary path (same envelope contract, no snapshot)
store.export(record, Path("/tmp/exported.yaml"))

# Remove a baseline by id
store.delete(record.baseline_id)
```

Concurrency contract: single-host, multi-process safe for
non-overlapping baselines. Two stores against the same directory
are fine until they both try to save the same record; the second
save raises `BaselineConcurrentModificationError` rather than
silently overwriting (R5.2). Pass `force=True` to bypass the check
on overwrite-confirmation flows. There are no lock files in v1;
safety is provided by atomic write + mtime/size snapshot only.

The CLI exposes the same surface:

```bash
.venv/bin/loki baseline --storage-path ~/.local/share/loki/baselines list
.venv/bin/loki baseline --storage-path ~/.local/share/loki/baselines \
  show 550e8400-e29b-41d4-a716-446655440000
.venv/bin/loki baseline --storage-path ~/.local/share/loki/baselines \
  import /tmp/foreign-baseline.yaml
.venv/bin/loki baseline --storage-path ~/.local/share/loki/baselines \
  export 550e8400-e29b-41d4-a716-446655440000 /tmp/exported.yaml
.venv/bin/loki baseline --storage-path ~/.local/share/loki/baselines \
  delete --yes 550e8400-e29b-41d4-a716-446655440000
```

`--storage-path` is mandatory for every baseline subcommand so
tests and scripts never accidentally hit the user's real baseline
directory. Typed errors surface as exit codes 2-6:
`BaselineNotFoundError` -> 2, `BaselineSerializationError` -> 3,
`BaselineConcurrentModificationError` -> 4,
`BaselineAlreadyExistsError` -> 5,
`BaselineStorageUnwritableError` -> 6.

The GUI's **Baselines** navigation group is wired to a real
`BaselineStore`. On startup the window constructs a store rooted
at `~/.local/share/loki/baselines` and runs `load()` on a
background `QThread` (`BaselineLoadWorker`); the navigation pane
populates from the worker's result signal so the window comes up
responsive even at 1000+ baselines. Tests opt out of the
threaded path with `MainWindow(..., background_load=False)` so
existing assertion patterns still work without
`qtbot.waitUntil` rewrites. **View -> Open Baseline Registry…**
picks an arbitrary Baseline_File via a file dialog and loads it
without persisting to the Storage_Directory.
**View -> Save Baseline…** writes the active baseline tab's
record back to disk; an existing-file conflict prompts to
overwrite, a concurrent-modification error shows a dialog and
stops (no automatic retry). Demo-data baselines retain the
`(demo)` suffix; real-loaded entries label as
`{vendor} {model} {firmware_version}`.

Performance: with libyaml's `CSafeLoader` (auto-detected at
import time), the load path runs ~7x faster than pure-Python
PyYAML. Calibrated load budget on a 2024-class developer laptop
with a local SSD: under 30 s for 128 baselines x 256
classifications, under 180 s for 1024 baselines x 256
classifications. R9.1's original "5 seconds for 1024 x 256"
figure underestimated YAML parse cost; the slow-marked perf
suite at `tests/baseline/test_performance.py` measures actual
load duration and asserts against the calibrated budgets.

## Classification pipeline

Turns `ExtractedComponent` records produced by the extraction
pipeline into validated `ClassificationRecord` instances along
the four taxonomic axes (type, vendor, security_posture,
mutability). The subsystem is synchronous, single-threaded, and
deterministic: same input + same Rule_Set produces the same
records modulo the run-start `timestamp` field.

The public API is a single free function plus a result container:

```python
from pathlib import Path
from loki.classification import classify_components, ClassificationResult
from loki.models import ClassificationConfig

config = ClassificationConfig(
    taxonomy_version="1.0.0",
    confidence_threshold=0.6,         # reserved; not consumed in v1
    rules_path=str(Path("/etc/loki/rules")),
)
result: ClassificationResult = classify_components(components, config)
print(len(result.records), "records,", len(result.errors), "errors")
```

`classify_components` is a free function, not a class method, so
the Rule_Set-immutable-for-lifetime contract is structurally hard
to violate. The internal coordinator
(`loki.classification.pipeline.ClassificationPipeline`) is not
part of the public surface. Optional `progress` and `cancel`
keyword arguments are documented under the Progress and
cancellation sub-section below.

Rule files live as YAML under `ClassificationConfig.rules_path`,
one or more `.yaml` / `.yml` files at depth 1. The loader sorts
files lexicographically before parsing (so duplicate-`rule_id`
diagnostics are reproducible across filesystems), validates each
file's top-level shape `{taxonomy_version, rules}`, rejects any
file whose `taxonomy_version` mismatches the config's, and
surfaces both source paths when two files declare the same
`rule_id`. A minimal rule file:

```yaml
taxonomy_version: "1.0.0"
rules:
  - rule_id: vendor.intel.well-known-guids
    axis: vendor
    matcher:
      guid:
        in:
          - 4aafd29d-68df-49ee-8aa9-347d375665a7
          - a7d8d9a6-6ab0-4ae7-ad8f-90fa7d3f0b1d
    effect:
      label: INTEL
      confidence: 0.95
      method: GUID_LOOKUP
      evidence: matched canonical Intel platform GUIDs
```

Matcher predicates are conjunctive: every populated predicate
must fire. The closed predicate set is `guid`, `name` (with
`equals`/`prefix`/`suffix`/`contains` operators),
`component_type_hint`, `size` (with `min` / `max` bounds), and
`raw_hash`. Each predicate has both a single-value sugar form and
an `{in: [...]}` form; the loader normalizes both to the same
internal `RuleSet` shape.

For each component, the per-axis classifier filters rules to that
axis, evaluates every matcher, and picks the Winning_Rule by
highest `effect.confidence` with lexicographic `rule_id` as the
tie-breaker. When no rule fires, the axis falls back to the axis-
specific `UNKNOWN` value (`ComponentTypeLabel.UNKNOWN`,
`VendorLabel.UNKNOWN`, etc.) with `confidence=0.0` and
`method=HEURISTIC`. The model layer's
`composite_confidence = mean(axis_confidences)` and
`needs_review = composite_confidence < 0.60` invariants are
enforced at record construction.

**Signature detection** runs two header-only recognizers (PE32
Authenticode security data-directory presence; UEFI
`EFI_FIRMWARE_IMAGE_AUTHENTICATION` wrapper with
`EFI_CERT_TYPE_PKCS7_GUID` cert type). v1 reports presence only —
`SignatureInfo.verified` is always `False`, `signer` and
`cert_expiry` are always `None`. No certificate parsing, no trust
roots. Signature *verification* is a future spec.

**The R5.6 dual-record contract.** When `component.raw_path` is
`None` or unreadable, signature detection cannot run, but the
classification axes still apply. The pipeline emits both a
`ClassificationRecord` (with `signature_info.present=False`,
all four axes classified normally) AND a
`ClassificationError(component_id=..., error_message=
"signature detection failed: raw_path missing")` for the same
component. Callers iterating `result.records` and `result.errors`
should expect this overlap on missing-bytes components.

Per-component failures during rule evaluation or record
construction never raise: they're recorded as
`ClassificationError` rows and the pipeline continues to the
next component. Whole-run failures (rule-load errors,
config-file problems) raise typed
`ClassificationPipelineError` subclasses
(`ClassificationConfigError`, `ClassificationRuleError`) at
pipeline construction time so they surface immediately rather
than being swallowed by an empty-input run.

**Progress and cancellation.** Optional keyword arguments expose
a synchronous progress callback (invoked once per component on
the calling thread with a `ProgressEvent(index, total,
component_id)`) and a cancel token (polled between components;
returning `True` stops further classification and records a
single cancellation `ClassificationError`). Both are documented
on the entry point's docstring; tests in
`test_pipeline_progress.py` and `test_pipeline_cancel.py` pin
the contract.

**Determinism caveats from the v1 design.** The classifier does
linear scan over `RuleSet.rules` per axis; no GUID-keyed
prefilter or other rule indexing in v1 (R11.5 defers this).
Matchers are strictly conjunctive — disjunction is expressed by
writing multiple rules with the same `effect.label`, not by an
`any_of:` block. The `name` predicate operators are
`equals`/`prefix`/`suffix`/`contains`; no regex, no glob. Rule
sets cannot reference each other across axes, so a
`type=MICROCODE` classification cannot imply
`vendor=INTEL` automatically. Each is tracked in the design's
deferred-decisions section as a cheap future revision.

What's explicitly out of scope for classification v1:
signature *verification*, CVE feed integration (`cve_matches`
is always `[]`), classification persistence to disk, and a GUI
classification view. The `loki classify` CLI subcommand ships
in v0.6.0 — see the next section. Each remaining item has its
own future spec.

## Classification CLI

The `loki classify` subcommand wraps `classify_components`
behind a thin CLI handler. It reads a previously-saved
`ExtractionManifest` JSON document (file path or `-` for
stdin), runs the classification library against a caller-
supplied rules directory, and emits a single
`ClassificationResult` JSON object on stdout plus a one-line
counts summary on stderr. No model layer changes; no new public
Python API.

Synopsis:

```bash
.venv/bin/loki classify <manifest|->- --rules-path DIR \
  [--taxonomy-version VERSION] \
  [--progress] [--debug] [--summary-only]
```

The positional `manifest` argument is either a file path or the
literal `-` to read from stdin. When `manifest` is `-` and
stdin is connected to a TTY, the CLI exits 2 with a guard
message rather than blocking on interactive input.

Stdout shape on every successful or partially-cancelled run is
a single indented JSON object with exactly two top-level keys
in this order:

```json
{
  "records": [ /* ClassificationRecord, model_dump(mode="json") */ ],
  "errors":  [ /* ClassificationError, model_dump(mode="json") */ ]
}
```

Two runs against the same manifest + same rules + same
`--taxonomy-version` produce byte-identical stdout modulo each
record's `timestamp` field (upstream R8.1).

Stderr always carries a single one-line summary on success,
partial-cancellation, and per-component-error paths. Format:

```
classify: <N> records (<K> need_review), <E> errors, duration=<S>s
```

`<N>` is the record count, `<K>` is the count of records with
`needs_review = True`, `<E>` is the error count, `<S>` is the
wall-clock duration of the library call rendered with four
decimal places. Whole-run failures (configuration error, rule-
load error, pipeline error) emit a typed-error message line
instead of the summary; the two are mutually exclusive.

Exit-code taxonomy is a closed set:

| Code | Meaning |
| - | - |
| 0 | Success: `ClassificationResult` written; summary line emitted. |
| 2 | `BadInput`: missing flag, malformed JSON, Pydantic validation failure, stdin TTY guard. |
| 3 | `SerializationError`: stdout JSON serialization failed; partial JSON not written. |
| 4 | `ClassificationPipelineError` (catchall) or unexpected `Exception`. |
| 5 | `ClassificationRuleError`: rules directory failed to load. |
| 6 | `ClassificationConfigError`: rules path invalid or taxonomy version mismatch. |
| 130 | `Sigint`: cooperative cancellation; partial result still written. |

Cooperative cancellation pattern: a SIGINT delivered to the
process flips an in-process `_CancelFlag` between the library's
per-component iterations. The library observes the flag at the
next iteration boundary, appends a single Cancellation_Marker
to `ClassificationResult.errors`, and returns. The CLI then
serializes the partial result to stdout, emits the summary line
to stderr, and exits 130. Cancellation is a return path, never
a throw path; the contract is identical to the upstream
classification library's R7.

Flags:

- `--rules-path DIR` (required): a directory of YAML rule files
  matching the `ClassificationConfig.rules_path` contract from
  upstream classification.
- `--taxonomy-version VERSION` (default `1.0.0`): rejects rule
  files whose `taxonomy_version` does not match.
- `--progress`: emits one `[<index>/<total>] <component_id>`
  line per successfully-classified component to stderr,
  flushed for real-time visibility. The Progress_Line is the
  only stderr surface that may interpolate `component_id`.
- `--debug`: scoped to the `loki.classification` logger only.
  Sets the logger to DEBUG level, attaches a stderr
  `StreamHandler` if none is already configured, and sets
  `propagate = False` for the duration of the run so externally-
  attached parent loggers do not double-log. The `loki.baseline`,
  `loki.extraction`, and `loki.analysis` loggers are not
  modified. The Forbidden_Leakage_Field_Set audit is not
  bypassed at DEBUG level.
- `--summary-only`: suppresses the stdout JSON entirely; only
  the stderr summary line is emitted. Pairs cleanly with
  `2>/dev/null` for fully-silent runs and with cancellation
  for partial-progress reporting that doesn't dump records.

The R5.6 dual-record contract from upstream classification is
preserved verbatim: when an input component's `raw_path` is
`None` or unreadable, signature detection cannot run, but the
classification axes still apply. The pipeline emits both a
`ClassificationRecord` (with `signature_info.present=False`,
all four axes classified normally) AND a paired
`ClassificationError` carrying the same `component_id`. Callers
iterating `result.records` and `result.errors` should expect
this overlap on missing-bytes components; the CLI never
collapses or de-duplicates the pair.

The seven design defaults D1-D7 (helpers in
`loki/classify_helpers.py` rather than inline; `_CancelFlag` as
a tiny `@dataclass`; `--debug` sets `propagate=False` for the
run; TTY guard fires first when manifest is `-`; exit code 4
catches both `ClassificationPipelineError` and unexpected
`Exception`; helpers are module-private with single-leading-
underscore names; `_load_manifest` returns `int` on failure
rather than raising) are documented in
`.kiro/specs/classification-cli/design.md`. Each is revertable
cheaply if a future revision wants different behavior.

The test suite lives at `tests/classify_cli/`: 13 modules
covering the helper-level invariants (R1-R8), the four-case
emission discipline (P57), the static + dynamic no-leakage
audits (P58), the static side-channels audit, the Hypothesis
property tests for stdin-or-file equivalence (P53),
`--summary-only` zero-stdout (P56), the deterministic
cancellation contract (P55), the SIGINT subprocess end-to-end
test, the wrapper-only timing performance test (R11.1, slow
marker), and the integration smoke (`test_smoke.py`).

## Analysis engine

Turns a sequence of `ClassificationRecord` instances plus a
`BaselineRegistry` into a validated `ImageAnalysisReport` that
describes how a target firmware image deviates from its matched
baseline. The subsystem is synchronous, single-threaded, and
deterministic: same target records + same baseline + same config +
same engine version produce a bit-equal report modulo two explicit
fields (the run-start `timestamp` and the cancellation marker's
`evidence.raw_indicators`, when cancelled).

The public API is a single free function plus a progress-event
dataclass:

```python
from loki.analysis import analyze_image, AnalysisProgressEvent
from loki.models import (
    AnalysisConfig,
    BaselineRegistry,
    MatchStrategy,
    SeverityLevel,
)

config = AnalysisConfig(
    severity_weights={
        "type": 0.4,
        "vendor": 0.2,
        "security_posture": 0.3,
        "mutability": 0.1,
    },
    default_severity_threshold=SeverityLevel.MEDIUM,
    match_strategy=MatchStrategy.AUTO,           # or EXPLICIT / EXPLICIT_OR_AUTO
    confidence_gap_threshold=0.6,                # below = classification_gap finding
)

report = analyze_image(
    target_records=classification_result.records,  # from classify_components
    registry=baseline_registry,                    # from BaselineStore.load_all()
    target_image=firmware_image,
    config=config,
)
print(report.posture_rating)                       # COMPROMISED / AT_RISK / DEGRADED / BASELINE
print(len(report.findings), "findings")
```

`analyze_image` is a free function, not a class method, so the
"matched baseline immutable for the lifetime of one call" contract
is structurally hard to violate. The internal coordinator
(`loki.analysis.pipeline.AnalysisPipeline`) is not part of the
public surface.

The engine emits findings in six v1 categories:

- `classification_mismatch`: a paired (target, baseline) pair
  disagrees on at least one of the four taxonomic axes. Carries a
  full `DeviationScore` (per-axis breakdown + composite score in
  `[0.0, 10.0]` weighted by `severity_weights` + priority rank
  among all mismatches).
- `signature_regression`: a paired pair has both signatures present
  and their `present` flags differ. Severity `HIGH` for lost
  signatures, `MEDIUM` for gained.
- `unexpected_component`: a target record's `component_id` does
  not appear in the baseline manifest. Severity flat `MEDIUM` in v1.
- `missing_required_component`: a baseline record's `component_id`
  does not appear in the target records. Severity flat `HIGH` in v1.
- `classification_gap`: a target record's `composite_confidence`
  is below the configured `confidence_gap_threshold`. Severity
  flat `LOW`. Independent of pairing.
- `analysis_cancelled`: cooperative cancellation marker. Emitted
  exactly once per cancelled run, as the LAST entry of `findings`,
  with a deterministic sentinel `component_id` and the cancellation
  index in `evidence.raw_indicators[0]` only (never logged).

The `posture_rating` is derived from the finished finding list via
a six-rule cascade (R17.5 post-HARDEN):

1. `COMPROMISED` if any `signature_regression: HIGH`, any
   `missing_required_component`, or any `classification_mismatch`
   with `composite_score >= 8.0` (severity CRITICAL — the G4-B
   HARDEN escalation).
2. `AT_RISK` if any `classification_mismatch` with
   `composite_score >= 6.0`.
3. `DEGRADED` if any `classification_mismatch` with
   `composite_score >= 2.0`.
4. `DEGRADED` (catch-all) if any finding is emitted but no rule
   above fires (the G3-A HARDEN catch-all; covers MEDIUM/LOW-only
   runs).
5. `BASELINE` if no findings are emitted at all.
6. `HARDENED` is reserved for a future revision and SHALL NOT be
   emitted by v1.

Cooperative cancellation (R7) is a return path, not a throw path:
when the optional `cancel: Callable[[], bool]` callback returns
`True`, the engine emits the Cancellation_Marker as the LAST entry
of `findings` and returns the partial report without raising.

```python
from loki.analysis import analyze_image

def cancel() -> bool:
    return user_clicked_cancel_button()

def progress(event: AnalysisProgressEvent) -> None:
    print(f"component {event.index} of {event.total}")

report = analyze_image(
    target_records,
    registry,
    target_image,
    config,
    progress=progress,
    cancel=cancel,
)
if report.findings and report.findings[-1].category == "analysis_cancelled":
    print("partial result; user cancelled at index",
          report.findings[-1].evidence.raw_indicators[0])
```

The engine raises only typed `AnalysisError` subclasses on
whole-run failures: `AnalysisConfigError` (invalid
`AnalysisConfig`), `BaselineNotFoundError` (matching miss),
`AnalysisInputError` (duplicate `component_id` on either side of
the pairing), and `AnalysisReportConstructionError` (final-report
Pydantic validation failure). Cooperative cancellation never
raises.

Determinism is enforced by an AST audit at
`tests/analysis/test_no_side_channels.py` (Property 51): no
`os.environ`, `random`, `secrets`, `socket`, `urllib`, `requests`,
or `httpx` import; `time.*` allowed only in
`loki/analysis/timing.py`; `datetime.now()` allowed only in
`loki/analysis/pipeline.py`. The Forbidden_Leakage_Field_Set is
pinned by both a static AST audit
(`tests/analysis/test_no_log_leakage.py`) and a dynamic caplog
audit (`tests/analysis/test_log_no_leakage.py`); together they
implement Property 50.

Properties 43-52 cover the complete correctness contract under
Hypothesis (`tests/analysis/test_properties.py`): report Pydantic
validation, deterministic baseline matching, pairing
bijection-with-defects, axis_score and composite_score determinism
in their declared ranges, two-runs-equal-modulo-timestamp, lossless
JSON round-trip, posture-rating closed function, and the
Cancellation_Marker contract.

Performance: 1024-component target × 1024-component baseline
analysis completes in approximately 0.10 seconds wall time on a
2024-class developer laptop, well under the R18.1 budget of 5
seconds. The slow-marker performance suite at
`tests/analysis/test_performance.py` validates the budget.

What's explicitly out of scope for analysis engine v1: CVE
matching (`evidence.matched_cve` always `None`), signature
verification, fleet analysis (`analyze_fleet` reserved), persistence
of `ImageAnalysisReport`, analyst overrides on findings, the
`loki analyze` CLI subcommand, and a GUI analysis view. Each has
its own future spec or HANDOFF reservation.

## Feeds subsystem

Manages NVD-derived CVE snapshots and curated implant-rule sets,
exposing two lookup surfaces consumed by the analysis engine. The
subsystem is the project's first surface with outbound network egress
and trust-anchor verification; its threat context is FULL.

The public API is a registry class:

```python
from loki.feeds import FeedRegistry
from loki.feeds.models import CVELookupQuery, ImplantRuleLookupQuery
from loki.models.config import LokiConfig

config = LokiConfig.from_yaml("config/loki.yaml")
registry = FeedRegistry.from_config(config.feeds)

# CVE lookup (deterministic against fixed cache)
result = registry.cve_lookup(
    CVELookupQuery(vendor="intel", product="firmware", version="1.0.0"),
    allow_refresh=False,
)
print(len(result.matches), "CVE matches")

# Implant-rule lookup (in-memory, no network)
implant_result = registry.implant_rule_lookup(
    ImplantRuleLookupQuery(content_hash="a" * 64, firmware_guid=None)
)
print(len(implant_result.matches), "implant matches")

# Explicit refresh (fetches NVD bundle, validates trust anchor, commits)
refresh_result = registry.refresh(force=True)
print(refresh_result.status, refresh_result.cves_imported, "CVEs imported")
```

The CLI exposes refresh and status:

```bash
loki feeds refresh --config loki.yaml [--force] [--summary-only]
loki feeds status --config loki.yaml
```

Exit-code taxonomy: `{0, 2, 3, 4, 5, 6, 130}` — success,
config error, signature error, partial download, cache write error,
network error, and SIGINT cancellation respectively.

Key design choices:

- **D1 hash-pin trust anchor:** v1 uses SHA-256 hash verification
  against a `.sha256` sibling artifact. Operator can override via
  `FeedsConfig.trust_anchor_path`.
- **D2 NVD JSON 2.0 format:** full bundle download, validate, commit
  atomically. No streaming.
- **D5 10,000-row INSERT batches** with per-batch cancellation checks.
- **D7 same-host-only redirect policy:** cross-origin redirects raise
  `FeedsNetworkError`.
- **Inline refresh:** `cve_lookup` with `allow_refresh=True` checks
  cache age and triggers an inline refresh when stale. Network failure
  on inline refresh falls back to stale cache with `stale_warning=True`.

Six FULL-context security audits enforce the no-leakage discipline:
static side-channels AST, static log-leakage AST, dynamic caplog,
static request-leakage AST, dynamic request-capture, TLS verification,
and redirect-policy verification.

Performance budgets (R12): `cve_lookup` under 50 ms against 200k CVEs;
`implant_rule_lookup` under 5 ms against 1024 rules; `refresh` under
60 s against a 100 MiB bundle (network excluded).

## Fleet analysis

Aggregates pre-produced `ImageAnalysisReport` instances across an
operator-defined fleet into a `FleetAnalysisReport`. The engine is
batch, synchronous, single-threaded, and deterministic. It reads
already-produced per-image reports (never re-runs analysis) and
produces cross-image rollups: posture distribution, common findings,
CVE rollup, outlier detection, and worst-image ranking.

```python
from loki.fleet import analyze_fleet
from loki.fleet.membership import load_from_config, load_from_directory
from pathlib import Path

# Config-driven mode
fleet_id, reports = load_from_config(Path("fleet.yaml"))
report = analyze_fleet(reports=reports, fleet_id=fleet_id)

# Directory-scan mode
fleet_id, reports = load_from_directory(Path("/data/reports/"))
report = analyze_fleet(reports=reports, fleet_id=fleet_id)

print(report.image_count, "images")
print(report.fleet_posture)
print(len(report.common_findings), "common findings")
print(len(report.outlier_images), "outliers")
print(len(report.systemic_risks), "systemic risks")
```

The CLI exposes fleet analysis:

```bash
loki fleet analyze --config fleet.yaml
loki fleet analyze --dir /data/reports/ [--fleet-id custom-name]
```

Stdout: `FleetAnalysisReport` as indented JSON. Stderr: one-line
summary. Exit codes: 0 (success), 2 (config/input error).

Five aggregation passes:
- **Posture distribution:** count images per PostureRating
- **Common findings:** findings appearing in 2+ images (normalized
  titles, grouped by category + severity)
- **CVE rollup:** CVE IDs affecting 2+ images
- **Outlier detection:** images whose posture is worse than the
  fleet median (skipped for < 3 images)
- **Worst-image ranking:** top-3 images by risk score surfaced as
  `ActionRecord` entries with `action_type="INVESTIGATE"`

Performance: 100 images x 1000 findings completes in ~2 seconds.

## Quick start

Requires Python 3.11 or newer (3.12 recommended).

```bash
git clone <your-fork-or-source-url> loki
cd loki
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Verify the install:

```bash
.venv/bin/python -c "from loki.models import FirmwareImage, LokiConfig; print('ok')"
```

You will see `ok`.

## Using the model layer

```python
from datetime import datetime, UTC
from loki.models import (
    FirmwareImage,
    ExtractedComponent,
    ExtractionManifest,
)
import uuid

image = FirmwareImage(
    file_path="/firmware/laptop-bios.rom",
    file_hash="a" * 64,             # 64-char lowercase hex
    file_size=8 * 1024 * 1024,
    vendor="INTEL",
    model="X1-G11",
    firmware_version="1.42",
)
# image.image_id is deterministic — same hash always produces the same UUID
print(image.image_id)

assert image.image_id is not None
component = ExtractedComponent(
    component_id=uuid.uuid4(),
    source_image_id=image.image_id,
    offset="0x40000",
    size=512 * 1024,
    raw_hash="b" * 64,
    name="DXE Driver: TcgPlatformPei",
)

manifest = ExtractionManifest(
    source_image=image,
    components=[component],
    extraction_timestamp=datetime.now(tz=UTC),
    extractor_version="loki-extract-0.1",
)

# Lossless JSON round-trip
payload = manifest.model_dump_json()
restored = ExtractionManifest.model_validate_json(payload)
assert restored == manifest
```

## Loading a config from YAML

```python
from pathlib import Path
from loki.models import LokiConfig

cfg = LokiConfig.from_yaml(Path("config/loki.yaml"))
print(cfg.classification.confidence_threshold)
```
A minimal `loki.yaml` looks like:

```yaml
general:
  default_output_format: HUMAN
  color: AUTO
  verbosity: 1
  log_level: INFO
extraction:
  default_output_dir: /tmp/loki-extracted
  max_component_size: 50000000
  timeout_per_component: 60
classification:
  taxonomy_version: 1.0.0
  confidence_threshold: 0.6
  rules_path: /tmp/loki-rules
analysis:
  severity_weights:
    critical: 0.5
    high: 0.3
    medium: 0.15
    low: 0.05
  default_severity_threshold: MEDIUM
  report_template: null
baseline:
  storage_path: /tmp/loki-baselines
  auto_match: true
feeds:
  nvd_url: https://services.nvd.nist.gov/rest/json/cves/2.0
  update_interval: 3600
  cache_path: /tmp/loki-cache
  implant_rules_path: /tmp/loki-implants
fleet:
  default_severity_threshold: MEDIUM
  storage_path: /tmp/loki-fleet
```

The `severity_weights` dict must sum to 1.0 within floating-point
tolerance — this is enforced at construction time.

## GUI

A PyQt6 desktop app surfaces the firmware analysis workflow. The model
layer + extraction pipeline are real; classification, baseline
comparison, and analysis are still scaffolding awaiting their own
specs. The GUI exposes whatever's wired up at the time and clearly
labels everything else.

Launch it via the console script installed by `pip install -e .`:

```bash
.venv/bin/loki gui
```

Or, equivalently, from Python:

```bash
.venv/bin/python -c "from loki.gui import run; run()"
```

What you get:

- **File → Open Firmware Image…** picks a real binary, hashes it
  (chunked SHA-256, no `read()`-the-whole-thing), and constructs a
  validated `FirmwareImage`.
- **View → Extract Firmware Components…** (`Ctrl+E`) runs the real
  extraction pipeline against the open image on a background
  ``QThread`` and opens an `ExtractionView` tab when it finishes.
  The status bar shows live phase / component progress while the
  worker runs; the menu item disables until extraction completes.
- **View → Load Demo Data** populates the workspace with a coherent
  set of synthetic Pydantic instances: 2 firmware images, 1 baseline
  with a 5-component manifest, 1 baseline comparison summary
  (1 ADDED + 1 MODIFIED + 1 UNCHANGED), and 1 image analysis report
  with 3 findings spanning CRITICAL / HIGH / LOW. Every tab and
  navigation entry is suffixed `(demo)` so synthetic data can never
  be confused with real analysis output.
- **View → Reset Workspace** closes every tab and clears the
  navigation pane.

Caveats worth being explicit about:

- The Analysis and Classification tabs are still scaffold
  placeholders awaiting their respective subsystems.
- No persistence yet. Window geometry and splitter state survive
  via `QSettings`, but loaded images, baselines, and reports do
  not. Closing the app drops them.
- Background extraction runs on a ``QThread`` so the UI stays
  responsive on multi-hundred-MB binaries. Cancellation is
  cooperative — the worker checks the cancel flag between
  components, so a stuck pure-Python extractor wouldn't be
  killable mid-step. The global timeout from R5.9 is the
  safety net.
- Background baseline loading also runs on a ``QThread`` via
  `BaselineLoadWorker`, so a Storage_Directory full of baselines
  doesn't freeze the window on startup. The worker emits
  per-file progress events on a `progress` Qt signal; the status
  bar shows `"Loading baselines… {index}/{total} ({basename})"`
  while the load runs (R7.10). **View → Cancel Baseline Load**
  triggers cooperative cancellation between files (R7.11);
  closing the window also cancels in-flight loads before the
  worker join, so window-close never blocks on a slow load.

## Development

```bash
.venv/bin/pytest                 # run the test suite
.venv/bin/mypy loki tests        # type-check (strict)
.venv/bin/ruff check loki tests  # lint
.venv/bin/ruff format loki tests # format
```

The test suite has three layers:

- **`tests/test_smoke.py`** — example-based tests covering
  imports, public-API surface, enum string serialization,
  `LokiConfig.from_yaml()` happy path, and a few representative
  validation rejections.
- **`tests/test_property_invariants.py`** — Hypothesis property
  tests for the nine domain invariants (Properties 3–11 from
  `.kiro/specs/loki-data-models/design.md`): deterministic
  image-id generation, hash-format validation, bounded float
  ranges, classification-record computed fields, manifest
  count invariant, comparison summary invariant, registry
  lookup correctness, report summary invariant, severity
  weight constraints.
- **`tests/test_property_round_trip.py`** — Hypothesis property
  tests for Properties 1 and 2: every model type round-trips
  through both JSON and YAML without data loss.

Generators for valid model instances live in `tests/conftest.py`.

- **`tests/extraction/`** — pytest suite for the extraction pipeline.
  Covers the public API contract, per-format extractors against
  synthetic binaries, the determinism + manifest-invariant property
  suites (Hypothesis Properties 12-22), the no-side-channels static
  AST audit, the no-leakage logging audit, a golden-file regression,
  and a `slow`-marked performance smoke test (skipped on CI; run
  locally with `pytest -m slow`).
- **`tests/baseline/`** — pytest suite for the persistence layer.
  Covers the load + save + delete flows, the typed-error
  hierarchy, two-store concurrency races, edge cases (malformed
  UTF-8, empty / whitespace-only files, oversized files), the
  Hypothesis-backed determinism + manifest-invariant suites
  (Properties 23-26), the no-side-channels AST audit, the
  no-leakage logging audit, a golden-file regression, and two
  `slow`-marked performance tests at 128 x 256 and 1024 x 256
  scales.
- **`tests/test_cli_baseline.py`** — pytest suite for the
  `loki baseline list/show/import/export/delete` CLI subcommands.
  Each subcommand has happy-path + typed-error coverage with
  exit-code assertions (2-6 mapping). The `--storage-path` flag
  is mandatory so tests can isolate themselves on `tmp_path`.

The GUI scaffold has its own test module:

- **`tests/gui/test_main_window.py`** — `pytest-qt` tests covering
  main-window construction, the file-open flow on a synthetic
  binary, demo-data population of all four navigation groups,
  closable workspace tabs, and the navigation double-click /
  reset workspace flows. Runs offscreen via
  `QT_QPA_PLATFORM=offscreen`, set in `tests/gui/conftest.py`.
- **`tests/gui/test_baseline_actions.py`** — `pytest-qt` tests
  covering the GLEIPNIR GUI integration: load on startup,
  quarantine-count surfacing, the open / save baseline actions,
  the overwrite-confirmation and concurrent-modification dialogs,
  and the navigation-label conventions (`{vendor} {model}
  {firmware_version}` for real-loaded entries, `(demo)` suffix
  for demo-data entries). An autouse fixture stubs every
  `QMessageBox` static method so missed monkeypatches can never
  hang the suite on a blocked dialog.

## Repository layout

```
loki/
├── README.md
├── pyproject.toml
├── .kiro/
│   └── specs/
│       ├── loki-data-models/        # spec for the model layer
│       │   ├── design.md
│       │   ├── tasks.md
│       │   └── .config.kiro
│       ├── extraction-pipeline/     # spec for the extraction subsystem
│       │   ├── requirements.md
│       │   ├── design.md
│       │   ├── tasks.md
│       │   └── .config.kiro
│       ├── baseline-persistence/    # spec for GLEIPNIR
│       │   ├── requirements.md
│       │   ├── design.md
│       │   ├── tasks.md
│       │   └── .config.kiro
│       ├── classification-pipeline/ # spec for the classification subsystem
│       │   ├── requirements.md
│       │   ├── design.md
│       │   ├── tasks.md             # 25 tasks, 8 waves; all ticked
│       │   └── .config.kiro
│       └── analysis-engine/         # spec for the analysis engine
│           ├── requirements.md
│           ├── requirements-tension-pass.md  # TENSION + HARDEN audit trail
│           ├── design.md
│           ├── tasks.md             # 28 tasks, 8 waves; all ticked
│           └── .config.kiro
├── loki/
│   ├── __init__.py
│   ├── cli.py                       # top-level CLI: loki gui / extract / baseline
│   ├── models/                      # Pydantic v2 data models
│   │   ├── __init__.py
│   │   ├── enums.py
│   │   ├── firmware.py
│   │   ├── classification.py
│   │   ├── baseline.py
│   │   ├── analysis.py
│   │   ├── reports.py
│   │   └── config.py
│   ├── extraction/                  # extraction pipeline
│   │   ├── __init__.py
│   │   ├── api.py                   # public extract_firmware()
│   │   ├── detection.py             # format detection
│   │   ├── manifest.py              # ManifestBuilder + add_inner_component
│   │   ├── ids.py                   # deterministic uuid5 derivation
│   │   ├── inner_carve.py           # walks decompressed UEFI payloads
│   │   ├── streaming.py             # chunked SHA-256 + slice
│   │   ├── timing.py                # stopwatch + global budget
│   │   ├── errors.py                # typed exception hierarchy
│   │   ├── extractors/              # per-format strategies
│   │   │   ├── base.py
│   │   │   ├── uefi_volume.py       # decompresses Tiano + LZMA-Custom sections
│   │   │   ├── ffs.py
│   │   │   ├── ifd.py
│   │   │   ├── capsule.py
│   │   │   ├── option_rom.py
│   │   │   └── microcode.py
│   │   └── tools/                   # third-party tool boundary
│   │       ├── base.py
│   │       ├── uefi_firmware.py     # required wrapper
│   │       ├── uefitool.py          # optional wrapper, probe-only in v1
│   │       └── chipsec.py           # optional wrapper, probe-only in v1
│   ├── baseline/                    # GLEIPNIR persistence layer
│   │   ├── __init__.py
│   │   ├── store.py                 # BaselineStore: load/save/delete/load_one/export
│   │   ├── envelope.py              # YAML envelope (de)serialization
│   │   ├── naming.py                # slug + Baseline_Filename + collision handling
│   │   ├── concurrency.py           # mtime/size snapshot + check helpers
│   │   ├── quarantine.py            # QuarantineEntry + QuarantineSet
│   │   ├── schema.py                # SCHEMA_VERSION + supported set
│   │   └── errors.py                # typed exception hierarchy
│   ├── classification/              # classification pipeline (DONE — Waves 1-7)
│   │   ├── __init__.py              # public re-exports
│   │   ├── api.py                   # public classify_components()
│   │   ├── pipeline.py              # internal coordinator
│   │   ├── version.py               # CLASSIFICATION_VERSION = "1.0.0"
│   │   ├── classifier.py            # per-axis Winning_Rule selection
│   │   ├── signatures.py            # PE32 + UEFI auth wrapper
│   │   ├── errors.py                # typed exception hierarchy + ClassificationError
│   │   ├── timing.py                # Stopwatch context manager
│   │   └── rules/
│   │       ├── __init__.py          # re-exports Effect, Matcher, Rule, RuleSet
│   │       ├── loader.py            # YAML rule-set loader
│   │       ├── schema.py            # 8 typed Pydantic shapes
│   │       └── matcher.py           # conjunctive evaluator
│   ├── analysis/                    # analysis engine (DONE — Waves 1-8)
│   │   ├── __init__.py              # public re-exports
│   │   ├── api.py                   # public analyze_image() + AnalysisProgressEvent
│   │   ├── pipeline.py              # internal AnalysisPipeline orchestrator
│   │   ├── version.py               # ANALYSIS_VERSION = "1.0.0"
│   │   ├── matching.py              # R2 Match_Strategy resolution + R14.1 keyset check
│   │   ├── pairing.py               # R3 Component_Pairing logic
│   │   ├── findings.py              # 5 per-category emitters + Cancellation_Marker + finding_id helper
│   │   ├── scoring.py               # 6 pure scoring helpers (axis_score, composite_score, ...)
│   │   ├── posture.py               # R17.5 PostureRating six-rule cascade
│   │   ├── report.py                # ImageAnalysisReport assembly + priority_rank pass
│   │   ├── errors.py                # typed exception hierarchy (4 subclasses)
│   │   └── timing.py                # Stopwatch context manager (mirrors classification)
│   ├── fleet/                       # fleet analysis engine (DONE — Waves 1-5)
│   │   ├── __init__.py              # public re-exports (analyze_fleet, FLEET_VERSION, errors)
│   │   ├── api.py                   # public analyze_fleet() entry point
│   │   ├── aggregation.py           # 5 aggregation functions
│   │   ├── membership.py            # config-driven + directory-scan loaders
│   │   ├── models.py                # FleetRiskScore (internal)
│   │   ├── errors.py                # FleetError, FleetConfigError, FleetInputError
│   │   ├── version.py               # FLEET_VERSION = "1.0.0"
│   │   └── cli.py                   # register_fleet_subcommand
│   └── gui/                         # PyQt6 desktop scaffold
│       ├── __init__.py
│       ├── app.py                   # QApplication entry point
│       ├── main_window.py           # background_load flag for tests
│       ├── navigation.py
│       ├── workspace.py
│       ├── extraction_worker.py     # QThread for extraction
│       ├── baseline_load_worker.py  # QThread for baseline load
│       ├── views/                   # one read-only widget per model
│       ├── actions/                 # File→Open, View→Load Demo Data, View→Extract,
│       │                            # View→Open Baseline, View→Save Baseline
│       └── demo/                    # synthetic workspace builder
├── scripts/
│   └── smoke_gui.py                 # offscreen manual smoke check
└── tests/
    ├── __init__.py
    ├── conftest.py                  # Hypothesis strategies
    ├── test_smoke.py
    ├── test_property_invariants.py
    ├── test_property_round_trip.py
    ├── test_cli_extract.py
    ├── test_cli_baseline.py
    ├── extraction/                  # extraction subsystem tests
    │   ├── conftest.py
    │   ├── fixtures/                # synthetic binary builders
    │   ├── test_api_contract.py
    │   ├── test_determinism.py
    │   ├── test_extractor_*.py
    │   ├── test_format_detection.py
    │   ├── test_golden.py
    │   ├── test_inner_carve.py      # decompressed-payload section walker
    │   ├── test_log_no_leakage.py
    │   ├── test_manifest_invariants.py
    │   ├── test_no_side_channels.py
    │   └── test_performance.py      # marked `slow`; skipped on CI
    ├── baseline/                    # baseline-persistence tests
    │   ├── __init__.py
    │   ├── conftest.py              # Hypothesis strategy + fixtures
    │   ├── fixtures/                # synthetic baseline builder + golden snapshot
    │   ├── test_concurrency.py      # FileSnapshot + check_unchanged
    │   ├── test_determinism.py      # PBT for Properties 24-26
    │   ├── test_envelope.py
    │   ├── test_exceptions.py
    │   ├── test_fixtures.py
    │   ├── test_golden.py
    │   ├── test_log_no_leakage.py
    │   ├── test_manifest_invariants.py  # PBT for Property 23
    │   ├── test_naming.py
    │   ├── test_no_side_channels.py     # AST audit for Property 32
    │   ├── test_performance.py          # marked `slow`; skipped on CI
    │   ├── test_quarantine.py
    │   ├── test_schema_version.py
    │   ├── test_store_basics.py
    │   ├── test_store_concurrency.py
    │   ├── test_store_errors.py
    │   ├── test_store_load.py
    │   ├── test_store_save.py
    │   └── test_store_singletons.py
    ├── classification/              # classification subsystem tests (Waves 1-7)
    │   ├── __init__.py
    │   ├── conftest.py              # synthetic_components / synthetic_rules_dir fixtures + Hypothesis strategies
    │   ├── test_api_contract.py     # public surface + R1 contract
    │   ├── test_classifier.py       # R4 Winning_Rule selection + UNKNOWN fallback
    │   ├── test_classifier_property.py # Property 34 (Hypothesis)
    │   ├── test_determinism.py      # Properties 35-38 (Hypothesis)
    │   ├── test_exceptions.py       # typed hierarchy + ClassificationError
    │   ├── test_fixtures.py         # synthetic-component fixture smoke tests
    │   ├── test_golden.py           # canonical_classifications_v1.json regression
    │   ├── test_log_no_leakage.py   # Property 40 dynamic capture
    │   ├── test_manifest_invariants.py # Property 33 (Hypothesis)
    │   ├── test_no_log_leakage.py   # Property 40 static AST audit
    │   ├── test_no_side_channels.py # Property 41 static AST audit
    │   ├── test_performance.py      # marked `slow`; R11.1 + R11.3 budgets
    │   ├── test_pipeline.py         # happy path + dual-record + ordering
    │   ├── test_pipeline_cancel.py  # R1.9 cooperative cancellation
    │   ├── test_pipeline_dual_record.py # R5.6 + Property 42
    │   ├── test_pipeline_errors.py  # R9 per-component error rows
    │   ├── test_pipeline_inner.py   # R7 inner-component handling
    │   ├── test_pipeline_progress.py # R12.1-R12.2 progress callback
    │   ├── test_signatures.py       # R5 PE32 + UEFI recognizers
    │   ├── test_timing.py           # Stopwatch context manager
    │   ├── test_version.py          # CLASSIFICATION_VERSION semver
    │   ├── fixtures/                # synthetic builders + golden snapshot
    │   │   ├── __init__.py
    │   │   ├── README.md            # regeneration procedure (bump _v1 -> _v2)
    │   │   ├── synthetic_components.py
    │   │   ├── synthetic_rules.py
    │   │   ├── test_rules_fixture.py
    │   │   └── golden/
    │   │       ├── canonical_rules_v1.yaml
    │   │       └── canonical_classifications_v1.json
    │   └── rules/
    │       ├── __init__.py
    │       ├── test_loader.py       # R2 loader contract
    │       ├── test_matcher.py      # R3 conjunctive evaluator
    │       └── test_schema.py       # 8 Pydantic shape validator suites
    ├── test_classification_smoke.py # end-to-end extract -> classify smoke test
    ├── test_analysis_smoke.py       # end-to-end smoke triggering all six analysis finding categories
    ├── analysis/                    # analysis-engine subsystem tests (Waves 1-7)
    │   ├── __init__.py
    │   ├── conftest.py
    │   ├── _helpers.py              # shared test fixture builders (underscore = not collected)
    │   ├── test_analysis_config_extension.py    # AnalysisConfig three-field extension
    │   ├── test_api.py              # public surface + R1.9 no-loki-gui audit
    │   ├── test_cancellation_marker.py # R7.1-R7.7 marker contract
    │   ├── test_errors.py           # typed AnalysisError hierarchy
    │   ├── test_finding_evidence_extension.py   # FindingEvidence.deviation_score field
    │   ├── test_finding_id.py       # R15.7 derive_finding_id determinism
    │   ├── test_findings_classification_gap.py  # R10 emitter
    │   ├── test_findings_classification_mismatch.py # R4 emitter + R9 DeviationScore
    │   ├── test_findings_missing_required.py    # R8 emitter
    │   ├── test_findings_signature_regression.py # R5 emitter
    │   ├── test_findings_unexpected_component.py # R6 emitter
    │   ├── test_log_no_leakage.py   # Property 50 dynamic capture
    │   ├── test_match_strategy_enum.py # MatchStrategy StrEnum
    │   ├── test_matching.py         # R2 Match_Strategy resolution
    │   ├── test_no_log_leakage.py   # Property 50 static AST audit
    │   ├── test_no_side_channels.py # Property 51 static AST audit
    │   ├── test_pairing.py          # R3 Component_Pairing logic
    │   ├── test_performance.py      # marked `slow`; R18.1 budget
    │   ├── test_pipeline.py         # AnalysisPipeline orchestration
    │   ├── test_posture.py          # R17.5 six-rule cascade
    │   ├── test_properties.py       # Hypothesis P43-P52 property suite
    │   ├── test_report.py           # report assembly + priority_rank
    │   ├── test_scoring.py          # 6 scoring helpers + boundary cases
    │   ├── test_timing.py           # Stopwatch context manager
    │   └── test_version.py          # ANALYSIS_VERSION semver
    └── gui/
        ├── __init__.py
        ├── conftest.py              # offscreen Qt platform
        ├── test_baseline_actions.py # GLEIPNIR GUI integration
        ├── test_baseline_load_worker.py # threaded baseline-load worker
        ├── test_extraction_view.py
        └── test_main_window.py
```

## Verification at the current checkpoint

- 1655 tests pass on the default suite (model + GUI + extraction +
  baseline-persistence + classification + classify-cli + analysis +
  analyze-cli + feeds + consumer-wiring + fleet). 13 additional
  `slow`-marked performance tests are deselected by default (2 from
  extraction, 2 from baseline-persistence, 2 from classification, 1
  from classify-cli, 2 from analysis, 3 from feeds, 1 from fleet);
  run `pytest -m slow` to include them.
- `mypy --strict` clean across 303 source files.
- `ruff check` clean. `ruff format --check` clean (303 files).
- Offscreen GUI smoke run via `QT_QPA_PLATFORM=offscreen
  .venv/bin/python scripts/smoke_gui.py` is clean.
- All 11 spec correctness properties from the model layer plus
  Properties 12-22 from extraction, Properties 23-32 from
  baseline-persistence, Properties 33-42 from classification,
  Properties 43-52 from analysis, Properties 53-58 from classify-cli,
  Properties 59-68 from feeds, Properties 69-71 from consumer-wiring,
  and Properties 72-76 from fleet analysis have at least one
  Hypothesis-backed test or AST/log-leakage audit. The feeds subsystem
  ships the full six-audit FULL-context discipline (AST + dynamic for
  side-channels, log-leakage, and request-leakage; plus TLS + redirect
  audits).
- Every public model serializes losslessly to both JSON and
  YAML with no data loss across deterministic random inputs.
- Feeds performance budgets pass locally: R12.1 (cve_lookup against
  200k CVEs) under 50 ms; R12.2 (implant_rule_lookup against 1024
  rules) under 5 ms; R12.3 (refresh against 100 MiB bundle) under
  60 s, actual ~12 s.
- Fleet performance budget passes locally: 100 images x 1000
  findings in ~2 seconds (budget: 10 s).

## Next moves

In rough priority order:

1. **GUI classification + analysis + fleet view.** v1's library APIs
   run headless; a future GUI spec defines the desktop surface that
   wires `classify_components`, `analyze_image`, and `analyze_fleet`
   onto background `QThread`s and renders the results.
2. **Schema migration tool.** v1 supports exactly one
   `Schema_Version` and quarantines any other; the future
   `baseline-schema-migration` spec defines an explicit
   migration command.
3. **Native packaging.** `.app` bundle, code-signing, and
   notarization are deferred until the rest of the platform is
   feature-complete.
