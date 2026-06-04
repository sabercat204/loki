
# Design Document — GUI Views (Loki Desktop)

## Overview

The GUI subsystem (codename **Loki Desktop**) is a **thin presentation layer** sitting on top of the headless library APIs (`loki.extraction`, `loki.classification`, `loki.analysis`, `loki.baseline`, plus offline `FleetAnalysisReport` JSON). It exists to render Pydantic model instances produced upstream as read-only views inside a single PyQt6 desktop window. The library subsystems hold the deterministic, audited, threat-modelled logic; the GUI's job is to (a) marshal operator input through a small set of file-dialog-driven Action_Functions, (b) run the long-running library calls on background QThread workers so the event loop stays responsive, and (c) display the resulting Pydantic instances in `QTableWidget` / `QTreeWidget`-based view widgets that never mutate.

This design document is **retroactive**: the GUI shipped at v1.0.0 in lifecycle stage `IMPLEMENTED` with `spec_status = AD_HOC`. The architecture is already decided and lives in ~2,700 lines of code under `loki/gui/`. This document binds the existing architecture to the requirements rather than proposing one greenfield. Where future revisions could revisit a choice, the design lists it under **Open questions** or **Design defaults**, both at the bottom; everything else is descriptive of what `loki/gui/` already does after the OT-LK-004 Cleanup Waves A and C have landed (commits `98c2110` + `e138baf`).

The shape mirrors `extraction-pipeline`, `baseline-persistence`, `classification-pipeline`, `analysis-engine`, and `fleet-analysis` at a structural level (subsystem positioning, public surface, exception boundaries, properties), but the section depth is intentionally shallower. A retroactive design doc is short because the implementation already pins the contract; the design's job is to make every contract reviewable in one place.

The toolkit is **PyQt6** with a single-window `QMainWindow` topology (D1) hosting a horizontal `QSplitter` that places a fixed-width navigation pane on the left and a growable workspace `QTabWidget` on the right. Workers are `QThread` subclasses (D2 — `QObject.moveToThread()` / `QThreadPool` migration is forward-tracked). Cancellation primitives are `threading.Event` uniformly across all three workers (D3 — `ExtractionWorker` migrated from a `bool` flag to `threading.Event` in harness round v1.0.3 post-v1.0.0; method names remain distinct to preserve the v1.0.0 caller contract). Views are immediate-mode `QTableWidget` / `QTreeWidget` instances populated in `__init__` (D4); they never mutate the supplied Pydantic instance and never register a `QAbstractItemModel`. All views set `NoEditTriggers` (D5). The action surface is **menu-bar-only** (D6) with three top-level menus and four `Ctrl+`-shortcuts. Status updates go to a single `QLabel` in the status bar (D7). Errors surface as `QMessageBox.warning` (D8). Tabs are closable and movable, keyed by an opaque kind-namespaced string (`image:<id>`, `analysis:<id>`, etc., D9). Single-active-worker enforcement is UI-level via menu enablement (D10). Configuration exposure is deferred to the CLI (D11). Per-view export is deferred (D12). Demo data is constructed at runtime by `build_demo_workspace` (D13). Tests run under `QT_QPA_PLATFORM=offscreen` with `pytest-qt` and an autouse SilentDialogs fixture that monkeypatches `QMessageBox` (D14). Theming is OS platform default (D15).

## Goals and non-goals

### Goals

- Deliver a single-window `QMainWindow`-rooted PyQt6 desktop application launchable as `python -m loki.gui.app` and via `loki gui` (R1).
- Render every public field on `FirmwareImage`, `ExtractionManifest`, `BaselineRecord` + `BaselineComparison`, `ImageAnalysisReport`, and `FleetAnalysisReport` in dedicated read-only views (R2-R7).
- Provide a stable navigation pane with four fixed top-level groups (`Images`, `Baselines`, `Reports`, `Fleet`) and a stable double-click contract (R8).
- Provide a tabbed workspace whose tabs are deduplicated by opaque kind-namespaced string keys (R9).
- Run extraction, baseline-load, and analysis on background `QThread` workers with cooperative-cancellation, typed-error reporting, and a single-active-worker policy enforced via menu enablement (R10-R12, R15).
- Expose every menu action as a free function under `loki.gui.actions.*` whose first positional argument is a `MainWindow`, so tests can drive every flow without a file dialog (R13).
- Persist exactly three QSettings keys (`main_window/geometry`, `main_window/state`, `main_window/splitter`) under `QSettings("LOKI", "Desktop")`; never persist file paths, model identifiers, or any field from the `Forbidden_Leakage_Field_Set` (R18).
- Provide a one-click demo flow producing a coherent set of synthetic Pydantic instances spanning every view kind, with `(demo)` suffixed labels and a `save_baseline` refusal for demo-tagged baselines (R13, R19).
- Be testable headlessly under `QT_QPA_PLATFORM=offscreen` with an autouse SilentDialogs fixture and a standalone `scripts/smoke_gui.py` smoke harness (R21, R26).
- Honour the platform-wide `Forbidden_Egress_Set`: no network egress, no firmware mutation, no credential read; only the GUI's primary STANDARD-threat surface is the operator-supplied firmware / fleet-report file (R22).
- Allocate property IDs P77-P85 for the GUI subsystem; the next subsystem starts at P86 (R25).

### Non-goals (explicit)

- **Authoring surfaces.** v1 is read-only; baseline curation, rule authoring, and configuration editing are CLI-only.
- **Preferences dialog.** v1 uses default-pipeline-only; CLI is the operator-config surface (D11).
- **Per-view export (CSV / JSON / PDF).** Operators use the CLI for JSON output; baseline save is the only persistence path (D12).
- **Sort / filter / search across views.** v1 renders models immediate-mode in `__init__` with no `QAbstractItemModel` separation (D4); sort / filter / search would require a model/view rewrite, which is forward-tracked.
- **Detach-to-window or multi-window topologies.** v1 is single `QMainWindow` per process (D1, D9); multi-window is **explicitly not on the v1 roadmap** and requires a fresh OT-LK to revisit (R24).
- **Theming, dark-mode detection, custom QSS.** v1 uses the OS platform default palette (D15).
- **Toolbars, context menus on navigation, drag-and-drop.** Action surface is menu-bar-only (D6).
- **`QThreadPool` / `QRunnable` migration.** v1 ratifies the existing `QThread`-subclass pattern; migration is forward-tracked (D2, R24).
- **Network egress.** GUI is offline-only; `FleetAnalysisReport` ingestion reads local JSON only (R22).
- **Per-component progress in `AnalysisWorker`.** Analysis-engine v1 emits `AnalysisProgressEvent`s but `AnalysisWorker` does not subscribe — the worker exposes only `finished_with_report` and `errored`. Wiring is forward-tracked (R16, R24).

## Constraints carried forward

- Python 3.11+ (3.12 baseline). All new code must satisfy `mypy --strict`, `ruff check`, and `ruff format`.
- PyQt6 6.6+ (the version pinned in `pyproject.toml`). No PySide6 fallback; no Qt5.
- `loki.gui` SHALL NOT import any symbol from `loki.cli` or `loki.cli.*`. The `cli → gui` direction (the `loki gui` subcommand wraps `gui.app.run`) is the only permitted edge between the two packages. Pinned by a CI grep audit (R1, R26).
- `loki.gui` SHALL NOT call `socket`, `urllib.*`, `requests`, `httpx`, or any DNS-resolving stdlib symbol. Pinned by an import-graph audit at smoke-time (R22, R26).
- `loki.gui` SHALL NOT call `QApplication.processEvents()` from action functions, view constructors, or worker slots. Pinned by a CI grep audit; `scripts/smoke_gui.py` is exempt because it drives the event loop synchronously without `app.exec()` (R22, R26).
- Logging via the stdlib `logging` module under `loki.gui` and `loki.gui.baselines`. The view layer renders `Forbidden_Leakage_Field_Set` members; the log layer SHALL NOT include them (R22, R23). The concrete `logging.Filter` mechanism is a BIND task (Q3 below).
- Property numbering picks up at **P77** per the platform-wide convention; the prior subsystem (`fleet-analysis`) consumed P72-P76. The next subsystem after `gui` starts at P86.

## Subsystem positioning in the dependency graph

The GUI sits at the top of the dependency graph: it consumes every other library subsystem, and only `cli` consumes it.

```
                    ┌─────────────────────────────────────┐
                    │            cli (loki gui)           │
                    │     wraps loki.gui.app.run()        │
                    └────────────────┬────────────────────┘
                                     │ imports / invokes
                                     ▼
                    ┌─────────────────────────────────────┐
                    │              loki.gui               │   ← THIS SUBSYSTEM
                    │  (MainWindow + Workers + Views)     │
                    └────┬───┬───┬───┬───┬─────────────────┘
                         │   │   │   │   │
            ┌────────────┘   │   │   │   └────────────┐
            │                │   │   │                │
            ▼                ▼   ▼   ▼                ▼
       ┌────────┐      ┌──────────┐ ┌──────────┐ ┌──────────┐
       │ models │ ◄────│extraction│ │classifi- │ │ analysis │
       │        │      │          │ │  cation  │ │          │
       └────────┘      └────┬─────┘ └────┬─────┘ └────┬─────┘
            ▲               │            │            │
            │               ▼            ▼            ▼
            │          ┌──────────┐ (consumes models, baseline)
            └──────────│ baseline │
                       └──────────┘

            (FleetAnalysisReport JSON read offline; no live fleet subsystem dep)
```

**`gui` consumes:**

- `loki.models` — every view consumes Pydantic model types (`FirmwareImage`, `ExtractionManifest`, `BaselineRecord`, `BaselineComparison`, `ImageAnalysisReport`, `FleetAnalysisReport`, `FindingRecord`, `FindingEvidence`, `DeviationScore`, all enums).
- `loki.extraction` — `api.extract_firmware`, `ProgressEvent`, `InvalidInputError`, `ManifestConstructionError`, `ExtractionPipelineError`.
- `loki.classification` — `classify_components`, `ClassificationPipelineError`.
- `loki.analysis` — `analyze_image`, `AnalysisError` (and its subclasses by parent-catch).
- `loki.baseline` — `BaselineStore`, `BaselineConfig`, `BaselineStoreError` (and its subclasses), `LoadProgressEvent`, `BaselineAlreadyExistsError`, `BaselineConcurrentModificationError`, `BaselineSerializationError`.
- `FleetAnalysisReport` (model only) — read offline from local JSON via `FleetAnalysisReport.model_validate_json`. No runtime dependency on the `fleet-analysis` engine.

**`gui` is consumed by:**

- `loki.cli` — only `cli/loki_gui.py` (the `loki gui` subcommand) imports `loki.gui.app.run`.

**`gui` is NOT consumed by:**

- Any other subsystem. The GUI is a leaf node on the consumer side; the import graph has no edge from `gui` to any subsystem above `cli`.

The CI gate `grep -rE "^from loki\.cli" loki/gui/` returns zero matches; this is the load-bearing invariant that prevents the `gui ↔ cli` cycle (R1, R26).

## Architecture

```
loki/gui/
├── __init__.py                     # re-exports the public surface (run)
├── app.py                          # QApplication + run() entry point + namespace metadata
├── main_window.py                  # MainWindow (~700 LOC): nav + workspace + workers + actions
├── navigation.py                   # NavigationPane: QTreeWidget with 4 fixed groups
├── workspace.py                    # Workspace: QTabWidget keyed by opaque strings
├── extraction_worker.py            # ExtractionWorker (QThread)
├── baseline_load_worker.py         # BaselineLoadWorker (QThread)
├── analysis_worker.py              # AnalysisWorker (QThread)
├── views/
│   ├── __init__.py
│   ├── firmware_image_view.py      # FirmwareImageView (R2)
│   ├── extraction_view.py          # ExtractionView (R3)
│   ├── baseline_view.py            # BaselineView (R4)
│   ├── report_view.py              # ImageAnalysisReportView — summary altitude (R5)
│   ├── analysis_view.py            # AnalysisView — full evidence altitude (R6)
│   └── fleet_view.py               # FleetAnalysisView (R7)
├── actions/
│   ├── __init__.py
│   ├── open_firmware.py            # open_firmware + open_firmware_from_path
│   ├── extract_components.py       # extract_components
│   ├── open_baseline.py            # open_baseline + open_baseline_from_path
│   ├── save_baseline.py            # save_baseline
│   └── load_demo_data.py           # load_demo_data
└── demo/
    ├── __init__.py
    └── synthetic.py                # build_demo_workspace + DemoWorkspace + BaselineRegistry
```

The diagram of the runtime topology:

```
   MainWindow (QMainWindow)
     │
     ├── QSplitter (horizontal, sizes: [260, growable])
     │     │
     │     ├── NavigationPane (left, fixed-width-ish)
     │     │     QTreeWidget; 4 fixed top-level groups:
     │     │       Images, Baselines, Reports, Fleet
     │     │     emit item_activated(group, key, label) on double-click
     │     │
     │     └── Workspace (right, growable)
     │           QTabWidget; closable, movable
     │           opaque-string-keyed tabs of 7 view widget kinds:
     │             FirmwareImageView      keyed image:<image_id>
     │             ExtractionView         keyed extraction:<image_id>:<ts>
     │             BaselineView           keyed baseline:<baseline_id>
     │             ImageAnalysisReportView keyed report:<report_id>
     │             AnalysisView           keyed analysis:<report_id>
     │             FleetAnalysisView      keyed fleet:<report_id>
     │             (placeholder ExtractionView with manifest=None for empty workspaces)
     │
     ├── Workers (QThread subclasses, one slot per type)
     │     │
     │     ├── ExtractionWorker         calls loki.extraction.extract_firmware
     │     ├── BaselineLoadWorker       calls loki.baseline.BaselineStore.load
     │     └── AnalysisWorker           calls classify_components → analyze_image
     │
     └── Actions (plain free functions accepting window: MainWindow)
           │
           ├── open_firmware (Ctrl+O)         → MainWindow.add_firmware_image
           ├── extract_components (Ctrl+E)    → MainWindow.start_extraction
           ├── open_baseline                  → MainWindow.add_baseline
           ├── save_baseline                  → BaselineStore.save_baseline
           └── load_demo_data                 → MainWindow.add_* with demo=True
```

The MainWindow is the one place every wire converges:

- `NavigationPane.item_activated` is wired to `MainWindow._on_navigation_activated` which looks up a registered widget by `(group, key)` and calls `Workspace.open_tab`.
- Each worker's `pyqtSignal(object)` fires into a `_on_*_progress` / `_on_*_finished` / `_on_*_errored` slot. Slots respect the `self._closing` flag (set inside `closeEvent`) and early-return if teardown has begun.
- Action_Functions receive `window: MainWindow` as their first argument and call `window.add_*` / `window.start_extraction` / `window.baseline_store` to mutate state. They never raise out to the menu trigger; errors surface as `QMessageBox.warning`.

## View ↔ Model binding table

The seven view widgets bind one-to-one onto Pydantic model types from `loki.models`. Each view is constructed immediate-mode in `__init__` from the model instance(s) it receives, and rebuilt-by-replacement to refresh.

| View widget                | Tab_Key prefix    | Source model(s)                                  | Key fields surfaced                                                                                                                                                                                                                                                                                              |
| -------------------------- | ----------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FirmwareImageView`        | `image:`          | `FirmwareImage`                                  | `image_id`, `file_path`, `file_hash`, `file_size`, `vendor`, `model`, `firmware_version`, `extraction_timestamp` (R2.2)                                                                                                                                                                                          |
| `ExtractionView`           | `extraction:`     | `ExtractionManifest` + `ExtractionResult.errors` | header `extractor_version`; metadata `image_id`, `file_path`, `file_size`, `extraction_timestamp`, `total_components`, `len(extraction_errors)`; components table `(Offset, Size, Type hint, Name, Hash(12))`; errors table `(Component ID, Message)` (R3)                                                       |
| `BaselineView`             | `baseline:`       | `BaselineRecord` + optional `BaselineComparison` | metadata `baseline_id`, `name`, `vendor`, `model`, `firmware_version`, `baseline_version`, `source_image_hash`, `created_timestamp`, `manifest_size`, `notes`; comparison summary by `DeltaType` with TOTAL row (R4)                                                                                             |
| `ImageAnalysisReportView`  | `report:`         | `ImageAnalysisReport`                            | header includes `posture_rating.value`; metadata `image_id`, `analysis_version`, `timestamp`; severity-distribution table; findings table `(Severity, Category, Title, Recommended action)` (R5)                                                                                                                 |
| `AnalysisView`             | `analysis:`       | `ImageAnalysisReport` (full depth)               | header includes `posture_rating.value` and `len(findings)`; metadata `report_id`, `image_id`, `analysis_version`, `timestamp`; optional `image_metadata` sub-section; findings tree with full per-finding `FindingEvidence` (axes, deviation_score, matched_rule/cve/signature, raw_indicators); `recommended_actions` table; optional `baseline_comparison` section (R6) |
| `FleetAnalysisView`        | `fleet:`          | `FleetAnalysisReport`                            | header `fleet_id`, `image_count`; metadata `report_id`, `timestamp`; posture-distribution table; outliers list; systemic-risks list; common-findings table; `recommended_actions` table (R7)                                                                                                                     |
| (placeholder via `ExtractionView(manifest=None)`) | n/a | n/a                                              | centred placeholder label directing operator to `View → Extract Firmware Components…` (R3.5)                                                                                                                                                                                                                     |

The duality between `ImageAnalysisReportView` (summary altitude, opened via `add_image_report`) and `AnalysisView` (full-evidence altitude, opened via `AnalysisWorker.finished_with_report`) is intentional in v1 and disclosed at R5.6: the same `ImageAnalysisReport` may live in two simultaneous tabs.

Refresh contract: every view exposes a property accessor (`.image`, `.manifest`, `.baseline`, `.report`) returning the **same Pydantic instance** passed to the constructor by identity (R20.4, P83). Refresh-on-change is rebuild-and-replace: close the existing tab, construct a new view widget, open the tab again under the same key. v1 has no in-place mutation API on any view (R20.3, D5).

Read-only enforcement is layered: every `QTableWidget` and `QTreeWidget` calls `setEditTriggers(NoEditTriggers)` at construction (R20.1); the `BaselineView`'s comparison TOTAL row also clears `Qt.ItemFlag.ItemIsEditable` defensively (R4.5); navigation entries set `setEditTriggers(NoEditTriggers)` and `setHeaderHidden(True)` on the tree itself (R8.6).

## Worker contracts

The three QThread workers share a common shape: subclass `QThread`, override `run()`, declare typed `pyqtSignal(object)` signals, expose a cancellation primitive, and never raise out of `run()`. Each worker is single-use; the main thread spawns a fresh instance per task and discards it after `finished` fires.

### Common shape

Every worker:

- Is a `QThread` subclass (D2).
- Declares `pyqtSignal(object)` signals on the subclass for every typed completion / progress payload it emits. The inherited `started` and `finished` signals from `QThread` are also exposed and the `MainWindow` connects to `worker.finished` for slot cleanup (the `*_finished_with_*` / `errored` signals plus the inherited ones, jointly).
- Captures every typed exception inside `run()` and re-emits it via the `errored` signal carrying an `Exception` instance (never a string, dict, or `None`). The worker thread always exits cleanly. The mutual-exclusion invariant: per `run()` invocation, exactly one of `finished_with_*` or `errored` fires (R12.7, P80).
- Receives a cancellation request via `request_cancel()` (or `request_cancellation()` for `ExtractionWorker` — different method name, but same `threading.Event` primitive after the v1.0.3 D3 closure); the underlying library API receives the cancellation token as a `cancel: Callable[[], bool]` parameter that returns `True` once the request has been registered. Cancellation is cooperative and **not** an exception path; partial results are returned via `finished_with_*`.

The full inherited-and-declared signal sets per worker:

```
ExtractionWorker     : started, finished                             (inherited from QThread)
                       progress_event, finished_with_result, errored  (declared on subclass)

BaselineLoadWorker   : started, finished                             (inherited from QThread)
                       progress, finished_with_result, errored        (declared on subclass)

AnalysisWorker       : started, finished                             (inherited from QThread)
                       finished_with_report, errored                  (declared on subclass)
```

### `ExtractionWorker` (R10)

- Calls `loki.extraction.extract_firmware(path, config, progress=..., cancel=...)`.
- Cancellation primitive: `threading.Event` (post-v1.0.3 D3 closure; previously a `bool` flag). `request_cancellation()` sets the event; the event's `is_set` method is passed as the `cancel` callback to `extract_firmware`. The public method names (`request_cancellation()` / `cancelled` property) are intentionally distinct from the other workers' `request_cancel()` / `is_cancel_requested()` to preserve the v1.0.0 caller contract; only the underlying primitive changed.
- Errored payload: instance of `InvalidInputError`, `ManifestConstructionError`, or `ExtractionPipelineError`. `MainWindow._on_extraction_errored` dispatches on runtime type via `isinstance`.
- Progress payload: `ProgressEvent` from `loki.extraction`. The status bar formats it as `"Extracting {basename}: {phase} ({n}/{total}) {message}"`.
- Default config: `DEFAULT_EXTRACTION_CONFIG` in `loki/gui/actions/extract_components.py` with `default_output_dir=""`, `max_component_size=50_000_000`, `timeout_per_component=60` (D11 — config exposure deferred to CLI).
- Lifecycle: spawned by `MainWindow.start_extraction(image, path, config)`; refused if `self._active_worker is not None` (R10.5, R15.2). `closeEvent` calls `request_cancellation()` then `wait(5_000)`.

### `BaselineLoadWorker` (R11)

- Calls `BaselineStore.load(progress=..., cancel=...)`.
- Cancellation primitive: `threading.Event`. `request_cancel()` sets the event; `is_cancel_requested()` reads it (R11.3).
- Errored payload: `BaselineStoreError` instance (in v1 always `BaselineStorageUnwritableError`, the only documented load-time error per the baseline-persistence spec; the catch is rooted at the parent class `BaselineStoreError` to remain forward-compatible — see R11.4 and R17.3 isinstance-vs-parent-catch design).
- Progress payload: `LoadProgressEvent`. Status bar formats `"Loading baselines… {index}/{total} ({path.name})"`.
- Cancellation contract (delegated): `BaselineStore.load` returns a partial `LoadResult` per the baseline-persistence spec R2.9 when cancellation fires; the worker emits `finished_with_result` (NOT `errored`) carrying the partial result, and `MainWindow` applies it on the same code path as a full load.
- Lifecycle: spawned at `MainWindow.__init__` (background_load=True default); v1 only spawns this worker once per MainWindow lifecycle. `closeEvent` calls `request_cancel()` then `wait(30_000)` (the 30 s budget reflects the 1024-baseline worst case at the per-`Baseline_File` cancellation cadence; see R1.4 implementation note).

### `AnalysisWorker` (R12)

- After Wave A: constructs a fresh `BaselineStore` from `BaselineConfig(storage_path=baseline_path, auto_match=True)` on the worker thread (rather than reusing `MainWindow._baseline_store`), calls `BaselineStore.load`, then `loki.classification.classify_components`, then `loki.analysis.analyze_image`. The fresh-store construction keeps the worker decoupled from the main thread's in-memory snapshot (R12.1).
- Cancellation primitive: `threading.Event`. `request_cancel()` sets the event; the event's `is_set` method is passed as the `cancel` callback to every underlying pipeline call (R12.3).
- Errored payload: instance of `AnalysisError`, `ClassificationPipelineError`, `BaselineStoreError`, or `RuntimeError`. Non-typed exceptions are wrapped in `RuntimeError` so the worker thread always exits cleanly (R12.4).
- Cancellation contract (delegated): the analysis pipeline's R1.10 cancellation-as-return-path contract returns a partial `ImageAnalysisReport` carrying a `Cancellation_Marker` finding; `AnalysisWorker` emits `finished_with_report` (NOT `errored`) carrying the partial report (R12.5).
- AnalysisConfig used: `severity_weights={type:0.25, vendor:0.25, security_posture:0.30, mutability:0.20}`, `default_severity_threshold=SeverityLevel.MEDIUM`, plus the model defaults `match_strategy=MatchStrategy.AUTO` and `confidence_gap_threshold=0.6`. `ClassificationConfig` with `confidence_threshold=0.6` and `taxonomy_version="1.0.0"` (R12.7).
- Progress callback: **NOT subscribed** in v1. The status bar shows the literal `"Running analysis…"` for the duration of the worker run (R16.6). Wiring the analysis-engine's `AnalysisProgressEvent` is forward-tracked (Q1 below, R24).
- Lifecycle: spawned by `MainWindow._on_run_analysis` (Ctrl+A); single-active enforcement is via `self._analyze_action.setEnabled(False)` for the duration of the run (R15.4). `closeEvent` calls `request_cancel()` then `wait(5_000)`.

### Slot guard during teardown (R1.5)

`MainWindow.closeEvent` sets `self._closing = True` **before** invoking any worker's `request_cancel()` / `request_cancellation()`. Every `_on_*_finished` and `_on_*_progress` slot early-returns when `self._closing is True`. Worker-emitted Qt signals are queued by Qt's queued-connection mechanism, so a signal in flight at the moment teardown begins is delivered to the slot AFTER the flag is set; the flag-check is the authoritative guard. This prevents tab creation, navigation-entry insertion, and status-bar updates on a partially-torn-down window.

### closeEvent timeout fallback (R1.6)

When any `worker.wait(N)` returns `False` during `MainWindow.closeEvent`, the MainWindow logs a WARNING under `loki.gui` containing the worker class name (NOT the firmware path or any `Forbidden_Leakage_Field_Set` member), proceeds to `QSettings` persistence and `super().closeEvent` regardless, and SHALL NOT call `thread.terminate()` — forced termination corrupts Qt state. The worker is left to exit when the process does. The `wait(...)` budgets are best-effort, not load-bearing for the Qt-state contract.

## Action surface

The action surface is **menu-bar-only** (D6). No toolbar, no context menu on the navigation pane, no drag-and-drop handler. Three top-level menus, ten entries.

### Menu bar layout (R14)

```
&File                            &View                                           &Help
  &Open Firmware Image…  Ctrl+O    Load &Demo Data                                 &About Loki
  ───────────────────              &Extract Firmware Components…  Ctrl+E
  &Quit                  Ctrl+Q    Run &Analysis…                Ctrl+A
                                   Load &Fleet Report…
                                   ───────────────────
                                   &Open Baseline Registry…
                                   &Save Baseline…
                                   &Cancel Baseline Load
                                   ───────────────────
                                   &Reset Workspace
```

### Keyboard shortcuts (closed v1 set)

| Shortcut | Action                                |
| -------- | ------------------------------------- |
| `Ctrl+O` | Open Firmware Image…                  |
| `Ctrl+Q` | Quit                                  |
| `Ctrl+E` | Extract Firmware Components…          |
| `Ctrl+A` | Run Analysis…                         |

The closed v1 set is intentional. Additional shortcuts (e.g. `Ctrl+S` for Save Baseline, `Ctrl+R` for Reset Workspace, `Ctrl+W` for Close Tab) are forward-tracked and not part of v1.

### Help menu closure (R14.4)

The `&Help` menu contains exactly one entry — `&About Loki` — whose handler renders an `about` dialog containing the package version resolved via `importlib.metadata.version("loki")`, falling back to `"unknown"` when the package is not installed. **Documentation links, keyboard-shortcut help, bug-report shortcuts, and any update-check entry are OUT OF SCOPE for v1.**

### Contextual enablement matrix

The menu actions are **contextually enabled** based on MainWindow state. The single-active-worker invariant (R15) is enforced exclusively at this layer.

| Action                        | Enabled iff                                                                                                | Notes                                                                                                                |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Open Firmware Image…          | Always                                                                                                     | File-dialog fronted; `*_from_path` companion is the test surface (R13.3).                                            |
| Quit                          | Always                                                                                                     | Calls `self.close()`; triggers `closeEvent`.                                                                         |
| Load Demo Data                | Always                                                                                                     | One-shot; idempotent in v1 (re-clicking re-loads).                                                                   |
| Extract Firmware Components…  | (≥1 firmware image is loaded) AND (no extraction worker is currently running)                              | Re-evaluated when an image is added / removed / extracted (R14.5, R10.5).                                            |
| Run Analysis…                 | (≥1 extraction result is available)                                                                        | `_refresh_analyze_action_enabled` is the single point of truth (R14.6, R15.4).                                       |
| Load Fleet Report…            | Always                                                                                                     | File-dialog fronted; size cap + pre-flight enforced before `model_validate_json` (R7.2).                             |
| Open Baseline Registry…       | Always                                                                                                     | File-dialog fronted; pre-flight on directory path (R13.6).                                                           |
| Save Baseline…                | A `BaselineView` is the currently-active workspace tab AND the underlying `BaselineRecord` is not demo-tagged | Re-evaluated on tab change (R14.7); demo-tagged baselines refuse to persist (R13.4).                                 |
| Cancel Baseline Load          | A `BaselineLoadWorker` is running AND no cancellation has been requested yet                               | Re-evaluated on worker spawn / cancel-request (R14.8).                                                               |
| Reset Workspace               | Always                                                                                                     | Clears every nav entry, every tab, every cached view; requests cancellation of any active extraction worker (R19.5). |
| About Loki                    | Always                                                                                                     | About dialog only (R14.4).                                                                                           |

### Action_Function contract (R13)

Every Action_Function under `loki.gui.actions.*`:

1. Is a free function whose first positional parameter is `window: MainWindow`.
2. Does NOT subclass `MainWindow`, hold module-level mutable state, or hold a class-level reference to the active window.
3. If it dispatches a file dialog, exposes a `*_from_path` companion (e.g. `open_firmware_from_path`, `open_baseline_from_path`) that accepts the chosen path directly so tests can bypass the dialog.
4. Each `*_from_path` companion applies the same input-validation pre-flight as the dialog flow: `Path(path).resolve(strict=True)`, `path.is_file()` or `path.is_dir()`, `os.access(path, os.R_OK)`, the entry-point-specific size cap. The `*_from_path` entry-point is NOT a privilege escalation around the dialog flow.
5. Returns `None` on failure; the caller can chain on success-or-None. Every typed exception surfaces via `QMessageBox.warning` (or `.question` for the overwrite prompt in `save_baseline`).

The duck-typed contract is bound to the `MainWindow` class in v1 (D-coupled); widening to a `Protocol` is forward-tracked (Q2 below, R24).

## Persistence

`QSettings` persistence is the **only** state the GUI persists across launches. The footprint is intentionally tiny — three keys, no file paths, no model identifiers — so the namespace acts as a stable surface across upgrades.

### QSettings keys

| Key                       | Value type            | Restored on init | Persisted on closeEvent |
| ------------------------- | --------------------- | ---------------- | ----------------------- |
| `main_window/geometry`    | `QByteArray`          | yes (R18.3)      | yes (R1.4)              |
| `main_window/state`       | `QByteArray`          | yes              | yes                     |
| `main_window/splitter`    | `QByteArray`          | yes              | yes                     |

The `QSettings` namespace is `QSettings("LOKI", "Desktop")` — the organization is the literal `"LOKI"` and the application is the literal `"Desktop"`. v1 binds these as platform-stable identifiers; namespace forks would orphan stored geometry from prior sessions (R18.2). The `QApplication` itself sets `setOrganizationName("LOKI")`, `setOrganizationDomain("loki.invalid")`, `setApplicationName("Loki")`, and `setApplicationDisplayName("Loki")` — those four strings are ALSO load-bearing.

### Init lifecycle (R18.3, R18.4)

```python
# loki/gui/main_window.py — sketch of __init__ restoration
settings = QSettings("LOKI", "Desktop")
geometry = settings.value("main_window/geometry")
if isinstance(geometry, QByteArray) and not geometry.isEmpty():
    self.restoreGeometry(geometry)
else:
    self.resize(*_DEFAULT_SIZE)  # _DEFAULT_SIZE = (1280, 800)

state = settings.value("main_window/state")
if isinstance(state, QByteArray) and not state.isEmpty():
    self.restoreState(state)

splitter = settings.value("main_window/splitter")
if isinstance(splitter, QByteArray) and not splitter.isEmpty():
    self._splitter.restoreState(splitter)
else:
    self._splitter.setSizes([260, 1020])
```

The `isinstance(value, QByteArray)` guard is load-bearing: a stored value of an unexpected Qt type (cross-version drift, manual settings file edit) is skipped without crashing, and the MainWindow falls back to the default geometry.

### closeEvent lifecycle (R1.4, R1.6)

```
closeEvent fires
    │
    ├── self._closing = True
    │
    ├── (a) request cancellation on _active_worker (extraction)
    │       wait(5_000); on False → log WARNING, continue
    │
    ├── (b) request cancellation on _baseline_load_worker
    │       wait(30_000); on False → log WARNING, continue
    │
    ├── (c) request cancellation on _active_analysis_worker
    │       wait(5_000); on False → log WARNING, continue
    │
    ├── (d) settings.setValue("main_window/geometry", self.saveGeometry())
    │       settings.setValue("main_window/state", self.saveState())
    │       settings.setValue("main_window/splitter", self._splitter.saveState())
    │
    └── (e) super().closeEvent(a0)
```

The cancellation+join phase and the QSettings write both complete before the superclass call returns. The `super().closeEvent` does not return until all five steps have finished.

### Forbidden persistence (R18.5)

The GUI subsystem SHALL NOT persist:

- File paths (firmware-image paths, baseline-registry directories, fleet-report paths) — these frequently embed customer / device / case identifiers and are within the spirit of the `Forbidden_Leakage_Field_Set` even though the path string itself is not on the enumerated list.
- Model identifiers (`image_id`, `baseline_id`, `report_id`, `component_id`).
- Recent-files lists.
- Open-tab snapshots.
- Preferences.
- Any field from the `Forbidden_Leakage_Field_Set` defined in the requirements Glossary.

P82 (`settings_namespace_stability`) enforces both the round-trip stability of the three v1 keys AND the substring-scan that no operator-chosen file path or any model identifier from the demo workspace's known string members appears in the stored bytes after a full demo cycle.

## Threading model

### v1: QThread subclass per task (D2)

Each of the three workers is a `QThread` subclass with its own `run()` method. The pattern is:

1. The MainWindow constructs a fresh worker instance per task.
2. The MainWindow connects worker signals to MainWindow slots **before** calling `worker.start()`.
3. `worker.start()` queues the thread for execution.
4. `run()` calls the underlying library API synchronously, captures any exception, and emits exactly one `finished_with_*` or `errored`.
5. The `finished` (inherited) signal fires; the connected MainWindow slot does cleanup.
6. The worker is discarded; a fresh instance is constructed for the next task.

Cross-thread payload marshalling uses Qt's queued-connection mechanism via the `pyqtSignal(object)` declarations. The MainWindow SHALL NOT call `QApplication.processEvents()` from action functions, view constructors, or worker slots (R22.5); the `pyqtSignal` ↔ slot pairing is the authoritative cross-thread bridge.

### Forward-tracked migration (R24.1, Q1 below)

Migration to `QObject.moveToThread()` or `QThreadPool` + `QRunnable` is on the roadmap and is OUT OF SCOPE for v1. Trigger conditions for revisiting:

- Operator reports of "GUI feels heavy" tied to QThread spawn cost.
- A second concurrent worker type per slot (e.g. simultaneous extraction of two firmware images) becomes a real requirement.
- A measurable memory-fragmentation concern from per-task QThread allocation across long sessions.

The migration is a separate OT-LK; it would replace the three `QThread` subclasses with `QRunnable` subclasses dispatched through `QApplication.instance().threadPool()` (or a private `QThreadPool` for prioritisation), and require re-binding the cancellation primitive (the `threading.Event` pattern carries forward unchanged, but the request-cancel path moves from `worker.request_cancel()` → `runnable.cancel()`).

### `bool` flag → `threading.Event` migration (R24.2, D3) — CLOSED v1.0.3

`ExtractionWorker._cancelled` was a `bool` at v1.0.0; the CPython GIL made the attribute write atomic in practice. **Closed in harness round v1.0.3** by replacing it with a `threading.Event` (`self._cancel_event`) so the cancellation primitive is uniform across all three workers. The public surface (`request_cancellation()` / `cancelled` property) is unchanged — only the underlying primitive moved. Coverage: `tests/gui/test_extraction_worker.py::test_request_cancellation_is_idempotent` mirrors the P79 idempotence property the spec mandates for `BaselineLoadWorker` and `AnalysisWorker`.

## Test surface

### Test layout (R26)

```
tests/gui/
├── conftest.py                            # SilentDialogs autouse fixture; pytest-qt qtbot setup
├── test_app.py                            # run() entry point + QApplication metadata
├── test_main_window_lifecycle.py          # __init__, closeEvent, _closing flag, wait() fallback
├── test_navigation.py                     # NavigationPane structure, add_entry, reset, sanitisation
├── test_workspace.py                      # open_tab dedupe, has_tab, close-tab cleanup
├── test_views_firmware_image.py           # offscreen render of FirmwareImageView
├── test_views_extraction.py               # offscreen render of ExtractionView (incl. placeholder)
├── test_views_baseline.py                 # offscreen render of BaselineView (incl. comparison)
├── test_views_image_analysis_report.py    # offscreen render of ImageAnalysisReportView
├── test_views_analysis.py                 # offscreen render of AnalysisView (incl. baseline_comparison sub-section)
├── test_views_fleet.py                    # offscreen render of FleetAnalysisView
├── test_extraction_worker.py              # qtbot.waitSignal on finished_with_result + errored
├── test_baseline_load_worker.py           # qtbot.waitSignal on finished_with_result + errored + progress
├── test_analysis_worker.py                # qtbot.waitSignal on finished_with_report + errored — GAP CLOSED IN BIND
├── test_actions_open_firmware.py          # open_firmware_from_path happy path + every error path
├── test_actions_extract_components.py     # extract_components happy path + error path
├── test_actions_open_baseline.py          # open_baseline_from_path happy path + error path
├── test_actions_save_baseline.py          # save_baseline happy + overwrite-prompt + concurrent + demo-refusal
├── test_actions_load_demo_data.py         # load_demo_data full demo cycle
├── test_settings_persistence.py           # QSettings round-trip + paths-not-stored audit
├── test_status_bar.py                     # idle and transient text formatting
├── test_error_dialogs.py                  # SilentDialogs assertions on every dispatched-error path
├── test_imports.py                        # cli-import audit + processEvents audit + network-egress audit
└── properties/
    ├── __init__.py
    ├── test_p77_navigation.py             # P77 navigation_entry_invariants
    ├── test_p78_workspace.py              # P78 workspace_tab_uniqueness
    ├── test_p79_worker_cancel.py          # P79 worker_cancel_idempotence (BaselineLoadWorker + AnalysisWorker)
    ├── test_p80_analysis_error_typing.py  # P80 analysis_worker_error_typing
    ├── test_p81_error_dialog.py           # P81 error_dialog_total_function
    ├── test_p82_settings.py               # P82 settings_namespace_stability
    ├── test_p83_render_purity.py          # P83 view_render_purity
    ├── test_p84_offscreen_render.py       # P84 offscreen_full_render
    └── test_p85_view_text.py              # P85 view_text_determinism
```

### SilentDialogs autouse fixture (R21.2, D14)

```python
# tests/gui/conftest.py — sketch
import pytest
from PyQt6.QtWidgets import QMessageBox

@pytest.fixture(autouse=True)
def silent_dialogs(monkeypatch):
    """Replace QMessageBox blocking calls with record-and-return stubs.

    Required to prevent the offscreen Qt event loop from freezing on any
    application-modal dialog. The fixture's call records are exposed for
    test assertions on R17 / R13 dialog dispatch.
    """
    calls = []

    def _record_and_return(level, parent, title, message, *args, **kwargs):
        calls.append((level, title, message))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(
        QMessageBox, "warning",
        lambda *a, **kw: (_record_and_return("warning", *a), QMessageBox.StandardButton.Ok)[-1],
    )
    monkeypatch.setattr(
        QMessageBox, "information",
        lambda *a, **kw: (_record_and_return("information", *a), QMessageBox.StandardButton.Ok)[-1],
    )
    monkeypatch.setattr(
        QMessageBox, "question",
        lambda *a, **kw: (_record_and_return("question", *a), QMessageBox.StandardButton.No)[-1],
    )
    monkeypatch.setattr(
        QMessageBox, "about",
        lambda *a, **kw: _record_and_return("about", *a),
    )
    yield calls
```

The fixture is autouse to prevent any test that accidentally trips a QMessageBox path from freezing the event loop (R21.2).

### `scripts/smoke_gui.py` contract (R21.3, R26.5)

The standalone smoke harness exercises the full demo cycle outside `pytest`. It:

1. Sets `QT_QPA_PLATFORM=offscreen`.
2. Constructs a `QApplication` and a `MainWindow(background_load=False)`.
3. Calls `load_demo_data(window)`.
4. Asserts: 4 navigation groups present; ≥4 navigation entries (2 images, 1 baseline, 1 report); 4 workspace tabs (open every demo entry by simulating `item_activated`).
5. Calls `MainWindow.reset_workspace`.
6. Asserts: 0 navigation entries (placeholders restored), 0 workspace tabs.
7. Calls `window.close()` and processes events until close-related signals drain.
8. Exits 0 on success, non-zero on any assertion failure.

The script calls `QApplication.processEvents()` because it drives the event loop synchronously without `app.exec()`; this is by design for CI smoke verification and is OUT OF SCOPE for the `loki/gui/` import-graph invariant. The CI grep audit at R26 explicitly excludes `scripts/smoke_gui.py`.

### CI gate audits (R26.6)

Three import / source audits run as CI gates that fail the build on regression:

```bash
# (a) cli → gui import audit (zero matches in either grep)
grep -rE "^from loki\.cli" loki/gui/   # → 0 matches
grep -rE "^import loki\.cli" loki/gui/ # → 0 matches

# (b) processEvents audit (zero matches inside loki/gui/)
grep -rE "\.processEvents\(" loki/gui/ # → 0 matches
                                        # scripts/smoke_gui.py is exempt by path

# (c) network-egress import-time audit
python -c "
import sys, builtins
import unittest.mock as m
with m.patch('socket.socket'), m.patch('urllib.request.urlopen'):
    import loki.gui  # noqa: F401
print('OK')
"  # → exits 0 with no socket / urllib call
```

Mocking `requests` and `httpx` is conditional on whether they are installed; the import-time audit treats their absence as evidence of compliance.

### Hypothesis settings carried forward

- In-memory invariant properties (P77, P78, P79, P80, P82): `max_examples=50`, `suppress_health_check=[HealthCheck.too_slow]`.
- Render-purity / offscreen properties (P83, P84, P85): `max_examples=25`, `suppress_health_check=[HealthCheck.too_slow]`.

## Cross-cutting properties P77-P85

The GUI subsystem allocates **Properties 77 through 85**, picking up where `fleet-analysis` left off (P72-P76). These nine properties are validated by `pytest-qt` + Hypothesis tests at `tests/gui/properties/`. Each property carries a `**Validates-Requirements: X.Y**` mapping anchoring it to the requirements document.

### Property 77: navigation_entry_invariants

For any sequence of `add_entry(group, key, label)` and `reset()` calls applied to a fresh `NavigationPane`, the resulting child count under each group SHALL equal the cardinality of distinct `key`s passed to `add_entry` for that group since the last `reset`. Re-adding the same key updates the label in-place rather than appending a duplicate. After `reset()`, every group has exactly one disabled placeholder child.

**Validates-Requirements: 8.1, 8.3, 8.7**

### Property 78: workspace_tab_uniqueness

For any sequence of `Workspace.open_tab(key, title, widget)` calls on a fresh `Workspace`, the count of tabs SHALL equal the cardinality of distinct `key`s seen so far. Re-opening with an already-registered key focuses the existing tab and returns its index. Closing a tab drops every key whose registered widget is the closing widget AND calls `widget.deleteLater()`.

**Validates-Requirements: 9.1, 9.3, 9.5**

### Property 79: worker_cancel_idempotence

For any sequence of `request_cancel()` calls on a fresh `BaselineLoadWorker`, `is_cancel_requested()` SHALL return `True` after the first call and remain `True` for all subsequent calls and reads. The same property SHALL hold for the analogous APIs on `AnalysisWorker`. (P79 covers both workers; the property is parametrised over the two worker classes.)

**Validates-Requirements: 11.3, 12.3**

### Property 80: analysis_worker_error_typing

For every exception raised inside `AnalysisWorker.run`, the `errored` signal payload SHALL be an `Exception` instance (never a string, dict, or `None`); the property is enforced via `isinstance(payload, Exception)` in the test harness. The payload's runtime type is one of: `AnalysisError`, `ClassificationPipelineError`, `BaselineStoreError`, or `RuntimeError` — non-typed exceptions are wrapped in `RuntimeError` per R12.4.

**Validates-Requirements: 12.4, 12.7**

### Property 81: error_dialog_total_function

For every member of the closed v1 error category set in R17.3 (`InvalidInputError`, `ManifestConstructionError`, `ExtractionPipelineError`, `BaselineAlreadyExistsError`, `BaselineConcurrentModificationError`, `BaselineSerializationError`, `AnalysisError`, `ClassificationPipelineError`, `RuntimeError`, `ValueError`, `OSError`), the `MainWindow` slot wired to that error type SHALL produce exactly one `QMessageBox.warning` invocation per error signal. The property is enforced via SilentDialogs call-count assertions.

**Validates-Requirements: 17.1, 17.3, 17.6**

### Property 82: settings_namespace_stability

A round-trip through `QSettings.setValue` / `QSettings.value` for each of the three v1 keys (`main_window/geometry`, `main_window/state`, `main_window/splitter`) SHALL preserve the value bit-equal. Additionally: for every key under `QSettings("LOKI", "Desktop")` after a full demo cycle, the stored bytes SHALL NOT contain any operator-chosen file path or any model identifier from the `Demo_Workspace`'s known string members (verifiable via substring scan over the demo workspace's string surface). This extension is the demo-baseline-poisoning guard from R13.4 and R18.5.

**Validates-Requirements: 18.1, 18.5**

### Property 83: view_render_purity

For any model instance `m` and any view kind `V` rendering it, calling `V(m).<accessor>` SHALL return `m` itself (identity, not equality). The property is enforced via `assert view.<accessor> is m` in offscreen rendering tests. Views never mutate the supplied Pydantic instance; refresh-on-change is rebuild-and-replace.

**Validates-Requirements: 20.4**

### Property 84: offscreen_full_render

For every view kind `V` in the v1 closed set (`FirmwareImageView`, `ExtractionView`, `BaselineView`, `ImageAnalysisReportView`, `AnalysisView`, `FleetAnalysisView`) and a representative model instance, constructing `V(model)` under `QT_QPA_PLATFORM=offscreen` SHALL NOT raise. The property is enforced via parametrised offscreen rendering tests.

**Validates-Requirements: 21.1, 26.3**

### Property 85: view_text_determinism

For any model instance `m` and any view kind `V`, two independent constructions `V(m)` SHALL produce equal sequences of `(row, column, text)` tuples for every embedded `QTableWidget` (and equal `(parent_path, text, [child paths])` shapes for every embedded `QTreeWidget`). The property is enforced via parametrised offscreen rendering tests.

**Validates-Requirements: 23.1**

## Open questions Q1-Q3 (deferred to BIND time)

These are decisions the design pass deliberately defers to BIND. Each one is a concrete trigger condition the BIND pass should evaluate; deferring keeps DRAFT honest about what is and is not decided.

### Q1 — When to migrate from QThread subclass to QObject.moveToThread() / QThreadPool

**Forward-track context:** D2 ratifies the `QThread`-subclass-per-task pattern for v1. R24.1 marks migration as a separate OT-LK.

**Decision deferred:** the BIND pass should record the trigger conditions for revisiting:

1. A measured GUI-spawn-cost regression in long sessions (e.g. >100 ms wall time per worker spawn on contemporary hardware, attributable to `QThread.start()`).
2. A new requirement for concurrent workers of the same type (e.g. simultaneous extraction of two firmware images).
3. Operator feedback that "the GUI stalls when I open a baseline registry" tied to the `QThread.wait(30_000)` budget on `BaselineLoadWorker`.

If none of these surface during the v1 lifecycle, the migration may legitimately stay deferred indefinitely. BIND is the right time to record the trigger thresholds; no v1-blocking decision is needed.

### Q2 — Whether to widen the Action_Function MainWindow contract to a Protocol

**Forward-track context:** R24.7 ratifies the concrete-coupling between Action_Functions and the `MainWindow` class. R13.2 says the duck-typed surface IS the test extension point.

**Decision deferred:** the BIND pass should record the trigger condition for revisiting: a second consumer of the action functions materialises (e.g. a plugin / extension surface, an alternate `LiteMainWindow` for embedded use, or a CI smoke harness that wants to drive actions without the full MainWindow). No v1-blocking decision is needed; the duck-typed test surface (the `*_from_path` companions) is sufficient until then.

### Q3 — Concrete logging.Filter mechanism for Forbidden_Leakage_Field_Set redaction

**Forward-track context:** R22.6 + R23.3 bind the contract (no Forbidden_Leakage_Field_Set substrings in log records). The TENSION pass deferred the implementation mechanism (logging.Filter class, hook registration, unit-test plumbing) to design.md (L2.G11).

**Decision deferred:** the BIND pass should choose between:

1. **Hand-written `logging.Filter`** at `loki/gui/logging.py` registered on the `loki.gui` and `loki.gui.baselines` loggers. The filter scans every record's formatted message for any Forbidden_Leakage_Field_Set member's substring representation; on a match, it either drops the record or substitutes a redacted placeholder.
2. **Static AST audit** at `tests/gui/test_no_log_leakage.py` mirroring `tests/analysis/test_no_log_leakage.py`. AST-walks every Python file in `loki/gui/` and asserts no `logging.Logger.*` call has a format-string or %-style argument referencing any field in the set. Catch-time is reviewer-checkable.
3. **Both** — defence-in-depth: the AST audit at static-time, the runtime filter at dynamic-time.

The TENSION pass leaned toward (3) for parity with the analysis-engine pattern. BIND should evaluate whether (1) is a release-blocking risk relative to (2) alone, given that v1's logging is sparse (one warning on `BaselineLoadWorker` startup-fallback path; one warning on `closeEvent` `wait()` timeout). If the audit-only path covers v1's actual log-call sites, (2) is the minimal-surface choice.

## Design defaults D1-D5 (revertable cheaply)

These are local design choices the implementation pins for v1 that future revisions could revisit without amending the requirements document. They sit beneath the operator-banked CAST decisions (D1-D15 in the requirements Glossary, which are higher-altitude and revertable only via explicit operator sign-off).

### D1 — Tab key string convention: `<kind>:<uuid>` (or `<kind>:<image_id>:<timestamp>` for extraction)

**Default:** Tab_Keys are minted as `f"{kind}:{model.id}"` for views keyed off a single model, and `f"extraction:{image_id}:{timestamp.isoformat()}"` for extraction tabs (which need an extra disambiguator because a single image can be re-extracted multiple times in a session).

**Why this could change:** if collisions become a real risk (e.g. a future view kind shares a model identifier across two distinct contexts), the convention can migrate to `(kind, uuid)` tuples or to an explicit `TabKey` dataclass with an `__hash__`. v1's flat-string keys are the cheapest option that satisfies R9 while remaining grep-friendly. R27 forward-tracks the `(kind, uuid)` enum / type-tag option.

### D2 — Status bar message timeout: persistent (no auto-clear)

**Default:** Transient status-bar messages persist until explicitly cleared via `_set_status_message(None)`; the GUI does NOT auto-clear after a timeout. The idle summary text (`"images: {n}  last extraction: {iso8601_or_dash}  classification version: {version_or_dash}"`) returns when the transient is cleared.

**Why this could change:** if operators report that "the status bar is stale after a worker finishes", a 3-second auto-clear timeout via `QStatusBar.showMessage(text, msecs=3000)` would be a one-line revertable change. v1 prefers persistent transients because the messages are short and the operator-driven cancellation flow benefits from a stable signal.

### D3 — QMessageBox button presets: defaults

**Default:**

- `QMessageBox.warning` uses the default OK button only.
- `QMessageBox.question` (used by `save_baseline` for the overwrite prompt) uses `Yes | No` defaulting to `No`.
- `QMessageBox.information` and `.about` use the default OK button only.

The "default to No" on the overwrite prompt is the safe-default choice; an operator who hits Enter without reading the prompt does NOT overwrite an existing baseline.

**Why this could change:** if the overwrite-prompt UX needs a "Yes to all" button (e.g. for a future bulk-import action), the preset can extend with `Yes | YesToAll | No | Cancel`. v1's two-button preset is the minimal correct surface.

### D4 — Default splitter sizes: `[260, 1020]` (= 260 nav, growable workspace)

**Default:** The MainWindow's `QSplitter` opens with sizes `[260, 1020]` on first run (260 px nav, 1020 px workspace). The 260 px nav width fits the four group headers and most navigation entries without horizontal scroll.

**Why this could change:** if operator screen sizes shift (e.g. ultra-wide monitors become standard) or if the navigation group headers grow, the default can be revised to a percentage-based split (`[20%, 80%]`) or to a wider nav (`[320, 960]`). v1's pixel-based default is cheap to change and is overridden the first time the operator drags the splitter (the new size is persisted to `main_window/splitter`).

### D5 — Default window dimensions: `(1280, 800)`

**Default:** When no stored geometry is found, the MainWindow opens at `(1280, 800)`. This fits a standard 1920x1080 display with margin and is large enough to render the seven view kinds without horizontal scroll.

**Why this could change:** if telemetry (which v1 does not collect — see R22) or operator feedback shows that 1024x768 is still common in the field, the default can drop to `(1024, 768)`. v1 prefers the larger default because the views render densely at 1280 wide. Stored geometry (R18.3) overrides the default whenever present.

---

*End of design.md. tasks.md is the next session per the OT-LK-004 finalization plan; the harness flip from AD_HOC to APPROVED happens after tasks.md lands.*
