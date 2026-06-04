
# Requirements Document

## Introduction

The GUI subsystem (codename **Loki Desktop**) is the operator-facing
PyQt6 desktop surface for the LOKI firmware analysis platform. v1
ships a single-window, single-process desktop application that
renders Pydantic model instances produced by the headless library
APIs (`loki.extraction`, `loki.classification`, `loki.analysis`,
`loki.baseline`, and offline-loaded `FleetAnalysisReport` JSON) as
read-only views, organised by a left-hand navigation pane and a
central tabbed workspace.

This spec is a **retroactive ratification** of an already-implemented
subsystem (~2,700 LOC under `loki/gui/`). The GUI shipped at v1.0.0 in
lifecycle stage `IMPLEMENTED` with `spec_status = AD_HOC`; this document
is the artifact that flips `spec_status` to `APPROVED` in the subsystem
registry. **No prior spec triple existed** — the codebase preceded the
requirements document. The CAST decisions enumerated on the OT-LK-004
ticket are inputs to this spec, not relitigated; this document binds
those decisions to acceptance criteria. Where the implementation already
pins a behavioural contract, acceptance criteria cite the file:line
evidence so future contributors cannot drift away from it accidentally.

Acceptance Criteria bullets in this document use the EARS shape
established in `specs/analysis-engine/requirements.md`; new requirements
should match its phrasing and citation density.

The spec is organised model-fidelity-first: each Pydantic data model
the GUI surfaces (`FirmwareImage`, `ExtractionManifest`,
`BaselineRecord` + `BaselineComparison`, `ImageAnalysisReport`,
`FleetAnalysisReport`) gets a dedicated requirement establishing
rendering completeness against every public field on the model,
read-only enforcement, empty-state UX, and refresh contract. This
keeps the GUI honest as a *viewer of pipeline output*: when the model
layer evolves, the corresponding GUI requirement must evolve with it.

This spec covers GUI behaviour only:

- The application entry point (`loki.gui.app.run`) and its
  composition with `MainWindow`.
- The four navigation groups, the tabbed workspace, the menu bar,
  and the status bar.
- Each read-only view widget and the model fields it renders.
- The three QThread workers (`ExtractionWorker`,
  `BaselineLoadWorker`, `AnalysisWorker`) and their signal /
  cancellation / lifecycle contracts.
- The action functions (`open_firmware`, `extract_components`,
  `open_baseline`, `save_baseline`, `load_demo_data`) and the
  duck-typed `MainWindow` contract they consume.
- Demo data construction, status bar formatting, error dialog
  policy, QSettings persistence, and offscreen testability.

It does **not** cover:

- Authoring surfaces. The GUI is a viewer; baseline curation, rule
  authoring, and configuration editing are CLI-only in v1.
- A preferences / settings dialog. v1 uses default-pipeline-only;
  the CLI is the operator-config surface (D11).
- Per-view export (CSV / JSON / PDF). Operators use the CLI for
  JSON output; baseline save is the only persistence path (D12).
- Sort / filter / search across views. v1 renders models
  immediate-mode in `__init__` with no `QAbstractItemModel` /
  `QAbstractTableModel` separation (D4); this rendering choice
  precludes sort / filter / search without a model/view rewrite,
  which is forward-tracked.
- Detach-to-window or multi-window topologies. v1 is single
  `QMainWindow` per process (D1).
- Theming, dark-mode detection, custom QSS. v1 uses the OS
  platform default palette (D15).
- Toolbars, context menus on navigation, drag-and-drop. The
  action surface is menu-bar-only (D6).
- A `QThreadPool` / `QRunnable` migration. v1 ratifies the
  existing `QThread`-subclass pattern; the migration is
  forward-tracked to a future OT-LK (D2).
- Network egress. The GUI is offline-only; its
  `FleetAnalysisReport` ingestion path reads from local JSON.

The shape and quality bar mirror `extraction-pipeline`,
`baseline-persistence`, `classification-pipeline`,
`analysis-engine`, and `fleet-analysis`. Determinism of pure
rendering, the typed exception boundary at the worker / dialog seam,
the cooperative-cancellation pattern, and the offline-only audit all
carry forward from the upstream subsystems.

## Glossary

- **MainWindow**: The single `QMainWindow` subclass at
  `loki.gui.main_window.MainWindow` that hosts the navigation pane,
  tabbed workspace, menu bar, and status bar. One `MainWindow`
  instance per process; v1 is single-window per D1.
- **NavigationPane**: The `QTreeWidget` subclass at
  `loki.gui.navigation.NavigationPane` rendering the four fixed
  top-level groups (`Images`, `Baselines`, `Reports`, `Fleet`) and
  their child entries. Double-click on a child entry emits the
  `item_activated(group, key, label)` signal that MainWindow
  consumes to focus or open the matching tab.
- **Workspace**: The `QTabWidget` subclass at
  `loki.gui.workspace.Workspace` hosting the read-only View widgets
  for opened items. Tabs are closable, movable, and keyed by an
  opaque string identifier so re-activation focuses the existing
  tab instead of opening a duplicate.
- **View**: One of six read-only `QWidget` subclasses under
  `loki.gui.views.*`, each rendering one Pydantic model
  immediate-mode at construction time. The closed v1 set is
  `FirmwareImageView`, `ExtractionView`, `BaselineView`,
  `ImageAnalysisReportView`, `AnalysisView`, and `FleetAnalysisView`.
  Refresh is rebuild-and-replace; views never mutate.
- **Worker**: One of three `QThread` subclasses under
  `loki.gui.*_worker.py` that run a headless library API on a
  background thread and report progress / completion / failure via
  Qt signals. The closed v1 set is `ExtractionWorker`,
  `BaselineLoadWorker`, and `AnalysisWorker`.
- **Action_Function**: A free function under `loki.gui.actions.*`
  that mutates `MainWindow` state in response to a menu trigger.
  Action_Functions accept a single `window: MainWindow` argument
  (and additional caller-supplied data where applicable) so tests
  can drive them without invoking the file dialogs.
- **Tab_Key**: An opaque string identifier minted by `MainWindow`
  for each Workspace tab. Tab_Keys are namespaced by view kind
  (`image:<image_id>`, `baseline:<baseline_id>`,
  `report:<report_id>`, `extraction:<image_id>:<timestamp>`,
  `analysis:<report_id>`, `fleet:<report_id>`) so two views of
  different kinds cannot collide. The Workspace API treats
  Tab_Keys as opaque strings.
- **Demo_Workspace**: The `DemoWorkspace` dataclass returned by
  `loki.gui.demo.synthetic.build_demo_workspace`. A coherent set
  of Pydantic instances (2 `FirmwareImage`, 1 `BaselineRegistry`
  holding 1 `BaselineRecord`, 1 `BaselineComparison`,
  1 `ImageAnalysisReport`) used by the `View → Load Demo Data`
  menu action. Every entry the action inserts into `MainWindow`
  carries the `(demo)` label suffix.
- **BaselineRegistry**: The in-memory wrapper dataclass at
  `loki.gui.demo.synthetic.BaselineRegistry` that pairs a single
  `BaselineRecord` with its associated demo data. Distinct from
  the upstream `BaselineStore` (the on-disk persistence root) and
  from the `BaselineRecord` (the Pydantic model). Used only in the
  demo flow; production GUI flows surface `BaselineRecord`
  instances directly.
  (`loki/gui/demo/synthetic.py:48-51`)
- **Forbidden_Leakage_Field_Set**: The closed set of upstream
  Pydantic-model fields the GUI SHALL NOT include in any log
  record: `component_id`, `signer`, `source_image_hash`, the
  contents of `FindingEvidence.matched_rule`,
  `FindingEvidence.matched_cve`,
  `FindingEvidence.matched_signature`,
  `FindingEvidence.raw_indicators`, `FindingRecord.title`,
  and `FindingRecord.description`. The view layer SHALL render
  these fields (Requirements 5, 6); the log layer SHALL NOT.
  Defined here once so Requirements 22 and 23 reference the same
  closed set.
- **SilentDialogs**: A pytest-fixture pattern that monkey-patches
  `QMessageBox.warning`, `.information`, `.question`, and
  `.about` to record-and-return rather than block on a modal
  dialog. SilentDialogs is the only mechanism by which the test
  suite exercises Action_Function error paths without freezing
  the offscreen Qt event loop.
- **Forbidden_Egress_Set**: The set of operations the GUI SHALL
  NOT perform under any circumstance. The set is `{network
  socket open, HTTP request, DNS resolution beyond loopback,
  cloud SDK call, telemetry beacon, automatic update check,
  firmware-image mutation, credential read}`. v1 is offline-only
  by construction; this set is auditable from the import graph.

## Requirements

### Requirement 1: Application entry point and lifecycle

**User Story:** As an operator launching `loki gui` from the CLI, I
want the application to start, restore my last window geometry,
load any persisted baselines, and shut down cleanly when I close
the window — without leaving worker threads running and without
losing my window placement.

#### Acceptance Criteria

- THE GUI subsystem SHALL expose a synchronous public entry point
  importable as `from loki.gui.app import run` returning the
  Qt event-loop exit code as `int`.
  (`loki/gui/app.py:74-82`)
- WHEN `run()` is called, THE GUI subsystem SHALL build (or reuse,
  if `QApplication.instance()` is non-None) a `QApplication`,
  set its `applicationName` to `"Loki"`, `organizationName` to
  `"LOKI"`, `organizationDomain` to `"loki.invalid"`, construct
  exactly one `MainWindow`, call `show()` on it, and enter
  `app.exec()`.
  (`loki/gui/app.py:49-71`)
- THE `MainWindow` constructor SHALL inject a default
  `BaselineStore` rooted at `~/.local/share/loki/baselines` when
  no caller-supplied store is provided, and SHALL silently fall
  back to `None` (logging a warning under `loki.gui.baselines`)
  when the path cannot be created.
  (`loki/gui/app.py:23-46`)
- WHEN the user closes the window, THE GUI subsystem SHALL
  invoke `MainWindow.closeEvent` which SHALL execute, in this
  order: (a) request cancellation on the active extraction
  worker (if any) and `wait(5_000)`; (b) request cancellation
  on the active baseline-load worker (if any) and
  `wait(30_000)`; (c) request cancellation on the active
  analysis worker (if any) and `wait(5_000)`; (d) persist
  `main_window/geometry`, `main_window/state`, and
  `main_window/splitter` into the
  `QSettings("LOKI", "Desktop")` namespace; and finally
  (e) call `super().closeEvent(a0)`. The cancellation+join
  phase and the QSettings write SHALL both complete before
  the superclass call returns.
  *Implementation note:* The 30 s budget on (b) reflects the
  per-`Baseline_File` cancellation cadence and the
  1024-baseline worst case noted in
  `loki/gui/baseline_load_worker.py:1`.
  (`loki/gui/main_window.py:418-445`)
- BEFORE requesting cancellation on any worker (step (a) above),
  THE `MainWindow.closeEvent` SHALL set `self._closing = True`;
  every `_on_*_finished` and `_on_*_progress` slot SHALL
  early-return when `self._closing is True`. This prevents
  tab-creation, navigation-entry-insertion, and status-bar
  update on a partially-torn-down window. Worker-emitted Qt
  signals are queued by Qt's queued-connection mechanism, so a
  signal in flight at the moment teardown begins is delivered
  to the slot AFTER the flag is set; the flag-check is the
  authoritative guard.
- WHEN any `worker.wait(N)` returns `False` during
  `MainWindow.closeEvent`, THE `MainWindow` SHALL: (a) log a
  WARNING under `loki.gui` containing the worker class name
  (NOT the firmware path or any `Forbidden_Leakage_Field_Set`
  member); (b) proceed to `QSettings` persistence and
  `super().closeEvent` regardless; (c) NOT call
  `thread.terminate()` (forced termination corrupts Qt state) —
  the worker is left to exit when the process does. The
  `wait(...)` budgets are best-effort, not load-bearing for the
  Qt-state contract.
- THE CLI subcommand `loki gui` SHALL invoke `loki.gui.app.run`
  and SHALL exit with the returned event-loop exit code.
- THE GUI subsystem SHALL be importable from a process that has
  already constructed a `QApplication` (e.g. under
  `pytest-qt`) without raising on the second `QApplication(...)`
  attempt.
  (`loki/gui/app.py:60-64`)
- WHEN `run()` is called against an existing
  `QApplication.instance()`, THE GUI subsystem SHALL NOT call
  `setOrganizationName` / `setApplicationName` /
  `setOrganizationDomain` / `setApplicationDisplayName` — those
  metadata calls are gated on `QApplication` construction in v1
  and would otherwise mutate a host process's namespace. The
  `QSettings("LOKI", "Desktop")` persistence path uses explicit
  organization/application arguments and does NOT depend on
  `QApplication` metadata, so this restriction is cosmetic-only
  for stand-alone use and operationally safe for embedding.
  (`loki/gui/app.py:60-68`)
- THE `QApplication` SHALL set `setOrganizationName("LOKI")`,
  `setOrganizationDomain("loki.invalid")`,
  `setApplicationName("Loki")`, and
  `setApplicationDisplayName("Loki")`; these four strings are
  load-bearing — a namespace fork would orphan stored geometry
  from prior sessions.
  (`loki/gui/app.py:65-68`)
- THE `loki.gui` package SHALL NOT import any symbol from
  `loki.cli` or `loki.cli.*`; the `cli → gui` direction
  (the `loki gui` subcommand wraps `gui.app.run`) is the only
  permitted edge between the two packages, and the reverse
  edge would create a circular import and a layering
  violation. The invariant SHALL be enforced as a CI gate
  that fails the build on regression: the gate runs
  `grep -rE "^from loki\.cli" loki/gui/` and
  `grep -rE "^import loki\.cli" loki/gui/` and asserts both
  return zero matches (see Requirement 26 for the gate
  registration).
- THE `loki.gui` package SHALL NOT make any network call,
  spawn any subprocess that performs network I/O, or perform
  DNS resolution, mirroring the headless library subsystems'
  offline contract; this invariant is the GUI's contribution
  to the platform-wide Forbidden_Egress_Set.

### Requirement 2: FirmwareImage rendering (FirmwareImageView)

**User Story:** As an analyst opening a firmware binary, I want to
see every metadata field on the constructed `FirmwareImage` in a
read-only table so I can confirm the file path, hash, and size
before running an extraction.

#### Acceptance Criteria

- WHEN `MainWindow.add_firmware_image(image)` is called with a
  `FirmwareImage` instance, THE GUI subsystem SHALL construct
  exactly one `FirmwareImageView` for that instance and open a
  Workspace tab keyed `image:<image.image_id>`.
  (`loki/gui/main_window.py:151-164`)
- THE `FirmwareImageView` SHALL render a two-column read-only
  `QTableWidget` containing exactly these eight rows in this
  order: `image_id`, `file_path`, `file_hash`, `file_size`
  (formatted as `"{n:,} bytes"`), `vendor`, `model`,
  `firmware_version`, `extraction_timestamp` (ISO-8601).
  (`loki/gui/views/firmware_image_view.py:52-69`)
- WHERE a field is `None`, THE `FirmwareImageView` SHALL render
  the literal `"—"` (em-dash) in the value cell rather than the
  Python string `"None"` or an empty cell.
  (`loki/gui/views/firmware_image_view.py:53-63`)
- THE `FirmwareImageView` SHALL set
  `setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)`
  on the metadata table, enforcing read-only at the Qt API
  level.
  (`loki/gui/views/firmware_image_view.py:45`)
- THE `FirmwareImageView` SHALL expose the rendered model as a
  `image` property returning the same `FirmwareImage` instance
  passed to the constructor; this property is consumed by
  `MainWindow._currently_selected_image` to dispatch
  Extract / Run Analysis actions.
  (`loki/gui/views/firmware_image_view.py:78-81`,
  `loki/gui/main_window.py:644-660`)
- THE `FirmwareImageView` SHALL never mutate the supplied
  `FirmwareImage` instance; refresh-on-change is achieved by
  closing the tab, reconstructing the view, and re-opening
  per the Workspace open_tab contract.
- THE `MainWindow` SHALL update the navigation entry label as
  `<file_basename>` (with `(demo)` suffix when the image came
  from `load_demo_data`); the entry SHALL appear under the
  `Images` navigation group.
  (`loki/gui/main_window.py:959-967`)

### Requirement 3: ExtractionManifest rendering (ExtractionView)

**User Story:** As an analyst who has just run extraction, I want
to see the full manifest summary, every component the extractor
emitted, and any extraction errors, so I can confirm coverage
before running classification.

#### Acceptance Criteria

- WHEN `MainWindow.add_extraction_result(image, result)` is called,
  THE GUI subsystem SHALL construct exactly one `ExtractionView`
  rendering `result.manifest` and open a Workspace tab keyed
  `extraction:<image.image_id>:<manifest.extraction_timestamp.isoformat()>`.
  (`loki/gui/main_window.py:208-222`)
- THE `ExtractionView` SHALL render a header `QLabel` containing
  `extractor_version`, and a metadata `QLabel` containing
  `image_id`, `file_path`, `file_size` (with thousands separator),
  `extraction_timestamp` (ISO-8601), `total_components`, and
  `len(extraction_errors)`.
  (`loki/gui/views/extraction_view.py:71-86`)
- THE `ExtractionView` SHALL render a five-column components
  `QTableWidget` with columns `Offset`, `Size`, `Type hint`,
  `Name`, `Hash (12)`; one row per `manifest.components` entry;
  the hash column SHALL show the first 12 characters of
  `component.raw_hash`.
  (`loki/gui/views/extraction_view.py:88-110`)
- WHEN `manifest.extraction_errors` is non-empty, THE
  `ExtractionView` SHALL render a two-column errors table
  (`Component ID`, `Message`) below the components table; when
  empty, the errors section SHALL be omitted entirely (no empty
  table rendered).
  (`loki/gui/views/extraction_view.py:112-134`)
- WHEN `ExtractionView` is constructed with `manifest=None`, THE
  view SHALL render a centred placeholder label directing the
  operator to `View → Extract Firmware Components…` and SHALL
  NOT raise.
  (`loki/gui/views/extraction_view.py:42-65`)
- THE `ExtractionView` SHALL set `NoEditTriggers` on every table
  it renders.
  (`loki/gui/views/extraction_view.py:96, 122`)
- THE `MainWindow` SHALL store the `ExtractionResult` keyed by
  image so that `Run Analysis` can look it up via
  `last_extraction_result_for(image)` without round-tripping
  through the view layer.
  (`loki/gui/main_window.py:208-222, 258-260`)

### Requirement 4: BaselineRecord and BaselineComparison rendering (BaselineView)

**User Story:** As a baseline curator, I want to see every metadata
field on a `BaselineRecord` plus, when one is loaded, the
`BaselineComparison` summary rolled up by `DeltaType`, so I can
confirm what the persisted baseline contains and how a target
image deviates from it.

#### Acceptance Criteria

- WHEN `MainWindow.add_baseline(baseline, comparison=...)` is
  called, THE GUI subsystem SHALL construct exactly one
  `BaselineView` and open a Workspace tab keyed
  `baseline:<baseline.baseline_id>`.
  (`loki/gui/main_window.py:166-192`)
- THE `BaselineView` metadata table SHALL render exactly these
  ten rows: `baseline_id`, `name` (or `"—"` when None),
  `vendor`, `model`, `firmware_version`, `baseline_version`,
  `source_image_hash`, `created_timestamp` (ISO-8601),
  `manifest_size` (formatted as `"{n} components"`), `notes`
  (or `"—"` when None). The `name` row is included to honour the
  Introduction's "rendering completeness against every public
  field" promise; if the implementation currently omits it,
  closing the gap is a one-line addition to
  `_build_metadata_table` and is tracked as a BIND task.
  (`loki/gui/views/baseline_view.py:50-76`)
- WHEN `comparison is not None`, THE `BaselineView` SHALL render
  a two-column comparison summary table whose rows are sorted by
  `DeltaType.value` ascending and whose final row is a `TOTAL`
  row equal to `len(comparison.deviations)`.
  (`loki/gui/views/baseline_view.py:78-102`)
- WHEN `comparison is None`, THE `BaselineView` SHALL render the
  literal italic label `"No comparison loaded for this baseline."`
  in place of the comparison table.
  (`loki/gui/views/baseline_view.py:46-47`)
- THE `BaselineView` SHALL set `NoEditTriggers` on every table
  it renders, and SHALL clear `Qt.ItemFlag.ItemIsEditable` on
  the `TOTAL` row's cells defensively.
  (`loki/gui/views/baseline_view.py:68, 87, 98-99`)
- THE navigation label for a `BaselineRecord` SHALL be
  `"{vendor} {model} {firmware_version}"` (with `(demo)` suffix
  for demo data); navigation entries SHALL appear under the
  `Baselines` group.
  (`loki/gui/main_window.py:180-184`)
- THE `BaselineView` SHALL expose `baseline` as a property
  returning the same `BaselineRecord` instance passed to the
  constructor; this property is consumed by
  `MainWindow._currently_selected_baseline` to dispatch the
  Save Baseline action.
  (`loki/gui/views/baseline_view.py:104-106`,
  `loki/gui/main_window.py:690-702`)

### Requirement 5: ImageAnalysisReport summary rendering (ImageAnalysisReportView)

**User Story:** As an operator looking at a finished analysis run,
I want a compact summary view that surfaces posture, severity
distribution, and the per-finding short form, so I can
triage before drilling into the full evidence tree.

#### Acceptance Criteria

- WHEN `MainWindow.add_image_report(report)` is called, THE GUI
  subsystem SHALL construct exactly one `ImageAnalysisReportView`
  and open a Workspace tab keyed `report:<report.report_id>`.
  (`loki/gui/main_window.py:194-206`)
- THE `ImageAnalysisReportView` SHALL render a header containing
  the rendered string `report.posture_rating.value` interpolated
  into a labelled prefix (e.g.
  `"Analysis Report — posture: <value>"`); a metadata block
  containing `image_id`, `analysis_version`, and `timestamp`
  (ISO-8601); a severity distribution table; and a four-column
  findings table (`Severity`, `Category`, `Title`,
  `Recommended action`). This is the **summary altitude** view;
  full per-finding evidence and the `image_metadata`
  `FirmwareImage` sub-section are the responsibility of
  `AnalysisView` (Requirement 6).
  (`loki/gui/views/report_view.py:34-84`)
- THE severity distribution table SHALL contain one row per
  populated `SeverityLevel`, sorted by `SeverityLevel.value`
  ascending; absent severities SHALL NOT appear as zero rows.
  (`loki/gui/views/report_view.py:46-62`)
- THE `ImageAnalysisReportView` SHALL set `NoEditTriggers` on
  every table.
  (`loki/gui/views/report_view.py:52, 72`)
- THE navigation label for a report SHALL be
  `"Report — {model_or_image_id} [{posture_rating.value}]"`
  (with `(demo)` suffix for demo reports); the entry SHALL
  appear under the `Reports` group.
  (`loki/gui/main_window.py:198-202`)
- THE same `ImageAnalysisReport` MAY be rendered into two tabs
  simultaneously: an `ImageAnalysisReportView` keyed
  `report:<id>` (this requirement, summary altitude) and an
  `AnalysisView` keyed `analysis:<id>` (Requirement 6, full
  evidence altitude). This duality is intentional in v1 — the
  summary view is opened via `add_image_report` (e.g. when a
  report is loaded from disk or from the demo flow), and the
  analysis view is opened via the `AnalysisWorker` finish path.
  Operators may see both tabs for the same report; this is
  by design and not an oversight.

### Requirement 6: ImageAnalysisReport full-evidence rendering (AnalysisView)

**User Story:** As a firmware analyst drilling into a finding, I
want to see the complete evidence payload for every finding —
classification axes, deviation score per-axis breakdown, matched
rule / CVE / signature, raw indicators — and the optional
baseline comparison sub-section, so I have everything the
analysis pipeline produced in one place.

#### Acceptance Criteria

- WHEN the `AnalysisWorker.finished_with_report` signal fires
  with an `ImageAnalysisReport`, THE `MainWindow` SHALL
  construct exactly one `AnalysisView` and open a Workspace tab
  keyed `analysis:<report.report_id>`.
  (`loki/gui/main_window.py:540-550`)
- THE `AnalysisView` SHALL render a header `QLabel` containing
  the rendered string `report.posture_rating.value` and
  `len(report.findings)` interpolated into a labelled prefix
  (e.g. `"Analysis — posture: <value> (<n> findings)"`); a
  metadata block containing `report_id`, `image_id`,
  `analysis_version`, and `timestamp`; and a severity
  distribution table when `report.summary.findings_by_severity`
  is non-empty.
  (`loki/gui/views/analysis_view.py:52-90`)
- WHEN `report.image_metadata` is populated, THE `AnalysisView`
  SHALL render an `image_metadata` sub-section containing the
  visible `FirmwareImage` fields (`file_path`, `file_hash`,
  `file_size` formatted as `"{n:,} bytes"`, `vendor`, `model`,
  `firmware_version`); when `None`, the sub-section SHALL be
  omitted. This honours the Introduction's "rendering
  completeness against every public field" promise; if the
  implementation currently omits this sub-section, closing the
  gap is a BIND task.
- THE `AnalysisView` SHALL render a `QTreeWidget` whose top-level
  items are findings; for each `FindingRecord`, the tree SHALL
  expose, at minimum: `[severity] category` / `title` (top-level
  text), `finding_id`, `component_id`, `description`,
  `recommended_action`, and conditional sub-trees for every
  populated field on `FindingEvidence`.
  (`loki/gui/views/analysis_view.py:92-101, 133-215`)
- THE `AnalysisView` SHALL render the `classification_record`
  sub-tree when `evidence.classification_record is not None`,
  including the four axes (`type_axis`, `vendor_axis`,
  `security_axis`, `mutability_axis`) each shown as
  `"<label> (conf=<float, 2dp>, method=<method>)"`; the
  optional signature leaf SHALL carry the literal label
  `"signature"` (NOT `"signature_info"`) with detail text
  `"present=<present> verified=<verified> signer=<signer or '—'>"`;
  and the optional `cve_matches` list SHALL be joined by `", "`.
  (`loki/gui/views/analysis_view.py:152-186`)
- THE `AnalysisView` SHALL render the `deviation_score` sub-tree
  when `evidence.deviation_score is not None`, including
  `composite_score`, `priority_rank`, `base_severity`,
  `component_criticality`, `security_direction`,
  `signature_delta`, `cve_introduced`, and `mutability_change`.
  (`loki/gui/views/analysis_view.py:188-204`)
- THE `AnalysisView` SHALL render the `matched_rule`,
  `matched_cve`, `matched_signature`, and `raw_indicators`
  sub-tree leaves only when their respective fields are
  populated; absent fields SHALL NOT produce empty leaves.
  (`loki/gui/views/analysis_view.py:206-213`)
- WHEN `report.recommended_actions` is non-empty, THE
  `AnalysisView` SHALL render a three-column actions table
  (`Action type`, `Description`, `Reference`) below the findings
  tree; when empty, the actions section SHALL be omitted.
  (`loki/gui/views/analysis_view.py:103-123`)
- WHEN `report.baseline_comparison is not None`, THE `AnalysisView`
  SHALL render a baseline comparison sub-section containing the
  delta-type summary table and the per-deviation table
  (`Delta type`, `Component`, `Description`); when `None`, the
  sub-section SHALL be omitted.
  (`loki/gui/views/analysis_view.py:125-126, 218-272`)
- THE `AnalysisView` SHALL set `NoEditTriggers` on every table
  and tree it renders, including the summary table and
  deviations table inside the baseline-comparison sub-section.
  (`loki/gui/views/analysis_view.py:76, 96, 112, 240, 259`)
- THE navigation label for an analysis view SHALL be
  `"Analysis — {posture_rating.value} ({len(report.findings)} findings)"`
  and SHALL appear under the `Reports` navigation group,
  mirroring the summary `ImageAnalysisReportView` in
  Requirement 5.
  (`loki/gui/main_window.py:545-549`)

### Requirement 7: FleetAnalysisReport rendering (FleetAnalysisView)

**User Story:** As a fleet operator, I want to load a
`FleetAnalysisReport` JSON file from disk and see the posture
distribution, outliers, systemic risks, common findings, and
recommended actions in one view.

#### Acceptance Criteria

- WHEN `View → Load Fleet Report…` is triggered, THE
  `MainWindow` SHALL show a file dialog accepting `*.json`,
  apply the fleet-report input-validation pre-flight (next
  bullet), parse the chosen file via
  `FleetAnalysisReport.model_validate_json` (with `bytes` input
  decoded as UTF-8), construct exactly one `FleetAnalysisView`,
  and open a Workspace tab keyed `fleet:<report.report_id>`.
  (`loki/gui/main_window.py:574-606`)
- THE fleet-report input-validation pre-flight SHALL, in order:
  (a) call `Path(path).resolve(strict=True)` to fail fast on
  dangling symlinks (`FileNotFoundError`); (b) require
  `path.is_file()` (a directory or special file SHALL surface a
  dialog and abort); (c) require `os.access(path, os.R_OK)`
  (unreadable files SHALL surface a dialog and abort);
  (d) require `0 < path.stat().st_size <= 64 * 1024 * 1024`
  (zero-byte and >64 MiB files SHALL surface a dialog with title
  `"Fleet report too large"` or `"Fleet report empty"` and
  abort, BEFORE `model_validate_json` is invoked); (e) read the
  first non-whitespace byte and require it to be `{` or `[`
  (any other prefix surfaces a dialog and aborts). The size cap
  is the threat-context input-validation gate that prevents a
  multi-GiB JSON from pinning memory or freezing the Qt event
  loop. WHEN any pre-flight check fails, THE `MainWindow` SHALL
  render a `QMessageBox.warning` and SHALL NOT call
  `model_validate_json`.
- WHEN reading the chosen file or calling
  `FleetAnalysisReport.model_validate_json` raises any
  exception, THE `MainWindow` SHALL render a
  `QMessageBox.warning` titled `"Load Fleet Report"` containing
  `f"Failed to load fleet report:\n{exc}"` and SHALL NOT open a
  tab. (The single try/except wraps both `Path.read_text` and
  `model_validate_json`, so file-read errors —
  `FileNotFoundError`, `PermissionError`, `UnicodeDecodeError` —
  surface via the same dialog as Pydantic validation errors.)
  (`loki/gui/main_window.py:591-600`)
- THE `FleetAnalysisView` SHALL render a header containing
  `fleet_id` and `image_count`, a metadata block containing
  `report_id` and `timestamp`, and a posture distribution
  table with one row per `(rating, count)` in
  `report.fleet_posture`.
  (`loki/gui/views/fleet_view.py:35-61`)
- WHEN `report.outlier_images` is non-empty, THE
  `FleetAnalysisView` SHALL render a `QListWidget` of
  outlier `image_id` UUIDs (string-converted); when empty, the
  outlier section SHALL be omitted.
  (`loki/gui/views/fleet_view.py:63-69`)
- WHEN `report.systemic_risks` is non-empty, THE
  `FleetAnalysisView` SHALL render a `QListWidget` of risk
  strings; when empty, the systemic risks section SHALL be
  omitted.
  (`loki/gui/views/fleet_view.py:71-77`)
- WHEN `report.common_findings` is non-empty, THE
  `FleetAnalysisView` SHALL render a three-column table
  (`Severity`, `Category`, `Title`); when empty, the common
  findings section SHALL be omitted.
  (`loki/gui/views/fleet_view.py:79-96`)
- WHEN `report.recommended_actions` is non-empty, THE
  `FleetAnalysisView` SHALL render a three-column table
  (`Action type`, `Description`, `Reference`); when empty, the
  actions section SHALL be omitted.
  (`loki/gui/views/fleet_view.py:98-117`)
- THE `FleetAnalysisView` SHALL set `NoEditTriggers` on every
  table it renders.
  (`loki/gui/views/fleet_view.py:52, 86, 107`)
- THE navigation label for a fleet report SHALL be
  `"Fleet — {fleet_id} ({image_count} images)"` and SHALL
  appear under the `Reports` group (the `Fleet` navigation
  group is reserved for future fleet-membership features and
  carries only the placeholder row in v1).
  (`loki/gui/main_window.py:602-606`,
  `loki/gui/navigation.py:13-30`)

### Requirement 8: NavigationPane structure and entry contract

**User Story:** As an operator using the desktop UI, I want a
predictable left-hand pane that always shows the four model
families I work with, with a clear placeholder when a family is
empty and a stable double-click-to-open contract.

#### Acceptance Criteria

- THE `NavigationPane` SHALL render exactly four top-level
  groups in this order: `Images`, `Baselines`, `Reports`,
  `Fleet`; the order SHALL be the platform-stable enumeration
  from `_GROUP_ORDER`.
  (`loki/gui/navigation.py:13-22`)
- WHEN a group has no child entries, THE `NavigationPane` SHALL
  render exactly one disabled placeholder child carrying the
  group-specific message from `_PLACEHOLDERS` (e.g.
  `"No images loaded yet"`); placeholders SHALL carry the
  sentinel UserRole payload `("__placeholder__", group)` and
  SHALL NOT emit `item_activated` on double-click.
  (`loki/gui/navigation.py:25-30, 93-115`)
- THE `NavigationPane.add_entry(group, key, label)` method SHALL
  remove any placeholder for `group`, append a new child item
  carrying the `(group, key)` tuple as its UserRole payload, and
  expand the parent; WHEN a child for `(group, key)` already
  exists, THE method SHALL update the label in-place rather than
  appending a duplicate.
  (`loki/gui/navigation.py:59-84`)
- THE `NavigationPane.add_entry` method SHALL bound and
  sanitise the visible `label` text before insertion: labels
  exceeding 200 characters SHALL be truncated to 197 characters
  plus the literal `"..."`; ASCII control codepoints (U+0000
  through U+001F except space U+0020, plus U+007F) SHALL be
  stripped; bidirectional override codepoints (U+202A-U+202E,
  U+2066-U+2069) SHALL be stripped; the original (unsanitised)
  label SHALL be preserved as the `QTreeWidgetItem.toolTip()`.
  The Tab_Key remains the unsanitised opaque identifier
  (Tab_Keys are content-addressable; labels are display-only).
  This guards against operator-supplied paths or
  `BaselineRecord` `vendor` / `model` fields that contain
  hostile codepoints from distorting the navigation pane.
- WHEN `add_entry` is called with a `group` value not in
  `_GROUP_ORDER`, THE `NavigationPane` SHALL raise `ValueError`
  with the offending group name embedded.
  (`loki/gui/navigation.py:67-68`)
- THE `NavigationPane` SHALL set
  `setEditTriggers(QTreeWidget.EditTrigger.NoEditTriggers)` on
  itself and `setHeaderHidden(True)`; entry text SHALL NOT be
  user-editable.
  (`loki/gui/navigation.py:47-48`)
- THE `NavigationPane.reset()` method SHALL remove every child
  from every group and re-install the placeholders; the
  `MainWindow.reset_workspace` action consumes this.
  (`loki/gui/navigation.py:86-91`,
  `loki/gui/main_window.py:272-298`)
- WHEN the user double-clicks a non-placeholder entry, THE
  `NavigationPane` SHALL emit
  `item_activated(group: str, key: str, label: str)` exactly
  once; `MainWindow._on_navigation_activated` SHALL look up the
  view by `(group, key)` and call `Workspace.open_tab`.
  (`loki/gui/navigation.py:113-119`,
  `loki/gui/main_window.py:625-638`)
- THE `Fleet` navigation group SHALL be registered as a
  top-level group with its placeholder row but SHALL carry no
  child entries in v1; both `MainWindow._on_load_fleet_report`
  and `MainWindow.add_image_report` register their entries
  under `NavigationGroup.REPORTS`. This is intentional in v1
  and is forward-tracked as a future-OT-LK design question
  (live-fleet-membership UX), not a v1 blocker. Operators
  SHOULD expect the `Fleet` group to display only the
  `_PLACEHOLDERS[FLEET]` row for the entire v1 release; this is
  a known UX seam carried as a cost of the retroactive
  ratification, not a transient bug.
  (`loki/gui/main_window.py:194-206, 602-606`)
- **Property P77 (navigation_entry_invariants)**: For any
  sequence of `add_entry` / `reset` calls applied to a fresh
  `NavigationPane`, the resulting child count under each group
  SHALL equal the cardinality of distinct `key`s passed to
  `add_entry` for that group since the last `reset`. (Property
  test: invariants under randomised key sequences.)

### Requirement 9: Workspace tab identity and lifecycle

**User Story:** As an operator who has dozens of images and
reports loaded, I want repeated navigation activations to focus
the existing tab instead of opening duplicates, and I want to be
able to close any tab via the `X` button.

#### Acceptance Criteria

- THE `Workspace.open_tab(key, title, widget)` method SHALL
  treat `key` as an opaque string identifier; WHEN a widget is
  already registered under `key` and is still attached, THE
  method SHALL `setCurrentIndex` to that tab and return its
  index without creating a new tab; OTHERWISE THE method SHALL
  call `addTab(widget, title)`, register the widget under
  `key`, set the new index as current, and return it.
  (`loki/gui/workspace.py:25-40`)
- THE `Workspace` SHALL `setTabsClosable(True)` and
  `setMovable(True)`; tabs SHALL be re-orderable by drag and
  closable via the per-tab `X` button.
  (`loki/gui/workspace.py:20-21`)
- WHEN the user closes a tab, THE `Workspace` SHALL drop every
  key whose registered widget is the closing widget, call
  `removeTab(index)`, and call `widget.deleteLater()` so Qt
  reclaims the C++ resource.
  (`loki/gui/workspace.py:53-62`)
- THE GUI subsystem SHALL mint Tab_Keys with kind-namespaced
  prefixes so views of different kinds cannot collide on the
  same identifier; the closed v1 prefix set is `image:`,
  `extraction:`, `baseline:`, `report:`, `analysis:`, and
  `fleet:`.
  (`loki/gui/main_window.py:153, 180, 196, 211, 545, 602`)
- THE GUI subsystem SHALL NOT, in v1, expose a detach-to-window
  control; every view lives inside the single `MainWindow`'s
  Workspace.
- THE `Workspace.has_tab(key)` query SHALL return `True` if and
  only if a widget is registered under `key` and remains
  attached to a tab; the query is consumed by tests that
  verify uniqueness invariants.
  (`loki/gui/workspace.py:42-45`)
- **Property P78 (workspace_tab_uniqueness)**: For any sequence
  of `open_tab(key, title, widget)` calls on a fresh
  `Workspace`, the count of tabs SHALL equal the cardinality
  of distinct `key`s seen so far. (Property test: keys are
  drawn from a small alphabet so collisions occur.)

### Requirement 10: ExtractionWorker contract

**User Story:** As an operator extracting a multi-hundred-megabyte
firmware binary, I want extraction to run on a background thread
with per-component progress, cancellation, and typed-error
reporting, so the UI stays responsive and so a malformed binary
surfaces as a dialog rather than a crash.

#### Acceptance Criteria

- THE `ExtractionWorker` SHALL be a `QThread` subclass at
  `loki.gui.extraction_worker.ExtractionWorker` whose `run()`
  method calls `loki.extraction.extract_firmware(path, config,
  progress=..., cancel=...)`.
  (`loki/gui/extraction_worker.py:36-115`)
- THE `ExtractionWorker` SHALL declare exactly three
  `pyqtSignal(object)` signals on the subclass —
  `progress_event` (emitted per `ProgressEvent` from the
  underlying pipeline), `finished_with_result` (emitted with
  the `ExtractionResult` on success), and `errored` (emitted
  with the typed exception on failure) — in addition to the
  `started` and `finished` signals inherited from `QThread`
  (the `MainWindow` connects to `worker.finished` for slot
  cleanup).
  (`loki/gui/extraction_worker.py:54-56`)
- THE `ExtractionWorker.errored` payload SHALL be an instance
  of `InvalidInputError`, `ManifestConstructionError`, or
  `ExtractionPipelineError`; `MainWindow._on_extraction_errored`
  SHALL dispatch on the runtime type via `isinstance`.
  (`loki/gui/extraction_worker.py:99-112`,
  `loki/gui/main_window.py:904-928`)
- THE `ExtractionWorker.request_cancellation()` method SHALL
  set a thread-safe `threading.Event` the worker checks before
  invoking `extract_firmware`; the underlying `extract_firmware`
  call SHALL respond to the cancel callback by completing the
  in-flight component and returning a partial
  `ExtractionResult` (or raising a typed pipeline error per
  the extraction-pipeline spec). THE worker SHALL re-emit that
  result via `finished_with_result` or the typed exception via
  `errored`. The partial-result-on-cancel contract is enforced
  by the upstream pipeline, not the worker class itself; the
  worker is a transparent re-emitter.
  *Implementation note:* The cancellation primitive is
  `threading.Event`, matching `BaselineLoadWorker` and
  `AnalysisWorker` (D3 — primitive uniformity landed
  post-v1.0.0 in harness round v1.0.3). The public method names
  (`request_cancellation()` / `cancelled` property) are
  intentionally distinct from the other workers'
  `request_cancel()` / `is_cancel_requested()` to preserve the
  v1.0.0 caller contract; the underlying primitive is now
  uniform.
  (`loki/gui/extraction_worker.py:64-84`)
- THE `MainWindow.start_extraction(image, path, config)` method
  SHALL refuse to spawn a second worker while
  `self._active_worker is not None`, returning the existing
  worker as a belt-and-braces guard against the
  single-active-worker policy in Requirement 15.
  (`loki/gui/main_window.py:224-251`)
- THE default extraction config used by the menu action SHALL
  be the module-level constant `DEFAULT_EXTRACTION_CONFIG`
  with `default_output_dir=""`,
  `max_component_size=50_000_000`, and
  `timeout_per_component=60`; the v1 GUI ships only this
  default (D11 — configuration exposure deferred to CLI).
  (`loki/gui/actions/extract_components.py:43-47`)
- THE worker SHALL never raise out of `run()`; every typed
  pipeline exception SHALL be captured and re-emitted via the
  `errored` signal, and the worker thread SHALL exit cleanly.
  (`loki/gui/extraction_worker.py:99-114`)
- WHEN the worker emits `finished_with_result`,
  `MainWindow._on_extraction_finished` SHALL call
  `add_extraction_result(image, result)` to open the
  `ExtractionView` tab and update the status bar.
  (`loki/gui/main_window.py:899-902`)

### Requirement 11: BaselineLoadWorker contract

**User Story:** As an operator with a thousand baselines on disk, I
want the startup baseline scan to run on a background thread with
per-file progress and a cancel control, so I can shut the window
without waiting for a 117-second scan to finish.

#### Acceptance Criteria

- THE `BaselineLoadWorker` SHALL be a `QThread` subclass at
  `loki.gui.baseline_load_worker.BaselineLoadWorker` whose
  `run()` method calls
  `BaselineStore.load(progress=..., cancel=...)`.
  (`loki/gui/baseline_load_worker.py:45-123`)
- THE `BaselineLoadWorker` SHALL declare exactly three
  `pyqtSignal(object)` signals on the subclass:
  `finished_with_result`, `errored`, and `progress` — in
  addition to the `started` and `finished` signals inherited
  from `QThread` (the `MainWindow` connects to
  `worker.finished` for slot cleanup).
  (`loki/gui/baseline_load_worker.py:64-66`)
- THE `BaselineLoadWorker` SHALL use a `threading.Event` as the
  cancellation primitive; `request_cancel()` SHALL set the
  event and `is_cancel_requested()` SHALL read it.
  (`loki/gui/baseline_load_worker.py:79-101`)
- THE `BaselineLoadWorker.errored` payload SHALL be a
  `BaselineStoreError` instance (in v1 always
  `BaselineStorageUnwritableError`, the only documented
  load-time error per the baseline-persistence spec; the catch
  is rooted at the parent class to remain forward-compatible);
  `MainWindow._on_baseline_load_errored` SHALL render a
  `QMessageBox.warning` titled `"Could not load baselines"`
  with the storage path embedded.
  (`loki/gui/baseline_load_worker.py:115-121`,
  `loki/gui/main_window.py:867-882`)
- THE `BaselineLoadWorker.progress` SHALL emit each
  `LoadProgressEvent` produced by `BaselineStore.load`;
  `MainWindow._on_baseline_load_progress` SHALL update the
  status bar with `"Loading baselines… {index}/{total}
  ({path.name})"`.
  (`loki/gui/baseline_load_worker.py:107-110`,
  `loki/gui/main_window.py:781-789`)
- WHEN cancellation is requested, the underlying
  `BaselineStore.load` SHALL return the partial `LoadResult`
  (records and quarantine entries accumulated before
  cancellation) per the baseline-persistence spec R2.9, and
  the worker SHALL still emit `finished_with_result` (not
  `errored`); the `MainWindow` SHALL apply the partial
  `LoadResult` with the same code path as a full load.
  (`loki/gui/baseline_load_worker.py:112-123`,
  `loki/gui/main_window.py:801-811`)
- WHEN `MainWindow.closeEvent` fires while the
  `BaselineLoadWorker` is running, the close path SHALL call
  `request_cancel()` and `wait(30_000)` before persisting
  geometry and exiting.
  (`loki/gui/main_window.py:430-432`)
- **Property P79 (worker_cancel_idempotence)**: For any sequence
  of `request_cancel()` calls on a fresh `BaselineLoadWorker`,
  `is_cancel_requested()` SHALL return `True` after the first
  call and remain `True` for all subsequent calls and reads;
  the property SHALL hold for the analogous APIs on
  `AnalysisWorker`.

### Requirement 12: AnalysisWorker contract

**User Story:** As an operator running classification + analysis on
a large extraction, I want the run to happen on a background
thread with cooperative cancellation and typed-error reporting,
so the UI stays responsive and so a baseline-store or rules
failure surfaces as a dialog rather than a crash.

#### Acceptance Criteria

- THE `AnalysisWorker` SHALL be a `QThread` subclass at
  `loki.gui.analysis_worker.AnalysisWorker` whose `run()`
  method (a) constructs a fresh `BaselineStore` from
  `BaselineConfig(storage_path=baseline_path, auto_match=True)`
  on the worker thread (rather than reusing
  `MainWindow._baseline_store`) and calls `BaselineStore.load`,
  (b) calls `loki.classification.classify_components`, and
  (c) calls `loki.analysis.analyze_image`. The fresh-store
  construction keeps the worker decoupled from the main
  thread's in-memory snapshot and matches the analysis
  pipeline's contract that registries are read-only inputs;
  the cost is one re-scan of the storage directory per analysis
  run, ratified in v1 with store-injection forward-tracked if
  it becomes a measured latency problem.
  (`loki/gui/analysis_worker.py:42-153`)
- THE `AnalysisWorker` SHALL declare exactly two
  `pyqtSignal(object)` signals on the subclass:
  `finished_with_report` and `errored` — in addition to the
  `started` and `finished` signals inherited from `QThread`
  (the `MainWindow` connects to `worker.finished` for slot
  cleanup).
  (`loki/gui/analysis_worker.py:62-63`)
- THE `AnalysisWorker` SHALL use a `threading.Event` as the
  cancellation primitive; `request_cancel()` SHALL set the
  event and the event's `is_set` method SHALL be passed as the
  `cancel` callback to every underlying pipeline call.
  (`loki/gui/analysis_worker.py:79-99, 117-145`)
- THE `AnalysisWorker.errored` payload SHALL be an instance of
  `AnalysisError`, `ClassificationPipelineError`,
  `BaselineStoreError`, or `RuntimeError`; non-typed
  exceptions SHALL be wrapped in `RuntimeError` so the worker
  thread always exits cleanly.
  (`loki/gui/analysis_worker.py:147-153`)
- WHEN cancellation is requested, the analysis pipeline SHALL
  return a partial `ImageAnalysisReport` per its R1.10
  cancellation-as-return-path contract (analysis-engine spec;
  see also R7 for the `Cancellation_Marker` shape and R16.6
  for the no-raise discipline), and the worker SHALL emit
  `finished_with_report` (not `errored`).
  (`loki/gui/analysis_worker.py:139-146`)
- WHEN `MainWindow.closeEvent` fires while the `AnalysisWorker`
  is running, the close path SHALL call `request_cancel()` and
  `wait(5_000)` before persisting geometry and exiting.
  (`loki/gui/main_window.py:436-440`)
- THE `AnalysisWorker.run` method SHALL build the
  `AnalysisConfig` with the v1 default severity weights
  (`type=0.25, vendor=0.25, security_posture=0.30,
  mutability=0.20`), `default_severity_threshold=
  SeverityLevel.MEDIUM`, and SHALL rely on the
  `AnalysisConfig` model defaults
  `match_strategy=MatchStrategy.AUTO` and
  `confidence_gap_threshold=0.6` for the unset fields. THE
  worker SHALL construct `ClassificationConfig` with
  `confidence_threshold=0.6` and SHALL pass
  `taxonomy_version="1.0.0"` through the classification call.
  Future changes to the upstream `AnalysisConfig` /
  `ClassificationConfig` defaults SHALL be audit-visible
  through this requirement so the GUI's reliance on those
  defaults does not silently shift behaviour.
  (`loki/gui/analysis_worker.py:117-145`,
  `loki/models/config.py:94-95`)
- EVERY worker SHALL emit either exactly one
  `finished_with_*` or exactly one `errored` per `run()`
  invocation; the two signals are mutually exclusive. No
  worker code path SHALL leave `run()` via an uncaught
  exception or emit both classes of signal.
- **Property P80 (analysis_worker_error_typing)**: For every
  exception raised inside `AnalysisWorker.run`, the
  `errored` signal payload SHALL be an `Exception` instance
  (never a string, dict, or `None`); the property is enforced
  via `isinstance(payload, Exception)` in the test harness.

### Requirement 13: Action_Function contract and MainWindow protocol

**User Story:** As a test author, I want to drive every menu
action from headless tests without invoking a file dialog, so
extraction / baseline / analysis flows are deterministic under
`pytest-qt`.

#### Acceptance Criteria

- EACH Action_Function under `loki.gui.actions.*` SHALL be a
  free function whose first positional parameter is a
  `MainWindow` instance; Action_Functions SHALL NOT subclass
  `MainWindow` or hold module-level state about the active
  window.
  (`loki/gui/actions/open_firmware.py:44, 62`,
  `loki/gui/actions/extract_components.py:50, 71`,
  `loki/gui/actions/open_baseline.py:29, 51`,
  `loki/gui/actions/save_baseline.py:33`,
  `loki/gui/actions/load_demo_data.py:21`)
- THE Action_Function contract SHALL specify that the
  `window` argument is duck-typed against the methods invoked:
  `add_firmware_image`, `add_baseline`, `add_image_report`,
  `add_extraction_result`, `start_extraction`,
  `last_extraction_result_for`, `baseline_store` (property);
  v1 binds the contract to the `MainWindow` class but the
  duck-typed surface is the test extension point.
- EACH Action_Function that dispatches a file dialog SHALL
  expose a `*_from_path` companion (e.g.
  `open_firmware_from_path`, `open_baseline_from_path`) that
  accepts the chosen path directly so tests can bypass the
  dialog; the `*_from_path` companion is the load-bearing
  test surface.
  (`loki/gui/actions/open_firmware.py:62-88`,
  `loki/gui/actions/open_baseline.py:51-90`)
- EACH `*_from_path` Action_Function companion SHALL apply
  the same input-validation pre-flight as the dialog flow:
  for file paths, `Path(path).resolve(strict=True)`,
  `path.is_file()`, `os.access(path, os.R_OK)`, and (where
  applicable) the size cap; for directory paths,
  `Path(path).resolve(strict=True)` and `path.is_dir()`. The
  `*_from_path` entry-point SHALL NOT be a privilege
  escalation around the dialog flow — the dialog is a UX
  affordance, NOT a security boundary. WHEN any pre-flight
  check fails, THE companion SHALL surface the same typed
  `QMessageBox.warning` the dialog flow would surface and
  SHALL return `None`.
- THE `MainWindow` SHALL track demo-provenance for every
  `BaselineRecord`, `FirmwareImage`, and
  `ImageAnalysisReport` it ingests via `load_demo_data` (e.g.
  via a `_demo_baseline_ids: set[BaselineId]` attribute keyed
  by `baseline_id`); the provenance tag SHALL travel
  alongside the navigation entry, NOT baked into the model
  instance per D13. The `save_baseline` Action_Function SHALL
  refuse to persist a demo-tagged `BaselineRecord` and SHALL
  render `QMessageBox.warning` titled `"Cannot save demo
  baseline"` containing a message that explains the demo
  guard; the action SHALL return `None` without writing to
  the `BaselineStore`. (Property test extension at P82: for
  any demo workspace, `save_baseline` against any of its
  baselines returns `None` and writes nothing under the
  `BaselineStore` root.)
- EACH Action_Function SHALL surface typed errors via
  `QMessageBox.warning` (or `.question` for the overwrite
  prompt in `save_baseline`) and SHALL NOT raise out to the
  caller; the return value carries the success / failure
  signal as `BaselineRecord | None`, `FirmwareImage | None`,
  `Path | None`, or `ExtractionWorker`.
  (`loki/gui/actions/open_firmware.py:79-88`,
  `loki/gui/actions/open_baseline.py:71-89`,
  `loki/gui/actions/save_baseline.py:50-94`)
- EACH operator-supplied path entry-point (`open_firmware`
  for a firmware image, `open_baseline` for a baseline
  registry directory, `View → Load Fleet Report…` for a
  fleet-report JSON file — Requirement 7) SHALL apply a
  canonical input-validation pre-flight: (a)
  `Path(path).resolve(strict=True)` (broken symlinks raise
  `FileNotFoundError`); (b) the kind check appropriate to the
  entry-point (`path.is_file()` for firmware and fleet report,
  `path.is_dir()` for baseline registry); (c) `os.access(path,
  os.R_OK)`; (d) the entry-point-specific size cap (firmware:
  no cap but streamed in 1 MiB chunks per R22.3; fleet
  report: 64 MiB cap per R7; baseline registry: not
  applicable); (e) for files, a non-empty size check. WHEN any
  pre-flight step fails, THE Action_Function SHALL surface a
  `QMessageBox.warning` whose title names the entry-point and
  whose body contains the typed exception, and SHALL return
  `None` without progressing to the underlying API call.
- WHEN `save_baseline` catches `BaselineAlreadyExistsError`,
  THE Action_Function SHALL prompt with `QMessageBox.question`
  defaulting to **No** and SHALL retry with `force=True` only
  on explicit **Yes**; **No** (or dialog-cancel) SHALL return
  `None` without persisting. WHEN the same Action_Function
  catches `BaselineConcurrentModificationError`, it SHALL
  surface a `QMessageBox.warning` titled
  `"Concurrent modification detected"` and SHALL NOT
  auto-retry — the operator must manually reload.
  (`loki/gui/actions/save_baseline.py:50-94`)
- NO Action_Function SHALL hold module-level mutable state;
  every Action_Function SHALL be safe to call against a fresh
  `MainWindow` from any test without explicit teardown.
- THE test harness SHALL be able to substitute SilentDialogs
  for `QMessageBox` to assert error-paths without freezing the
  offscreen event loop; this contract is bound by Requirement
  21.

### Requirement 14: Menu bar action surface and keyboard shortcuts

**User Story:** As a keyboard-first operator, I want every action
the GUI exposes reachable via a menu and the most-used actions
bound to a stable keyboard shortcut.

#### Acceptance Criteria

- THE `MainWindow` SHALL render exactly three top-level menus
  in the menu bar in this order: `&File`, `&View`, `&Help`.
  (`loki/gui/main_window.py:312-376`)
- THE `&File` menu SHALL contain `&Open Firmware Image…`
  (Ctrl+O, dispatches `open_firmware`) and `&Quit` (Ctrl+Q,
  dispatches `self.close`); a separator SHALL appear between
  them.
  (`loki/gui/main_window.py:317-328`)
- THE `&View` menu SHALL contain, in order: `Load &Demo Data`,
  `&Extract Firmware Components…` (Ctrl+E, initially
  disabled), `Run &Analysis…` (Ctrl+A, initially disabled),
  `Load &Fleet Report…`, separator, `&Open Baseline Registry…`,
  `&Save Baseline…` (initially disabled), `&Cancel Baseline
  Load` (initially disabled), separator, `&Reset Workspace`.
  (`loki/gui/main_window.py:330-369`)
- THE `&Help` menu SHALL contain exactly one entry — `&About
  Loki` — whose handler renders an `about` dialog containing
  the package version resolved via
  `importlib.metadata.version("loki")`, falling back to the
  literal `"unknown"` when the package is not installed.
  Documentation links, keyboard-shortcut help, bug-report
  shortcuts, and any update-check entry are OUT OF SCOPE for
  v1 and are forward-tracked.
  (`loki/gui/main_window.py:371-376, 608-623`)
- THE `Extract Firmware Components` action SHALL be enabled if
  and only if at least one firmware image is loaded AND no
  extraction worker is currently running; the contextual
  enablement SHALL be re-evaluated whenever an image is added
  / removed / extracted.
  (`loki/gui/main_window.py:662-674`)
- THE `Run Analysis` action SHALL be enabled if and only if at
  least one extraction result is available;
  `_refresh_analyze_action_enabled` SHALL be the single point
  of truth.
  (`loki/gui/main_window.py:566-572`)
- THE `Save Baseline` action SHALL be enabled if and only if a
  `BaselineView` is the currently active workspace tab;
  contextual enablement SHALL be re-evaluated on tab change.
  (`loki/gui/main_window.py:704-710, 738-740`)
- THE `Cancel Baseline Load` action SHALL be enabled if and only
  if a `BaselineLoadWorker` is running and no cancellation has
  been requested yet.
  (`loki/gui/main_window.py:712-718`)
- THE GUI subsystem SHALL NOT, in v1, register a toolbar, a
  context menu on the navigation pane, or any drag-and-drop
  handler; the menu bar is the closed v1 action surface (D6).

### Requirement 15: Single-active-worker concurrency policy

**User Story:** As an operator, I want the GUI to refuse to spawn
two extractions or two analyses against the same image
concurrently, so I never have two workers writing to the same
status bar slot.

#### Acceptance Criteria

- THE `MainWindow` SHALL enforce single-active-worker per
  worker type via the menu enablement guards in Requirement
  14; the invariant is UI-level (not enforced by the worker
  classes themselves).
- THE `ExtractionWorker` slot SHALL be guarded by
  `_active_worker is None`; spawning is refused when the slot
  is occupied.
  (`loki/gui/main_window.py:238-251`)
- THE `BaselineLoadWorker` slot SHALL be guarded by
  `_baseline_load_worker is None`; the v1 implementation only
  spawns this worker once per `MainWindow` lifecycle (during
  `__init__`).
  (`loki/gui/main_window.py:770-779`)
- THE `AnalysisWorker` slot SHALL be guarded by
  `self._analyze_action.setEnabled(False)` for the duration of
  the run; `_refresh_analyze_action_enabled` re-enables the
  action only after the worker's `finished` signal fires.
  (`loki/gui/main_window.py:525-538, 566-572`)
- THE concurrency invariant SHALL be documented as a UI-level
  guard, not a library-level guard; future contributors who
  invoke `start_extraction` from non-GUI code SHALL NOT rely
  on the worker classes themselves to refuse re-entrancy.

### Requirement 16: Status bar discipline

**User Story:** As an operator, I want a single, predictable
status-bar slot that shows me what the GUI is doing right now.

#### Acceptance Criteria

- THE `MainWindow` status bar SHALL render a single `QLabel`
  with `TextSelectableByMouse` text-interaction flags; no
  progress bar, no per-phase indicator, no modal progress
  dialog (D7).
  (`loki/gui/main_window.py:378-385`)
- THE idle status text SHALL be formatted as
  `"images: {n}  last extraction: {iso8601_or_dash}
  classification version: {version_or_dash}"`.
  (`loki/gui/main_window.py:387-397`)
- WHEN a transient status is active (e.g. extraction in
  progress, baseline load in progress, analysis in progress),
  THE status label SHALL show the transient text instead of
  the idle summary; clearing the transient (via
  `_set_status_message(None)`) SHALL restore the idle
  summary.
  (`loki/gui/main_window.py:399-402`)
- THE extraction transient text SHALL be formatted as
  `"Extracting {basename}: {phase} ({n}/{total}) {message}"`
  reflecting `ProgressEvent` fields.
  (`loki/gui/main_window.py:888-897`)
- THE baseline-load transient text SHALL be formatted as
  `"Loading baselines… {index}/{total} ({path.name})"`.
  (`loki/gui/main_window.py:781-789`)
- THE analysis transient text SHALL be the literal
  `"Running analysis…"` for the duration of the worker run;
  per-component progress events from
  `loki.analysis.AnalysisProgressEvent` are intentionally NOT
  subscribed to by `AnalysisWorker` in v1 (the worker exposes
  only `finished_with_report` and `errored` per Requirement
  12). Wiring the analysis-engine progress callback into a
  third worker signal is forward-tracked under Requirement
  24.
  (`loki/gui/main_window.py:526, 535`)

### Requirement 17: Error dialog discipline

**User Story:** As an operator, I want every typed error from a
worker or action to surface as a `QMessageBox.warning` with
enough context to act on, and no errors to crash the event loop.

#### Acceptance Criteria

- THE GUI subsystem SHALL surface errors via
  `QMessageBox.warning` exclusively (with one `QMessageBox.question`
  for the overwrite prompt and one `QMessageBox.about` for the
  About dialog); no other modal dialog kinds appear in v1.
- EVERY `QMessageBox` surfaced by the GUI subsystem SHALL be
  application-modal in v1 (the Qt default for
  `QMessageBox.warning` / `.information` / `.question` /
  `.about`). WHILE a `QMessageBox` is up, worker threads
  SHALL continue executing — modal dialogs block ONLY the
  GUI thread; worker `pyqtSignal(object)` emissions are
  queued by Qt's queued-connection mechanism and delivered to
  slots after dialog dismissal. THE GUI subsystem SHALL NOT
  use window-modal or sheet-modal dialogs in v1
  (cross-platform sheet semantics differ enough to be a
  future-OT-LK concern). Action_Function callers MAY assume
  the dialog has been dismissed by the time `QMessageBox.*`
  returns (the operator's click happens before the call
  returns).
- THE closed v1 set of error categories THE GUI dispatches on
  via `isinstance` is: `InvalidInputError`,
  `ManifestConstructionError`, `ExtractionPipelineError`,
  `BaselineAlreadyExistsError`,
  `BaselineConcurrentModificationError`,
  `BaselineSerializationError`, `AnalysisError`,
  `ClassificationPipelineError`, `RuntimeError`,
  `ValueError`, and `OSError`. Subclass instances NOT in this
  list — including `BaselineStorageUnwritableError` and the
  `AnalysisError` subclasses (`AnalysisConfigError`,
  `AnalysisInputError`, `AnalysisReportConstructionError`,
  `BaselineNotFoundError`) — surface via the parent-class
  catch (`BaselineStoreError` for the storage subclass,
  `AnalysisError` for the analysis subclasses) and produce
  the generic dialog rather than a subclass-specific UI. v1
  ratifies this isinstance-dispatch-vs-parent-catch split as
  a deliberate design.
  (`loki/gui/main_window.py:904-928, 813-882, 552-564`,
  `loki/gui/actions/open_firmware.py:79-85`,
  `loki/gui/actions/save_baseline.py:50-94`,
  `loki/gui/actions/open_baseline.py:69-84`)
- WHEN a worker emits its `errored` signal, the connected
  `MainWindow` slot SHALL render the dialog on the main thread
  via Qt's queued connection; the worker thread SHALL exit
  cleanly without raising.
- THE GUI subsystem SHALL NOT silently swallow exceptions: the
  open-firmware path catches `(OSError, ValueError)` to
  preserve the user's chance to retry, but the offending
  exception is always logged via the
  `loki.gui.baselines` / standard logging path or surfaced in
  the dialog body.
  (`loki/gui/main_window.py:867-882`,
  `loki/gui/actions/open_firmware.py:79-85`)
- **Property P81 (error_dialog_total_function)**: For every
  member of the v1 error category set above, the
  `MainWindow` slot wired to that error type SHALL produce
  exactly one `QMessageBox.warning` invocation per error
  signal; the property is enforced via SilentDialogs call
  count assertions.

### Requirement 18: QSettings persistence

**User Story:** As a returning operator, I want my window
geometry, window state, and splitter ratio preserved across
launches.

#### Acceptance Criteria

- THE `MainWindow` SHALL persist three keys under the
  `QSettings("LOKI", "Desktop")` namespace:
  `main_window/geometry`, `main_window/state`, and
  `main_window/splitter`.
  (`loki/gui/main_window.py:441-444`)
- THE `QSettings` organization SHALL be the literal
  `"LOKI"` and the application SHALL be the literal
  `"Desktop"`; v1 binds these as the platform-stable
  identifiers — namespace forks would break stored
  geometry across upgrades.
  (`loki/gui/main_window.py:405, 441`)
- WHEN a stored geometry is present and non-empty, THE
  `MainWindow` SHALL restore it on construction;
  OTHERWISE THE `MainWindow` SHALL `resize(*_DEFAULT_SIZE)`
  with `_DEFAULT_SIZE = (1280, 800)`.
  (`loki/gui/main_window.py:404-416`)
- WHEN restoring a stored value of an unexpected Qt type,
  THE `MainWindow` SHALL skip the restoration and fall
  back to the default; the `isinstance(value, QByteArray)`
  guard SHALL prevent a crash on cross-version settings.
  (`loki/gui/main_window.py:407-416`)
- THE GUI subsystem SHALL NOT persist any other state to
  `QSettings` in v1; in particular, no recent-files list,
  no open-tab snapshot, no preferences, AND no
  firmware-image file paths, baseline-registry directory
  paths, fleet-report file paths, `FirmwareImage` /
  `BaselineRecord` / `ImageAnalysisReport` identifiers, or
  any field from the `Forbidden_Leakage_Field_Set`. File
  paths frequently embed customer / device / case identifiers
  and are within the spirit of the leakage set even though
  the path string itself is not on the enumerated list.
- **Property P82 (settings_namespace_stability)**: A round-trip
  through `QSettings.setValue` / `QSettings.value` for each of
  the three v1 keys SHALL preserve the value bit-equal; the
  property is enforced by an offscreen integration test.
  Additionally: for every key under `QSettings("LOKI",
  "Desktop")` after a full demo cycle, the stored bytes SHALL
  NOT contain any operator-chosen file path or any model
  identifier from the `Demo_Workspace`'s known string members
  (verifiable via substring scan over the demo workspace's
  string surface). This extension is the demo-baseline-poisoning
  guard from Requirement 13's demo-provenance contract.

### Requirement 19: Demo data flow

**User Story:** As a new user evaluating the GUI before having
real firmware to extract, I want a one-click demo that loads a
coherent set of synthetic Pydantic instances spanning every view
kind, with every entry clearly labeled `(demo)` so I cannot
confuse it with real pipeline output.

#### Acceptance Criteria

- THE `loki.gui.demo.synthetic.build_demo_workspace()` callable
  SHALL return a `DemoWorkspace` dataclass containing exactly
  2 `FirmwareImage`, 1 `BaselineRegistry` wrapping 1
  `BaselineRecord` (with a 5-component manifest), 1
  `BaselineComparison` (3 deviations: 1 ADDED, 1 MODIFIED, 1
  UNCHANGED), and 1 `ImageAnalysisReport` (3 findings spanning
  HIGH / CRITICAL / LOW severities). `BaselineRegistry` is
  defined in the Glossary as the demo-only in-memory wrapper
  dataclass at `loki/gui/demo/synthetic.py:48-51`; it is
  distinct from the upstream `BaselineStore`.
  (`loki/gui/demo/synthetic.py:112-350`)
- EVERY model instance returned by `build_demo_workspace` SHALL
  pass its Pydantic validators on construction; the demo data
  SHALL NOT bypass model validation via `model_construct` or
  any other escape hatch.
  (`loki/gui/demo/synthetic.py:37-46, 112-122`)
- WHEN `View → Load Demo Data` is triggered, THE
  `load_demo_data` Action_Function SHALL call
  `build_demo_workspace`, push every image / baseline / report
  through the corresponding `MainWindow.add_*` method with
  `demo=True`, and return the `DemoWorkspace` instance for
  caller / test inspection.
  (`loki/gui/actions/load_demo_data.py:21-34`)
- THE `(demo)` label suffix SHALL be applied at navigation
  insertion time by `MainWindow.add_firmware_image`,
  `add_baseline`, and `add_image_report` based on the
  caller-supplied `demo: bool` keyword; the label SHALL NOT be
  baked into the model instances themselves.
  (`loki/gui/main_window.py:151-206, 959-967`)
- THE `View → Reset Workspace` action SHALL clear every
  navigation entry, close every Workspace tab, drop every
  cached view / baseline-record / extraction-result, and
  request cancellation of any active extraction worker;
  reset SHALL leave the `MainWindow` in the same observable
  state as a freshly-constructed instance with the same
  `BaselineStore` injection.
  (`loki/gui/main_window.py:272-298`)

### Requirement 20: Read-only enforcement and refresh contract

**User Story:** As an analyst, I want every view to be
unambiguously read-only — both visually and at the Qt API
level — so I cannot accidentally edit a Pydantic field rendered
in a cell.

#### Acceptance Criteria

- EVERY view in the v1 closed set (`FirmwareImageView`,
  `ExtractionView`, `BaselineView`, `ImageAnalysisReportView`,
  `AnalysisView`, `FleetAnalysisView`) SHALL call
  `setEditTriggers(NoEditTriggers)` (where `NoEditTriggers`
  resolves to `QTableWidget.EditTrigger.NoEditTriggers` or
  `QTreeWidget.EditTrigger.NoEditTriggers` as appropriate) on
  every `QTableWidget` and `QTreeWidget` it constructs.
- VIEWS SHALL be constructed immediate-mode in `__init__` via
  `setItem` / `addTopLevelItem`; no view in v1 wires a
  `QAbstractItemModel` or `QAbstractTableModel` (D4).
- TO refresh a view against an updated model instance, the
  GUI subsystem SHALL close the existing tab and construct a
  new view; v1 has no in-place mutation API on any view.
- VIEWS SHALL NOT mutate the supplied Pydantic instance;
  property accessors (`.image`, `.baseline`, `.report`,
  `.manifest`) SHALL return the same instance passed to the
  constructor.
  (`loki/gui/views/firmware_image_view.py:78-81`,
  `loki/gui/views/baseline_view.py:104-106`,
  `loki/gui/views/extraction_view.py:136-139`,
  `loki/gui/views/analysis_view.py:128-130`,
  `loki/gui/views/report_view.py:86-88`,
  `loki/gui/views/fleet_view.py:121-123`)
- **Property P83 (view_render_purity)**: For any model
  instance `m` and any view kind `V` rendering it, calling
  `V(m).<accessor>` SHALL return `m` itself (identity, not
  equality); the property is enforced via `assert
  view.<accessor> is m` in offscreen rendering tests.

### Requirement 21: Offscreen testability and smoke harness

**User Story:** As a CI consumer, I want every GUI behaviour
testable headlessly under `QT_QPA_PLATFORM=offscreen` and a
standalone smoke script that exercises the full demo cycle so we
can verify the GUI builds without a display server.

#### Acceptance Criteria

- THE GUI test suite SHALL run under
  `QT_QPA_PLATFORM=offscreen` with `pytest-qt`'s `qtbot`
  fixture; tests SHALL use `qtbot.waitSignal` (or
  `waitUntil`) to synchronise on worker completion.
- THE GUI subsystem SHALL expose a SilentDialogs autouse
  fixture (or equivalent monkeypatch) that replaces
  `QMessageBox.warning`, `.information`, `.question`, and
  `.about` with record-and-return stubs; this fixture SHALL
  be the only mechanism by which Action_Function error paths
  are exercised in tests.
- THE repository SHALL ship `scripts/smoke_gui.py` exercising
  the full demo cycle (build window → load demo → assert 4
  Workspace tabs + 4 navigation groups → reset → close)
  under `QT_QPA_PLATFORM=offscreen` and SHALL be invocable
  outside `pytest`; the script SHALL exit non-zero on any
  assertion failure.
  (`scripts/smoke_gui.py`)
- THE `MainWindow` constructor SHALL accept a
  `background_load: bool` keyword (defaulting to `True`) so
  tests can opt into a synchronous baseline load path,
  avoiding a wait on the `BaselineLoadWorker` for tests that
  don't care about the background path.
  (`loki/gui/main_window.py:81-82, 763-768`)
- THE GUI test suite SHALL include at least one
  `qtbot.waitSignal` test for each of the three workers'
  `finished_with_*` and `errored` signals; v1 ratifies the
  existing `ExtractionWorker` and `BaselineLoadWorker`
  coverage and **requires `AnalysisWorker` coverage to be
  added during BIND**, closing the gap surveyed during DRAFT.
- **Property P84 (offscreen_full_render)**: For every view
  kind `V` and a representative model instance, constructing
  `V(model)` under `QT_QPA_PLATFORM=offscreen` SHALL NOT
  raise; the property is enforced via parametrised offscreen
  rendering tests.

### Requirement 22: Threat context and offline-only audit

**User Story:** As a security operator running LOKI on
operator-controlled firmware images, I need confidence the GUI
itself does not expand the platform's threat surface — no
network egress, no firmware mutation, no credential handling.

#### Acceptance Criteria

- THE GUI subsystem SHALL be classified as `STANDARD` threat
  context: untrusted firmware-image input is the primary
  risk surface, and the GUI's only role is to surface
  pipeline output read-only.
- `STANDARD` threat context means the GUI is NOT privileged
  beyond the operator running it; it inherits the operator's
  filesystem read privileges via `QFileDialog` and has no
  sandboxing layer in v1. The threat boundary is the
  Pydantic-validated input surface plus the
  `Forbidden_Egress_Set` import-graph audit, NOT OS-level
  isolation.
- THE GUI subsystem SHALL NOT, in v1, perform any operation
  in the Forbidden_Egress_Set defined in the Glossary; in
  particular, no automatic update check, no telemetry, no
  cloud SDK call, no DNS resolution beyond loopback.
- THE GUI subsystem SHALL NOT mutate any firmware image
  file; the open-firmware path SHALL stream the file in
  1 MiB chunks (`compute_sha256` at
  `loki/gui/actions/open_firmware.py:24-41`) so a multi-GiB
  binary does not pin memory, and SHALL open it in `"rb"`
  mode only.
  (`loki/gui/actions/open_firmware.py:26-41, 70-78`)
- THE GUI subsystem SHALL NOT call
  `QApplication.processEvents()` from action functions, view
  constructors, or worker slots; cross-thread payload
  marshalling SHALL go through Qt's queued-connection
  mechanism via the worker `pyqtSignal(object)` declarations
  exclusively. (Audit: `grep -rE "\.processEvents\(" loki/gui/`
  returns zero matches.) The smoke harness in
  `scripts/smoke_gui.py` calls `processEvents` because it
  drives the Qt event loop synchronously without `app.exec()`;
  this is by design for CI smoke verification and is OUT OF
  SCOPE for the `loki/gui/` import-graph invariant. The
  `loki/gui/` audit is enforced as a CI gate per Requirement
  26.
- THE GUI subsystem SHALL NOT read or store any credential,
  secret, or token; `QSettings` persistence is restricted
  to the three keys enumerated in Requirement 18.
- THE GUI subsystem SHALL NOT emit log records that include
  any field from the `Forbidden_Leakage_Field_Set` defined in
  the Glossary. The view layer SHALL display these fields
  (Requirements 5, 6); the log layer SHALL reference
  baselines and findings by stable identifiers (path,
  `baseline_id`, `vendor/model/firmware_version`) only. The
  concrete `logging.Filter` mechanism that enforces the
  redaction contract is design-doc territory; the contract
  itself is bound here.
- THE GUI subsystem SHALL surface `BaselineStoreError`
  failures (filesystem permission, malformed YAML, schema
  drift) as dialogs without auto-recovering the underlying
  files; the corruption / quarantine path is owned by
  `BaselineStore` per the baseline-persistence spec.
  (`loki/gui/main_window.py:849-865`)

### Requirement 23: Determinism, performance, and observability

**User Story:** As a maintainer, I want the GUI's pure rendering
to be deterministic and the latency-sensitive paths
(extraction-progress dispatch, baseline-load progress dispatch)
to land within budget so the UI doesn't perceptibly stall.

#### Acceptance Criteria

- VIEW construction SHALL be deterministic: rendering the
  same Pydantic instance twice into two view widgets SHALL
  produce widgets whose `QTableWidget` / `QTreeWidget` cell
  contents are bit-equal (modulo Qt internal handles); the
  invariant is testable via cell-text iteration.
- THE GUI subsystem SHOULD keep `MainWindow.__init__` well
  under one second on contemporary developer hardware with
  an empty `BaselineStore`. v1 ships without a
  regression-testing harness for this metric; the target is
  informational, not a release gate. A regression-detection
  harness (e.g. a `pytest-benchmark` test rooted at the
  baseline-persistence R9.1 budget) is forward-tracked.
- THE GUI subsystem SHALL log under the `loki.gui.baselines`
  and standard `loki.gui` loggers; logs SHALL NOT contain
  fields from the `Forbidden_Leakage_Field_Set` defined in
  the Glossary. The view layer SHALL display these fields;
  the log layer SHALL NOT.
- **Property P85 (view_text_determinism)**: For any model
  instance `m` and any view kind `V`, two independent
  constructions `V(m)` SHALL produce equal sequences of
  `(row, column, text)` tuples for every embedded
  `QTableWidget`; the property is enforced via parametrised
  offscreen rendering tests.

### Requirement 24: Forward-tracked migrations and v1 closure

**User Story:** As a maintainer planning the next OT-LK, I want
the v1 spec to be explicit about which behaviours are
forward-tracked so the next wave's scope is unambiguous.

#### Acceptance Criteria

- THE v1 spec SHALL ratify the existing `QThread`-subclass
  worker pattern; migration to `QObject.moveToThread()` or
  `QThreadPool` + `QRunnable` is forward-tracked to a
  future OT-LK and is OUT OF SCOPE for v1 (D2).
- THE v1 spec SHALL ratify the existing `ExtractionWorker`
  `bool`-flag cancellation primitive; migration to
  `threading.Event` (matching `BaselineLoadWorker` and
  `AnalysisWorker`) is forward-tracked as a non-blocking
  nit and is OUT OF SCOPE for v1 (D3).
- THE v1 spec SHALL ratify the menu-bar-only action surface;
  toolbars, context menus, and drag-and-drop are
  forward-tracked and OUT OF SCOPE for v1 (D6).
- THE v1 spec SHALL ratify the default-pipeline-only
  configuration exposure; a preferences dialog, per-view
  export, and per-view sort / filter / search are
  forward-tracked and OUT OF SCOPE for v1 (D11, D12, D4).
- THE v1 spec SHALL ratify the OS platform default palette;
  theming, dark-mode detection, and custom QSS are
  forward-tracked and OUT OF SCOPE for v1 (D15).
- THE v1 spec SHALL ratify the hard-coded XDG default
  `BaselineStore` path (`~/.local/share/loki/baselines`);
  migration to the Briefcase bundle's per-platform
  user-data path (appauthor/appname-aware) is
  forward-tracked under the OT-LK packaging stream once
  codesign + notarize land (Step 6).
- THE v1 spec SHALL ratify the concrete-coupling between
  Action_Functions and the `MainWindow` class; widening to
  a `Protocol` or duck-typed interface is forward-tracked
  and SHALL be revisited only when (and only when) a second
  consumer of the action functions materializes (e.g. a
  plugin / extension surface).
- THE v1 spec SHALL ratify the `NavigationGroup.FLEET`
  group remaining unused (fleet reports register under
  `NavigationGroup.REPORTS`); a live-fleet-membership UX
  surfacing under the `Fleet` group is forward-tracked.
- THE v1 spec SHALL ratify the **single-window topology**
  (D1, D9). Detach-to-window or multi-window workspaces are
  NOT on the v1 roadmap and require a fresh OT-LK to be
  considered. Operators SHOULD treat the single-window
  constraint as a stable contract, not a transient v1
  limitation; this distinguishes "future feature" (e.g. Wave
  B threading migration) from "explicitly not on the
  roadmap" (multi-window).
- WHEN a future OT-LK lands a forward-tracked migration, the
  corresponding requirement above SHALL be amended (not
  removed) and a successor spec SHALL ratify the new
  contract.

### Requirement 25: Property numbering allocation

**User Story:** As a property-test maintainer, I want a single
authoritative place that lists the GUI subsystem's property IDs
so they don't collide with upstream subsystems' allocations.

#### Acceptance Criteria

- THE GUI subsystem SHALL allocate property IDs in the
  contiguous range **P77-P85** (inclusive); the next
  subsystem after `gui` SHALL start at P86.
- THE GUI subsystem property allocation SHALL be:
  - **P77**: navigation entry add/remove invariants
    (Requirement 8).
  - **P78**: workspace tab key uniqueness (Requirement 9).
  - **P79**: worker cancel idempotence (Requirement 11;
    covers `BaselineLoadWorker` and `AnalysisWorker`).
  - **P80**: analysis worker error typing (Requirement 12).
  - **P81**: error dialog total function (Requirement 17).
  - **P82**: settings namespace stability (Requirement 18).
  - **P83**: view render purity / identity (Requirement 20).
  - **P84**: offscreen full render (Requirement 21).
  - **P85**: view text determinism (Requirement 23).
- EACH property test SHALL be implemented under
  `tests/gui/properties/` (or platform-equivalent path) and
  SHALL run under `QT_QPA_PLATFORM=offscreen` in CI.
- THE prior subsystem (`fleet-analysis`) consumed P72-P76 per
  its requirements.md R10.4 / R11.2; the GUI allocation
  picks up at P77 with no gap.

### Requirement 26: Testing coverage requirements

**User Story:** As a CI maintainer, I want the GUI subsystem's
test coverage to be unambiguous so review can confirm every
requirement has a corresponding test.

#### Acceptance Criteria

- BY THE TIME OF THE AD_HOC → APPROVED FLIP (Requirement
  27), AT LEAST one test per requirement SHALL exist under
  `tests/gui/`; the test name SHALL reference the requirement
  by number (e.g. `test_R10_extraction_worker_typed_errors`).
  The full per-requirement coverage map is enumerated in the
  BIND tasks document so the gap closure is auditable.
- THE GUI test suite SHALL include `qtbot.waitSignal`
  coverage for every signal declared on every worker; the v1
  surveyed gap (no `AnalysisWorker` GUI test) SHALL be
  closed during the BIND phase of OT-LK-004.
- THE GUI test suite SHALL include offscreen rendering tests
  for every view kind in the v1 closed set; rendering tests
  SHALL assert (a) construction does not raise and (b) the
  view's accessor returns the supplied model instance by
  identity.
- THE GUI test suite SHALL include the property tests
  P77-P85 enumerated in Requirement 25.
- THE GUI test suite SHALL include `scripts/smoke_gui.py` as
  a CI step so the full demo cycle is exercised under
  `QT_QPA_PLATFORM=offscreen` outside the `pytest` runner.
- THE GUI test suite SHALL include three import / source
  audits run as CI gates that fail the build on regression:
  (a) `grep -rE "^from loki\.cli" loki/gui/` returns zero
  matches AND `grep -rE "^import loki\.cli" loki/gui/`
  returns zero matches (the `cli → gui` direction is the only
  permitted edge per Requirement 1);
  (b) `grep -rE "\.processEvents\(" loki/gui/` returns zero
  matches (Requirement 22);
  (c) an import of `loki.gui` in a subprocess with `socket`,
  `urllib`, `requests`, and `httpx` mocked to raise on any
  call asserts no `Forbidden_Egress_Set` member is invoked at
  import time (Requirement 22). These promote the audits from
  documentation to enforced contracts.

### Requirement 27: Acceptance gate for the AD_HOC → APPROVED flip

**User Story:** As the harness operator flipping the `gui` subsystem
from `AD_HOC` to `APPROVED`, I want a checklist of the conditions
that must hold before the registry update lands.

#### Acceptance Criteria

- REQUIREMENTS R1-R26 SHALL be implemented in the codebase at
  the time of the flip. R1-R23 are already implemented at v1.0.0
  (Cleanup Waves A and C landed in commits `98c2110` +
  `e138baf`); R24 is observational and ratifies forward-tracked
  out-of-scope items; R25-R26 codify the property-test allocation
  and per-requirement coverage budget that BIND closes.
- THE one currently-known coverage gap — no
  `tests/gui/test_analysis_worker.py` covering
  `AnalysisWorker.start()` against a synthetic manifest with
  both the `finished_with_report` happy path and the
  `errored`-with-typed-exception unhappy path — SHALL be closed
  in BIND before the flip lands.
- THE forward-tracked items below SHALL be recorded in the
  design doc and in the registry's `forward_track` list:
  - Wave B: `QThreadPool` + `QRunnable` threading migration (D2).
  - ~~`ExtractionWorker._cancelled` bool → `threading.Event`
    (D3).~~ **CLOSED in harness round v1.0.3:**
    `ExtractionWorker` now uses `threading.Event` for primitive
    uniformity with the other two workers; the public method
    names remain distinct (`request_cancellation()` /
    `cancelled` property) to preserve the v1.0.0 caller
    contract.
  - `NavigationGroup.FLEET` group surface (currently unused;
    reserved for live-fleet-membership UX).
  - Action_Function `MainWindow` coupling → optional `Protocol`
    if a plugin / extension surface lands.
  - Per-platform `BaselineStore` default path migration to the
    Briefcase bundle's user-data path once codesign + notarize
    land (Step 6 of the project plan).
  - Tab-key `"{kind}:{uuid}"` convention → optional enum / type
    tag if collisions become a real risk.
- ON success, THE harness SHALL update the subsystem registry
  entry to:
  ```
  subsystem_name: "gui"
  codename:       "Loki Desktop"
  spec_status:    "APPROVED"
  lifecycle_stage:"IMPLEMENTED"
  threat_context: "STANDARD"
  spec_path:      "specs/gui-views/"
  design_path:    "specs/gui-views/design.md"
  tasks_path:     "specs/gui-views/tasks.md"
  ```
