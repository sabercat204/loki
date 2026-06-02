
# Implementation Plan — GUI Views (Loki Desktop)

## Overview

This is the BIND-phase task list for the **gui-views** spec triple under
OT-LK-004. **Critical framing:** the GUI subsystem is already implemented
(~2,700 LOC under `loki/gui/`) and shipped in `v1.0.0` as
`IMPLEMENTED + AD_HOC`. Cleanup Waves A and C have already landed
(commits `98c2110` + `e138baf`). This BIND wave is therefore a
**verification + documentation + acceptance-gate** pass, NOT a
greenfield implementation pass; tasks are framed as "verify the
implementation matches each requirement's acceptance criteria" and "fix
the small surveyed gaps", not "implement X". The scope finishes when
the harness's subsystem registry can flip `gui.spec_status` from
`AD_HOC` to `APPROVED`.

The fifteen design defaults locked in at the OT-LK-004 CAST gate
(D1 single-window topology, D2 QThread-subclass workers,
D3 `threading.Event` cancellation, D4 immediate-mode rendering,
D5 read-only views, D6 menu-bar-only action surface, D7 status-bar
transient text, D8 typed `QMessageBox.warning` errors, D9 closable +
movable tabs keyed by opaque strings, D10 UI-level single-active-worker
policy, D11 deferred preferences, D12 deferred export,
D13 demo-data-runtime construction, D14 offscreen + SilentDialogs test
harness, D15 OS default palette) are inputs, not relitigated; this
plan binds them to per-task acceptance verification.

Each task lists a `T-GUI-NNN` id, dependencies, the requirement(s) and
design section(s) it references, the deliverables it produces, the
verification step that closes it, and explicit out-of-scope notes.
Tasks are smaller in number than the analysis-engine's 28 because the
implementation has already landed; the BIND work here is reading,
running, and ratifying.

## Pre-flight checklist

Before starting Wave 1, confirm the repo is healthy at the cleanup
checkpoint:

```bash
.venv/bin/pytest -q
.venv/bin/mypy --strict loki tests scripts
.venv/bin/ruff check
.venv/bin/ruff format --check
QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py
```

All five MUST be green. `pytest -q` is run with the project default
`addopts = "-ra --strict-markers -m 'not slow'"`; the slow performance
tests are exercised independently by Wave 5's gate.

The GUI subsystem's threat context is **STANDARD** per the loom harness
and Requirement 22. No new credential handling, no new network egress,
no destructive operations are introduced by this BIND — every change is
either a verification step, a small test gap close, a doc refresh, or a
forward-tracked OT-LK entry that lands AFTER the spec ships.

## Tasks

### Wave 1 — Acceptance verification (read-confirm against running GUI)

For every requirement in `specs/gui-views/requirements.md`, walk the
acceptance criteria and confirm the running GUI matches them. Each task
in this wave produces a one-paragraph verification note attached to its
checkbox in the live `STATE.md` worklog, naming the requirement and the
file:line evidence consulted. NO code changes land in this wave; if a
verification step uncovers a real gap, that gap becomes a Wave 2 task,
not a Wave 1 patch.

- [ ] **T-GUI-001. Verify Requirements 1, 18, 22 — application
  lifecycle, QSettings persistence, threat context.**
  - depends-on: none
  - references: R1 (entry point + closeEvent + cli/gui edge), R18
    (QSettings keys + organization namespace), R22 (offline-only
    audit + Forbidden_Egress_Set + Forbidden_Leakage_Field_Set in
    log layer); design §Subsystem positioning, §Constraints carried
    forward, §Threat context.
  - deliverables: a verification note covering (a) `loki.gui.app.run`
    is importable and returns `int`; (b) `MainWindow` constructor
    injects the default `BaselineStore` rooted at
    `~/.local/share/loki/baselines` and falls back to `None` on
    creation failure; (c) `closeEvent` orders cancellation +
    QSettings write per R1; (d) `_closing` flag guards every
    `_on_*_finished` / `_on_*_progress` slot; (e) the four
    `QApplication` metadata strings (`LOKI`, `loki.invalid`,
    `Loki`, `Loki`) match exactly; (f) `loki/gui/` has zero matches
    for `^from loki\.cli` and `^import loki\.cli`; (g) no
    network-related stdlib symbols are imported at module load; (h)
    QSettings persists exactly the three keys.
  - verification: launch the GUI, close it, confirm `qsettings list`
    (or platform equivalent) shows only `main_window/{geometry,
    state, splitter}` under `LOKI/Desktop`. Run
    `grep -rE "^from loki\.cli|^import loki\.cli" loki/gui/` and
    confirm zero output. Run `grep -rE "\.processEvents\(" loki/gui/`
    and confirm zero output (smoke harness exempt).
  - out-of-scope: rewriting any of the import-graph audits as CI
    gates (that work belongs to Wave 2 if a gap surfaces and to a
    forward-tracked OT-LK otherwise).

- [ ] **T-GUI-002. Verify Requirements 2-7 — every view's rendering
  completeness against the upstream Pydantic models.**
  - depends-on: T-GUI-001
  - references: R2 (FirmwareImageView), R3 (ExtractionView),
    R4 (BaselineView, including the `name` row and `TOTAL` row
    defenses), R5 (ImageAnalysisReportView summary altitude),
    R6 (AnalysisView full-evidence altitude after Wave C),
    R7 (FleetAnalysisView + 64 MiB pre-flight); design §Per-view
    rendering contracts.
  - deliverables: a verification note that walks every requirement's
    bullet list against the live view widgets, ticking off each
    field, table column, ordering rule, empty-state handling, and
    `NoEditTriggers` call site. Specifically capture: the eight
    `FirmwareImageView` rows; the `ExtractionView` header / metadata
    / five-column components table / conditional errors table /
    `manifest=None` placeholder; the ten `BaselineView` rows
    including `name` + comparison summary + `TOTAL` row defenses;
    the summary-altitude `ImageAnalysisReportView`; the full-evidence
    `AnalysisView` (Wave C result — recommended_actions table,
    baseline_comparison sub-section, all `FindingEvidence` leaves);
    the `FleetAnalysisView` posture distribution + outliers +
    systemic risks + common findings + recommended actions sections.
  - verification: open one tab of each kind via the demo flow plus
    one tab via a real extraction → classification → analysis run,
    visually compare the rendered cells against `model_dump_json`
    of the same instance, and confirm parity for every public field.
    `NoEditTriggers` is also checkable via Qt's read-only behaviour
    (clicking a cell never enters edit mode).
  - out-of-scope: any field-rendering gap closure (that becomes its
    own task in Wave 2 if uncovered); per-view sort / filter / search
    additions (forward-tracked under D4).

- [ ] **T-GUI-003. Verify Requirements 8 + 9 — NavigationPane
  structure and Workspace tab identity.**
  - depends-on: T-GUI-001
  - references: R8 (four-group order, placeholder discipline,
    `add_entry` bound + sanitisation, double-click contract,
    `Fleet` group v1 placeholder, P77), R9 (Tab_Key opaque-string
    contract, closable + movable, kind-namespaced prefixes, P78);
    design §NavigationPane and Workspace.
  - deliverables: a verification note confirming (a) `_GROUP_ORDER`
    enumerates the four groups in the documented order; (b) every
    placeholder sentinel UserRole payload is `("__placeholder__",
    group)` and does NOT emit `item_activated`; (c) `add_entry`
    truncation at 200 chars, control-char strip, and bidi-override
    strip behave per R8; (d) `add_entry` raises `ValueError` on a
    group not in `_GROUP_ORDER`; (e) `reset()` re-installs every
    placeholder; (f) the closed v1 Tab_Key prefix set is
    `image:`, `extraction:`, `baseline:`, `report:`, `analysis:`,
    `fleet:`; (g) `Workspace.has_tab` returns true iff a widget is
    attached.
  - verification: drive the demo flow and confirm the four-group
    order; run a paste-bombing test against `add_entry` (200-char
    truncation + control-char strip) using a transient script; close
    a tab and confirm `widget.deleteLater()` semantics by checking
    Qt's destroyed signal.
  - out-of-scope: surfacing fleet-membership entries under the
    `Fleet` group (forward-tracked per R8 / R24); migrating the
    Tab_Key string scheme to an enum (forward-tracked per R27).

- [ ] **T-GUI-004. Verify Requirements 10, 11, 12, 15 — three workers
  and the single-active-worker concurrency policy.**
  - depends-on: T-GUI-001
  - references: R10 (ExtractionWorker signals, typed errors,
    cancellation, `bool`-flag forward-tracked), R11
    (BaselineLoadWorker `threading.Event`, partial-result-on-cancel,
    P79), R12 (AnalysisWorker fresh BaselineStore, two signals,
    `threading.Event`, default config values, P80), R15 (UI-level
    single-active guards via menu enablement); design §Worker
    contracts, §Concurrency policy.
  - deliverables: a verification note confirming (a) each worker
    declares exactly the signal set R10 / R11 / R12 specify;
    (b) `errored` payloads are typed `Exception` instances (after
    Wave A); (c) `request_cancel()` sets the `threading.Event`
    on `BaselineLoadWorker` + `AnalysisWorker` (Wave A) while
    `ExtractionWorker` still uses a `bool` flag (forward-tracked
    nit, not a v1 blocker); (d) `_active_worker` /
    `_baseline_load_worker` / `_analyze_action.setEnabled(False)`
    guards prevent double-spawn; (e) AnalysisWorker constructs a
    fresh `BaselineStore` per run with the documented
    `BaselineConfig(storage_path=..., auto_match=True)`; (f) the
    AnalysisConfig defaults (`type=0.25, vendor=0.25,
    security_posture=0.30, mutability=0.20`,
    `default_severity_threshold=MEDIUM`) match.
  - verification: run an extraction, confirm the menu's `Extract
    Firmware Components…` greys while the worker is alive; same for
    Run Analysis. Trigger close-while-running for each worker and
    confirm the `wait(N)` budgets per R1 close cleanly. Read
    `loki/gui/extraction_worker.py`, `baseline_load_worker.py`, and
    `analysis_worker.py` line by line and tick off the signal /
    cancellation / config bullets.
  - out-of-scope: ExtractionWorker `bool → threading.Event`
    migration (forward-tracked OT-LK; T-GUI-014); QThreadPool
    migration (forward-tracked OT-LK; T-GUI-013).

- [ ] **T-GUI-005. Verify Requirements 13, 14, 17, 19 —
  Action_Functions, menu surface, error dialog discipline, demo
  flow.**
  - depends-on: T-GUI-001
  - references: R13 (Action_Function MainWindow contract +
    `*_from_path` companions + demo provenance + `save_baseline`
    overwrite prompt + concurrent-modification handling),
    R14 (three menus, four shortcuts, contextual enablement,
    no toolbar / no context menu / no DnD), R17 (closed v1 error
    category set + isinstance dispatch + parent-catch fallback +
    P81), R19 (DemoWorkspace shape + Pydantic-validated demo
    instances + `(demo)` label suffix + Reset Workspace);
    design §Action_Function contract, §Error dialog discipline,
    §Demo data flow.
  - deliverables: a verification note confirming (a) every
    Action_Function under `loki.gui.actions.*` is a free function
    accepting `window: MainWindow`; (b) every dialog-driven action
    has a `*_from_path` companion that runs the same input
    pre-flight (resolve / is_file / is_dir / R_OK / size cap);
    (c) the menu order matches R14 exactly (`File: Open Firmware
    Image…, Quit`; `View: Load Demo Data, Extract Firmware
    Components…, Run Analysis…, Load Fleet Report…, Open Baseline
    Registry…, Save Baseline…, Cancel Baseline Load, Reset
    Workspace`; `Help: About Loki`); (d) the four shortcut keys
    Ctrl+O / Ctrl+Q / Ctrl+E / Ctrl+A bind to the documented
    actions; (e) the closed error-category set per R17 dispatches
    `isinstance` to the documented dialogs and the parent-catch
    fallback works for `BaselineStorageUnwritableError` and
    `AnalysisError` subclasses; (f) `build_demo_workspace` returns
    a `DemoWorkspace` with 2 images / 1 baseline / 1 comparison /
    1 report and every instance passes Pydantic validation;
    (g) `(demo)` suffix is applied at navigation insertion time,
    not in models; (h) `save_baseline` against a demo-tagged
    baseline returns `None` and writes nothing.
  - verification: drive each action via SilentDialogs in a
    transient pytest run; verify the demo flow visually and via
    `tests/gui/`'s existing harness; verify the toolbar /
    context-menu / drag-and-drop absences via `grep -rE
    "addToolBar|setContextMenuPolicy|setAcceptDrops" loki/gui/`.
  - out-of-scope: a preferences dialog (forward-tracked per D11);
    per-view export (forward-tracked per D12); detach-to-window
    (explicitly not on the v1 roadmap per R24).

- [ ] **T-GUI-006. Verify Requirements 16, 20, 21, 23 — status bar
  discipline, read-only enforcement, offscreen testability,
  determinism / observability.**
  - depends-on: T-GUI-001
  - references: R16 (single-`QLabel` status bar, transient text
    formats, no progress bar / dialog, AnalysisWorker per-component
    progress forward-tracked), R20 (every view immediate-mode +
    NoEditTriggers + `.image` / `.baseline` / `.report` /
    `.manifest` accessor identity, P83), R21 (offscreen +
    SilentDialogs + `scripts/smoke_gui.py` + `background_load`
    keyword + AnalysisWorker test gap callout, P84),
    R23 (rendering determinism + log-layer Forbidden_Leakage_Field_Set
    discipline, P85); design §Status bar discipline,
    §Read-only views, §Offscreen testability.
  - deliverables: a verification note confirming (a) status bar
    shows the documented idle / extraction / baseline-load /
    analysis transient strings; (b) every view's
    `setEditTriggers(NoEditTriggers)` call site matches the
    requirement's file:line citation; (c) accessor properties
    (`.image`, `.baseline`, `.manifest`, `.report`) return the
    same instance passed to the constructor by identity (`is`,
    not `==`); (d) `scripts/smoke_gui.py` runs and exits zero
    under `QT_QPA_PLATFORM=offscreen` outside pytest;
    (e) `background_load: bool = True` keyword exists and the
    synchronous path is exercised by tests that don't care about
    the worker; (f) `loki.gui` and `loki.gui.baselines` log
    records do NOT contain any
    Forbidden_Leakage_Field_Set member (cross-checked via the
    capLog audit of T-GUI-007).
  - verification: run `scripts/smoke_gui.py`; run the offscreen
    `pytest tests/gui/`; spot-check one of each view kind for
    accessor identity in a debugger.
  - out-of-scope: wiring `AnalysisWorker` to subscribe to
    per-component analysis-engine progress (forward-tracked per
    R16); benchmarking `MainWindow.__init__` startup (R23 marks
    the budget informational; a pytest-benchmark harness is
    forward-tracked).

- [ ] **T-GUI-007. Verify Requirements 24, 25, 26, 27 — forward
  tracking, property-numbering, testing coverage gates,
  acceptance gate readiness.**
  - depends-on: T-GUI-001 .. T-GUI-006
  - references: R24 (forward-tracked items list — Wave B threading,
    ExtractionWorker bool flag, fleet group, Action protocol,
    Briefcase user-data path, tab-key enum), R25 (P77-P85
    allocation; next subsystem starts at P86), R26 (per-requirement
    coverage map + worker signal coverage + view rendering tests +
    properties + smoke + three CI grep gates), R27 (BIND-time gap
    closure: AnalysisWorker test); design §Forward-tracked
    migrations, §Property numbering, §Testing strategy.
  - deliverables: (a) a verification note that the existing test
    suite under `tests/gui/` covers every requirement at least
    once except for the AnalysisWorker happy/unhappy gap called
    out in R27 (closed in Wave 2 via T-GUI-008); (b) confirmation
    that property IDs P77-P85 are not used by any other subsystem
    in the repo; (c) a row-by-row tick of the R24 forward-track
    list against the same items the harness will record under
    `forward_track` (for Wave 3); (d) a row-by-row tick of the
    three R26 CI grep audits (cli imports, processEvents,
    network egress) producing zero matches today.
  - verification: `grep -rE "P7[7-9]|P8[0-5]" specs/` for
    property uniqueness; visually walk
    `tests/gui/conftest.py` + every `tests/gui/test_*.py` to
    enumerate per-requirement coverage; run the three audit
    greps from R26 and R22.
  - out-of-scope: actually closing the AnalysisWorker test gap
    (T-GUI-008); writing the forward-tracked OT-LK entries
    (T-GUI-013 .. T-GUI-016); harness flip (T-GUI-018).

### Wave 2 — Test coverage gaps

The Wave 1 verification + the requirements-tension pass surface
exactly one substantive coverage gap (no GUI-level
`AnalysisWorker.start()` test exercising both the
`finished_with_report` happy path and the typed-`errored` unhappy
path) plus a small property-test backfill for properties P77-P85.
Wave 2 closes both. No production-code changes land in this wave;
only `tests/gui/` additions.

- [ ] **T-GUI-008. Add `tests/gui/test_analysis_worker.py` covering
  the `AnalysisWorker` GUI-level signal contract.**
  - depends-on: T-GUI-007
  - references: R12 (AnalysisWorker contract — `finished_with_report`
    + `errored` mutual exclusivity, `threading.Event` cancellation,
    typed-exception payload, fresh BaselineStore construction,
    AnalysisConfig defaults, P80), R21 (offscreen + SilentDialogs
    + `qtbot.waitSignal` discipline), R26 (per-requirement coverage
    + per-worker `qtbot.waitSignal` requirement), R27 (the
    explicit BIND-time gap closure); design §Worker contracts,
    §Testing strategy.
  - deliverables: a new `tests/gui/test_analysis_worker.py` that
    (a) constructs an `AnalysisWorker` with a synthetic but
    Pydantic-valid `(target_records, BaselineRegistry, FirmwareImage,
    AnalysisConfig)` quadruple and asserts via `qtbot.waitSignal`
    that `finished_with_report` fires exactly once with an
    `ImageAnalysisReport` instance (happy path); (b) constructs
    an `AnalysisWorker` whose AnalysisConfig forces an
    `AnalysisConfigError` (e.g. `severity_weights` missing the
    `vendor` key) and asserts `errored` fires exactly once with a
    typed `Exception` subclass (unhappy path); (c) constructs an
    `AnalysisWorker`, calls `request_cancel()` before `start()`,
    and asserts the partial-report-with-Cancellation_Marker path
    per R12.4 + analysis-engine R7; (d) explicitly asserts
    `isinstance(payload, Exception)` on every `errored` signal
    (P80); (e) asserts the `finished_with_report` and `errored`
    signals are mutually exclusive (Property: at most one fires
    per `start()`).
  - verification: `.venv/bin/pytest tests/gui/test_analysis_worker.py
    -q` passes; `.venv/bin/mypy --strict tests` passes; the new
    file is referenced from R26's coverage map note.
  - out-of-scope: wiring AnalysisWorker to per-component progress
    events from analysis-engine (forward-tracked under R16); any
    production-code change to `loki/gui/analysis_worker.py`.

- [ ] **T-GUI-009. Add property tests for P77-P85 under
  `tests/gui/properties/`.**
  - depends-on: T-GUI-007
  - references: R8 (P77 navigation entry invariants), R9 (P78
    workspace tab uniqueness), R11 (P79 worker cancel idempotence;
    extends to AnalysisWorker), R12 (P80 analysis worker error
    typing), R17 (P81 error dialog total function),
    R18 (P82 settings namespace stability + demo-baseline
    poisoning guard), R20 (P83 view render purity), R21 (P84
    offscreen full-render), R23 (P85 view text determinism),
    R25 (allocation table); design §Correctness Properties.
  - deliverables: a new `tests/gui/properties/` tree with one
    `test_p<NN>_*.py` per property:
    - `test_p77_navigation_entry_invariants.py`: Hypothesis-driven
      sequences of `add_entry` / `reset` + group sampling.
    - `test_p78_workspace_tab_uniqueness.py`: small-alphabet
      `open_tab` sequences with collisions.
    - `test_p79_worker_cancel_idempotence.py`: parametrised over
      `BaselineLoadWorker` and `AnalysisWorker`.
    - `test_p80_analysis_worker_error_typing.py`: extends
      T-GUI-008's typed-payload assertion under Hypothesis.
    - `test_p81_error_dialog_total_function.py`: SilentDialogs
      call-count over the closed v1 error-category set from R17.
    - `test_p82_settings_namespace_stability.py`: round-trip the
      three keys + demo-baseline-poisoning substring scan.
    - `test_p83_view_render_purity.py`: every view kind asserts
      `view.<accessor> is m`.
    - `test_p84_offscreen_full_render.py`: parametrised view-kind
      construction never raises under offscreen.
    - `test_p85_view_text_determinism.py`: two constructions →
      equal `(row, column, text)` tuple sequences.
  - verification: `.venv/bin/pytest tests/gui/properties/ -q`
    passes under `QT_QPA_PLATFORM=offscreen`; mypy clean;
    coverage map note updated.
  - out-of-scope: re-validating upstream properties (e.g.
    classification's P33-P42); cross-subsystem property
    plumbing.

### Wave 3 — Forward-tracked refactor candidates (post-spec OT-LKs)

Each Wave 3 task **becomes an OT-LK ticket entry that is opened
AFTER this spec triple ships**, NOT executed during BIND. Wave 3's
deliverable is the entry-text itself: a one-paragraph description,
the design defaults / requirements it relaxes, and the success
criteria that would close it. The orchestrator collects these for
the next planning cycle.

- [ ] **T-GUI-013. Open OT-LK-N: QThreadPool / QRunnable migration
  (D2 forward-track, OT-LK-004 Wave B).**
  - depends-on: T-GUI-008, T-GUI-009 (so the regression surface
    around the workers is locked in before migration)
  - references: R10, R11, R12 (worker contracts must survive
    the migration), R24 (D2 forward-tracked); design §Threading
    model, §Open questions.
  - deliverables: an OT-LK ticket draft titled "Migrate GUI workers
    to QObject.moveToThread() or QThreadPool + QRunnable"
    capturing (a) the existing `QThread` subclass pattern as the
    pre-state; (b) the migration target with a clear preference
    decision deferred to that ticket's CAST gate; (c) the
    invariant the migration MUST preserve (`finished_with_*` /
    `errored` mutual exclusivity, typed-exception payload,
    cancellation token semantics, single-active enablement in
    MainWindow); (d) the success criterion (every test in
    `tests/gui/` passes unchanged after the migration; smoke and
    properties P79, P80, P84 stay green).
  - verification: ticket entry committed to the Sloptropy task
    queue / repo's planning surface (operator decides exact
    storage); no code change in this repo until the new ticket
    enters its own BIND.
  - out-of-scope: actually performing the migration in this
    OT-LK; introducing any worker base-class abstraction in this
    OT-LK.

- [ ] **T-GUI-014. Open OT-LK-N: ExtractionWorker `bool → threading.Event`
  cancellation primitive uniformity (D3 forward-track).**
  - depends-on: T-GUI-008
  - references: R10 (ExtractionWorker bool flag ratified for v1
    with the migration explicitly forward-tracked), R11 / R12
    (BaselineLoadWorker + AnalysisWorker already use
    `threading.Event`), R24 (D3 forward-tracked), R27 (recorded
    in the registry's `forward_track` list); design §Cancellation
    primitive.
  - deliverables: an OT-LK ticket draft titled "Migrate
    ExtractionWorker cancellation from bool flag to
    threading.Event for primitive uniformity" capturing (a) the
    cross-platform GIL-atomicity caveat documented in R10's
    implementation note; (b) the public API delta — none, the
    `request_cancellation()` method signature is unchanged; (c)
    the test surface — a Hypothesis property mirroring P79's
    idempotence claim against ExtractionWorker; (d) the success
    criterion (one-line cancellation primitive unification, no
    behavioural change visible at the Action_Function or smoke
    layer).
  - verification: ticket entry committed.
  - out-of-scope: the migration itself.

- [ ] **T-GUI-015. Open OT-LK-N: GUI configuration exposure +
  preferences dialog (D11 forward-track).**
  - depends-on: T-GUI-007
  - references: R14 (menu surface; preferences would extend File
    or View menu), R24 (D11 forward-tracked), R10 (default
    extraction config currently locked to
    `DEFAULT_EXTRACTION_CONFIG`); design §Configuration exposure.
  - deliverables: an OT-LK ticket draft titled "Surface
    AnalysisConfig + ExtractionConfig overrides in the GUI"
    capturing (a) the v1 contract: GUI uses default-pipeline-only
    and the CLI is the operator-config surface; (b) the v2
    target: a Preferences dialog (or a per-run config sheet) that
    lets the operator override the documented defaults without
    breaking the offscreen test harness; (c) the open question of
    whether overrides persist in QSettings (currently disallowed
    by R18) or only for the live session — that decision is the
    new ticket's CAST input; (d) the success criterion (every
    test in `tests/gui/` passes; new tests cover the config-edit
    flow under SilentDialogs).
  - verification: ticket entry committed.
  - out-of-scope: any preferences-storage decision (it's a CAST
    item for the new ticket).

- [ ] **T-GUI-016. Open OT-LK-N: Per-view export surface
  (D12 forward-track) + minor consistency items
  (D14 navigation `Fleet` group population, tab-key enum).**
  - depends-on: T-GUI-007
  - references: R7 (FleetAnalysisView load path is the only
    persistence path today besides baseline save), R8 (`Fleet`
    navigation group v1 placeholder, fleet entries register
    under `Reports`), R9 (Tab_Key opaque-string scheme), R24
    (D12 + fleet-group + tab-key forward-tracked); design
    §Export, §Tab-key scheme.
  - deliverables: a single OT-LK ticket draft titled "GUI v2
    consistency: per-view export, Fleet group population,
    tab-key typing" or three siblings, at the operator's
    discretion. Each sibling captures (a) the v1 contract;
    (b) the v2 target (CSV/JSON/PDF export per view kind;
    live-fleet-membership rendering under the Fleet group; an
    enum or dataclass for tab keys); (c) the migration test
    surface; (d) the success criterion.
  - verification: ticket entry(ies) committed.
  - out-of-scope: any of the migrations themselves.

### Wave 4 — Documentation refresh

Wave 4 ratifies the spec triple in the project-level docs that
operators read first. No source code under `loki/gui/` changes.

- [ ] **T-GUI-017. Refresh `README.md` GUI row + `CHANGELOG.md`
  GUI section.**
  - depends-on: T-GUI-008, T-GUI-009 (test counts stabilise
    first), T-GUI-013 .. T-GUI-016 (forward-track entries are
    catalogued in the changelog)
  - references: every R in `requirements.md` (the README + changelog
    summarise the contract), R24 (forward-tracks called out in the
    changelog), R27 (`spec_path` / `design_path` / `tasks_path`
    paths to update).
  - deliverables:
    - **README.md**: confirm the **At a Glance** test-count row
      reflects the post-Wave-2 total (it grows by the count of
      tests added in T-GUI-008 + T-GUI-009); confirm the
      **Subsystems** table's `**GUI**` row's description reflects
      the v1 surface (extraction, analysis, baseline, fleet
      views; demo flow; offscreen tested) and that the CLI cell
      stays `loki gui`. If a `## GUI` section exists, refresh it
      to match the depth of the `## Analysis engine` section in
      analysis-engine's README contribution; if it doesn't,
      adding one is OUT OF SCOPE for this task.
    - **CHANGELOG.md**: add a GUI section under the next
      release entry (or under an "Unreleased" header per the
      project's existing convention) recording (a) the OT-LK-004
      cleanup waves A + C that landed at `98c2110` + `e138baf`;
      (b) the spec-triple ratification (`AD_HOC → APPROVED`); (c)
      the AnalysisWorker test-coverage gap closure (T-GUI-008);
      (d) the property-test backfill P77-P85 (T-GUI-009); (e) a
      bullet list of the Wave 3 forward-tracked OT-LK entries.
  - verification: `git diff README.md CHANGELOG.md` is reviewable
    in one screen; the row counts are accurate (e.g.
    `pytest --collect-only -q | tail -1` matches the README cell);
    Markdown lint clean.
  - out-of-scope: rewriting the GUI quickstart in README; adding
    user-facing GUI docs under `docs/` (a doc refresh of that
    depth is forward-tracked alongside the configuration-exposure
    OT-LK in T-GUI-015).

### Wave 5 — Final acceptance gate (registry flip)

Wave 5 is the gate that flips `gui.spec_status` from `AD_HOC` to
`APPROVED` in the harness's subsystem registry. It is the only wave
that touches `loom-loki.md`.

- [ ] **T-GUI-018. Run the four-gate plus smoke plus slow checks;
  bump the harness; record the OT-LK-004 resolution.**
  - depends-on: every prior task
  - references: R26 (CI gates: ruff, format, mypy --strict, pytest,
    smoke_gui.py, three import / process / egress audits), R27
    (acceptance gate checklist + the registry update payload);
    design §Forward-tracked migrations, §Open questions
    (unanswered Q items rolled into Wave 3 OT-LK drafts).
  - deliverables:
    - Run all five gates and confirm green:
      ```bash
      .venv/bin/pytest -q
      .venv/bin/mypy --strict loki tests scripts
      .venv/bin/ruff check
      .venv/bin/ruff format --check
      QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py
      .venv/bin/pytest -m slow tests/gui/ -q  # if any slow GUI tests exist; otherwise skip
      ```
    - Edit `loom-loki.md` to update the `gui` subsystem registry
      entry to:
      ```
      subsystem_name: "gui"
      codename:       "Loki Desktop"
      spec_status:    "APPROVED"   # was AD_HOC
      lifecycle_stage:"IMPLEMENTED"
      threat_context: "STANDARD"
      spec_path:      "specs/gui-views/"
      design_path:    "specs/gui-views/design.md"
      tasks_path:     "specs/gui-views/tasks.md"
      ```
      and append a `forward_track` list with the items recorded
      in Wave 3 (Wave B QThreadPool migration; ExtractionWorker
      bool→Event uniformity; preferences dialog; per-view export;
      fleet group population; tab-key enum; Briefcase user-data
      path). Add an evolution-log entry recording the OT-LK-004
      RESOLVED transition and the spec-triple landing.
    - Bump the loom version per the harness's standing semver
      discipline (the operator decides the bump magnitude; the
      OT-LK-004 RESOLVED transition is at minimum a minor bump).
    - Mark OT-LK-004 status RESOLVED in whichever ticketing
      surface the operator uses (the in-repo `STATE.md`
      worklog, or a dedicated OT-LK file).
  - verification: every gate green; `loom-loki.md` diff reviewable;
    OT-LK-004 status RESOLVED is locatable from `STATE.md`'s
    next read.
  - out-of-scope: actually doing any of the Wave 3 migrations;
    flipping any other subsystem's spec_status; bumping the
    project's release version (orthogonal to the harness bump).

## Task Dependency Graph

The dependency graph organises tasks into five waves. Tasks within a
wave run in parallel; each wave waits for the previous one. Wave 1
is read-only; Wave 2 closes the surveyed gaps; Wave 3 stages
forward-tracked OT-LKs (no code change); Wave 4 refreshes docs;
Wave 5 flips the registry.

```json
{
  "waves": [
    {
      "name": "wave-1-acceptance-verification",
      "tasks": [
        "T-GUI-001",
        "T-GUI-002",
        "T-GUI-003",
        "T-GUI-004",
        "T-GUI-005",
        "T-GUI-006",
        "T-GUI-007"
      ]
    },
    {
      "name": "wave-2-test-coverage",
      "tasks": ["T-GUI-008", "T-GUI-009"]
    },
    {
      "name": "wave-3-forward-tracked-otlks",
      "tasks": [
        "T-GUI-013",
        "T-GUI-014",
        "T-GUI-015",
        "T-GUI-016"
      ]
    },
    {
      "name": "wave-4-documentation-refresh",
      "tasks": ["T-GUI-017"]
    },
    {
      "name": "wave-5-final-acceptance-gate",
      "tasks": ["T-GUI-018"]
    }
  ]
}
```

Suggested cadence:

- **Session 1 — Wave 1.** Walk every requirement against the running
  GUI; produce one verification note per task. No source change.
  Wave 1 is the bulk of the BIND time investment because the GUI is
  large and the survey is dense.
- **Session 2 — Wave 2.** Add the AnalysisWorker test and the
  property-test backfill. Two test-only commits.
- **Session 3 — Wave 3.** Draft the four forward-tracked OT-LK
  entries. No code change in this repo.
- **Session 4 — Wave 4.** README + CHANGELOG refresh.
- **Session 5 — Wave 5.** Run the gates; bump the harness; mark
  OT-LK-004 RESOLVED.

Sessions 3 and 4 can run in parallel with session 2 if separate
operators are driving them; session 5 is the serial bottleneck.

## Notes

- **This BIND is a verification + small-gap-close, not an
  implementation.** The single biggest risk is treating Wave 1 as
  a chance to "improve" a view or a worker; that work belongs to a
  Wave 3 OT-LK draft, not an inline edit. The retroactive
  spec-triple discipline is: ratify the existing implementation,
  surface gaps as forward-tracks, and only fix the small surveyed
  gaps that the requirements-tension pass calls out by name (the
  AnalysisWorker test and the P77-P85 property-test backfill).
- **The fifteen design defaults D1-D15 are inputs, not deliverables.**
  Every task references a default by number; if a default needs
  revisiting, that revisit is a new OT-LK, not a Wave 1 patch.
- **The Forbidden_Leakage_Field_Set + Forbidden_Egress_Set audits
  are already enforced by the existing tests** (`tests/gui/` +
  `tests/test_no_log_leakage.py` if present); this BIND verifies
  they remain green and adds the property-test backfill on top.
- **`AnalysisWorker` is the single known coverage gap.** Every other
  worker has at least one `qtbot.waitSignal` test. Closing the
  gap is the load-bearing Wave 2 deliverable; the property
  backfill is the secondary Wave 2 deliverable.
- **Property numbering picks up at P77** by project-wide convention.
  The next subsystem to ship a Tier 3 spec triple picks up at P86.
- **Wave 3 outputs are TICKET DRAFTS, not code.** The OT-LK numbers
  are assigned by the operator at the time the tickets land in the
  planning surface; this tasks file uses `OT-LK-N` placeholders
  intentionally.
- **The OS default palette (D15) and the
  single-window topology (D1) are explicitly OFF the v1 roadmap
  per R24** — they require a fresh OT-LK to be considered, not a
  forward-tracked entry under OT-LK-004.
