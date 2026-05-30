

# CONTEXT TRANSFER: Loki — analysis engine fully landed (Wave 8 complete; OT-LK-001 closed)

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Sloptropy/loki/`. **Five subsystems have
shipped**: model layer, extraction pipeline, baseline persistence
(GLEIPNIR), classification pipeline, and now the **analysis engine**.
The analysis-engine spec triple is fully closed out — all 28 tasks
across all 8 waves of `.kiro/specs/analysis-engine/tasks.md` are
ticked off. The README has been refreshed with a dedicated
`## Analysis engine` section. The Loom harness is at v0.4.0 and
records the lifecycle transition PROPOSED → IMPLEMENTED.

There is **no in-progress code work**. All five verification gates
are green. Slow performance tests pass locally including the new
analysis-engine R18.1 budget. Offscreen GUI smoke is clean.

The single largest piece of work was a same-day eleven-round arc
that took the analysis engine from "stub requirements only" to
"v1.0.0 IMPLEMENTED + APPROVED." That work is closed. The next
candidate piece of work is the **CVE feed integration / `feeds`
subsystem** (OT-LK-002), which has no spec yet.

## STATUS — what's shipped

Five subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models, 14 StrEnums plus the
  new `MatchStrategy` enum, eight modules. Strict validation on
  construction, lossless JSON / YAML round-trip. Spec at
  `.kiro/specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. v1 covers Intel
  Flash Descriptor (full-flash) images, UEFI PI firmware volumes,
  raw FFS blobs, UEFI capsules, PCI option ROMs, Intel CPU
  microcode update blobs. UEFI volume decompression and
  inner-component emission. Spec at
  `.kiro/specs/extraction-pipeline/`. **All 28 tasks ticked.**
- **`loki/baseline/`** — GLEIPNIR persistence layer. YAML-on-disk,
  one human-readable file per baseline, atomic writes, mtime/size
  concurrency check, typed exception hierarchy, `loki baseline
  list/show/import/export/delete` CLI surface, GUI integration
  with background-thread loading plus per-file progress and
  cancellation. Spec at `.kiro/specs/baseline-persistence/`.
  **All 22 tasks ticked.**
- **`loki/classification/`** — classification pipeline. Turns
  `ExtractedComponent` records into validated `ClassificationRecord`
  instances along the four taxonomic axes (type, vendor,
  security_posture, mutability). Public entry point: ``from
  loki.classification import classify_components``. R5.6
  dual-record contract honored. Spec at
  `.kiro/specs/classification-pipeline/`. **All 25 tasks ticked.**
- **`loki/analysis/`** — analysis engine. Turns a sequence of
  `ClassificationRecord` instances plus a `BaselineRegistry` into
  a validated `ImageAnalysisReport`. Public entry point: ``from
  loki.analysis import analyze_image``. Six finding categories;
  R17.5 post-HARDEN PostureRating six-rule cascade with G3-A
  catch-all + G4-B CRITICAL escalation. All ten Properties P43-P52
  covered by Hypothesis tests. Spec at
  `.kiro/specs/analysis-engine/`. **All 28 tasks ticked.**

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` | DONE — `.kiro/specs/loki-data-models/` | DONE |
| `loki/gui/` | None — handoff plan | DONE (scope B + GLEIPNIR + threaded extraction + threaded baseline load with progress/cancel) |
| `loki/cli.py` | Spec dir empty | `loki gui`, `loki extract --progress`, `loki baseline list/show/import/export/delete` |
| Extraction pipeline | DONE — `.kiro/specs/extraction-pipeline/` | DONE — all 28 tasks |
| Baseline management (GLEIPNIR) | DONE — `.kiro/specs/baseline-persistence/` | DONE — all 22 tasks |
| Classification pipeline | DONE — `.kiro/specs/classification-pipeline/` | DONE — all 25 tasks |
| Analysis engine | DONE — `.kiro/specs/analysis-engine/` | DONE — all 28 tasks |
| Feeds (NVD, implant rules) | Not specced | Not started |
| Fleet analysis | Models exist | Engine not started |

## VERIFICATION (current checkpoint)

- **`pytest -q`**: **1211 passed, 8 deselected**.
- **`pytest -m slow`**: **8 passed** (2 baseline + 2 classification +
  2 extraction + 2 analysis); 1211 deselected.
- **`mypy --strict loki tests scripts`**: 0 issues across **217
  source files**.
- **`ruff check`**: clean repo-wide.
- **`ruff format --check`**: clean (217 files already formatted).
- **Slow performance tests**: all pass locally — R11.1 (4096
  components × 1024 rules under 30s, actual ~3s), R11.3 (4096
  components × 256 MiB total under 60s, actual ~3s), and the new
  **R18.1 (1024+1024 components under 5s, actual ~0.10s — 50× under
  budget)**. Run with `pytest -m slow`.
- **Offscreen GUI smoke run**:
  `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`
  is clean. (See "Workspace observation" below for the actual
  invocation pattern.)
- **Public API smoke**: ``from loki.analysis import analyze_image,
  AnalysisProgressEvent, ANALYSIS_VERSION`` works;
  `ANALYSIS_VERSION = "1.0.0"`.

## WHAT'S NEXT — CVE feed integration (`feeds` subsystem; no spec yet)

OT-LK-001 closed with the analysis-engine v1.0.0 ship. The new top
priority is **OT-LK-002 — CVE feed integration**, which has no spec
yet. Will populate `ClassificationRecord.cve_matches` (currently
always `[]` in v1 per classification R6) by mapping
`(component, classification)` pairs against an NVD-style feed. Once
feeds ship, the analysis-engine's `evidence.matched_cve` and
`DeviationScore.cve_introduced` surfaces (currently always `None`
and `False` per analysis R9.9) start carrying real values.

Two CAST-phase questions for the feeds subsystem:

1. **Feed-refresh cadence.** Daily? Weekly? On demand? The answer
   informs storage layout and the cache-eviction policy.
2. **Signature-trust posture.** Signed feeds with key pinning vs.
   plaintext fetch with hash verification? Threat context will
   likely lift toward FULL on the network-egress path with
   credential handling if pinning is chosen.

**Spec drafting is its own conversation.** Don't try to merge spec
drafting with implementation in a single session. The classification
spec was drafted across multiple turns of a recent conversation and
the implementation followed across a half-dozen wave-sized sessions;
the analysis engine followed the same multi-turn cadence and shipped
in eleven same-day rounds (TENSION + HARDEN + design BIND + tasks
BIND + Waves 1-8). The same cadence is the path of least surprise
for feeds.

Other candidate next moves, in rough priority order (from the loom
harness § 5 Open Threads):

1. **Fleet analysis (`fleet-analysis` subsystem; OT not yet
   numbered).** Models exist (`FleetAnalysisReport` in
   `loki/models/reports.py`); the engine that produces them
   (`analyze_fleet`) is reserved per analysis R19.7. Aggregates
   per-image `FindingRecord` sets across an operator-defined
   fleet. Depends on feeds landing first because `evidence.matched_cve`
   is the most useful aggregation key.
2. **OT-LK-003 — classification CLI subcommand (LOW).** v1 ships
   only the library API. A future `classification-cli` spec
   defines `loki classify run/show/...`. Self-contained.
3. **OT-LK-004 — GUI classification + analysis view (LOW).** Both
   classification and analysis ship as headless library APIs; a
   future GUI spec defines the desktop surface that wires
   `classify_components` and `analyze_image` onto background
   `QThread`s.
4. **OT-LK-005 — Baseline schema migration tool (LOW).** v1
   supports exactly one `Schema_Version` and quarantines any
   other; the future `baseline-schema-migration` spec defines an
   explicit migration command. Out of scope for GLEIPNIR v1 but
   tracked in the design's deferred-decisions section.


## CARRY-FORWARD CONSTRAINTS

- **Python 3.12** baseline. No `backports.strenum` fallback.
- **`mypy --strict`** is the bar across `loki tests scripts`
  (217 source files clean as of Wave 8).
- **`ruff check` + `ruff format`** must be clean repo-wide.
  `RUF002` catches `×` (multiplication sign) and `–` (en dash) in
  Python comments and docstrings — replace with ASCII `x` and `-`.
  Markdown is not affected by RUF002; the existing specs use
  `—` / `→` / `≤` / `×` / `⇒` freely.
- **No `fs_write` for existing files.** Standing directive after
  the archive-clobber incident. Use `fs_append` for extension and
  `str_replace` for in-place edits. New file creation goes via
  `touch <path>` followed by `fs_append`. To prepend content to
  an existing file, use `str_replace` to insert before the file's
  first content line — that preserves all existing content. To
  rewrite an existing file from scratch, use `delete_file`
  followed by `touch` + `fs_append`.
- **No git commits.** User commits when ready.
- **Property numbering is sequential across the platform.** Model
  layer owns 1-11, extraction owns 12-22, baseline-persistence
  owns 23-32, classification owns 33-42, **analysis owns 43-52**.
  Whatever subsystem comes next picks up at 53. The `feeds`
  subsystem is the most likely candidate.
- **Honest about state.** Demo data stays clearly labeled `(demo)`.
  Quarantined baselines surface with their reason. The Analysis
  tab in the GUI is still scaffold pending its own subsystem
  (the analysis engine ships as a library API only; GUI wiring
  is OT-LK-004).
- **Loki only.** Razor-Rooster at
  `/Users/daborond/Sloptropy/razorrooster/` is unrelated.
- **Stick to the spec when one exists; deviate only with explicit
  user OK.** Specs for the five shipped subsystems are closed; the
  next subsystem starts with a fresh requirements / design / tasks
  cycle.

## WORKSPACE OBSERVATION (read this before running tests)

The `.venv/bin/*` entry-point shebangs are stale. They point at
`/Users/daborond/Projects/loki/.venv/bin/python3.12`, which no
longer exists — the project was relocated to
`/Users/daborond/Sloptropy/loki/` in a prior workspace cleanup.
The Python interpreter at `.venv/bin/python` works fine; only the
wrapper-script shebangs (pytest, mypy, ruff, etc.) are broken.

**Workaround in use throughout the analysis-engine implementation:**

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m ruff check
.venv/bin/python -m ruff format --check
```

For the offscreen GUI smoke, the script's own shebang is also
stale; invoke it through python -c:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -c \
  "import sys; sys.argv = ['smoke']; exec(open('scripts/smoke_gui.py').read())"
```

A clean fix is to rebuild the venv:

```bash
rm -rf .venv
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Operator may want to do this between sessions but it is not
blocking implementation.

## TEST INFRASTRUCTURE WORTH KNOWING

- **`pytest-timeout` is installed.** Use `--timeout=30
  --timeout-method=signal` on any GUI test invocation.
- **`tests/gui/test_baseline_actions.py`** has an autouse
  `no_blocking_dialogs` fixture pattern worth replicating in any
  future GUI test file.
- **Hypothesis settings.** Persistence-layer PBT uses
  `max_examples=25`; model layer uses `max_examples=50`.
  Classification adopted both: 50 for in-memory matcher /
  classifier properties, 25 for full-pipeline properties. Analysis
  picked up the same convention: `max_examples=50` for
  axis_score / composite_score / pairing properties,
  `max_examples=25` for full-pipeline determinism / round-trip /
  cancellation properties. Both also set
  `suppress_health_check=[HealthCheck.too_slow,
  HealthCheck.function_scoped_fixture]`. Apply the same
  convention to future subsystems.
- **`slow` marker is registered** in `pyproject.toml` and
  `addopts = "-ra --strict-markers -m 'not slow'"` keeps
  performance tests off the default `pytest -q` run.
- **`filterwarnings = ["error"]`** is set in `pyproject.toml`. Any
  `DeprecationWarning` emitted during a run will fail the test.
  Follow the extraction pattern when one fires: either upgrade
  the pin or add a narrow `filterwarnings("ignore", ...)` in the
  affected test module's `conftest.py` with a documented rationale.
- **The static AST + dynamic caplog audit pair is now in four
  subsystems** (extraction, baseline, classification, analysis).
  The pattern: `tests/<subsys>/test_no_log_leakage.py` does the
  static AST audit; `tests/<subsys>/test_log_no_leakage.py` does
  the dynamic caplog audit. Mirror this in any future subsystem
  that owns log records.
- **Pydantic strict-mode round-trip pattern.** When testing JSON
  / YAML round-trip on a strict-mode Pydantic model:
  - JSON: use `Model.model_validate_json(model.model_dump_json())`.
    Native decoder handles enums + UUIDs.
  - dict / YAML: use `Model.model_validate(data, strict=False)`.
    Mirrors `LokiConfig.from_yaml`'s relaxed-mode coercion path.
  Using `Model.model_validate(model.model_dump(mode="json"))`
  (no strict=False) on a strict model FAILS on string-encoded
  enums and UUIDs — this caught us twice during the analysis
  implementation.
- **Floating-point composite scores can overflow strict bounds.**
  `10.0 * (0.4+0.2+0.3+0.1) = 10.0+~2e-15`, which the model layer's
  strict `composite_score <= 10.0` validator on `DeviationScore`
  rejects. The analysis engine clamps composite scores to
  `[0.0, 10.0]` at the producer side in
  `emit_classification_mismatch`. If you ever add another field
  with a strict numeric range, plan the producer-side clamp
  preemptively.
- **`tests/analysis/_helpers.py`** is an underscore-prefixed
  helpers module (pytest doesn't collect it as a test module). It
  exposes `make_axis`, `make_record`, `make_baseline_record`,
  `make_image`, `make_signature_info`, and the `VALID_WEIGHTS`
  constant. Reuse it from any future analysis-related test file.

## THINGS THAT MIGHT TRIP THE NEW AGENT

- **All five subsystems are end-to-end implemented.** No
  half-finished surfaces lurking. Every public API is callable;
  every contract is enforced by at least one test.
- **The analysis engine has eight design defaults baked into the
  implementation.** Documented as D1-D8 in
  `.kiro/specs/analysis-engine/design.md` § "Deferred decisions
  and open questions":
  - D1: free function `analyze_image`, not class method (mirrors
    classification).
  - D2: `loki/analysis/errors.py` exception module.
  - D3: `FindingEvidence.deviation_score` direct model-layer
    extension.
  - D4: `AnalysisConfig` extended with `match_strategy`,
    `confidence_gap_threshold`, `baseline_id`.
  - D5: `MatchStrategy` is a StrEnum in `loki/models/enums.py`.
  - D6: `AnalysisProgressEvent` strips `component_id`. The
    classification pipeline's `ProgressEvent.component_id` was a
    deliberate exception to its leakage discipline; analysis
    takes the stricter side.
  - D7: Properties P43-P52, ten properties.
  - D8: five Property descriptions (P44, P45, P46, P49, P52) use
    multi-paragraph or bullet-list structure; the Kiro Spec Format
    checker emits five non-blocking warnings on the design.md;
    explicitly accepted to preserve structural clarity.
- **The R17.5 PostureRating mapping is a six-rule cascade** with
  G3-A catch-all + G4-B CRITICAL escalation. The cascade is in
  `loki/analysis/posture.py:derive_posture_rating`. If you ever
  need to extend it, the implementation walks the finding list
  once collecting four boolean flags + one running max; adding a
  sixth check is an O(N) addition to the same loop, not a new
  pass.
- **The Cancellation_Marker contract has nine acceptance criteria
  in R7.** The most important to remember: it's the LAST entry
  in `findings`, has a deterministic sentinel `component_id` =
  `uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")`, severity
  INFO, and the cancellation-at-index value lives in
  `evidence.raw_indicators[0]` ONLY (never logged per R7.4).
- **The R17.4 `BaselineComparison` lockstep with
  `ImageAnalysisReport.timestamp`** was a TENSION-pass HARDEN
  amendment (G1 + G2). The two timestamps move together so the
  determinism property in R15.1 strips one value. If you ever add
  a third timestamp anywhere in the report, plan the lockstep
  before BIND.
- **The TENSION pass review note** at
  `.kiro/specs/analysis-engine/requirements-tension-pass.md`
  records four substantive gaps (G1-G4) and three wording items
  (M1-M3) that the operator decided in flight. Operator chose
  G3-A (catch-all DEGRADED rule) and G4-B (escalate
  classification_mismatch CRITICAL to COMPROMISED). M1, M2 were
  cosmetic and skipped. Future amendments to R15.7 / R17.5 should
  re-read the TENSION note before deviating.
- **Analysis-engine v1 leaves `cve_matches`, `matched_cve`, and
  `cve_introduced` empty / None / False.** R9.9 contracts this.
  Once the feeds subsystem ships, these surfaces start carrying
  real values, and the analysis engine itself does not need a
  re-spec — only the feeds subsystem needs to populate
  `ClassificationRecord.cve_matches` upstream.
- **The `AnalysisProgressEvent` does NOT carry `component_id`.**
  This is design D6, deliberately stricter than classification's
  `ProgressEvent`. Don't extend the dataclass in flight; if a
  future GUI revision needs the UUID for a "show in workspace"
  button, the extension goes through a deliberate spec amendment.
- **Five judgment calls were locked in during the analysis-engine
  spec** (D1-D5 above plus D6 + D7). Each is documented in the
  design's "Deferred decisions" section. Any can be reverted
  cheaply if a future revision wants different behavior. The
  affected tasks are: 20 (D1 free function), 6 (D2 errors module),
  5 (D3 FindingEvidence extension), 4 (D4 AnalysisConfig
  extension), 3 (D5 MatchStrategy enum), 20 (D6 progress event
  shape), 24 (D7 P43-P52 numbering).


## REPOSITORY LAYOUT (current)

```
loki/                                 # /Users/daborond/Sloptropy/loki/
├── README.md                         # up to date as of analysis Wave 8
├── HANDOFF.md                        # this doc
├── HANDOFF.archive.md                # all prior handoffs preserved (most recent first)
├── STATE.md                          # WEAVE-style state + next-steps doc
├── loom-loki.md                      # WEAVE/Loom Tier 3 harness; v0.4.0
├── pyproject.toml
├── .kiro/
│   └── specs/
│       ├── loki-data-models/         # DONE
│       ├── extraction-pipeline/      # DONE — 28/28 tasks
│       ├── baseline-persistence/     # DONE — 22/22 tasks
│       ├── classification-pipeline/  # DONE — 25/25 tasks
│       └── analysis-engine/          # DONE — 28/28 tasks
│           ├── requirements.md       # 1194 lines, 20 EARS requirements
│           ├── requirements-tension-pass.md  # TENSION + HARDEN audit trail
│           ├── design.md             # 1211 lines, 11 sections, P43-P52
│           └── tasks.md              # 28 tasks, 8 waves; all ticked
├── loki/
│   ├── cli.py                        # gui / extract (--progress) / baseline
│   ├── models/                       # 8 modules, Pydantic v2 (extended for analysis)
│   ├── extraction/                   # extraction pipeline
│   ├── baseline/                     # GLEIPNIR persistence
│   ├── classification/               # classification pipeline
│   ├── analysis/                     # analysis engine (12 modules)
│   │   ├── __init__.py               # public re-exports
│   │   ├── api.py                    # analyze_image + AnalysisProgressEvent
│   │   ├── pipeline.py               # internal AnalysisPipeline orchestrator
│   │   ├── version.py                # ANALYSIS_VERSION = "1.0.0"
│   │   ├── matching.py               # R2 Match_Strategy resolution + R14.1
│   │   ├── pairing.py                # R3 Component_Pairing
│   │   ├── findings.py               # 5 emitters + Cancellation_Marker + finding_id
│   │   ├── scoring.py                # 6 scoring helpers
│   │   ├── posture.py                # R17.5 six-rule cascade
│   │   ├── report.py                 # ImageAnalysisReport assembly + priority_rank
│   │   ├── errors.py                 # 4-subclass exception hierarchy
│   │   └── timing.py                 # Stopwatch context manager
│   └── gui/                          # PyQt6 desktop, threaded workers
└── tests/
    ├── conftest.py                   # Hypothesis strategies
    ├── extraction/                   # extraction subsystem tests
    ├── baseline/                     # baseline-persistence tests
    ├── classification/               # classification tests
    ├── analysis/                     # analysis-engine tests (~22 files)
    │   ├── _helpers.py               # shared fixture builders
    │   ├── test_api.py               # public surface + R1.9 no-loki-gui audit
    │   ├── test_pipeline.py          # AnalysisPipeline orchestration
    │   ├── test_properties.py        # Hypothesis P43-P52
    │   ├── test_no_log_leakage.py    # static AST audit (Property 50)
    │   ├── test_log_no_leakage.py    # dynamic caplog audit (Property 50)
    │   ├── test_no_side_channels.py  # static AST audit (Property 51)
    │   ├── test_performance.py       # slow marker, R18.1 budget
    │   └── test_findings_*.py        # 5 per-category emitter tests
    ├── gui/                          # PyQt6 tests
    ├── test_classification_smoke.py  # extract → classify smoke
    └── test_analysis_smoke.py        # all 6 analysis finding categories smoke
```

## FILES TO READ FIRST

- `README.md` — current as of analysis Wave 8. Project overview,
  quick-start, and a current snapshot of the implementation
  status across all five shipped subsystems plus dedicated
  `## Classification pipeline` and `## Analysis engine` sections
  describing the public entry points, six finding categories,
  the PostureRating six-rule cascade, the cooperative-cancellation
  pattern, and the determinism + no-leakage discipline.
- `loom-loki.md` — Tier 3 WEAVE harness at v0.4.0. Subsystem
  registry now lists five IMPLEMENTED + APPROVED subsystems.
  Dependency graph materializes 17 edges. The v0.4.0 evolution-
  log entry summarizes the eleven same-day rounds that took
  analysis-engine from "stub requirements" to "v1.0.0
  IMPLEMENTED."
- `STATE.md` — current state + next-steps doc. Cross-references
  the workspace-level `../STATE_AND_NEXT_STEPS.md`.
- `.kiro/specs/analysis-engine/{requirements,design,tasks}.md` —
  the most recent reference for spec format. Mirror the structure
  when drafting the feeds spec.
- `.kiro/specs/analysis-engine/requirements-tension-pass.md` —
  records the TENSION + HARDEN audit trail. The pattern is worth
  mirroring for any future spec that needs a TENSION pass before
  HARDEN.
- `loki/analysis/` — twelve modules implementing the analysis
  engine. The cleanest reference implementation in the project
  for a five-component architecture (matching + pairing +
  scoring + posture + report assembly + pipeline orchestration).
  When designing the feeds subsystem, mirror this shape unless
  the design conversation explicitly diverges.
- `loki/extraction/` and `loki/baseline/` and
  `loki/classification/` — three additional reference
  implementations. Each shows the project's module layout, error
  hierarchy, side-channels audit, and no-leakage logging audit
  patterns.

## USER PREFERENCES (carry forward)

- **No git commits.** User commits when ready.
- **Loki workspace only.** Don't reference razor-rooster.
- **Stick to the spec when one exists; deviate only with explicit
  OK.** Specs for the five shipped subsystems are closed.
- **Spec drafting is its own conversation.** Don't merge it with
  implementation in a single session. The analysis-engine
  arc demonstrated this: 4 spec rounds (TENSION + HARDEN +
  design BIND + tasks BIND) preceded the 7 implementation rounds
  (Waves 1-7) preceded the final Wave 8 ratification. Each round
  was checkpoint-clean before advancing.
- **After each round of work, summarize what's done, what's
  tested, what's next, and offer 3-4 candidate next moves.**
- **Honest framing.** Don't claim work is done if it isn't. Don't
  paper over spec deviations; surface them and confirm.
- **Pause and ask** when the work scope is ambiguous, when a spec
  decision is needed, or when an approach has failed twice.
- **Never use `fs_write` against an existing file.** Standing
  directive after the archive-clobber incident. Use `fs_append`
  for extension and `str_replace` for in-place edits. New file
  creation goes through `touch` followed by `fs_append`.
- **TENSION pass is the right move on a substantial DRAFT.** When
  a spec DRAFT looks complete on first read, do a TENSION pass
  end-to-end before declaring HARDEN-ready. The analysis-engine
  TENSION pass surfaced four substantive gaps (G1-G4) and three
  wording items (M1-M3) that would have caused real implementation
  pain if missed.

## READY FOR NEXT SESSION

The codebase is at a clean checkpoint. **Five subsystems shipped;
all have closed-out specs.** This is doc-complete and gate-green.

The natural next session is the **CVE feed integration spec
drafting conversation** (OT-LK-002): requirements → design → tasks,
in that order, in its own session. The model layer's
`FeedsConfig` already exists in `loki/models/config.py`; the
feeds subsystem fills in the engine that populates
`ClassificationRecord.cve_matches`.

A second equally-valid next session is the **`loki analyze` CLI
subcommand** spec drafting. v1 of the analysis engine ships only
the library API; a future `analysis-cli` spec defines `loki
analyze run/show/diff/...`. Self-contained and smaller in scope
than feeds.

A third is the **GUI analysis view** (OT-LK-004). Probably best
paired with the GUI classification view since the two share a
worker / threading pattern.

Whichever direction the next session goes, the rules above
stand: test counts shouldn't regress (1211 baseline), all five
gates stay green, no git commits, loki only, no `fs_write`
against existing files.

---

**End of handoff.**

# CONTEXT TRANSFER: Loki — classification fully landed (Wave 8 complete)

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Projects/loki/`. **Four subsystems have
shipped**: model layer, extraction pipeline, baseline persistence
(GLEIPNIR), and the classification pipeline. The classification
spec is fully closed out — all 25 tasks across all 8 waves of
`.kiro/specs/classification-pipeline/tasks.md` are ticked off.
The README has been refreshed to reflect the new status, the new
test counts, and the new repository layout.

There is **no in-progress code work**. All four verification gates
are green. Slow performance tests pass locally. Offscreen GUI smoke
is clean. The natural next major piece of work is the **analysis
engine**, which has no spec yet.

## STATUS — what's shipped

Four subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models, 14 StrEnums, eight
  modules. Strict validation on construction, lossless JSON / YAML
  round-trip. Spec at `.kiro/specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. v1 covers Intel
  Flash Descriptor (full-flash) images, UEFI PI firmware volumes,
  raw FFS blobs, UEFI capsules, PCI option ROMs, Intel CPU
  microcode update blobs. UEFI volume decompression and
  inner-component emission. Spec at
  `.kiro/specs/extraction-pipeline/`. **All 28 tasks ticked off in
  `tasks.md`**.
- **`loki/baseline/`** — GLEIPNIR persistence layer. YAML-on-disk,
  one human-readable file per baseline, atomic writes, mtime/size
  concurrency check, typed exception hierarchy, `loki baseline
  list/show/import/export/delete` CLI surface, GUI integration
  with background-thread loading plus per-file progress and
  cancellation (R2.8-R2.10, R7.10-R7.11). Spec at
  `.kiro/specs/baseline-persistence/`. **All 22 tasks ticked off in
  `tasks.md`**.
- **`loki/classification/`** — classification pipeline. Turns
  `ExtractedComponent` records into validated
  `ClassificationRecord` instances along the four taxonomic
  axes (type, vendor, security_posture, mutability). Public
  entry point: ``from loki.classification import
  classify_components``. R5.6 dual-record contract honored
  (missing-bytes components emit both a record and an error for
  the same `component_id`). Spec at
  `.kiro/specs/classification-pipeline/`. **All 25 tasks ticked
  off in `tasks.md`**.

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` | DONE — `.kiro/specs/loki-data-models/` | DONE |
| `loki/gui/` | None — handoff plan | DONE (scope B + GLEIPNIR + threaded extraction + threaded baseline load with progress/cancel) |
| `loki/cli.py` | Spec dir empty | `loki gui`, `loki extract --progress`, `loki baseline list/show/import/export/delete` |
| Extraction pipeline | DONE — `.kiro/specs/extraction-pipeline/` | DONE — all 28 tasks |
| Baseline management (GLEIPNIR) | DONE — `.kiro/specs/baseline-persistence/` | DONE — all 22 tasks |
| Classification pipeline | DONE — `.kiro/specs/classification-pipeline/` | DONE — all 25 tasks |
| Analysis engine | Not specced | Not started |
| Feeds (NVD, implant rules) | Not specced | Not started |
| Fleet analysis | Models exist | Engine not started |

## VERIFICATION (current checkpoint)

- **`pytest -q`**: **897 passed, 6 deselected**.
- **`mypy --strict loki tests scripts`**: 0 issues across **176
  source files**.
- **`ruff check`**: clean repo-wide.
- **`ruff format --check`**: clean (176 files already formatted).
- **Slow performance tests**: both pass locally — R11.1
  (4096 components × 1024 rules under 30s, actual ~3s) and
  R11.3 (4096 components × 256 MiB total under 60s, actual
  ~3s). Run with
  `pytest -m slow tests/classification/test_performance.py`.
  The full slow suite (extraction + baseline-persistence +
  classification) is 6 tests; run with `pytest -m slow`.
- **Offscreen GUI smoke run**:
  `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`
  is clean.
- **Public API smoke**: ``from loki.classification import
  classify_components, ClassificationResult, ProgressEvent,
  ProgressCallback, CancellationToken`` works.

## WHAT'S NEXT — analysis engine (no spec yet)

The natural next major piece of work. Will produce
`FindingRecord` and `DeviationScore` instances by comparing
classifications against baselines and feed data. The model
layer's `loki/models/analysis.py` and `loki/models/reports.py`
already define the persisted contracts; the analysis subsystem
fills in the engine that produces them.

**Spec drafting is its own conversation.** Don't try to merge
spec drafting with implementation in a single session. The
classification spec was drafted across multiple turns of a
recent conversation and the implementation followed across a
half-dozen wave-sized sessions; the same cadence is the path of
least surprise for analysis.

Other candidate next moves, in rough priority order:

1. **CVE feed integration.** No spec yet. Will populate the
   `ClassificationRecord.cve_matches` list (currently always
   `[]` in v1 per R6) by mapping `(component, classification)`
   pairs against an NVD-style feed.
2. **Classification CLI subcommand.** v1 ships only the library
   API. A future `classification-cli` spec defines `loki
   classify run`, `loki classify show`, etc.
3. **GUI classification view.** v1's library API runs headless;
   a future GUI-classification spec defines the desktop surface.
4. **Schema migration tool.** v1 supports exactly one
   `Schema_Version` and quarantines any other; the future
   `baseline-schema-migration` spec defines an explicit
   migration command. Out of scope for GLEIPNIR v1 but tracked
   in the design's deferred-decisions section.

## CARRY-FORWARD CONSTRAINTS

- **Python 3.12** baseline. No `backports.strenum` fallback.
- **`mypy --strict`** is the bar across `loki tests scripts`
  (176 source files clean as of Wave 8).
- **`ruff check` + `ruff format`** must be clean repo-wide.
  `RUF002` catches `×` (multiplication sign) and `–` (en dash) in
  Python comments and docstrings — replace with ASCII `x` and `-`.
  Markdown is not affected by RUF002; the existing specs use
  `—` / `→` / `≤` / `×` / `⇒` freely.
- **No `fs_write` for existing files.** The user has a standing
  directive: use only methods that append/prepend
  (`fs_append`, `str_replace`). New file creation goes via
  `touch <path>` followed by `fs_append`. Violating this is how
  a prior session destroyed `HANDOFF.archive.md` — that file was
  reconstructed but the loss was real.
- **No git commits.** User commits when ready.
- **Property numbering is sequential across the platform.** Model
  layer owns 1-11, extraction owns 12-22, baseline-persistence
  owns 23-32, classification owns 33-42. Whatever subsystem comes
  next picks up at 43.
- **Honest about state.** Demo data stays clearly labeled `(demo)`.
  Quarantined baselines surface with their reason. The Analysis
  tab in the GUI is still scaffold pending its own subsystem.
- **Loki only.** Razor-Rooster at
  `/Users/daborond/Sloptropy/razorrooster/` is unrelated.
- **Stick to the spec when one exists; deviate only with explicit
  user OK.** Specs for the four shipped subsystems are closed;
  the next subsystem starts with a fresh requirements / design /
  tasks cycle.

## TEST INFRASTRUCTURE WORTH KNOWING

- **`pytest-timeout` is installed.** Use `--timeout=30
  --timeout-method=signal` on any GUI test invocation.
- **`tests/gui/test_baseline_actions.py`** has an autouse
  `no_blocking_dialogs` fixture pattern worth replicating in any
  future GUI test file.
- **Hypothesis settings.** Persistence-layer PBT uses
  `max_examples=25`; model layer uses `max_examples=50`.
  Classification adopted both: 50 for in-memory matcher /
  classifier properties, 25 for full-pipeline properties. Both
  set `suppress_health_check=[HealthCheck.too_slow]`. Apply the
  same convention to future subsystems.
- **`slow` marker is registered** in `pyproject.toml` and
  `addopts = "-ra --strict-markers -m 'not slow'"` keeps
  performance tests off the default `pytest -q` run.
- **`filterwarnings = ["error"]`** is set in `pyproject.toml`. Any
  `DeprecationWarning` emitted during a run will fail the test.
  Follow the extraction pattern when one fires: either upgrade
  the pin or add a narrow `filterwarnings("ignore", ...)` in the
  affected test module's `conftest.py` with a documented rationale.
- **The static AST no-leakage audit** at
  `tests/classification/test_no_log_leakage.py` is a pattern
  worth replicating in extraction and baseline-persistence if
  log-leakage regressions ever surface there. The dynamic
  `caplog`-based audit (`test_log_no_leakage.py`) is already
  present in all three subsystems.

## THINGS THAT MIGHT TRIP THE NEW AGENT

- **All four subsystems are end-to-end implemented.** No
  half-finished surfaces lurking. Every public API is callable;
  every contract is enforced by at least one test.
- **`ClassificationRecord` doesn't have a `raw_hash` field.** That's
  on `ExtractedComponent`. The Forbidden_Leakage_Field_Set for
  classification is `component_id` (extraction's and the
  mirrored copy on `ClassificationRecord`),
  `signature_info.signer`, the parent
  `BaselineRecord.source_image_hash`, and any
  `AxisClassification.evidence` string.
- **Inner components have offsets within the decompressed buffer**,
  not within the source firmware binary. The classification
  pipeline does not branch on inner-vs-outer — both classify
  through the same code path (R7).
- **`ClassificationConfig.confidence_threshold` is reserved**, not
  consumed by the v1 pipeline (R4.10). The v1 review gate is the
  model layer's hard-coded `needs_review = composite_confidence
  < 0.60` invariant. The analysis engine subsystem may consume
  the threshold; if it does, that's a deliberate choice, not a
  silent escalation.
- **The classification entry point is synchronous on the calling
  thread** (R1.7). No threading, no asyncio, no process pools.
  When the GUI eventually wires it up, it'll be on a `QThread`
  the same way extraction and baseline load already are.
- **Five judgment calls were locked in during the classification
  spec** (free function vs. class, `ProgressEvent.component_id`
  exposure, `ClassificationError` location, lexicographic file
  sort, WARNING records omit error message). Each is documented
  in the design's "Deferred decisions" section. Any can be
  reverted cheaply if a future revision wants different
  behavior.

## REPOSITORY LAYOUT (current)

```
loki/
├── README.md                        # up to date as of Wave 8
├── HANDOFF.md                       # this doc
├── HANDOFF.archive.md               # Wave 7 handoff archived; older entries below
├── pyproject.toml
├── .kiro/
│   └── specs/
│       ├── loki-data-models/        # DONE
│       ├── extraction-pipeline/     # DONE — 28/28 tasks
│       ├── baseline-persistence/    # DONE — 22/22 tasks
│       │                            # plus R2.8-R2.10, R7.10-R7.11 callbacks
│       └── classification-pipeline/ # DONE — 25/25 tasks
│           ├── requirements.md      # 13 EARS requirements
│           ├── design.md            # 11 sections, Properties 33-42
│           └── tasks.md             # 25 tasks, 8 waves; all ticked
├── loki/
│   ├── cli.py                       # gui / extract (--progress) / baseline
│   ├── models/                      # 8 modules, Pydantic v2
│   ├── extraction/                  # extraction pipeline
│   ├── baseline/                    # GLEIPNIR persistence
│   ├── gui/                         # PyQt6 desktop, threaded workers
│   └── classification/              # library API, four-axis classifier,
│                                    # R5.6 dual-record contract
└── tests/
    ├── conftest.py                  # Hypothesis strategies
    ├── extraction/                  # extraction subsystem tests
    ├── baseline/                    # baseline-persistence tests
    ├── classification/              # classification tests; full Property
    │                                # 33-42 coverage + golden + slow perf
    ├── gui/                         # PyQt6 tests
    └── test_classification_smoke.py # end-to-end extract → classify smoke
```

## FILES TO READ FIRST

- `README.md` — up to date as of Wave 8. Project overview,
  quick-start, and a current snapshot of the implementation
  status across all four shipped subsystems plus a dedicated
  `## Classification pipeline` section describing the public
  entry point, rule-file format, R5.6 dual-record contract, and
  determinism caveats.
- `loki/models/analysis.py` and `loki/models/reports.py` —
  the persisted contracts the analysis engine subsystem will
  produce (`FindingRecord`, `DeviationScore`,
  `ImageAnalysisReport`).
- `.kiro/specs/loki-data-models/` and the three completed
  subsystem specs — structural templates for the analysis
  engine spec when its drafting conversation starts.
- `loki/extraction/` and `loki/baseline/` and
  `loki/classification/` — three reference implementations of
  the project's module layout, error hierarchy, side-channels
  audit, and no-leakage logging audit. The analysis engine
  should mirror this shape unless the design conversation
  explicitly diverges.

## USER PREFERENCES (carry forward)

- **No git commits.** User commits when ready.
- **Loki workspace only.** Don't reference razor-rooster.
- **Stick to the spec when one exists; deviate only with explicit
  OK.** Specs for the four shipped subsystems are closed.
- **Spec drafting is its own conversation.** Don't merge it with
  implementation in a single session.
- **After each round of work, summarize what's done, what's
  tested, what's next, and offer 3-4 candidate next moves.**
- **Honest framing.** Don't claim work is done if it isn't. Don't
  paper over spec deviations; surface them and confirm.
- **Pause and ask** when the work scope is ambiguous, when a spec
  decision is needed, or when an approach has failed twice.
- **Never use `fs_write` against an existing file.** Standing
  directive after the archive-clobber incident. Use `fs_append`
  for extension and `str_replace` for in-place edits. New file
  creation goes through `touch` followed by `fs_append`.

## READY FOR NEXT SESSION

The codebase is at a clean checkpoint. **Classification is
fully landed; all four shipped subsystems have closed-out
specs.** This is doc-complete and gate-green.

The natural next session is the **analysis engine spec drafting
conversation**: requirements → design → tasks, in that order, in
its own session. The model layer already defines the persisted
shapes (`FindingRecord`, `DeviationScore`, `ImageAnalysisReport`,
`FleetAnalysisReport`); the spec needs to define the engine that
produces them.

Whichever direction the next session goes, the rules above
stand: test counts shouldn't regress (897 baseline), all four
gates stay green, no git commits, loki only, no `fs_write`
against existing files.

---

**End of handoff.**

---

# Older entries below (most recent first) — preserved for context.

# CONTEXT TRANSFER: Loki — classification implementation Wave 7 complete

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Projects/loki/`. The project has three
shipped subsystems (model layer, extraction pipeline, baseline
persistence) plus a fourth (classification pipeline) that is fully
specced and **end-to-end implemented with the full test layer
landed** — Waves 1, 2, 3, 4, 5, 6, and 7 of `tasks.md` are
complete (23/25 tasks).

There is **no in-progress code work**. All four verification gates
are green. The public ``classify_components`` API is callable
end-to-end. Wave 7 added the cross-cutting test layer:
no-side-channels audit (Property 41), no-leakage logging audits
(Property 40 — both static AST and dynamic capture), Hypothesis
PBT for Properties 33-38, golden-file regression, slow-marked
performance tests (R11.1 + R11.3 budgets passing locally), and
an end-to-end extract→classify smoke test. **Only Wave 8 remains:
README refresh + final verification gate.**

## STATUS — what's shipped

Three subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models, 14 StrEnums, eight
  modules. Strict validation on construction, lossless JSON / YAML
  round-trip. Spec at `.kiro/specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. v1 covers Intel
  Flash Descriptor (full-flash) images, UEFI PI firmware volumes,
  raw FFS blobs, UEFI capsules, PCI option ROMs, Intel CPU
  microcode update blobs. UEFI volume decompression and
  inner-component emission. Spec at
  `.kiro/specs/extraction-pipeline/`. **All 28 tasks ticked off in
  `tasks.md`**.
- **`loki/baseline/`** — GLEIPNIR persistence layer. YAML-on-disk,
  one human-readable file per baseline, atomic writes, mtime/size
  concurrency check, typed exception hierarchy, `loki baseline
  list/show/import/export/delete` CLI surface, GUI integration
  with background-thread loading plus per-file progress and
  cancellation (R2.8-R2.10, R7.10-R7.11). Spec at
  `.kiro/specs/baseline-persistence/`. **All 22 tasks ticked off in
  `tasks.md`**.

A fourth subsystem is fully specced; Waves 1-7 of
implementation are landed:

- **`loki/classification/`** — classification pipeline. Turns
  `ExtractedComponent` records into validated
  `ClassificationRecord` instances along the four taxonomic
  axes. Spec at `.kiro/specs/classification-pipeline/`. **All
  three docs drafted**. **Waves 1-7 complete (23/25 tasks)**:
  end-to-end implementation, focused behavioral tests, and
  the full cross-cutting test layer. Properties 33-42
  pinned by Hypothesis PBT, AST audits (no-side-channels,
  no-leakage logging — both static and dynamic), golden-file
  regression, slow-marked performance smoke (R11.1 + R11.3
  budgets), and end-to-end extract→classify smoke. Only
  Wave 8 (README refresh + final gate) remains.

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` | DONE — `.kiro/specs/loki-data-models/` | DONE |
| `loki/gui/` | None — handoff plan | DONE (scope B + GLEIPNIR + threaded extraction + threaded baseline load with progress/cancel) |
| `loki/cli.py` | Spec dir empty | `loki gui`, `loki extract --progress`, `loki baseline list/show/import/export/delete` |
| Extraction pipeline | DONE — `.kiro/specs/extraction-pipeline/` | DONE — all 28 tasks ticked, plus UEFI decompression + inner-component emission |
| Baseline management (GLEIPNIR) | DONE — `.kiro/specs/baseline-persistence/` | DONE — all 22 tasks ticked, plus optional progress/cancel callbacks (R2.8-R2.10, R7.10-R7.11) |
| **Classification pipeline** | **DONE** — `.kiro/specs/classification-pipeline/` | **Waves 1-7 complete** — 23/25 tasks; full implementation + every test layer except final docs / gate (Wave 8) |
| Analysis engine | Not specced | Not started |
| Feeds (NVD, implant rules) | Not specced | Not started |
| Fleet analysis | Models exist | Engine not started |

## VERIFICATION (current checkpoint)

- **`pytest -q`**: **897 passed, 6 deselected** (was 862/4;
  Wave 7 added +35 tests across no-side-channels, no-leakage
  logging audits, Hypothesis PBT, golden, performance, and
  end-to-end smoke). The two new slow-marked perf tests are
  in addition to the 4 from extraction + baseline-persistence.
- **`mypy --strict loki tests scripts`**: 0 issues across **176
  source files** (was 167 pre-Wave-7; +9 from new test
  modules).
- **`ruff check`**: clean repo-wide.
- **`ruff format --check`**: clean (176 files already formatted).
- **Slow performance tests**: both pass locally — R11.1
  (4096 components × 1024 rules under 30s, actual ~3s) and
  R11.3 (4096 components × 256 MiB total under 60s, actual
  ~3s). Run with
  `pytest -m slow tests/classification/test_performance.py`.
- **Offscreen GUI smoke run**:
  `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`
  is clean.
- **Public API smoke**: ``from loki.classification import
  classify_components, ClassificationResult, ProgressEvent,
  ProgressCallback, CancellationToken`` works.

## WHAT'S NEXT — execute Wave 8 of `classification-pipeline/tasks.md`

Waves 1-7 are complete. **Only Wave 8 remains** — two tasks:

- **Task 24.** Update `README.md`: flip the classification
  status table entry to `DONE`, add a `## Classification
  pipeline` section between Baseline persistence and
  Development describing the public entry point + R5.6
  dual-record contract + determinism caveats, update the
  Repository layout tree, update Verification at the
  current checkpoint with 897/176, update Next moves to
  drop classification.
- **Task 25.** Final verification gate: pytest, mypy, ruff,
  format, slow perf tests once locally, offscreen GUI smoke.
  Document final test counts in the README.

After Wave 8, the classification spec is fully closed out.

(Wave 7 entry truncated for brevity — see the live `HANDOFF.md`
in commit-equivalent state at the end of Wave 7 for the full
"Wave 7 notes", "Design judgment calls", "Carry-forward
constraints", "Test infrastructure", "Things that might trip the
new agent", "Repository layout", "Recovery note", "Files to read
first", "User preferences", and "Ready for next session"
sections. The Wave 8 handoff that supersedes this one carries
the live versions of all those subsections going forward.)

---

**End of Wave 7 handoff.**

---

# CONTEXT TRANSFER: Loki — classification spec mid-flight

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Projects/loki/`. The project has three
shipped subsystems (model layer, extraction pipeline, baseline
persistence) plus a fourth (classification pipeline) **mid-spec**:
its `requirements.md` is drafted and analyzed, but `design.md` and
`tasks.md` aren't started yet.

There is **no in-progress code work**. All four verification gates
are green. The next session can either advance the classification
spec to the design phase, or pick up one of the smaller follow-ups
documented below.

## STATUS — what's shipped

Three subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models, 14 StrEnums, eight
  modules. Strict validation on construction, lossless JSON / YAML
  round-trip. Spec at `.kiro/specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. v1 covers Intel
  Flash Descriptor (full-flash) images, UEFI PI firmware volumes,
  raw FFS blobs, UEFI capsules, PCI option ROMs, Intel CPU
  microcode update blobs. **UEFI volume decompression and
  inner-component emission**: compressed sections (Tiano +
  LZMA-Custom GUID-defined) are decompressed via `uefi_firmware`,
  the resulting payload is walked for inner UEFI PI sections, and
  each inner section becomes its own `ExtractedComponent` with a
  synthetic `source_image_id` derived from the decompressed
  payload's hash. R5.8 holds: failed decompression records a typed
  error and the outer component still carries `raw_hash` over the
  on-disk compressed bytes. Spec at
  `.kiro/specs/extraction-pipeline/`. **All 28 tasks ticked off in
  `tasks.md`**.
- **`loki/baseline/`** — GLEIPNIR persistence layer. YAML-on-disk,
  one human-readable file per baseline, atomic writes, mtime/size
  concurrency check, typed exception hierarchy, `loki baseline
  list/show/import/export/delete` CLI surface, GUI integration with
  background-thread loading **plus per-file progress and
  cancellation** (R2.8-R2.10, R7.10-R7.11). Spec at
  `.kiro/specs/baseline-persistence/`. **All 22 tasks ticked off in
  `tasks.md`**.

A fourth subsystem is mid-spec:

- **`loki/classification/`** — classification pipeline. Turns
  `ExtractedComponent` records into validated `ClassificationRecord`
  instances along the four taxonomic axes. Spec at
  `.kiro/specs/classification-pipeline/`. **`requirements.md`
  drafted, design and tasks not yet started.** No implementation
  code exists.

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` | DONE — `.kiro/specs/loki-data-models/` | DONE |
| `loki/gui/` | None — handoff plan | DONE (scope B + GLEIPNIR + threaded extraction + threaded baseline load with progress/cancel) |
| `loki/cli.py` | Spec dir empty | `loki gui`, `loki extract --progress`, `loki baseline list/show/import/export/delete` |
| Extraction pipeline | DONE — `.kiro/specs/extraction-pipeline/` | DONE — all 28 tasks ticked, plus UEFI decompression + inner-component emission |
| Baseline management (GLEIPNIR) | DONE — `.kiro/specs/baseline-persistence/` | DONE — all 22 tasks ticked, plus optional progress/cancel callbacks (R2.8-R2.10, R7.10-R7.11) |
| **Classification pipeline** | **REQUIREMENTS DRAFTED** — design phase next | Not started |
| Analysis engine | Not specced | Not started |
| Feeds (NVD, implant rules) | Not specced | Not started |
| Fleet analysis | Models exist | Engine not started |

## VERIFICATION (current checkpoint)

- **`pytest -q`**: **566 passed, 4 deselected** (slow-marked perf
  tests: 2 from extraction at 1024-binary scale, 2 from
  baseline-persistence at 128/1024 baseline scale).
- **`mypy --strict loki tests scripts`**: 0 issues across **132
  source files**.
- **`ruff check`**: clean repo-wide.
- **`ruff format --check`**: clean (132 files already formatted).
- **Offscreen GUI smoke run**:
  `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`
  is clean.
- **Slow performance tests** pass when run explicitly:
  `pytest -m slow tests/baseline/test_performance.py` finishes in
  ~3 minutes; `pytest -m slow tests/extraction/test_performance.py`
  finishes in seconds.

## WHAT'S NEXT — the natural follow-up

The classification spec is **mid-flight**. Requirements are drafted
(13 EARS requirements, all C1-C11 analyze-pass concerns closed) and
the next phase is `design.md` followed by `tasks.md`. The
`spec-mode` UI panel exposes "Generate Tech Design" and "Generate
Task List" buttons that hand off to the design and tasks subagents
respectively.

Per the user's preference: **continue the classification spec in a
fresh single-purpose conversation rather than blending it with
implementation work**. The drafting subagent does interactive Q&A
with the user one design decision at a time — that pattern doesn't
work well alongside other implementation activity.

What's resolved in `requirements.md`:

- **Rule format**: YAML files under `ClassificationConfig.rules_path`,
  one rule per `Rule` entry with `rule_id` / `axis` / `matcher` /
  `effect`. Conjunctive matchers over `{guid, name,
  component_type_hint, size, raw_hash}`. No regex, no DSL.
- **Inference pipeline**: independent per-axis classification, no
  cross-axis influence in v1.
- **Signature handling**: presence detection only (no verification).
  `SignatureInfo.verified` and `signer` always `False`/`None` in v1.
  Recognizes PE32 Authenticode + UEFI EFI_FIRMWARE_IMAGE_AUTHENTICATION
  at minimum.
- **CVE matching**: out of scope. `cve_matches` always `[]` in v1.
- **Confidence aggregation**: max-confidence rule wins per axis,
  lexicographic `rule_id` tie-break. Defers `composite_confidence
  = min(...)` and `needs_review` to the model layer.
- **No-rule-fires fallback**: `UNKNOWN` enum value at confidence
  `0.0`, method `HEURISTIC`, `rule_id = None`, `evidence = None`.
- **Determinism contract**: same input + same rule set → same
  records modulo timestamp. Mirrors extraction R7.
- **Inner components**: in scope, treated identically to outer
  components.
- **API surface**: `from loki.classification import classify_components`
  returning `ClassificationResult` with separate `records` and
  `errors` lists. The missing-bytes signature-detection case is the
  only contracted v1 case where a single component appears in both
  lists.
- **`ClassificationConfig.confidence_threshold`**: explicitly NOT
  consumed in v1 (R4.10). Reserved for the future analysis engine's
  review-flag policy.

What's NOT in `requirements.md` and stays open for the design phase:

- **Module layout** under `loki/classification/`. The
  `extraction-pipeline/design.md` and `baseline-persistence/design.md`
  are reasonable templates but the user gets to drive the call.
- **Internal data model** (e.g. `Rule`, `Matcher`, `Effect`
  dataclasses inside the classification subsystem). Requirements
  describe the YAML schema, not the in-memory shapes.
- **Property numbering**: classification properties continue from
  **33** per platform convention. Counts and exact statements are
  design-phase work.
- **Deferred N2 / N3 polish**: pass-2 analyze identified two minor
  style items in `requirements.md` (forward-reference to a not-yet-
  existing test in R3.4, blockquote vs. numbered criterion in R6).
  Both are pure style — fine to defer to the design phase or skip.

## SMALLER FOLLOW-UPS — independent, none blocking

The user may want to land any of these before resuming the
classification spec, or never. None are blocking.

1. **Foreign-file cleanup CLI.** `loki/baseline/` quarantines
   `*.yaml.tmp` leftovers from interrupted Atomic_Write attempts;
   the GLEIPNIR design's deferred-decisions §3 calls out a future
   `loki baseline clean` subcommand. Small but touches the CLI spec.
2. **Schema migration tool.** GLEIPNIR R4.5 forbids auto-upgrade
   across schema versions. v1 supports exactly one Schema_Version
   (1.0.0) and quarantines anything else. A future
   `baseline-schema-migration` spec defines `loki baseline migrate`.
   Out of scope for v1; opening that spec is its own
   single-purpose conversation.
3. **Demo data variety.** Add additional synthetic workspaces so
   UI work can iterate against more scenarios (clean image,
   compromised image, fleet-level rollups). Useful for screenshots
   and walkthroughs.
4. **Native packaging.** `.app` bundle, code-signing, and
   notarization. Deferred until the rest of the platform is
   feature-complete.

## DESIGN DECISIONS WORTH KNOWING

These were decided explicitly across the platform's prior sessions
and are now baked into the code. A new agent should not reopen them
without reason.

### Inner-component emission (extraction-pipeline)

- **Inner-component offsets** are real positions in the decompressed
  buffer (e.g. `0x0`, `0x28`), not synthetic encodings.
- **`derive_component_id` is reused** with `source_image_hash` set
  to the SHA-256 of the parent's decompressed payload. Inner
  components get a stable triple `(decompressed_hash, offset,
  raw_hash)` that can't collide with outer-component IDs.
- **Decompressed bytes write to disk** when `--output-dir` is set,
  with filename
  `0x{parent_offset:x}-decompressed-0x{inner_offset:x}-{inner_raw_hash}.bin`.
- **`source_image_id` on inner components** is
  `uuid5(LOKI_NAMESPACE, decompressed_hash)` — same derivation
  pattern as `FirmwareImage.image_id`, but with the decompressed
  hash. No model-layer change required.
- **Section walk only**, no recursive format detection. UEFI PI
  sections (PE32, RAW, UI, etc.) are the realistic case; recursive
  FFS or capsule walks of the decompressed payload are out of scope
  until a fixture demands them.

### GLEIPNIR optional progress + cancel callbacks (R2.8-R2.10, R7.10-R7.11)

- **`BaselineStore.load(progress=None, cancel=None)`** — keyword-only,
  both default `None`. Backward-compatible: every existing call site
  works unchanged.
- **Per-file progress** via `LoadProgressCallback =
  Callable[[LoadProgressEvent], None]`. The event carries the
  candidate file path, 1-based index, and the static total. Files
  filtered out by the Discovery_Scan extension check (R1.4) do not
  produce events.
- **Cooperative cancellation** via `CancellationToken =
  Callable[[], bool]`. Polled before each file's progress event;
  returning `True` stops the loop and returns the partial
  `LoadResult` accumulated so far. R2.10 guarantees that omitting
  both callbacks produces a `LoadResult` byte-equal under
  `model_dump(mode="json")` to a stub-callback load.
- **GUI surface**: `BaselineLoadWorker` emits each event on a `progress`
  Qt signal and exposes `request_cancel()` / `is_cancel_requested()`
  backed by a `threading.Event`. `MainWindow` shows
  `"Loading baselines… {index}/{total} ({basename})"` in the status
  bar (R7.10) and exposes **View → Cancel Baseline Load** (R7.11).
  `closeEvent` calls `request_cancel()` before the worker join so
  window close doesn't block on a slow load.

### R8.7 (save-time storage-unwritable error)

`BaselineStore.save` correctly converts `OSError` /
`PermissionError` during the atomic-write sequence into
`BaselineStorageUnwritableError` per R8.7's contract.

### R9.1 budget revision (baseline-persistence)

Original spec said "load < 5s for 1024 × 256 baselines." Profiling
showed PyYAML parse cost dominates at scale. Production envelope
(de)serializer uses libyaml's `CSafeLoader` / `CSafeDumper` when
available (~7x faster). With that, 1024 × 256 takes ~117s on a
2024-class developer laptop. Revised R9.1 budgets to
`< 30s for 128 × 256` and `< 180s for 1024 × 256` — both with
measured ~60% headroom.

### `background_load=False` on `MainWindow` for tests

Production callers get the threaded baseline-load path by default.
Tests pass `background_load=False` to skip the worker and run the
load on the constructor thread, so existing test patterns
(`window_factory(store)` then `_navigation_labels(...)` immediately
afterward) keep working without `qtbot.waitUntil` rewrites.

### CLI `--progress` is opt-in (extraction)

`loki extract --progress` writes one line per `ProgressEvent` to
stderr in the form `[phase] index/estimated message`. Off by
default. The manifest JSON on stdout is unchanged regardless,
which means callers piping into `jq` aren't affected.

### Optional tool wrappers (`UefitoolWrapper`, `ChipsecWrapper`)

These are **scaffolding mandated by R4.4**, not dead code. v1
probes both for availability and surfaces them in
`ExtractionResult.tools_available`, but no v1 extractor routes
work through either binary. Future extractors that need
`UEFIExtract` or `chipsec_util` will consume them via
`SubprocessToolWrapper.run_subprocess`. Don't remove these.

## CARRY-FORWARD CONSTRAINTS

- **Python 3.12** baseline. No `backports.strenum` fallback.
- **`mypy --strict`** is the bar. Every test file uses real type
  hints. If a fixture would otherwise be `Any`-typed, write a
  small typed helper rather than reaching for generic dicts. The
  current canonical scope is `loki tests scripts` — `scripts/` is
  included since `smoke_gui.py` is a documented gate.
- **`ruff check` + `ruff format`** must be clean repo-wide before
  any checkpoint. The `RUF002` ambiguous-character lint catches
  `×` (multiplication sign) and `–` (en dash) in comments and
  docstrings — replace with ASCII `x` and `-`.
- **No git commits.** User commits when ready.
- **Property numbering is sequential across the platform.**
  Model layer owns 1-11, extraction owns 12-22, baseline-persistence
  owns 23-32. **Classification properties continue from 33** (not
  yet locked — the design phase will assign them).
- **Honest about state.** Demo data stays clearly labeled `(demo)`.
  Real-loaded baselines label as `{vendor} {model}
  {firmware_version}`. Quarantined baselines surface with their
  reason. The Analysis tab in the GUI is still scaffold pending
  its own subsystem.
- **Loki only.** Razor-Rooster at
  `/Users/daborond/Sloptropy/razorrooster/` is unrelated and out of
  scope for any loki session.
- **Stick to the spec when one exists; deviate only with explicit
  user OK.** When no spec exists for a subsystem, draft one in a
  fresh single-purpose conversation rather than inventing the
  contract on the fly.

## TEST INFRASTRUCTURE WORTH KNOWING

- **`pytest-timeout` is installed.** Use `--timeout=30
  --timeout-method=signal` on any GUI test invocation. A missed
  `QMessageBox` monkeypatch under `QT_QPA_PLATFORM=offscreen`
  blocks silently for hours; the timeout is the safety net.
- **`tests/gui/test_baseline_actions.py`** has an autouse
  `no_blocking_dialogs` fixture that stubs every `QMessageBox`
  static method. Tests that want to assert on a specific dialog
  override the stub via their own `monkeypatch.setattr`. Pattern is
  worth replicating in any future GUI test file.
- **`pytest-qt`'s `qtbot.waitUntil`** is the right tool for tests
  that exercise the threaded baseline-load worker. See
  `tests/gui/test_baseline_load_worker.py` for the pattern,
  including the new progress/cancel tests.
- **Hypothesis settings.** Persistence-layer PBT uses
  `max_examples=25` because each example saves and reads a YAML
  file (~5ms per example). Model layer uses `max_examples=50`. Both
  set `suppress_health_check=[HealthCheck.too_slow]`.
- **CSafeLoader/CSafeDumper auto-detection.**
  `loki/baseline/envelope.py` resolves the loader/dumper at module
  import via `getattr(yaml, "CSafeLoader", yaml.SafeLoader)` so the
  pure-Python fallback is automatic when libyaml isn't available.
  Output is byte-identical to the safe_dump path; the golden-file
  regression test verifies this.

## THINGS THAT MIGHT TRIP THE NEW AGENT

- **`yaml.safe_load` decodes timestamps as `datetime` objects, not
  strings.** The envelope deserializer accepts both because test
  paths use ISO strings (faster fixture build) but real files
  round-trip through `datetime`.
- **`BaselineRecord.model_validate(payload, strict=False)`** is the
  right call from disk-loaded payloads. `strict=True` rejects ISO
  datetime strings; `strict=False` lets Pydantic coerce them.
- **`BaselineRecord.source_image_hash` is a real field**, not a
  fictional one. It's a 64-char SHA-256 hex string and it lives on
  the persisted record. Logging it is forbidden by the
  classification spec's Forbidden_Leakage_Field_Set.
- **`ClassificationRecord` doesn't have a `raw_hash` field.**
  Confused with `ExtractedComponent`. The forbidden-leakage fields
  for classification are `component_id`,
  `signature_info.signer`, the parent
  `BaselineRecord.source_image_hash`, and per-axis
  `AxisClassification.evidence` strings.
- **Inner components have offsets within the decompressed buffer**,
  not within the source firmware binary. Code that wants to
  re-read inner-component bytes from disk needs the parent
  component's `raw_path` plus knowledge of the decompression step.
  The `decompressed_payload` field on `CarvedComponent` is
  per-extraction-run and not persisted.
- **The temp-filename pattern uses `os.getpid()` with a counter**
  in `loki/baseline/store.py`. Tests should never assume specific
  suffixes; verify temp-file cleanup by globbing `*.tmp`.
- **`pytest.MonkeyPatch` doesn't reach into
  `loki.baseline.store.datetime` via attribute setting.** Use
  `patch("loki.baseline.store.datetime", _FrozenDatetime)` with a
  subclass that overrides `now()`.
- **Don't break the `tests/extraction/test_no_side_channels.py`
  audit.** It walks `loki/extraction/` for forbidden imports and
  `time.now()` / `time.monotonic()` calls outside the timing
  module. Same audit pattern in
  `tests/baseline/test_no_side_channels.py` for `loki/baseline/`.
  The classification spec's R8.5 commits to mirroring this audit.
- **`test_log_no_leakage.py` audits live at both
  `tests/extraction/` and `tests/baseline/`.** Any new logging in
  these subsystems must avoid the forbidden field set. The
  classification spec's R13.5/R13.6 commits to a similar audit
  when implementation lands.
- **The `BaselineLoadWorker.progress` Qt signal carries a
  `LoadProgressEvent` object**, not a string or tuple. Connect with
  `worker.progress.connect(handler)` where `handler(event: object)`
  type-narrows via `isinstance(event, LoadProgressEvent)` — Qt's
  queued-connection serializer types the slot argument as `object`.

## REPOSITORY LAYOUT (current)

```
loki/
├── README.md
├── HANDOFF.md                       # this doc
├── HANDOFF.archive.md               # prior handoffs
├── pyproject.toml
├── .kiro/
│   └── specs/
│       ├── loki-data-models/        # DONE
│       ├── extraction-pipeline/     # DONE — 28/28 tasks ticked
│       ├── baseline-persistence/    # DONE — 22/22 tasks ticked
│       │                            # plus R2.8-R2.10, R7.10-R7.11 callbacks
│       └── classification-pipeline/ # IN PROGRESS — requirements only
│           └── requirements.md      # 13 EARS requirements, analyze-pass closed
├── loki/
│   ├── cli.py                       # gui / extract (--progress) / baseline
│   ├── models/                      # 8 modules, Pydantic v2
│   ├── extraction/                  # extraction pipeline
│   │   ├── api.py                   # extract_firmware()
│   │   ├── inner_carve.py           # walks decompressed payloads
│   │   ├── manifest.py              # ManifestBuilder + add_inner_component
│   │   ├── extractors/
│   │   │   ├── uefi_volume.py       # decompresses Tiano + LZMA-Custom sections
│   │   │   └── ...
│   │   └── tools/
│   │       ├── uefi_firmware.py     # required; decompress_tiano/lzma
│   │       ├── uefitool.py          # optional, probe-only in v1
│   │       └── chipsec.py           # optional, probe-only in v1
│   ├── baseline/                    # GLEIPNIR persistence
│   │   ├── store.py                 # load/save/delete/load_one/export
│   │   │                            # load now takes progress + cancel kwargs
│   │   ├── envelope.py              # CSafeLoader/CSafeDumper-backed
│   │   └── ...                      # 8 modules total
│   └── gui/
│       ├── app.py                   # QApplication entry
│       ├── main_window.py           # background_load flag, cancel action
│       ├── extraction_worker.py     # QThread for extraction
│       ├── baseline_load_worker.py  # QThread + progress signal + request_cancel
│       ├── actions/                 # File→Open, View→Extract,
│       │                            # View→Open Baseline, View→Save Baseline,
│       │                            # View→Cancel Baseline Load
│       └── ...
└── tests/
    ├── conftest.py                  # Hypothesis strategies
    ├── test_smoke.py
    ├── test_property_invariants.py
    ├── test_property_round_trip.py
    ├── test_cli_extract.py          # includes --progress tests
    ├── test_cli_baseline.py
    ├── extraction/                  # extraction subsystem tests
    │   ├── test_inner_carve.py
    │   └── ...
    ├── baseline/                    # baseline-persistence tests
    │   ├── test_store_load_callbacks.py # progress + cancel coverage
    │   └── ...
    └── gui/
        ├── test_baseline_load_worker.py # threaded worker + progress + cancel
        └── ...
```

## FILES TO READ FIRST (for any continuation work)

- `README.md` — project overview, quick start, layout. Up to date
  as of this handoff: status table reflects 542→566 test count, the
  GUI section documents threaded extraction + threaded baseline
  load, "Next moves" lists Classification → Analysis → GUI per-file
  progress (now redundant — shipped) → Cancellation hook (also now
  redundant — shipped). The README's "Next moves" 3 and 4 can be
  dropped or replaced; doc-only follow-up.
- `HANDOFF.archive.md` — prior handoffs across the project's
  history.
- `.kiro/specs/classification-pipeline/requirements.md` — the most
  recently drafted spec. 13 EARS requirements. Eleven design
  decisions resolved interactively with the user. Pass-2 analyze
  closed every blocker concern; only N2 / N3 minor style items
  remain.
- `.kiro/specs/baseline-persistence/` — most-recently-completed
  spec, including the new R2.8-R2.10 + R7.10-R7.11 acceptance
  criteria for the optional progress + cancel callbacks. Useful as
  a structural template for `classification-pipeline/design.md`.
- `.kiro/specs/extraction-pipeline/` — the other complete spec.
  `design.md` is now consistent with the shipped inner-component
  emission code.
- `loki/models/classification.py` and `loki/models/enums.py` — the
  model layer the future classification pipeline implementation
  will produce records for. The four axis enums
  (`ComponentTypeLabel`, `VendorLabel`, `SecurityPostureLabel`,
  `MutabilityLabel`) all have `UNKNOWN` members per the v1
  no-rule-fires fallback.
- `loki/models/config.py` — `ClassificationConfig` is already
  defined (`taxonomy_version`, `confidence_threshold`,
  `rules_path`). The classification spec inherits these as the
  configuration surface; v1 explicitly does not consume
  `confidence_threshold` (R4.10).

## USER PREFERENCES (carry forward)

- **No git commits.** User commits when ready.
- **Loki workspace only.** Don't reference razor-rooster.
- **Stick to the spec when one exists; deviate only with explicit
  OK.** For unspecced subsystems, draft a spec first.
- **Spec drafting is its own conversation.** The classification
  requirements were drafted in this session via interactive Q&A;
  design and tasks should likewise happen as fresh single-purpose
  conversations rather than blended with implementation work.
- **After each round of work, summarize what's done, what's tested,
  what's next, and offer 3-4 candidate next moves.** This is the
  user's expected cadence.
- **Honest framing.** Don't claim work is done if it isn't. Don't
  paper over spec deviations; surface them and confirm.
- **Pause and ask** when the work scope is ambiguous, when a spec
  decision is needed, or when an approach has failed twice. The
  user explicitly prefers the conversation overhead over the cost
  of building the wrong thing.

## READY FOR NEXT SESSION

The codebase is at a clean checkpoint. The next session can either:

- **Advance the classification spec to design phase.** Click
  "Generate Tech Design" in the spec-mode UI, or open a fresh
  conversation that hands off to the design subagent. The user
  drives architecture decisions one at a time; produce
  `design.md` with module layout, internal data model, correctness
  properties (numbered from 33), traceability matrix, and load /
  classify flow diagrams. Implementation happens in **separate**
  sessions after the spec is approved.
- **Tackle one of the smaller follow-ups.** Foreign-file cleanup
  CLI, schema migration tool, demo data variety, native packaging.
  None are blocking; pick based on user priorities.
- **Apply the deferred N2 / N3 polish** in
  `classification-pipeline/requirements.md`. R3.4 has a forward
  reference to a not-yet-existing test, and R6 has 2 numbered
  criteria + a markdown blockquote note instead of pure numbered
  list. Both are pure style.
- **Refresh the README's "Next moves" list.** Items 3 (GUI per-file
  progress) and 4 (cancellation hook) are now shipped; the README
  still lists them as deferred. Doc-only.
- **Pick something the user surfaces that isn't on this list.** The
  honest framing is that everything tracked is in good shape.

Whichever direction the next session goes, the rules above stand:
test counts shouldn't regress, all four gates stay green, no git
commits, loki only.

---

**End of handoff.**

# CONTEXT TRANSFER: Loki — baseline-persistence implementation in progress

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has everything it needs to pick up at Task 12
> and walk through Tasks 12–22 without further input.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Projects/loki/`. The platform's first three
subsystems are complete and the fourth (baseline persistence,
codename GLEIPNIR) is half-implemented.

## TASK 1: baseline-persistence — IN PROGRESS

- **SHORT DESCRIPTION**: GLEIPNIR. Persist `BaselineRecord` and
  `BaselineRegistry` instances to a YAML directory layout on disk.
  Add a `loki baseline list/show/import/export/delete` CLI surface
  and wire the GUI's Baselines navigation group to a real
  `BaselineStore` instead of the demo-data placeholder.
- **STATUS**: 11 of 22 tasks done. Foundations + load + save work
  end-to-end. Remaining: single-file load, delete, the cross-cutting
  test layer (PBT / audits / golden file / perf), CLI, GUI, docs,
  final gate.

## DECISIONS LOCKED (from the spec)

The full spec lives at `.kiro/specs/baseline-persistence/`. Three
documents, all clean (`getDiagnostics` reports zero issues for each):

- `requirements.md` — 10 requirements, 75 EARS-formatted acceptance
  criteria.
- `design.md` — 11 sections including a traceability matrix that
  maps every requirement to a design section.
- `tasks.md` — 22 tasks organized into 9 dependency waves.

Key decisions baked into the spec, repeated here for context:

- **One YAML file per baseline.** Filename is
  `{slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml`.
  Collision resolution appends `-{8 hex chars of baseline_id}`.
- **No lock files.** Concurrency safety is via `Atomic_Write` plus
  an mtime/size check; lost races raise
  `BaselineConcurrentModificationError`. Documented R5.5 explicitly
  rejects lock files.
- **Schema_Version is distinct from `baseline_version`.** v1 ships
  exactly one Schema_Version (`"1.0.0"`). Files at other versions
  get quarantined; no auto-upgrade. Migration tool is a future spec.
- **Discovery_Scan loads every `*.yaml` in the directory at depth 1.**
  Subdirectories and non-`.yaml` files are ignored entirely. Foreign
  files are never deleted.
- **Atomic_Write protocol.** Temp file with monotonic-counter +
  pid suffix → fsync → mtime/size check → `os.replace`. Failure
  before replace cleans the temp file and leaves the destination
  untouched.
- **Round-trip validation runs before any disk write.** A malformed
  `BaselineRecord` raises `BaselineSerializationError` before
  anything touches the filesystem.
- **`force=True` skips both the existence check AND the mtime check.**
  Used by the GUI's "overwrite" confirmation dialog. Documented as
  fairly destructive (no automatic backup).
- **Properties 23-32** continue the numbering from extraction's
  12-22 and the model layer's 1-11. The persistence-specific
  properties live in `design.md`.

## TASKS COMPLETED

| Task | Module | New tests |
|------|--------|----------|
| 1 | `loki/baseline/` skeleton | (smoke) |
| 2 | `errors.py` — typed exception hierarchy | 8 |
| 3 | `schema.py` — `SCHEMA_VERSION` + `SUPPORTED_SCHEMA_VERSIONS` | 6 |
| 4 | `naming.py` — `slug()`, `filename_for()`, `unique_filename_for()` | 15 (incl. 2 PBT) |
| 5 | `quarantine.py` — `QuarantineEntry`, `QuarantineSet` | 8 |
| 6 | `concurrency.py` — `FileSnapshot`, `snapshot()`, `check_unchanged()` | 7 |
| 7 | `envelope.py` — YAML envelope (de)serialization | 13 |
| 8 | `tests/baseline/fixtures/synthetic_baseline.py` — deterministic builder | 7 |
| 9 | `BaselineStore.__init__` + `LoadResult` + `storage_path`/`schema_version` properties | 8 |
| 10 | `BaselineStore.load` — Discovery_Scan + validation | 17 |
| 11 | `BaselineStore.save` — Atomic_Write + concurrency check | 14 |

103 baseline-persistence tests so far. Combined with the rest of
the platform: **386 tests passing** (model layer + extraction +
GUI + CLI + baseline), 2 slow performance tests deselected by
default.

## CURRENT STATE — verified

- **`pytest`** clean (386 passed, 2 deselected)
- **`mypy --strict`** clean across 113 source files
- **`ruff check`** clean
- **`ruff format --check`** clean
- **Offscreen GUI smoke run** clean
  (`QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`)

## TASKS REMAINING (in dependency order)

### Wave 6 — single-file helpers + extra edge tests

- **Task 12.** Implement `BaselineStore.load_one(path)` (raises
  typed errors instead of quarantining; used by the GUI's "Open
  Baseline Registry…" action and the CLI's `import` subcommand) and
  `BaselineStore.delete(baseline_id)` (removes file + clears the
  in-memory snapshot). Tests in `tests/baseline/test_store_singletons.py`.
- **Task 13.** Round out concurrency tests in
  `tests/baseline/test_store_concurrency.py` (two store instances
  against the same directory; second save raises after the first's
  mtime moved). Round out error tests in
  `tests/baseline/test_store_errors.py` (unwritable storage path,
  malformed UTF-8, empty file).

### Wave 7 — cross-cutting test suite

These are independent and can be tackled in any order or in
parallel.

- **Task 14.** Hypothesis property tests for Properties 23-26 in
  `tests/baseline/test_determinism.py` (save → load round-trip;
  byte-deterministic save modulo `written_at`; load → save → load
  preserves the baseline payload) and Property 23 in
  `tests/baseline/test_manifest_invariants.py` (every loaded
  record passes Pydantic re-validation).
- **Task 15.** Static AST audit in
  `tests/baseline/test_no_side_channels.py` (mirror of
  `tests/extraction/test_no_side_channels.py`). Walk
  `loki.baseline.__path__` and fail on forbidden imports
  (`os.environ`, `random`, `secrets`, `socket`, `urllib`,
  `requests`, `httpx`) and `time.time()`/`time.monotonic()` calls
  outside `store.py`. The persistence subsystem doesn't have a
  dedicated `timing.py`; clock access is restricted to
  `datetime.now(tz=UTC)` in `store.py` and `time.monotonic()` for
  the duration counter (already in place).
- **Task 16.** No-leakage logging audit in
  `tests/baseline/test_log_no_leakage.py`. Mirror of
  `tests/extraction/test_log_no_leakage.py`. Capture every record
  emitted on the `loki.baseline` logger during a curated load +
  save and assert no record's formatted message contains the test
  fixture's `source_image_hash`, any classification record's
  identifying fields beyond what's in the Baseline_Identifier, or
  the `notes` string.
- **Task 17.** Golden-file regression in
  `tests/baseline/test_golden.py`. Build a deterministic baseline
  via the synthetic fixture, save it, copy the resulting file to
  `tests/baseline/fixtures/golden/canonical_v1.yaml`, snapshot the
  re-loaded payload (timestamp-stripped) to
  `tests/baseline/fixtures/golden/canonical_v1.json`. Document
  regeneration in `tests/baseline/fixtures/README.md`.
- **Task 20.** Performance smoke test in
  `tests/baseline/test_performance.py` (mark `slow`, skipped on
  CI by default). Build 1024 synthetic baselines × 256
  classifications, save them all, load the directory. Assert
  load duration < 5 s and registry has 1024 entries (R9.1).

### Wave 8 — surface integration

- **Task 18.** Add `loki baseline list/show/import/export/delete`
  to `loki/cli.py`. Tests in `tests/test_cli_baseline.py`. Each
  subcommand mirrors `loki extract`'s error-handling pattern:
  typed errors → clean stderr + non-zero exit code, no Python
  traceback. The `--storage-path` flag is mandatory for tests.
- **Task 19.** Wire the GUI's Baselines navigation group to the
  real `BaselineStore`. New action modules
  `loki/gui/actions/open_baseline.py` and `save_baseline.py`.
  `MainWindow.__init__` constructs the store from a fallback
  `BaselineConfig`, runs `store.load()` synchronously on the main
  thread (deferred decision §2: backgrounding is a future
  enhancement), populates the navigation group from the loaded
  registry, shows a `QMessageBox.information` if quarantine is
  non-empty. **View → Open Baseline Registry…** uses
  `store.load_one`. **View → Save Baseline…** uses `store.save`
  with overwrite-confirmation and concurrent-modification
  dialogs. Tests in `tests/gui/test_baseline_actions.py`.

### Wave 9 — docs + gate

- **Task 21.** README updates: Status table, new
  `## Baseline persistence (GLEIPNIR)` section, repository layout
  tree, verification checkpoint, next-moves list.
- **Task 22.** Final verification gate: full pytest, mypy, ruff,
  format checks. Run the slow performance test once locally. Run
  the offscreen GUI smoke check. Document final test counts in
  the README.

## KEY CONSTRAINTS (carry-forward from prior sessions)

- **Python 3.12** baseline. The model layer dropped the
  `backports.strenum` fallback already.
- **`mypy --strict`** is the bar. Every test file uses real type
  hints; if a fixture would otherwise be `Any`-typed, write a tiny
  helper function rather than a generic dict spread.
- **`ruff check` + `ruff format`** must be clean before any
  checkpoint. The `RUF002` ambiguous-character lint catches
  `×` (multiplication sign) and `–` (en dash) in comments and
  docstrings — replace with ASCII `x` and `-`.
- **No git commits.** User commits when ready.
- **Property numbering is sequential across the platform.** Model
  layer owns 1-11, extraction owns 12-22, baseline-persistence
  owns 23-32. New properties continue from 33.
- **Honest about state.** Demo data stays clearly labeled
  `(demo)`. Quarantined baselines surface with their reason. The
  GUI's Baselines tab labels real-load entries differently from
  demo entries.

## ARCHITECTURAL NOTES WORTH KNOWING

- **`BaselineStore.save` uses a process-counter for temp-file
  suffixes**, not the random module. `_next_temp_suffix()`
  combines `os.getpid()` with a monotonic per-process counter
  for visibly-distinct names; correctness is guaranteed because
  each save owns its destination path. Property 32 (no random
  module) is satisfied.
- **Concurrency check runs between fsync and replace, not before.**
  Moving the check after the temp file is fully fsynced gives us a
  valid temp file to clean up if the check trips. The window
  between check and replace is nanoseconds wide; R5 explicitly
  acknowledges this is "last-writer-wins detection, not
  avoidance."
- **Round-trip validation in `save()` runs first.** A malformed
  `BaselineRecord` raises `BaselineSerializationError` before any
  I/O happens. This is what makes the load → save → load
  round-trip property test meaningful.
- **`_DEFAULT_WRITTEN_BY` is computed once at module import time**
  via `importlib.metadata.version('loki')`. Future LOKI version
  bumps automatically tag baseline files. Default is
  `"loki-0.1.0"` today.
- **`load_one` (Task 12) shares its parsing path with `load`** but
  raises typed errors instead of quarantining. The same per-file
  helper covers both modes; the distinction lives at the
  exception-handling layer.
- **GUI integration runs the load on the main thread.** Deferred
  decision §2 in the design. The R9.1 5-second budget for 1024 ×
  256 baselines is comfortable on local SSD; if this proves
  disruptive in practice, a future task adds a `BaselineLoadWorker`
  that mirrors the `ExtractionWorker`.

## THINGS THAT MIGHT TRIP THE NEW AGENT

- **`yaml.safe_load` decodes timestamps as `datetime` objects, not
  strings.** The envelope deserializer accepts both because the
  test path uses ISO strings (faster fixture build) but real
  files round-trip through `datetime`.
- **`BaselineRecord.model_validate(payload, strict=False)`** is the
  right call to make from disk-loaded payloads. `strict=True`
  rejects ISO datetime strings; `strict=False` lets Pydantic
  coerce them. The model layer's existing `LokiConfig.from_yaml`
  uses the same pattern.
- **`ClassificationRecord` doesn't have a `raw_hash` field.** I
  confused that with `ExtractedComponent` while writing the
  no-leakage tests; the right fields to check for in
  `test_log_no_leakage.py` are `component_id`, `signature_info.signer`,
  and the parent `BaselineRecord.source_image_hash` and `notes`.
- **The temp-filename pattern uses `os.getpid()` with a counter.**
  Tests should never assume specific suffixes. Verify temp files
  are gone after a save by globbing `*.tmp` and asserting empty.
- **`pytest.MonkeyPatch` doesn't reach into `loki.baseline.store.datetime`
  via attribute setting.** Use `patch("loki.baseline.store.datetime",
  _FrozenDatetime)` with a subclass that overrides `now()`.

## OUT OF SCOPE FOR THIS SUBSYSTEM

- **`BaselineComparison`** — deviation scoring, `DeviationRecord`
  generation. Downstream subsystem.
- **Classification pipeline** — production of
  `ClassificationRecord` instances inside
  `BaselineRecord.component_manifest`. Not yet specced.
- **Live extraction wiring.** Baselines reference firmware via
  `source_image_hash`, but turning an extraction manifest into a
  baseline requires classification first, which doesn't exist
  yet. Out of scope.
- **Inter-process locking.** No lock files in v1.
- **Schema migration.** Future `baseline-schema-migration` spec.
- **Multi-host synchronization.** Single-host only.

## FILES TO READ FIRST

- `.kiro/specs/baseline-persistence/requirements.md` — the
  approved requirements
- `.kiro/specs/baseline-persistence/design.md` — the approved
  design (especially the Components and Interfaces and
  Architecture sections)
- `.kiro/specs/baseline-persistence/tasks.md` — task breakdown
  with file references
- `loki/baseline/store.py` — the `BaselineStore` implementation as
  it stands at the end of Task 11
- `loki/baseline/envelope.py` — YAML envelope helpers
- `loki/baseline/errors.py` — typed exception hierarchy
- `tests/baseline/test_store_load.py` and
  `tests/baseline/test_store_save.py` — the 31 tests covering the
  load + save flows
- `tests/baseline/fixtures/synthetic_baseline.py` — deterministic
  builder used by every persistence test
- `tests/extraction/test_no_side_channels.py` — template for Task
  15 (the persistence equivalent has the same shape)
- `tests/extraction/test_log_no_leakage.py` — template for Task 16

## USER CORRECTIONS AND INSTRUCTIONS (carry forward)

- **Honest framing.** Persistence ≠ comparison. The GUI's Analysis
  tab is still scaffolding.
- **No git commits.** User commits when ready.
- **Stay in `/Users/daborond/Projects/loki/`.** Razor-Rooster at
  `/Users/daborond/Sloptropy/razorrooster/` is unrelated.
- **Stick to the spec when one exists; deviate only with explicit
  user OK.** The persistence spec is now complete.
- **After each round of work, summarize what's done, what's
  tested, what's next, and offer 3-4 candidate next moves.**

## READY TO START

The user has approved the spec and the partial implementation.
Pick up from Task 12 by reading the source files above, then walk
through Tasks 12-22 in dependency order. Pause for the user only
if you hit something genuinely ambiguous (e.g. a model-layer
issue, a Pydantic v2 version change that breaks
`model_validate(..., strict=False)`, or a real-world OS quirk
that the tests don't cover).

When the build is done and verified, the deliverables are:

- All 22 tasks checked off in `tasks.md`
- `loki/baseline/` complete (10 modules)
- `tests/baseline/` covering Properties 23-32 + R10.5 audit + R7.5
  static audit + golden-file regression + perf smoke
- `tests/test_cli_baseline.py` covering the 5 CLI subcommands
- `tests/gui/test_baseline_actions.py` covering the GUI actions
- README updated with the new section + Status table + repository
  layout + verification checkpoint
- All four checks (`pytest`, `mypy --strict`, `ruff check`,
  `ruff format --check`) clean

Then summarize and offer next moves. The natural follow-ups
are: classification pipeline (the biggest remaining subsystem),
decompression in the UEFI volume extractor (small polish on
extraction), or background-thread baseline loading in the GUI
(matches the extraction `QThread` work that already shipped).

---

**End of handoff.**

# CONTEXT TRANSFER: Loki Desktop App (PyQt6) — fresh build

> **How to use this doc.** Open a new agent / chat session and paste the
> entire contents below the horizontal rule as the first message. The
> receiving agent has everything it needs to start at Step 0 and walk
> straight through Steps 1–11 without further input.

---

You are continuing on the **Loki firmware analysis platform**, which lives at `/Users/daborond/Projects/loki/`. The user wants to build a desktop GUI for it. The Razor-Rooster work in the prior session is unrelated — do not touch it.

## TASK 1: Loki desktop app (PyQt6, scope B) — IN PROGRESS

- **SHORT DESCRIPTION**: First non-CLI surface for the Loki firmware analysis platform. PyQt6 desktop app with a main window, navigation pane, tabbed workspace, file-open flow that constructs `FirmwareImage` from a real binary, and a "Load Demo Data" action that populates the workspace with synthetic model instances so UI/UX work can iterate without an extraction pipeline.
- **STATUS**: not started
- **USER QUERIES**: "we need a gui" → "desktop app for loki, local read only web app for rooster" → "1. pyqt6. 2. b. 3.fastapi.4. razor roosterfirst"
- **DECISIONS LOCKED**:
  - **Framework: PyQt6** (chosen over Textual / Tauri). Rationale: firmware analysis benefits from tree views, hex dumps, file pickers, persistent windows. Real native widgets, ~150 MB install acceptable for desktop tool.
  - **Scope: Option B** — GUI scaffold + synthetic-data demo mode. Honest about Loki's current state (no extraction pipeline yet). Demo data clearly labeled "demo" so it never gets confused with real analysis.
  - **NOT scope C** — do not write a real firmware extraction pipeline. That's its own subsystem and warrants its own spec.
- **CURRENT LOKI STATE** (verified in the prior session):
  - Path: `/Users/daborond/Projects/loki/`
  - Package layout: `loki/` (pkg) → `loki/models/` (Pydantic v2 data layer, 8 modules, ~1100 lines, all working)
  - **2300 tests pass** (already shipped in the prior session): 9 smoke + 25 invariant + 30 round-trip property tests for the model layer, all tied to the 11 spec correctness properties
  - **mypy --strict clean** across 14 source files
  - **ruff check / ruff format clean**
  - `pyproject.toml` exists with dev extras (`pytest`, `hypothesis`, `mypy`, `ruff`, `types-PyYAML`)
  - `README.md` exists at the repo root (recently written, references "next moves" including CLI / extraction / etc.)
  - Spec dirs: `.kiro/specs/loki-data-models/` (filled), `.kiro/specs/cli/` (empty), `.kiro/specs/baseline/` (empty), `.kiro/specs/models/` (filled — overlaps with loki-data-models)
  - **Repo has zero git commits.** Everything is staged and uncommitted. Don't run `git commit` — the user explicitly said skip git in the prior session. They will commit when ready.

## Build plan (DO IN THIS ORDER)

### Step 0 — Read the existing state first

- `cat pyproject.toml` to confirm current deps (Pydantic 2.7+, pyyaml; dev: pytest, hypothesis, mypy, ruff, types-PyYAML)
- `cat README.md` to align README updates at the end
- `ls loki/models/` to confirm the model files
- `cat .kiro/specs/loki-data-models/design.md` only if you need to refresh the model field shapes

### Step 1 — Add PyQt6 to pyproject.toml

- Add `"pyqt6>=6.6"` to `[project.dependencies]`
- Run `.venv/bin/pip install -e ".[dev]"` to install
- Verify: `.venv/bin/python -c "from PyQt6.QtWidgets import QApplication; print('ok')"`

### Step 2 — Module structure

```
loki/
├── gui/
│   ├── __init__.py
│   ├── app.py              # main entry: QApplication, MainWindow construction
│   ├── main_window.py      # QMainWindow: menu bar, central widget, status bar
│   ├── navigation.py       # left QListWidget / QTreeWidget for navigation pane
│   ├── workspace.py        # central QTabWidget for opened items
│   ├── views/
│   │   ├── __init__.py
│   │   ├── firmware_image_view.py  # metadata table for one FirmwareImage
│   │   ├── extraction_view.py      # placeholder ("extraction not yet implemented")
│   │   ├── classification_view.py  # tree view of classification records
│   │   ├── baseline_view.py        # baselines + comparison summary
│   │   ├── analysis_view.py        # findings list + deviation scores
│   │   └── report_view.py          # ImageAnalysisReport summary panel
│   ├── actions/
│   │   ├── __init__.py
│   │   ├── open_firmware.py        # File → Open: pick file, hash it, build FirmwareImage
│   │   └── load_demo_data.py       # View → Load Demo Data: synthetic instances
│   └── demo/
│       ├── __init__.py
│       └── synthetic.py            # builds demo BaselineRegistry + classifications + findings + report
└── ...

loki/cli.py                  # NEW — top-level CLI with `loki gui` subcommand
```

### Step 3 — `pyproject.toml` adds a console script

- Add `[project.scripts]` table with `loki = "loki.cli:main"`
- The CLI just dispatches `loki gui` → `loki.gui.app.run()`. Click is fine, or argparse for now (no need for click yet — Loki has no other CLI surface)

### Step 4 — Build the main window

- `QMainWindow` with:
  - **Menu bar**: File (Open Firmware Image…, Quit), View (Load Demo Data, Reset Workspace), Help (About)
  - **Central widget**: `QSplitter` horizontal — left navigation pane, right tabbed workspace
  - **Status bar**: shows opened-file count, last-extraction time placeholder, classification version
  - **Window title**: "Loki — Firmware Analysis"
- Persistent geometry via `QSettings("LOKI", "Desktop")`

### Step 5 — Navigation pane

- `QTreeWidget` with top-level groups: Images, Baselines, Reports, Fleet
- Empty state: each group shows a placeholder "No <thing> loaded yet"
- Double-click on an item opens / focuses the corresponding tab in the workspace

### Step 6 — Workspace tabs

- `QTabWidget` with closable tabs (`setTabsClosable(True)`)
- One view class per item type. Each takes a Pydantic model instance as input and renders a read-only widget tree
- Views to start with: `FirmwareImageView`, `BaselineView`, `ImageAnalysisReportView`. The other three (extraction, classification, analysis) can be placeholder QLabel widgets for now — they're scope C territory

### Step 7 — File → Open Firmware Image

- `QFileDialog.getOpenFileName` → file path
- Compute SHA-256 (read in chunks, don't slurp the whole file)
- Construct `FirmwareImage(file_path=..., file_hash=..., file_size=...)` (the model auto-generates `image_id` via `uuid5`)
- Add to navigation pane under Images
- Open a `FirmwareImageView` tab showing metadata (file_path, image_id, file_hash, file_size, vendor=None, model=None, …)
- Show extraction placeholder: "Extraction pipeline not yet implemented; load demo data via View → Load Demo Data to preview the workflow."

### Step 8 — View → Load Demo Data

- `loki/gui/demo/synthetic.py` builds:
  - 2 synthetic `FirmwareImage` instances (different hashes)
  - 1 `BaselineRecord` with a `component_manifest` of 4-5 `ClassificationRecord` instances (one of each axis)
  - 1 `BaselineComparison` showing 1 ADDED, 1 MODIFIED, 1 UNCHANGED
  - 1 `ImageAnalysisReport` with 3 `FindingRecord` instances at varied `SeverityLevel`
- All instances valid Pydantic — exercise the validators
- The action populates navigation + opens one tab per item, each clearly labeled "(demo)" in the title

### Step 9 — Tests

- Use `pytest-qt` (add to dev extras)
- Test patterns:
  - `test_main_window_constructs(qtbot)` — assert window has menu bar + central splitter
  - `test_open_firmware_constructs_model(qtbot, tmp_path)` — write a fake binary, invoke open action, assert a `FirmwareImageView` tab appears
  - `test_demo_data_populates_workspace(qtbot)` — invoke action, assert 4 navigation entries
  - `test_workspace_tabs_closable(qtbot)` — open a tab, click close, assert it goes away
- Do NOT test full QApplication lifecycle — pytest-qt's `qtbot` fixture handles that

### Step 10 — Verification

- `pytest` clean
- `mypy --strict loki tests` clean (PyQt6 has stubs, but `pyqt6-stubs` may be needed)
- `ruff check / ruff format` clean
- Manual: launch `loki gui` and verify:
  - Window opens with empty navigation pane
  - File → Open Firmware Image lets you pick a file, populates Images group
  - View → Load Demo Data populates all four groups + opens tabs
  - Closing tabs works
  - About dialog shows the package version

### Step 11 — README update

- Add a "GUI" section showing `loki gui` invocation, screenshot caveat ("scaffold only; demo data labeled accordingly"), and a note about scope B

## Key constraints (carry-forward from prior session)

- **Python 3.12** baseline. The model layer dropped the `backports.strenum` fallback already.
- **mypy --strict** is the bar. PyQt6 has decent stubs but expect some `# type: ignore` for QObject signal connections — that's acceptable as long as you minimize them.
- **No git commits.** User commits when ready.
- **Honest about state.** Demo data is clearly labeled "demo" in tab titles and the status bar. Extraction / classification / analysis views show "(scaffold)" placeholders until the real pipelines exist.
- **Don't write a real extraction pipeline.** That's scope C and out of scope. Demo data is the iteration vehicle.

## Things that might trip the new agent

- **PyQt6 install size and time**: ~150 MB and ~30s on first install. Don't panic.
- **`asyncio` and PyQt6**: Don't mix. Loki has no async needs in the GUI; keep everything synchronous.
- **`qtbot` fixture**: comes from `pytest-qt`. Add `pytest-qt>=4.0` to dev extras.
- **Threading for file hashing**: A 100 MB firmware binary takes ~1 second to hash. Block the UI for v1. If it gets annoying, wrap in `QThread` later — out of scope for the initial build.
- **Pydantic round-trip in tests**: The model layer's `AxisClassification.label` is `str` (not `StrEnum`) per the resolution shipped in the prior session. Demo data should pass `StrEnum.value` strings or `StrEnum` instances; both work, the validator coerces.
- **Pydantic v2 `frozen=False`**: All models are mutable. View widgets can edit local copies if needed, but for the initial build just render read-only.

## Out of scope for this session

- Real firmware extraction (UEFI parsing, capsule parsing, etc.) — scope C
- Baseline registry persistence (storing demo + real baselines to disk) — needs a spec first
- CLI for non-GUI operations — defer until extraction lands
- macOS app bundle (`.app`) packaging — defer until the app is feature-complete
- Code-signing / notarization — defer

## Files to read

- `/Users/daborond/Projects/loki/pyproject.toml` — current deps + extras
- `/Users/daborond/Projects/loki/README.md` — to know what to add
- `/Users/daborond/Projects/loki/loki/models/__init__.py` — exports list
- `/Users/daborond/Projects/loki/loki/models/firmware.py`, `classification.py`, `baseline.py`, `reports.py` — to know field shapes for the views

## USER CORRECTIONS AND INSTRUCTIONS (carry forward)

- Honest framing: scaffolding is scaffolding, demo data is demo data. Don't oversell.
- Don't run git commits.
- Stay in `/Users/daborond/Projects/loki/`. Razor-Rooster (`/Users/daborond/Sloptropy/razorrooster/`) is unrelated.
- Stick to the spec when one exists; deviate only with explicit user OK.
- After each round of work, summarize what's done, what's tested, what's next, and offer 3-4 candidate next moves.

## Ready to start

The user has already approved this plan in the prior session. Start with Step 0 (read existing state), then walk straight through Steps 1-11. Pause for the user only if you hit something genuinely ambiguous (e.g. PyQt6 doesn't install cleanly, or the tests reveal a model-layer issue).

When the build is done and verified, the deliverables are:

- `pyproject.toml` updated
- `loki/gui/` populated per the structure above
- `loki/cli.py` with `loki gui` subcommand
- `tests/gui/` with `pytest-qt` tests
- `README.md` extended with the GUI section
- `mypy --strict`, `ruff`, `pytest` all clean

Then summarize and offer next moves (likely: extraction pipeline, baseline persistence, more demo data variety, native packaging).

---

**End of handoff.**

# CONTEXT TRANSFER: Loki — between major subsystems

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Projects/loki/`. The project is **between
major subsystems**: three are complete (model layer, extraction
pipeline, baseline persistence), and the next major piece
(classification pipeline) is unspecced and waiting on a fresh
single-purpose conversation to drive design decisions.

There is **no in-progress work**. The codebase is at a clean
checkpoint. All four verification gates are green. Anyone can pick
up from here without inheriting half-finished state.

## STATUS — what's shipped

Three subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models, 14 StrEnums, eight
  modules. Strict validation on construction, lossless JSON / YAML
  round-trip. Spec at `.kiro/specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. v1 covers Intel
  Flash Descriptor (full-flash) images, UEFI PI firmware volumes,
  raw FFS blobs, UEFI capsules, PCI option ROMs, Intel CPU
  microcode update blobs. **UEFI volume decompression and
  inner-component emission shipped this run**: compressed sections
  (Tiano + LZMA-Custom GUID-defined) are decompressed via
  `uefi_firmware`, the resulting payload is walked for inner UEFI
  PI sections, and each inner section becomes its own
  `ExtractedComponent` with a synthetic virtual `source_image_id`
  derived from the decompressed payload's hash. R5.8 holds: failed
  decompression records a typed error and the outer component still
  carries `raw_hash` over the on-disk compressed bytes. Spec at
  `.kiro/specs/extraction-pipeline/`.
- **`loki/baseline/`** — GLEIPNIR persistence layer. YAML-on-disk,
  one human-readable file per baseline, atomic writes,
  mtime/size concurrency check, typed exception hierarchy,
  `loki baseline list/show/import/export/delete` CLI surface, GUI
  integration with background-thread loading. Spec at
  `.kiro/specs/baseline-persistence/`. **All 22 tasks ticked off in
  `tasks.md`**.

> **[Partial recovery — original text from this entry's tail is
> unrecoverable.]** This handoff was the entry point for the session
> that landed: extraction-pipeline `design.md` inner-component
> description fix, README refresh, classification-pipeline
> `requirements.md` draft, extraction-pipeline `tasks.md` tick-off,
> GLEIPNIR per-file progress + cancellation hook, and the
> `smoke_gui.py` lint cleanups. The remaining sections of the
> original handoff (verification checkpoint, design decisions
> worth knowing, carry-forward constraints, files to read first,
> user preferences, ready-for-next-session) closely matched the
> structure of the entry above (classification-spec-mid-flight),
> which inherited and updated most of those sections verbatim.
> Refer to that entry for the canonical version of the
> carry-forward content.

---

**End of handoff.**



# CONTEXT TRANSFER: Loki — analysis engine fully landed (Wave 8 complete; OT-LK-001 closed)

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Sloptropy/loki/`. **Five subsystems have
shipped**: model layer, extraction pipeline, baseline persistence
(GLEIPNIR), classification pipeline, and now the **analysis engine**.
The analysis-engine spec triple is fully closed out — all 28 tasks
across all 8 waves of `.kiro/specs/analysis-engine/tasks.md` are
ticked off. The README has been refreshed with a dedicated
`## Analysis engine` section. The Loom harness is at v0.4.0 and
records the lifecycle transition PROPOSED → IMPLEMENTED.

There is **no in-progress code work**. All five verification gates
are green. Slow performance tests pass locally including the new
analysis-engine R18.1 budget. Offscreen GUI smoke is clean.

The single largest piece of work was a same-day eleven-round arc
that took the analysis engine from "stub requirements only" to
"v1.0.0 IMPLEMENTED + APPROVED." That work is closed. The next
candidate piece of work is the **CVE feed integration / `feeds`
subsystem** (OT-LK-002), which has no spec yet.

## STATUS — what's shipped

Five subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models, 14 StrEnums plus the
  new `MatchStrategy` enum, eight modules. Strict validation on
  construction, lossless JSON / YAML round-trip. Spec at
  `.kiro/specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. v1 covers Intel
  Flash Descriptor (full-flash) images, UEFI PI firmware volumes,
  raw FFS blobs, UEFI capsules, PCI option ROMs, Intel CPU
  microcode update blobs. UEFI volume decompression and
  inner-component emission. Spec at
  `.kiro/specs/extraction-pipeline/`. **All 28 tasks ticked.**
- **`loki/baseline/`** — GLEIPNIR persistence layer. YAML-on-disk,
  one human-readable file per baseline, atomic writes, mtime/size
  concurrency check, typed exception hierarchy, `loki baseline
  list/show/import/export/delete` CLI surface, GUI integration
  with background-thread loading plus per-file progress and
  cancellation. Spec at `.kiro/specs/baseline-persistence/`.
  **All 22 tasks ticked.**
- **`loki/classification/`** — classification pipeline. Turns
  `ExtractedComponent` records into validated `ClassificationRecord`
  instances along the four taxonomic axes (type, vendor,
  security_posture, mutability). Public entry point: ``from
  loki.classification import classify_components``. R5.6
  dual-record contract honored. Spec at
  `.kiro/specs/classification-pipeline/`. **All 25 tasks ticked.**
- **`loki/analysis/`** — analysis engine. Turns a sequence of
  `ClassificationRecord` instances plus a `BaselineRegistry` into
  a validated `ImageAnalysisReport`. Public entry point: ``from
  loki.analysis import analyze_image``. Six finding categories;
  R17.5 post-HARDEN PostureRating six-rule cascade with G3-A
  catch-all + G4-B CRITICAL escalation. All ten Properties P43-P52
  covered by Hypothesis tests. Spec at
  `.kiro/specs/analysis-engine/`. **All 28 tasks ticked.**

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` | DONE — `.kiro/specs/loki-data-models/` | DONE |
| `loki/gui/` | None — handoff plan | DONE (scope B + GLEIPNIR + threaded extraction + threaded baseline load with progress/cancel) |
| `loki/cli.py` | Spec dir empty | `loki gui`, `loki extract --progress`, `loki baseline list/show/import/export/delete` |
| Extraction pipeline | DONE — `.kiro/specs/extraction-pipeline/` | DONE — all 28 tasks |
| Baseline management (GLEIPNIR) | DONE — `.kiro/specs/baseline-persistence/` | DONE — all 22 tasks |
| Classification pipeline | DONE — `.kiro/specs/classification-pipeline/` | DONE — all 25 tasks |
| Analysis engine | DONE — `.kiro/specs/analysis-engine/` | DONE — all 28 tasks |
| Feeds (NVD, implant rules) | Not specced | Not started |
| Fleet analysis | Models exist | Engine not started |

## VERIFICATION (current checkpoint)

- **`pytest -q`**: **1211 passed, 8 deselected**.
- **`pytest -m slow`**: **8 passed** (2 baseline + 2 classification +
  2 extraction + 2 analysis); 1211 deselected.
- **`mypy --strict loki tests scripts`**: 0 issues across **217
  source files**.
- **`ruff check`**: clean repo-wide.
- **`ruff format --check`**: clean (217 files already formatted).
- **Slow performance tests**: all pass locally — R11.1 (4096
  components × 1024 rules under 30s, actual ~3s), R11.3 (4096
  components × 256 MiB total under 60s, actual ~3s), and the new
  **R18.1 (1024+1024 components under 5s, actual ~0.10s — 50× under
  budget)**. Run with `pytest -m slow`.
- **Offscreen GUI smoke run**:
  `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py`
  is clean. (See "Workspace observation" below for the actual
  invocation pattern.)
- **Public API smoke**: ``from loki.analysis import analyze_image,
  AnalysisProgressEvent, ANALYSIS_VERSION`` works;
  `ANALYSIS_VERSION = "1.0.0"`.

## WHAT'S NEXT — CVE feed integration (`feeds` subsystem; no spec yet)

OT-LK-001 closed with the analysis-engine v1.0.0 ship. The new top
priority is **OT-LK-002 — CVE feed integration**, which has no spec
yet. Will populate `ClassificationRecord.cve_matches` (currently
always `[]` in v1 per classification R6) by mapping
`(component, classification)` pairs against an NVD-style feed. Once
feeds ship, the analysis-engine's `evidence.matched_cve` and
`DeviationScore.cve_introduced` surfaces (currently always `None`
and `False` per analysis R9.9) start carrying real values.

Two CAST-phase questions for the feeds subsystem:

1. **Feed-refresh cadence.** Daily? Weekly? On demand? The answer
   informs storage layout and the cache-eviction policy.
2. **Signature-trust posture.** Signed feeds with key pinning vs.
   plaintext fetch with hash verification? Threat context will
   likely lift toward FULL on the network-egress path with
   credential handling if pinning is chosen.

**Spec drafting is its own conversation.** Don't try to merge spec
drafting with implementation in a single session. The classification
spec was drafted across multiple turns of a recent conversation and
the implementation followed across a half-dozen wave-sized sessions;
the analysis engine followed the same multi-turn cadence and shipped
in eleven same-day rounds (TENSION + HARDEN + design BIND + tasks
BIND + Waves 1-8). The same cadence is the path of least surprise
for feeds.

Other candidate next moves, in rough priority order (from the loom
harness § 5 Open Threads):

1. **Fleet analysis (`fleet-analysis` subsystem; OT not yet
   numbered).** Models exist (`FleetAnalysisReport` in
   `loki/models/reports.py`); the engine that produces them
   (`analyze_fleet`) is reserved per analysis R19.7. Aggregates
   per-image `FindingRecord` sets across an operator-defined
   fleet. Depends on feeds landing first because `evidence.matched_cve`
   is the most useful aggregation key.
2. **OT-LK-003 — classification CLI subcommand (LOW).** v1 ships
   only the library API. A future `classification-cli` spec
   defines `loki classify run/show/...`. Self-contained.
3. **OT-LK-004 — GUI classification + analysis view (LOW).** Both
   classification and analysis ship as headless library APIs; a
   future GUI spec defines the desktop surface that wires
   `classify_components` and `analyze_image` onto background
   `QThread`s.
4. **OT-LK-005 — Baseline schema migration tool (LOW).** v1
   supports exactly one `Schema_Version` and quarantines any
   other; the future `baseline-schema-migration` spec defines an
   explicit migration command. Out of scope for GLEIPNIR v1 but
   tracked in the design's deferred-decisions section.


## CARRY-FORWARD CONSTRAINTS

- **Python 3.12** baseline. No `backports.strenum` fallback.
- **`mypy --strict`** is the bar across `loki tests scripts`
  (217 source files clean as of Wave 8).
- **`ruff check` + `ruff format`** must be clean repo-wide.
  `RUF002` catches `×` (multiplication sign) and `–` (en dash) in
  Python comments and docstrings — replace with ASCII `x` and `-`.
  Markdown is not affected by RUF002; the existing specs use
  `—` / `→` / `≤` / `×` / `⇒` freely.
- **No `fs_write` for existing files.** Standing directive after
  the archive-clobber incident. Use `fs_append` for extension and
  `str_replace` for in-place edits. New file creation goes via
  `touch <path>` followed by `fs_append`. To prepend content to
  an existing file, use `str_replace` to insert before the file's
  first content line — that preserves all existing content. To
  rewrite an existing file from scratch, use `delete_file`
  followed by `touch` + `fs_append`.
- **No git commits.** User commits when ready.
- **Property numbering is sequential across the platform.** Model
  layer owns 1-11, extraction owns 12-22, baseline-persistence
  owns 23-32, classification owns 33-42, **analysis owns 43-52**.
  Whatever subsystem comes next picks up at 53. The `feeds`
  subsystem is the most likely candidate.
- **Honest about state.** Demo data stays clearly labeled `(demo)`.
  Quarantined baselines surface with their reason. The Analysis
  tab in the GUI is still scaffold pending its own subsystem
  (the analysis engine ships as a library API only; GUI wiring
  is OT-LK-004).
- **Loki only.** Razor-Rooster at
  `/Users/daborond/Sloptropy/razorrooster/` is unrelated.
- **Stick to the spec when one exists; deviate only with explicit
  user OK.** Specs for the five shipped subsystems are closed; the
  next subsystem starts with a fresh requirements / design / tasks
  cycle.

## WORKSPACE OBSERVATION (read this before running tests)

The `.venv/bin/*` entry-point shebangs are stale. They point at
`/Users/daborond/Projects/loki/.venv/bin/python3.12`, which no
longer exists — the project was relocated to
`/Users/daborond/Sloptropy/loki/` in a prior workspace cleanup.
The Python interpreter at `.venv/bin/python` works fine; only the
wrapper-script shebangs (pytest, mypy, ruff, etc.) are broken.

**Workaround in use throughout the analysis-engine implementation:**

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m ruff check
.venv/bin/python -m ruff format --check
```

For the offscreen GUI smoke, the script's own shebang is also
stale; invoke it through python -c:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -c \
  "import sys; sys.argv = ['smoke']; exec(open('scripts/smoke_gui.py').read())"
```

A clean fix is to rebuild the venv:

```bash
rm -rf .venv
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Operator may want to do this between sessions but it is not
blocking implementation.

## TEST INFRASTRUCTURE WORTH KNOWING

- **`pytest-timeout` is installed.** Use `--timeout=30
  --timeout-method=signal` on any GUI test invocation.
- **`tests/gui/test_baseline_actions.py`** has an autouse
  `no_blocking_dialogs` fixture pattern worth replicating in any
  future GUI test file.
- **Hypothesis settings.** Persistence-layer PBT uses
  `max_examples=25`; model layer uses `max_examples=50`.
  Classification adopted both: 50 for in-memory matcher /
  classifier properties, 25 for full-pipeline properties. Analysis
  picked up the same convention: `max_examples=50` for
  axis_score / composite_score / pairing properties,
  `max_examples=25` for full-pipeline determinism / round-trip /
  cancellation properties. Both also set
  `suppress_health_check=[HealthCheck.too_slow,
  HealthCheck.function_scoped_fixture]`. Apply the same
  convention to future subsystems.
- **`slow` marker is registered** in `pyproject.toml` and
  `addopts = "-ra --strict-markers -m 'not slow'"` keeps
  performance tests off the default `pytest -q` run.
- **`filterwarnings = ["error"]`** is set in `pyproject.toml`. Any
  `DeprecationWarning` emitted during a run will fail the test.
  Follow the extraction pattern when one fires: either upgrade
  the pin or add a narrow `filterwarnings("ignore", ...)` in the
  affected test module's `conftest.py` with a documented rationale.
- **The static AST + dynamic caplog audit pair is now in four
  subsystems** (extraction, baseline, classification, analysis).
  The pattern: `tests/<subsys>/test_no_log_leakage.py` does the
  static AST audit; `tests/<subsys>/test_log_no_leakage.py` does
  the dynamic caplog audit. Mirror this in any future subsystem
  that owns log records.
- **Pydantic strict-mode round-trip pattern.** When testing JSON
  / YAML round-trip on a strict-mode Pydantic model:
  - JSON: use `Model.model_validate_json(model.model_dump_json())`.
    Native decoder handles enums + UUIDs.
  - dict / YAML: use `Model.model_validate(data, strict=False)`.
    Mirrors `LokiConfig.from_yaml`'s relaxed-mode coercion path.
  Using `Model.model_validate(model.model_dump(mode="json"))`
  (no strict=False) on a strict model FAILS on string-encoded
  enums and UUIDs — this caught us twice during the analysis
  implementation.
- **Floating-point composite scores can overflow strict bounds.**
  `10.0 * (0.4+0.2+0.3+0.1) = 10.0+~2e-15`, which the model layer's
  strict `composite_score <= 10.0` validator on `DeviationScore`
  rejects. The analysis engine clamps composite scores to
  `[0.0, 10.0]` at the producer side in
  `emit_classification_mismatch`. If you ever add another field
  with a strict numeric range, plan the producer-side clamp
  preemptively.
- **`tests/analysis/_helpers.py`** is an underscore-prefixed
  helpers module (pytest doesn't collect it as a test module). It
  exposes `make_axis`, `make_record`, `make_baseline_record`,
  `make_image`, `make_signature_info`, and the `VALID_WEIGHTS`
  constant. Reuse it from any future analysis-related test file.

## THINGS THAT MIGHT TRIP THE NEW AGENT

- **All five subsystems are end-to-end implemented.** No
  half-finished surfaces lurking. Every public API is callable;
  every contract is enforced by at least one test.
- **The analysis engine has eight design defaults baked into the
  implementation.** Documented as D1-D8 in
  `.kiro/specs/analysis-engine/design.md` § "Deferred decisions
  and open questions":
  - D1: free function `analyze_image`, not class method (mirrors
    classification).
  - D2: `loki/analysis/errors.py` exception module.
  - D3: `FindingEvidence.deviation_score` direct model-layer
    extension.
  - D4: `AnalysisConfig` extended with `match_strategy`,
    `confidence_gap_threshold`, `baseline_id`.
  - D5: `MatchStrategy` is a StrEnum in `loki/models/enums.py`.
  - D6: `AnalysisProgressEvent` strips `component_id`. The
    classification pipeline's `ProgressEvent.component_id` was a
    deliberate exception to its leakage discipline; analysis
    takes the stricter side.
  - D7: Properties P43-P52, ten properties.
  - D8: five Property descriptions (P44, P45, P46, P49, P52) use
    multi-paragraph or bullet-list structure; the Kiro Spec Format
    checker emits five non-blocking warnings on the design.md;
    explicitly accepted to preserve structural clarity.
- **The R17.5 PostureRating mapping is a six-rule cascade** with
  G3-A catch-all + G4-B CRITICAL escalation. The cascade is in
  `loki/analysis/posture.py:derive_posture_rating`. If you ever
  need to extend it, the implementation walks the finding list
  once collecting four boolean flags + one running max; adding a
  sixth check is an O(N) addition to the same loop, not a new
  pass.
- **The Cancellation_Marker contract has nine acceptance criteria
  in R7.** The most important to remember: it's the LAST entry
  in `findings`, has a deterministic sentinel `component_id` =
  `uuid.uuid5(LOKI_NAMESPACE, "analysis-cancelled")`, severity
  INFO, and the cancellation-at-index value lives in
  `evidence.raw_indicators[0]` ONLY (never logged per R7.4).
- **The R17.4 `BaselineComparison` lockstep with
  `ImageAnalysisReport.timestamp`** was a TENSION-pass HARDEN
  amendment (G1 + G2). The two timestamps move together so the
  determinism property in R15.1 strips one value. If you ever add
  a third timestamp anywhere in the report, plan the lockstep
  before BIND.
- **The TENSION pass review note** at
  `.kiro/specs/analysis-engine/requirements-tension-pass.md`
  records four substantive gaps (G1-G4) and three wording items
  (M1-M3) that the operator decided in flight. Operator chose
  G3-A (catch-all DEGRADED rule) and G4-B (escalate
  classification_mismatch CRITICAL to COMPROMISED). M1, M2 were
  cosmetic and skipped. Future amendments to R15.7 / R17.5 should
  re-read the TENSION note before deviating.
- **Analysis-engine v1 leaves `cve_matches`, `matched_cve`, and
  `cve_introduced` empty / None / False.** R9.9 contracts this.
  Once the feeds subsystem ships, these surfaces start carrying
  real values, and the analysis engine itself does not need a
  re-spec — only the feeds subsystem needs to populate
  `ClassificationRecord.cve_matches` upstream.
- **The `AnalysisProgressEvent` does NOT carry `component_id`.**
  This is design D6, deliberately stricter than classification's
  `ProgressEvent`. Don't extend the dataclass in flight; if a
  future GUI revision needs the UUID for a "show in workspace"
  button, the extension goes through a deliberate spec amendment.
- **Five judgment calls were locked in during the analysis-engine
  spec** (D1-D5 above plus D6 + D7). Each is documented in the
  design's "Deferred decisions" section. Any can be reverted
  cheaply if a future revision wants different behavior. The
  affected tasks are: 20 (D1 free function), 6 (D2 errors module),
  5 (D3 FindingEvidence extension), 4 (D4 AnalysisConfig
  extension), 3 (D5 MatchStrategy enum), 20 (D6 progress event
  shape), 24 (D7 P43-P52 numbering).


## REPOSITORY LAYOUT (current)

```
loki/                                 # /Users/daborond/Sloptropy/loki/
├── README.md                         # up to date as of analysis Wave 8
├── HANDOFF.md                        # this doc
├── HANDOFF.archive.md                # all prior handoffs preserved (most recent first)
├── STATE.md                          # WEAVE-style state + next-steps doc
├── loom-loki.md                      # WEAVE/Loom Tier 3 harness; v0.4.0
├── pyproject.toml
├── .kiro/
│   └── specs/
│       ├── loki-data-models/         # DONE
│       ├── extraction-pipeline/      # DONE — 28/28 tasks
│       ├── baseline-persistence/     # DONE — 22/22 tasks
│       ├── classification-pipeline/  # DONE — 25/25 tasks
│       └── analysis-engine/          # DONE — 28/28 tasks
│           ├── requirements.md       # 1194 lines, 20 EARS requirements
│           ├── requirements-tension-pass.md  # TENSION + HARDEN audit trail
│           ├── design.md             # 1211 lines, 11 sections, P43-P52
│           └── tasks.md              # 28 tasks, 8 waves; all ticked
├── loki/
│   ├── cli.py                        # gui / extract (--progress) / baseline
│   ├── models/                       # 8 modules, Pydantic v2 (extended for analysis)
│   ├── extraction/                   # extraction pipeline
│   ├── baseline/                     # GLEIPNIR persistence
│   ├── classification/               # classification pipeline
│   ├── analysis/                     # analysis engine (12 modules)
│   │   ├── __init__.py               # public re-exports
│   │   ├── api.py                    # analyze_image + AnalysisProgressEvent
│   │   ├── pipeline.py               # internal AnalysisPipeline orchestrator
│   │   ├── version.py                # ANALYSIS_VERSION = "1.0.0"
│   │   ├── matching.py               # R2 Match_Strategy resolution + R14.1
│   │   ├── pairing.py                # R3 Component_Pairing
│   │   ├── findings.py               # 5 emitters + Cancellation_Marker + finding_id
│   │   ├── scoring.py                # 6 scoring helpers
│   │   ├── posture.py                # R17.5 six-rule cascade
│   │   ├── report.py                 # ImageAnalysisReport assembly + priority_rank
│   │   ├── errors.py                 # 4-subclass exception hierarchy
│   │   └── timing.py                 # Stopwatch context manager
│   └── gui/                          # PyQt6 desktop, threaded workers
└── tests/
    ├── conftest.py                   # Hypothesis strategies
    ├── extraction/                   # extraction subsystem tests
    ├── baseline/                     # baseline-persistence tests
    ├── classification/               # classification tests
    ├── analysis/                     # analysis-engine tests (~22 files)
    │   ├── _helpers.py               # shared fixture builders
    │   ├── test_api.py               # public surface + R1.9 no-loki-gui audit
    │   ├── test_pipeline.py          # AnalysisPipeline orchestration
    │   ├── test_properties.py        # Hypothesis P43-P52
    │   ├── test_no_log_leakage.py    # static AST audit (Property 50)
    │   ├── test_log_no_leakage.py    # dynamic caplog audit (Property 50)
    │   ├── test_no_side_channels.py  # static AST audit (Property 51)
    │   ├── test_performance.py       # slow marker, R18.1 budget
    │   └── test_findings_*.py        # 5 per-category emitter tests
    ├── gui/                          # PyQt6 tests
    ├── test_classification_smoke.py  # extract → classify smoke
    └── test_analysis_smoke.py        # all 6 analysis finding categories smoke
```

## FILES TO READ FIRST

- `README.md` — current as of analysis Wave 8. Project overview,
  quick-start, and a current snapshot of the implementation
  status across all five shipped subsystems plus dedicated
  `## Classification pipeline` and `## Analysis engine` sections
  describing the public entry points, six finding categories,
  the PostureRating six-rule cascade, the cooperative-cancellation
  pattern, and the determinism + no-leakage discipline.
- `loom-loki.md` — Tier 3 WEAVE harness at v0.4.0. Subsystem
  registry now lists five IMPLEMENTED + APPROVED subsystems.
  Dependency graph materializes 17 edges. The v0.4.0 evolution-
  log entry summarizes the eleven same-day rounds that took
  analysis-engine from "stub requirements" to "v1.0.0
  IMPLEMENTED."
- `STATE.md` — current state + next-steps doc. Cross-references
  the workspace-level `../STATE_AND_NEXT_STEPS.md`.
- `.kiro/specs/analysis-engine/{requirements,design,tasks}.md` —
  the most recent reference for spec format. Mirror the structure
  when drafting the feeds spec.
- `.kiro/specs/analysis-engine/requirements-tension-pass.md` —
  records the TENSION + HARDEN audit trail. The pattern is worth
  mirroring for any future spec that needs a TENSION pass before
  HARDEN.
- `loki/analysis/` — twelve modules implementing the analysis
  engine. The cleanest reference implementation in the project
  for a five-component architecture (matching + pairing +
  scoring + posture + report assembly + pipeline orchestration).
  When designing the feeds subsystem, mirror this shape unless
  the design conversation explicitly diverges.
- `loki/extraction/` and `loki/baseline/` and
  `loki/classification/` — three additional reference
  implementations. Each shows the project's module layout, error
  hierarchy, side-channels audit, and no-leakage logging audit
  patterns.

## USER PREFERENCES (carry forward)

- **No git commits.** User commits when ready.
- **Loki workspace only.** Don't reference razor-rooster.
- **Stick to the spec when one exists; deviate only with explicit
  OK.** Specs for the five shipped subsystems are closed.
- **Spec drafting is its own conversation.** Don't merge it with
  implementation in a single session. The analysis-engine
  arc demonstrated this: 4 spec rounds (TENSION + HARDEN +
  design BIND + tasks BIND) preceded the 7 implementation rounds
  (Waves 1-7) preceded the final Wave 8 ratification. Each round
  was checkpoint-clean before advancing.
- **After each round of work, summarize what's done, what's
  tested, what's next, and offer 3-4 candidate next moves.**
- **Honest framing.** Don't claim work is done if it isn't. Don't
  paper over spec deviations; surface them and confirm.
- **Pause and ask** when the work scope is ambiguous, when a spec
  decision is needed, or when an approach has failed twice.
- **Never use `fs_write` against an existing file.** Standing
  directive after the archive-clobber incident. Use `fs_append`
  for extension and `str_replace` for in-place edits. New file
  creation goes through `touch` followed by `fs_append`.
- **TENSION pass is the right move on a substantial DRAFT.** When
  a spec DRAFT looks complete on first read, do a TENSION pass
  end-to-end before declaring HARDEN-ready. The analysis-engine
  TENSION pass surfaced four substantive gaps (G1-G4) and three
  wording items (M1-M3) that would have caused real implementation
  pain if missed.

## READY FOR NEXT SESSION

The codebase is at a clean checkpoint. **Five subsystems shipped;
all have closed-out specs.** This is doc-complete and gate-green.

The natural next session is the **CVE feed integration spec
drafting conversation** (OT-LK-002): requirements → design → tasks,
in that order, in its own session. The model layer's
`FeedsConfig` already exists in `loki/models/config.py`; the
feeds subsystem fills in the engine that populates
`ClassificationRecord.cve_matches`.

A second equally-valid next session is the **`loki analyze` CLI
subcommand** spec drafting. v1 of the analysis engine ships only
the library API; a future `analysis-cli` spec defines `loki
analyze run/show/diff/...`. Self-contained and smaller in scope
than feeds.

A third is the **GUI analysis view** (OT-LK-004). Probably best
paired with the GUI classification view since the two share a
worker / threading pattern.

Whichever direction the next session goes, the rules above
stand: test counts shouldn't regress (1211 baseline), all five
gates stay green, no git commits, loki only, no `fs_write`
against existing files.

---

**End of handoff.**
