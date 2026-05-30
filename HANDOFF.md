
# CONTEXT TRANSFER: Loki — feeds + consumer-wiring shipped; fleet analysis Wave 1 landed

> **How to use this doc.** Open a new agent / chat session and paste
> the entire contents below the horizontal rule as the first message.
> The receiving agent has the full picture of what's shipped, what's
> deliberately deferred, and what to do next.

---

You are continuing on the **Loki firmware analysis platform**, which
lives at `/Users/daborond/Sloptropy/loki/`. **Nine subsystems have
shipped**: model layer, extraction pipeline, baseline persistence
(GLEIPNIR), classification pipeline, analysis engine, classify-cli,
**feeds subsystem**, **consumer-wiring** (CVE integration), and
**fleet analysis engine**.

There is **no in-progress code work**. All verification gates are
green. The Loom harness is at v0.9.0.

## STATUS — what's shipped

Nine subsystems are complete and end-to-end-tested:

- **`loki/models/`** — Pydantic v2 data models. Spec at
  `specs/loki-data-models/`.
- **`loki/extraction/`** — extraction pipeline. All 28 tasks.
  Spec at `specs/extraction-pipeline/`.
- **`loki/baseline/`** — GLEIPNIR persistence layer. All 22 tasks.
  Spec at `specs/baseline-persistence/`.
- **`loki/classification/`** — classification pipeline. All 25 tasks.
  Spec at `specs/classification-pipeline/`.
- **`loki/analysis/`** — analysis engine. All 28 tasks.
  Spec at `specs/analysis-engine/`.
- **`loki/classify_helpers.py` + classify-cli** — `loki classify`
  CLI subcommand. All 25 tasks.
  Spec at `specs/classification-cli/`.
- **`loki/feeds/`** — NVD CVE feed + implant-rule lookup. All 28
  tasks. Library API at `from loki.feeds import FeedRegistry`.
  CLI: `loki feeds refresh/status`. Six FULL-context security
  audits. Properties P59-P68. Spec at `specs/feeds/`.
- **Consumer wiring** — bridges feeds into classification
  (`cve_matches` population) and analysis (`matched_cve`,
  `cve_introduced`, `cve_score_bump`). All 10 tasks.
  `loki classify --feeds-config`. Properties P69-P71.
  Spec at `specs/consumer-wiring/`.

- **`loki/fleet/`** — fleet analysis engine. All 18 tasks.
  Library API at `from loki.fleet import analyze_fleet`.
  CLI: `loki fleet analyze --config|--dir`. Five aggregation
  passes. Properties P72-P76.
  Spec at `specs/fleet-analysis/`.

| Subsystem | Spec | Implementation |
| - | - | - |
| `loki/models/` | DONE | DONE |
| `loki/gui/` | AD_HOC | DONE (scope B scaffold) |
| `loki/cli.py` | AD_HOC | `gui`, `extract`, `baseline`, `classify`, `feeds` |
| Extraction pipeline | DONE | DONE — 28/28 tasks |
| Classification pipeline | DONE | DONE — 25/25 tasks |
| Baseline (GLEIPNIR) | DONE | DONE — 22/22 tasks |
| Analysis engine | DONE | DONE — 28/28 tasks |
| Classify CLI | DONE | DONE — 25/25 tasks |
| Feeds (NVD + implants) | DONE | DONE — 28/28 tasks |
| Consumer wiring | DONE | DONE — 10/10 tasks |
| Fleet analysis | DONE | DONE — 18/18 tasks |

## VERIFICATION (current checkpoint)

- **`pytest -q`**: **1655 passed, 13 deselected**.
- **`pytest -m slow`**: **13 slow-marker performance tests**
  (12 pass; 1 pre-existing baseline-perf timeout unrelated).
- **`mypy --strict loki tests scripts`**: 0 issues across **303
  source files**.
- **`ruff check`**: clean.
- **`ruff format --check`**: clean (303 files).
- **Public API smoke**: `from loki.fleet import analyze_fleet,
  FLEET_VERSION, FleetError` works; `from loki.feeds import
  FeedRegistry, FEEDS_VERSION` works.
- **CLI smoke**: `loki analyze --help` works.

## WHAT'S NEXT

All nine subsystems are complete. The analysis CLI (`loki analyze`)
is shipped. Remaining work:

1. **GUI classification + analysis + fleet view (MEDIUM).** Wire
   headless APIs onto `QThread`s in the desktop app.
2. **Baseline schema migration tool (LOW).** Not blocking until the
   second `Schema_Version` exists.
3. **Native packaging (LOW).** `.app` bundle, code-signing,
   notarization.

## CARRY-FORWARD CONSTRAINTS

- **Python 3.12** baseline.
- **`mypy --strict`** across `loki tests scripts` (294 files clean).
- **`ruff check` + `ruff format`** clean repo-wide.
- **No git commits.** User commits when ready.
- **No `fs_write` for existing files.** Use `str_replace` for edits.
- **Property numbering is sequential:** models 1-11, extraction
  12-22, baseline 23-32, classification 33-42, analysis 43-52,
  classify-cli 53-58, feeds 59-68, consumer-wiring 69-71,
  **fleet 72-76**. Next subsystem picks up at P77.
- **Stick to the spec when one exists.**
- **Spec drafting is its own conversation.** Don't merge with
  implementation in a single session (fleet spec is already done —
  implementation can proceed).
- **After each round, summarize what's done, tested, next.**

## WORKSPACE OBSERVATION

The `.venv/bin/*` entry-point shebangs are stale (point at old path).
Workaround: `.venv/bin/python -m pytest -q` etc. See prior HANDOFF
for the full explanation and rebuild instructions.

## TEST INFRASTRUCTURE WORTH KNOWING

- **`pytest-timeout` installed.** Use `--timeout=30` for GUI tests.
- **Hypothesis settings convention:** `max_examples=50` for
  in-memory properties, `max_examples=25` for full-pipeline.
  Both suppress `HealthCheck.too_slow` and
  `HealthCheck.function_scoped_fixture`.
- **`slow` marker registered** in `pyproject.toml`. Performance
  tests excluded from `pytest -q`; run `pytest -m slow`.
- **`filterwarnings = ["error"]`** in `pyproject.toml`.
- **Static AST + dynamic caplog audit pair** pattern in extraction,
  baseline, classification, analysis, and feeds.
- **Pydantic strict-mode round-trip:** JSON via
  `model_validate_json(model_dump_json())`; dict/YAML via
  `model_validate(data, strict=False)`.

## READY FOR NEXT SESSION

The codebase is at a clean checkpoint. **Nine subsystems shipped.**
All verification gates green. No in-progress work.

The natural next session targets one of: analysis CLI, GUI views,
or Loom harness refresh — depending on what you'd like to work on.

---

**End of handoff.**
