# loki/ — LOKI — State & Next Steps

**Last updated:** 2026-05-28
**Methodology lens:** WEAVE / Loom Tier 3 (Full Methodology). Harness initialized 2026-05-28 at `loki/loom-loki.md` v0.1.0; same-day eleven rounds took it to v0.4.0 (TENSION pass v0.1.1 → requirements HARDEN v0.2.0 → design BIND v0.3.0 → tasks BIND v0.3.1 → Wave 1+2 v0.3.2 → Wave 3 v0.3.3 → Wave 4 v0.3.4 → Wave 5 v0.3.5 → Wave 6 v0.3.6 → Wave 7 v0.3.7 → Wave 8 final-gate BIND v0.4.0). All five spec triples now live at `.kiro/specs/{loki-data-models,extraction-pipeline,baseline-persistence,classification-pipeline,analysis-engine}/`.
**Workspace context:** see `../STATE_AND_NEXT_STEPS.md` for cross-project view.

---

## State

- **Type:** Firmware analysis platform. Pulls firmware images, extracts components, classifies along four taxonomic axes, compares to baselines, scores deviations, **emits structured analysis reports**.
- **Workspace root:** `loki/`. Python 3.12, package `loki`. Extensive `.venv/`, `.kiro/specs/`.
- **Implementation maturity:** **Nine IMPLEMENTED + APPROVED subsystems** (`models`, `extraction`, `baseline` aka GLEIPNIR, `classification`, `analysis-engine`, `classify-cli`, `feeds`, `consumer-wiring`, `fleet-analysis`); two IMPLEMENTED + AD_HOC subsystems (`gui`, `cli`); one IMPLEMENTED + AD_HOC smoke-harness (`scripts`).
- **Verification gates (current checkpoint after analysis-cli lands):** `pytest -q` 1655 pass / 13 deselected; `mypy --strict` clean across 303 source files; `ruff check` clean; `ruff format --check` clean; offscreen GUI smoke clean. All 13 slow-marker performance tests pass (R11.1 classification, R11.1 classify-cli, R11.3, R18.1, R12.1-R12.3 feeds, fleet R10.2, plus extraction-pipeline performance gates).
- **Recent evidence:** `loki/HANDOFF.md` describes pre-analysis state (still says "next major piece of work is the analysis engine"); now stale and due for refresh. Archive at `loki/HANDOFF.archive.md` records past handoffs.

## Loom/WEAVE status

- **Harness:** `loki/loom-loki.md` v0.4.0 (initialized retroactively 2026-05-28; due for v0.5.0 bump to register feeds + consumer-wiring).
- **Tier:** 3 (Full Methodology).
- **Subsystem registry:** 10 registered subsystems. **8 IMPLEMENTED + APPROVED** (`models`, `extraction`, `baseline`, `classification`, `analysis-engine`, `classify-cli`, `feeds`, `consumer-wiring`). 2 IMPLEMENTED + AD_HOC (`gui`, `cli`). 1 PROPOSED + un-specced (`fleet-analysis`). Strict DAG with **20+ materialized edges** (feeds → models; consumer-wiring → classification / analysis / feeds / models).
- **Threat context default:** STANDARD. The data layer (`models`) is MINIMAL_EXPOSURE; the smoke harness (`scripts`) is MINIMAL_EXPOSURE. No subsystem is FULL — no network egress (until `feeds` lands), no destructive operations, no credential handling.
- **Warp:** Active (§7 of the harness; reflects the five spec-triple contracts plus the AD_HOC IMPLEMENTED surface for gui / cli).

## Next steps

OT-LK-001 closed 2026-05-28. OT-LK-002 (feeds) closed 2026-05-29. OT-LK-003 (classify-cli) closed earlier. Consumer-wiring closed 2026-05-29. Remaining open threads:

1. **OT-LK-004 — GUI classification + analysis + fleet view (MEDIUM).** All subsystems ship as headless library APIs; a future GUI spec wires them onto `QThread`s.
2. **OT-LK-005 — Baseline schema migration tool (LOW).** v1 quarantines non-matching `Schema_Version`s; not blocking until the second `Schema_Version` exists.
3. **Native packaging (LOW).** `.app` bundle, code-signing, and notarization deferred until feature-complete.
