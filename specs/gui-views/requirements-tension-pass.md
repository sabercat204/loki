# Requirements Tension Pass — gui-views

This document consolidates the findings from five parallel TENSION lenses
applied to `specs/gui-views/requirements.md` (the OT-LK-004 retroactive
ratification of the LOKI Desktop GUI subsystem). Each lens reviewed the
requirements draft against a different rigor axis:

1. **CORRECTNESS-VS-IMPLEMENTATION** — does each acceptance criterion
   match what the cited code actually does?
2. **THREAT-CONTEXT-COMPLETENESS** — given STANDARD threat context,
   are operator-supplied input failure modes, demo-data poisoning,
   and offline-only invariants tightly bound?
3. **CROSS-SUBSYSTEM-CONTRACT-ADHERENCE** — does the GUI spec honour
   the upstream extraction / classification / analysis / baseline /
   fleet contracts, and is every public model field rendered?
4. **EARS-FORMAT-COMPLIANCE** — does each criterion match the EARS
   shape used by the analysis-engine / fleet-analysis / classification
   reference specs?
5. **OPERATOR-HONEST-FRAMING** — does the spec explicitly name the
   AD_HOC pre-history, the v1 limitations, and the forward-tracked
   debt, without softening or hiding them?

Severities follow the project convention:

- **BLOCKING** — apply before HARDEN exits.
- **AMENDMENT** — apply during HARDEN; affects spec correctness.
- **INFO** — apply at editor's discretion; informational or stylistic.

---

## Lens 1: CORRECTNESS-VS-IMPLEMENTATION

| ID | Severity | Summary |
| --- | --- | --- |
| L1.G1 | AMENDMENT | Glossary `Demo_Workspace` says BaselineRecord; code holds a BaselineRegistry wrapping the BaselineRecord. |
| L1.G2 | INFO | R10.4 attributes partial-result-on-cancel to the worker; that contract lives upstream in `extract_firmware`. |
| L1.G3 | AMENDMENT | R6.9 NoEditTriggers citation omits lines 240, 259 in `_build_baseline_comparison_widget`. |
| L1.G4 | INFO | R22.4 grep audit excludes `scripts/smoke_gui.py` which deliberately calls `processEvents`. |
| L1.G5 | AMENDMENT | R7.2 try/except wraps both `Path.read_text` and `model_validate_json`; criterion under-specifies catch surface. |
| L1.G6 | AMENDMENT | R10.2 / R11.2 / R12.2 say "exactly three signals" but workers also inherit `started`/`finished` from QThread. |
| L1.G7 | INFO | R26.1 "AT LEAST one test per requirement" lacks a deadline; tie to R27 flip. |
| L1.G8 | INFO | R20.1 uses literal `*.EditTrigger.NoEditTriggers` glob inside an API call; not valid Python. |
| L1.G9 | AMENDMENT | R5.2 / R6.2 say header contains "literal posture_rating.value"; actually interpolated into a labelled prefix. |
| L1.G10 | INFO | R6.4 leaves the leaf-node label `"signature"` (vs `"signature_info"`) unspecified. |

Wording items M1-M10 cover Title_Snake_Case consistency, the multi-line
metadata QLabel rendering, R6.3's `/` ambiguity, the R10.4 worker-vs-pipeline
attribution, deduplicating the `Forbidden_Leakage_Field_Set` recital, the
embedded f-string spec strings, cross-spec link consistency, the
closeEvent rationale aside, the duplicated Fleet group note, and the
P77-P85 "enumerated" phrasing.

---

## Lens 2: THREAT-CONTEXT-COMPLETENESS

| ID | Severity | Summary |
| --- | --- | --- |
| L2.G1 | BLOCKING | File-dialog input failure modes (ENOENT, EACCES, EISDIR, dangling symlink, zero-byte, multi-GiB) are not specified for any of the four operator-supplied path surfaces. |
| L2.G2 | BLOCKING | Demo-flagged BaselineRecord can be saved to disk by `save_baseline`; the spec does not refuse demo persistence. |
| L2.G3 | BLOCKING | Fleet-report JSON load is on the GUI thread with no size cap, no streaming-parse, no worker. |
| L2.G4 | AMENDMENT | closeEvent timeout fallback contract (what happens when `wait()` returns `False`) is unspecified. |
| L2.G5 | AMENDMENT | QSettings allowlist forbids "preferences" but does not explicitly forbid storing operator-chosen file paths or model identifiers. |
| L2.G6 | AMENDMENT | QMessageBox modality contract is not stated; reader must infer worker threads keep running while a dialog is up. |
| L2.G7 | AMENDMENT | `*_from_path` Action_Function companions accept arbitrary paths with no input-validation pre-flight. |
| L2.G8 | AMENDMENT | Navigation labels from operator-supplied paths are not bounded for length or sanitised for control / RTL-override codepoints. |
| L2.G9 | AMENDMENT | Worker signals arriving after `closeEvent` begins teardown are not handled; no `_closing` flag specified. |
| L2.G10 | AMENDMENT | The grep audits in R22.4 / R1 are described but not promoted to CI gates. |
| L2.G11 | INFO | Forbidden_Leakage_Field_Set redaction has no concrete `logging.Filter` mechanism specified. |
| L2.G12 | INFO | `QApplication.instance()` reuse path does not specify whether namespace metadata is mutated when an existing QApplication is found. |

Wording items M1-M6 cover splitting Requirement 22, pinning SilentDialogs
as a fixture-or-class, model_validate_json input-encoding, the D3 cancel-flag
cross-reference, the BaselineRegistry term mismatch with the persistence spec,
and the duplicated Fleet group exposition.

---

## Lens 3: CROSS-SUBSYSTEM-CONTRACT-ADHERENCE

| ID | Severity | Summary |
| --- | --- | --- |
| L3.G1 | AMENDMENT | R4 lists nine BaselineRecord fields; the model has ten — `name` is unrendered. |
| L3.G2 | AMENDMENT | R5/R6 omit `image_metadata` (FirmwareImage subobject) from the rendered fields. |
| L3.G3 | AMENDMENT | R16 says analysis pipeline lacks a progress contract; it actually has one (`AnalysisProgressEvent`) — GUI just doesn't subscribe. |
| L3.G4 | AMENDMENT | R17 closed v1 error category set omits `BaselineStorageUnwritableError` and the four `AnalysisError` subclasses; framing should clarify isinstance-dispatch vs parent-catch. |
| L3.G5 | AMENDMENT | R12 doesn't disclose that AnalysisWorker constructs a fresh `BaselineStore` on the worker thread (re-scans disk) rather than reusing the main-thread snapshot. |
| L3.G6 | AMENDMENT | R12's AnalysisConfig recital omits `match_strategy=AUTO`, `confidence_gap_threshold=0.6`, and the ClassificationConfig's `confidence_threshold=0.6`. |
| L3.G7 | INFO | R11 wording "BaselineStoreError subclass" is technically stricter than the catch (which catches the root class). |
| L3.G8 | INFO | R6 doesn't specify the navigation group for AnalysisView (implementation uses REPORTS). |
| L3.G9 | INFO | Cancellation contract citations are scattered across R1.10 / R7 / R16.6 in spec, code, and lens prompts. |

Wording items M1-M6 cover worker ordering convention, progress-callback
vs progress-event terminology, cancellation-token vs cancellation-primitive
naming, "partial LoadResult" canonical phrasing, `finding` vs `FindingRecord`,
and the canonical citation for the analysis cancellation contract.

---

## Lens 4: EARS-FORMAT-COMPLIANCE

| ID | Severity | Summary |
| --- | --- | --- |
| L4.G1 | AMENDMENT | R10's "Requirement 16" cross-reference is stale; should be Requirement 15. |
| L4.G2 | INFO | AC bullets use `- ` instead of numbered `1. / 2.` enumeration, blocking `R<N>.<M>` cross-references. |
| L4.G3 | INFO | R17's `BaselineSerializationError` lacks a file:line citation; either add or remove. |
| L4.G4 | INFO | P79 covers two workers (BaselineLoadWorker + AnalysisWorker); R25's allocation entry only mentions one. |
| L4.G5 | INFO | Introduction does not name the canonical EARS template (analysis-engine spec). |

Wording items M1-M6 cover the R16→R15 fix, em-dash→en-dash in `P77-P85`,
the P79 multi-worker allocation, the BaselineSerializationError citation,
acceptable use of indented reference-data bullets in R25/R27, and the
optional bullet→numbered conversion across all 27 requirements.

---

## Lens 5: OPERATOR-HONEST-FRAMING

| ID | Severity | Summary |
| --- | --- | --- |
| L5.G1 | AMENDMENT | Introduction does not explicitly use the term AD_HOC or note the GUI shipped pre-spec. |
| L5.G2 | AMENDMENT | R19.1 invokes `BaselineRegistry`, a type the Glossary doesn't define and the persistence spec doesn't use. |
| L5.G3 | AMENDMENT | Two view kinds (`ImageAnalysisReportView` and `AnalysisView`) render the same model and produce two simultaneous tabs; this duality is not explicitly disclosed. |
| L5.G4 | AMENDMENT | R14 Help menu doesn't explicitly enumerate v1's single Help entry as the closed set. |
| L5.G5 | AMENDMENT | Fleet group is permanently empty in v1 but spec doesn't surface this as an enduring UX wart. |
| L5.G6 | AMENDMENT | R23.2 startup latency budget uses SHALL but has no enforcing test or measurement methodology — it's a handwave. |
| L5.G7 | INFO | R22 "STANDARD threat context" doesn't explicitly say the GUI inherits operator filesystem privileges (no sandboxing). |
| L5.G8 | INFO | R24 forward-track list omits detach-to-window; readers can't tell if multi-window is "future" or "never". |
| L5.G9 | INFO | Inclusive language audit passed (zero forbidden terms). No fix needed. |
| L5.G10 | AMENDMENT | The "no sort/filter/search" limitation cites D4 directly; readers can't tell why D4 implies the limitation. |

Wording items M1-M8 are largely positive INFO observations confirming
operator-honest framing already present in the spec (R9.4, R13.2, R14.9,
R16.6, R18.5, R22, R24.7).

---

## Consensus Findings (Multi-Lens Agreement)

The same gap surfaced under multiple lenses, increasing signal strength:

- **BaselineRegistry term mismatch**: L1.G1 (correctness), L2.M5 (threat),
  L5.G2 (operator-honesty). All three lenses agree the Glossary,
  Requirement 19, and the upstream baseline-persistence spec disagree
  on what type the Demo_Workspace holds. **Apply.**

- **R10.4 partial-result-on-cancel attribution**: L1.G2 + L1.M4 (correctness)
  agree the contract lives in the upstream pipeline, not the worker. **Apply** as wording.

- **R12 AnalysisWorker contract incompleteness**: L3.G5 (re-scans baselines
  on worker thread) and L3.G6 (undisclosed AnalysisConfig defaults) both
  expose load-bearing facts the spec doesn't recite. **Apply.**

- **R16 analysis-progress framing**: L3.G3 corrects the spec's claim that
  the upstream contract is missing; consistent with L5.M7's note that the
  current wording is operator-honest about the limitation but technically
  inaccurate about the cause. **Apply.**

- **closeEvent ordering / timeout discipline**: L2.G4 (timeout fallback)
  and L2.G9 (slot-arrival-after-teardown) are the same defensive
  programming concern at different times in the close sequence. **Apply both.**

- **EARS R16 → R15 cross-reference**: L4.G1 + L4.M1 + L1 (none surfaced
  this — spec-internal navigation only). **Apply.**

---

## Findings Dropped or Deferred

- **L4.G2** (numbered AC enumeration) — DEFERRED. Bullet-vs-numbered AC
  conversion is a corpus-wide reformatting decision; doing it for gui-views
  alone would create inconsistency with the in-flight specs. Track in
  R24 forward-list or a separate corpus housekeeping task.
- **L2.G11** (logging.Filter implementation detail) — DEFERRED to design.md.
  The contract (no Forbidden_Leakage_Field_Set substrings in log records)
  is in R22.6 + R23.3; the implementation mechanism is design-doc territory.
- **L5.G9** (inclusive language) — NO FIX NEEDED. Audit passed; logged for
  the record.
- **L1.M6** (f-string syntax in spec strings) — DEFERRED. The current form
  is intelligible to readers familiar with Python; forcing a stylistic
  rewrite across many criteria would create churn without semantic gain.

---

## Merged All-Findings Table

| Lens | ID | Severity | Description (one line) | Disposition |
| --- | --- | --- | --- | --- |
| 1 | G1 | AMENDMENT | Glossary Demo_Workspace says BaselineRecord; code has BaselineRegistry. | Applied |
| 1 | G2 | INFO | R10.4 partial-result-on-cancel is upstream contract, not worker-level. | Applied (wording) |
| 1 | G3 | AMENDMENT | R6.9 NoEditTriggers citation omits lines 240, 259. | Applied |
| 1 | G4 | INFO | R22.4 audit excludes scripts/smoke_gui.py. | Applied |
| 1 | G5 | AMENDMENT | R7.2 catch surface includes file-read errors. | Applied |
| 1 | G6 | AMENDMENT | R10.2/R11.2/R12.2 omit inherited QThread signals. | Applied |
| 1 | G7 | INFO | R26.1 lacks deadline. | Applied |
| 1 | G8 | INFO | R20.1 uses invalid `*.` glob. | Applied |
| 1 | G9 | AMENDMENT | R5.2/R6.2 "literal" mischaracterises interpolated string. | Applied |
| 1 | G10 | INFO | R6.4 leaf-node label unspecified. | Applied |
| 2 | G1 | BLOCKING | Operator-supplied path failure modes unspecified. | Applied (new R7 / R10 / R13 ACs) |
| 2 | G2 | BLOCKING | Demo baseline can be saved to disk. | Applied (new R13 + R19 ACs) |
| 2 | G3 | BLOCKING | Fleet-report JSON load has no size cap or pre-flight. | Applied (new R7 ACs) |
| 2 | G4 | AMENDMENT | closeEvent timeout fallback unspecified. | Applied |
| 2 | G5 | AMENDMENT | QSettings doesn't explicitly forbid paths/identifiers. | Applied |
| 2 | G6 | AMENDMENT | QMessageBox modality contract unstated. | Applied |
| 2 | G7 | AMENDMENT | `*_from_path` companions lack input-validation pre-flight. | Applied |
| 2 | G8 | AMENDMENT | Navigation labels not bounded / sanitised. | Applied |
| 2 | G9 | AMENDMENT | Worker-emitted signal during teardown unhandled. | Applied |
| 2 | G10 | AMENDMENT | Grep audits not promoted to CI gates. | Applied |
| 2 | G11 | INFO | logging.Filter mechanism unspecified. | Deferred to design.md |
| 2 | G12 | INFO | QApplication.instance() namespace-clobber unspecified. | Applied |
| 3 | G1 | AMENDMENT | R4 omits BaselineRecord.name. | Applied |
| 3 | G2 | AMENDMENT | R5/R6 omit image_metadata FirmwareImage subobject. | Applied |
| 3 | G3 | AMENDMENT | R16 mischaracterises analysis-pipeline progress contract availability. | Applied |
| 3 | G4 | AMENDMENT | R17 error category set omits BaselineStorageUnwritableError + analysis subclasses. | Applied |
| 3 | G5 | AMENDMENT | R12 omits worker-thread BaselineStore re-load. | Applied |
| 3 | G6 | AMENDMENT | R12 omits AnalysisConfig + ClassificationConfig defaults. | Applied |
| 3 | G7 | INFO | R11 catch wording stricter than runtime. | Applied |
| 3 | G8 | INFO | R6 doesn't specify navigation group for AnalysisView. | Applied |
| 3 | G9 | INFO | Cancellation contract citations scattered. | Applied |
| 4 | G1 | AMENDMENT | R10 cross-reference Requirement 16 → 15. | Applied |
| 4 | G2 | INFO | Bullet→numbered AC enumeration. | Deferred (corpus-wide) |
| 4 | G3 | INFO | BaselineSerializationError lacks citation. | Applied |
| 4 | G4 | INFO | R25 P79 entry doesn't acknowledge multi-worker scope. | Applied |
| 4 | G5 | INFO | Introduction doesn't name canonical EARS template. | Applied |
| 5 | G1 | AMENDMENT | Introduction doesn't say AD_HOC or pre-spec history. | Applied |
| 5 | G2 | AMENDMENT | R19.1 invokes BaselineRegistry that Glossary doesn't define. | Applied (consensus with L1.G1, L2.M5) |
| 5 | G3 | AMENDMENT | Report tab vs Analysis tab duality undisclosed. | Applied |
| 5 | G4 | AMENDMENT | R14 Help menu closure not enumerated. | Applied |
| 5 | G5 | AMENDMENT | Fleet group permanently empty in v1 not surfaced as enduring wart. | Applied |
| 5 | G6 | AMENDMENT | R23.2 startup-latency budget is unverifiable handwave. | Applied (relaxed to SHOULD) |
| 5 | G7 | INFO | STANDARD threat context not explicit about lack of sandboxing. | Applied |
| 5 | G8 | INFO | R24 forward-track omits detach-to-window. | Applied |
| 5 | G9 | INFO | Inclusive-language audit passed. | No fix needed |
| 5 | G10 | AMENDMENT | "No sort/filter/search" cites D4 without explaining why. | Applied |

---

## HARDEN footer

**Date:** 2026-06-02

**Audit-items applied:** 41

**Items deliberately not applied (with rationale):**

- **L4.G2 / L4.M6** (convert AC bullets `- ` to numbered `1. / 2.`):
  Deferred. The bullet-vs-numbered AC convention is a corpus-wide
  reformatting decision; doing it for `gui-views` alone would create
  inconsistency with the in-flight specs. Track in a separate corpus
  housekeeping task; no semantic loss in current state.
- **L2.G11** (concrete `logging.Filter` mechanism for
  `Forbidden_Leakage_Field_Set` redaction):
  Deferred to `design.md`. The CONTRACT (no leakage-field substrings
  in log records) is bound here in R22.6 + R23.3 with reference to
  the Glossary. The IMPLEMENTATION mechanism (filter class, hook
  registration, unit-test plumbing) is design-doc territory and will
  be addressed in the BIND design pass.
- **L1.M6** (rewrite f-string syntax in spec strings as `<placeholder>`
  format spec): Deferred. The current form is intelligible to readers
  familiar with Python; a stylistic rewrite would create churn across
  many criteria without semantic gain.
- **L5.G9** (inclusive-language audit): No fix needed. The audit
  passed (zero forbidden terms); this is a positive INFO finding
  logged for the record.
- **Lens 5 wording items M1-M8** (positive observations confirming
  operator-honest framing already present): No fix needed; logged
  for the record.

**Cross-lens consensus highlights:**

- BaselineRegistry term mismatch: surfaced under three lenses
  (correctness, threat, operator-honesty). Applied via Glossary
  definition and R19.1 alignment.
- closeEvent / cancellation discipline: surfaced under threat lens
  (G4 timeout + G9 slot-arrival-after-teardown) as the same defensive
  programming concern. Both applied to R1 with explicit `_closing`
  flag and `wait()` fallback handling.
- `R10 → Requirement 16` stale cross-reference: surfaced under EARS
  lens; applied (R10 now references R15).

**Forward-tracked items added to Requirement 24 by this pass:**

- Single-window-only stability ratification (vs detach-to-window).
- Worker BaselineStore re-load (vs main-thread injection) ratification.
- Help-menu single-entry closure (vs documentation / update / bug-report).

**New CI gates added to Requirement 26:**

- `loki.cli` import audit (zero matches).
- `processEvents` audit (zero matches in `loki/gui/`).
- Network-egress import-time audit (mocked socket / urllib /
  requests / httpx).
