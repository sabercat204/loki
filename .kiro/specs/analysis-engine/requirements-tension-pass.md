
# TENSION pass — analysis-engine requirements.md

**Date:** 2026-05-28
**Reviewed file:** `requirements.md` (1163 lines, 20 requirements)
**Reviewer's lens:** WEAVE / Loom Tier 3 — Shuttle Protocol stage TENSION (CAST → DRAFT → **TENSION** → HARDEN → FRAY → BIND).
**Outcome:** four substantive gaps and three minor wording items surfaced. None of them justify a return to DRAFT — they are HARDEN-phase decisions for the operator.

---

## How to read this note

The requirements doc is structurally complete (20 EARS-style requirements, all with `#### Acceptance Criteria` blocks, no TODO / OPEN-QUESTION markers, diagnostics-clean per the Kiro Spec Format checker). The TENSION pass walked the doc end-to-end against the existing model layer (`loki/models/{firmware,classification,baseline,analysis,reports,config,enums}.py`) and the four shipped subsystems' patterns (extraction, baseline, classification, models).

The findings are split into:

- **Gaps (G1–G4):** points where the doc is silent or under-specified, and where the design phase could go either way without further input. Each gap is paired with a recommended resolution and an alternative.
- **Wording (M1–M3):** points where the spec is internally consistent but a reader could be misled. These are clarifications, not changes of substance.

The recommendation at the end is: **resolve G1–G4 by minor amendment to `requirements.md`, then HARDEN**. M1–M3 can be folded into the same amendment or deferred to design-phase prose.

---

## Gaps

### G1 — `BaselineComparison.comparison_timestamp` is unspecified

**Location:** Requirement 17 acceptance criterion 17.4.

**Issue:** Acceptance criterion 17.4 instructs the engine to populate `ImageAnalysisReport.baseline_comparison` as a `BaselineComparison` whose `baseline_id` equals the Matched_Baseline's `baseline_id`, whose `target_image_id` equals `Target_Image.image_id`, and whose `deviations` list is `[]`. The `BaselineComparison` model in `loki/models/baseline.py` carries a fourth field `comparison_timestamp: datetime` that is not optional. The spec is silent on what value to set for it.

**Why it matters:** The engine cannot construct a valid `BaselineComparison` without a timestamp, and the determinism contract (R15.1) strips only `ImageAnalysisReport.timestamp` from equality, so a freshly-generated `comparison_timestamp` would break the determinism property unless also stripped.

**Recommended resolution:** Amend acceptance criterion 17.4 to read:

> ...whose `comparison_timestamp` equals `ImageAnalysisReport.timestamp` (the same UTC wall-clock moment captured at run start per acceptance criterion 1.6).

This keeps the engine's two timestamp fields in lockstep, removes a degree of freedom from the determinism property, and makes the round-trip property in R15.5 trivially clean.

**Alternative:** Set `comparison_timestamp` to a deterministic value derived from `(Target_Image.image_id, Matched_Baseline.baseline_id)` plus a fixed epoch offset. Stronger determinism, but introduces a non-wall-clock value into a field documented as "comparison timestamp." Not recommended.

---

### G2 — Determinism modulo `comparison_timestamp` not addressed

**Location:** Requirement 15 acceptance criterion 15.1.

**Issue:** R15.1 says two runs on the same inputs produce reports equal under `model_dump(mode="json")` "after stripping the `timestamp` field on the report." If G1 is resolved by tying `comparison_timestamp` to `ImageAnalysisReport.timestamp` (the recommended path above), R15.1's existing language is sufficient because the two timestamps are equal whenever `ImageAnalysisReport.timestamp` is fixed.

If G1 is resolved by giving `comparison_timestamp` an independent wall-clock reading, R15.1 needs amendment to also strip `baseline_comparison.comparison_timestamp` from the equality.

**Recommended resolution:** Adopt the G1 recommendation (tie `comparison_timestamp` to `ImageAnalysisReport.timestamp`); R15.1 then needs no amendment.

---

### G3 — `PostureRating` mapping has a fall-through gap for medium-severity-only runs

**Location:** Requirement 17 acceptance criterion 17.5.

**Issue:** The five `PostureRating` rules in 17.5 are:

1. `COMPROMISED` if any `signature_regression` is HIGH or any `missing_required_component` is emitted.
2. `AT_RISK` if any `classification_mismatch` has Composite_Score ≥ 6.0.
3. `DEGRADED` if any `classification_mismatch` has Composite_Score ≥ 2.0 but no other rule above fires.
4. `BASELINE` if no findings are emitted at all.
5. `HARDENED` reserved.

A run that emits only `unexpected_component` (R6.5: always MEDIUM), `signature_regression: MEDIUM` (R5.6: target-signed-baseline-unsigned direction), or `classification_gap` (R10.6: always LOW) findings — i.e. no `classification_mismatch ≥ 2.0`, no `missing_required_component`, no `signature_regression: HIGH` — falls through every rule. The `BASELINE` clause requires "no findings emitted at all," so it does not catch this case.

**Why it matters:** Without a catch-all, the engine cannot construct a valid `ImageAnalysisReport` (the `posture_rating` field is non-optional). The Pydantic validator on `PostureRating` would not raise on an unset value because Python would produce no value — the `posture_rating` would be unbound, which fails Pydantic strict construction.

**Recommended resolution:** Amend acceptance criterion 17.5 to add a sixth rule between the current rules 3 and 4:

> - `PostureRating.DEGRADED` if any finding of any category is emitted but no rule above fires; this catches runs whose only findings are `unexpected_component`, `signature_regression: MEDIUM`, or `classification_gap`.

Or, equivalently, amend the `BASELINE` rule to be the explicit catch-all and rewrite the rule order as:

> - `PostureRating.COMPROMISED` if any `signature_regression` is HIGH or any `missing_required_component` is emitted; otherwise
> - `PostureRating.AT_RISK` if any `classification_mismatch` has Composite_Score ≥ 6.0; otherwise
> - `PostureRating.DEGRADED` if any finding is emitted at all; otherwise
> - `PostureRating.BASELINE` if no finding is emitted.

The second formulation is cleaner. The `Composite_Score ≥ 2.0` lower bound on `DEGRADED` becomes implicit through R10.7's severity table (`Composite_Score < 2.0 → INFO`), and `INFO`-severity classification_mismatch findings are still findings, so they count toward `DEGRADED`.

**Alternative:** Add a more granular rule that distinguishes "MEDIUM-severity only" from "LOW-severity only" with separate ratings. Not recommended — the v1 closed five-value `PostureRating` enum (CRITICAL is COMPROMISED, etc.) does not have the granularity to support that.

---

### G4 — `classification_mismatch: CRITICAL` does not escalate `PostureRating` to `COMPROMISED`

**Location:** Requirement 17 acceptance criterion 17.5; Requirement 10 acceptance criterion 10.7.

**Issue:** R10.7 maps `Composite_Score ≥ 8.0` to `SeverityLevel.CRITICAL`. R17.5's `COMPROMISED` clause triggers only on `signature_regression: HIGH` or `missing_required_component`. A `classification_mismatch` with `Composite_Score = 9.5` (CRITICAL) → `severity = CRITICAL` finding → maps to `PostureRating.AT_RISK` (the `≥ 6.0` rule). A reader might reasonably expect the highest-severity classification mismatch to land at `COMPROMISED`, not `AT_RISK`.

**Why it matters:** Operator intent. The current rule reflects a deliberate design choice — `classification_mismatch` is "drift," `signature_regression: HIGH` and `missing_required_component` are "tampering" — and "compromised" is reserved for signs of tampering. But it could also reflect an oversight.

**Recommended resolution (option A — keep current behavior, document intent):** Amend acceptance criterion 17.5 to add a comment:

> The COMPROMISED rule is reserved for signs of tampering (signature regression to unsigned, missing-required-component). A `classification_mismatch` with `Composite_Score ≥ 8.0` (severity CRITICAL) does NOT escalate to COMPROMISED in v1; classification drift is treated as elevated risk (AT_RISK) but not as compromise. A future revision may revisit this if operational experience surfaces classification-mismatch CRITICAL events that warrant compromise treatment.

**Recommended resolution (option B — escalate CRITICAL):** Amend acceptance criterion 17.5 to extend the COMPROMISED rule:

> - `PostureRating.COMPROMISED` if any `signature_regression` finding has severity HIGH, OR any `missing_required_component` finding is emitted, OR any `classification_mismatch` finding has Composite_Score ≥ 8.0;

Option A preserves the strict tampering-vs-drift distinction. Option B treats critical classification drift as compromise. **Operator decision.**

---

## Wording

### M1 — `target_component_id` naming is misleading for `missing_required_component`

**Location:** Requirement 15 acceptance criterion 15.7.

**Issue:** The `finding_id` derivation tuple is named `(Matched_Baseline.baseline_id, finding_category, target_component_id)`. For `missing_required_component` findings, the `target_component_id` value is the unpaired baseline record's `component_id` per R8.3, not a target image's component_id (no target record matches). The math still produces a stable UUID, but the variable name is technically wrong.

**Recommended resolution:** Rename the third tuple element to `finding_subject_component_id` or similar in R15.7 prose. The acceptance-criterion wording cross-references R7.7, R8.3, etc., where the field is consumed; updating all uses is a small refactor.

**Alternative:** Leave as-is and add a footnote. Acceptable, since the formula is unambiguous.

---

### M2 — "highest-priority" in R17.5 is implicit-via-R9.10

**Location:** Requirement 17 acceptance criterion 17.5.

**Issue:** The PostureRating rule uses "the Composite_Score of the highest-priority `classification_mismatch` finding." R9.10 defines `priority_rank=1` as the highest-Composite_Score finding. So "highest-priority" reduces to `max(composite_scores)`. A reader who hasn't read R9.10 yet might be confused.

**Recommended resolution:** Replace "the Composite_Score of the highest-priority `classification_mismatch` finding" with "the maximum Composite_Score across all `classification_mismatch` findings emitted in the run."

---

### M3 — Determinism doesn't explicitly cover the cancellation-marker case

**Location:** Requirement 15 (overall); Requirement 7 acceptance criterion 7.4.

**Issue:** R7.4 says the cancellation marker carries `evidence.raw_indicators[0]` of the form `"cancelled-at-index=N"`. R7.7 derives the cancellation marker's `finding_id` from `(Matched_Baseline.baseline_id, "analysis_cancelled", sentinel_component_id)` — the index does NOT appear in the tuple. Two runs that cancel at different indices produce two reports that:

- Have the same `report_id` (R15.8 — only `(Target_Image.image_id, baseline_id, analysis_version)` is in the tuple).
- Have the same cancellation marker `finding_id` (R7.7).
- Differ in `cancellation_marker.evidence.raw_indicators[0]`.

R15.1's "equal under `model_dump(mode="json")` after stripping `timestamp`" is therefore violated by two runs that cancel at different indices, because `evidence.raw_indicators[0]` differs and is not stripped.

**Why it matters:** The determinism property is the foundation of the property-based test discipline carried forward from extraction / classification. A test that asserts "same inputs + same Analysis_Engine version → bit-equal report (modulo timestamp)" would fail if the Hypothesis strategy produces a cancellation token that fires at a different index across two runs.

**Recommended resolution:** Amend R15.1 to also strip the cancellation marker's `evidence.raw_indicators` from the equality, OR amend R15 to call out cancellation explicitly:

> Acceptance criterion 15.1 applies to runs that complete without cooperative cancellation. Cancelled runs are deterministic only modulo the `cancellation_at_index` value carried on the cancellation marker's `evidence.raw_indicators[0]`; the engine SHALL produce reports equal under `model_dump(mode="json")` after stripping both `ImageAnalysisReport.timestamp` AND, when the run was cancelled, `findings[-1].evidence.raw_indicators`.

The first formulation (strip raw_indicators on the cancellation marker only) is cleaner. **Light amendment to R15.1 is the recommended path.**

---

## Recommended HARDEN amendment

The following four-bullet edit to `requirements.md` resolves G1, G2, G3, M3 cleanly. G4 is an operator decision; M1 and M2 are aesthetics-only. Recommended HARDEN-phase amendment:

1. **R17.4** — append `whose comparison_timestamp equals ImageAnalysisReport.timestamp` after the existing field-by-field listing.
2. **R17.5** — restructure the PostureRating mapping as the four-clause "otherwise"-cascade in G3's recommended resolution. Pick option A or option B per G4 and document the choice in prose.
3. **R15.1** — amend the determinism wording to also strip the cancellation marker's `evidence.raw_indicators` when present.
4. **(optional)** apply M1's renaming of `target_component_id` to `finding_subject_component_id` in R15.7. Cosmetic.

After these edits, the doc is BIND-ready: every acceptance criterion is self-contained, the model-layer constraints are honored, the determinism property holds for both completed and cancelled runs, and the PostureRating mapping covers every input combination.

---

## What this TENSION pass did NOT find

To make the negative space explicit:

- **No conflicts** between any pair of acceptance criteria. The 20 requirements compose cleanly.
- **No missing model-layer dependencies.** Every type, enum value, and `BaselineRegistry` method the spec assumes exists in the model layer (`loki/models/{baseline,classification,enums,config,firmware,reports,analysis}.py`). This was verified by direct cross-reference.
- **No drift from the upstream subsystems' patterns.** The typed-exception hierarchy (R16), the no-side-channels audit (R15.4), the no-leakage logging contract (R20.5), the `AnalysisProgressEvent` shape (R19.2), and the cooperative-cancellation-with-partial-result contract (R1.10 + R7) all mirror extraction-pipeline / baseline-persistence / classification-pipeline. Property numbering picks up at 43 per the standing convention in `loki/HANDOFF.md`.
- **No Forbidden_Leakage_Field_Set drift.** The set in the Glossary is consistent with R20.3, R20.4, and R20.5. The `evidence.matched_signature` literals introduced by R5.5 (`"BASELINE_SIGNED"` / `"TARGET_SIGNED"`) are non-leaking constants, not derived from any forbidden field.
- **No CVE-feed entanglement.** R6 in classification (R6: `cve_matches=[]` in v1) is honored by R9.9 (`cve_introduced=False` in v1). The `feeds` subsystem (OT-LK-002) is correctly out-of-scope for this engine.
- **No fleet entanglement.** R19.7 explicitly defers `analyze_fleet`. The persisted `FleetAnalysisReport` model is correctly noted as "future spec" in the introduction.
- **No persistence entanglement.** R17.6 says the report serializes losslessly through JSON and YAML, but v1 doesn't write to disk. The `loki analyze save` / `loki analyze show` CLI surface is correctly deferred.

---

## Operator decisions queued

For HARDEN, the operator chooses:

1. **G4 — escalation policy for `classification_mismatch: CRITICAL`.** Option A (preserve tampering-vs-drift distinction; CRITICAL → AT_RISK) or option B (treat CRITICAL drift as COMPROMISED). The TENSION pass has no preference; both are defensible. The session that drafted this pass leans option A on the principle that "drift is not tampering," but option B is reasonable under "operationally, an analyst seeing a 9.5 composite score wants the most severe label."

2. **M1 — rename `target_component_id` in R15.7.** Cosmetic; no impact on engine behavior or the determinism property.

3. **G3 phrasing — pick the more elegant of the two formulations.** Both are equivalent in behavior; the four-clause "otherwise"-cascade is more readable.

Once these are settled, the amended `requirements.md` is HARDEN-ready and the next session can proceed to BIND and then to design-phase drafting.

---

*End of TENSION pass note.*


---

## HARDEN amendment landed — 2026-05-28

The operator chose **G3-A** (insert a sixth-rule DEGRADED catch-all between current rules 3 and 4 in R17.5) and **G4-B** (escalate `classification_mismatch: CRITICAL` to `PostureRating.COMPROMISED`). M1 (rename `target_component_id`) was skipped as cosmetic. M2 (explicit "max Composite_Score" wording) was not applied; the existing wording is unambiguous-via-R9.10 and reads cleanly as-is.

The HARDEN amendment to `requirements.md` consisted of three edits:

1. **R15.1 (M3 fix):** added a WHERE clause for cancelled runs that strips the Cancellation_Marker's `evidence.raw_indicators` from the determinism equality, so that two runs that cancel at different indices remain comparable. All other Cancellation_Marker fields (including `finding_id`, `category`, and `severity`) still match.

2. **R17.4 (G1 + G2 fix):** specified that `BaselineComparison.comparison_timestamp` equals `ImageAnalysisReport.timestamp`. The two timestamp fields move in lockstep, so the determinism property in R15.1 strips a single timestamp value as before, with no need to amend R15.1 for G2.

3. **R17.5 (G3-A + G4-B fix):** restructured the `PostureRating` mapping:
   - The COMPROMISED clause now also fires when any `classification_mismatch` finding has Composite_Score >= 8.0 (severity CRITICAL per R10.7).
   - A new sixth rule (a DEGRADED catch-all) was inserted: "if any finding of any category is emitted but no rule above fires," covering runs whose only findings are `unexpected_component`, `signature_regression: MEDIUM`, or `classification_gap`.
   - The `PostureRating` field is now defined for every input combination.

The amended `requirements.md` is BIND. The next session opens design.md drafting per HANDOFF.md's spec-drafting-is-its-own-conversation rule.

**Files touched in this round:**

- `loki/.kiro/specs/analysis-engine/requirements.md` (1163 → 1194 lines; three HARDEN edits to R15.1, R17.4, R17.5).
- `loki/.kiro/specs/analysis-engine/requirements-tension-pass.md` (this file; HARDEN-amendment record appended).
- `loki/loom-loki.md` (v0.1.1 → v0.2.0; analysis-engine subsystem `spec_status: DRAFT` → `APPROVED`; OT-LK-001 status updated; new evolution-log entry).
- `loki/STATE.md` (harness version + OT-LK-001 status updated).
- `STATE_AND_NEXT_STEPS.md` (workspace-level loki entry refreshed).

No source code edits. No test changes. Verification gates unchanged at 897 pytest pass / 176 mypy-strict-clean source files.
