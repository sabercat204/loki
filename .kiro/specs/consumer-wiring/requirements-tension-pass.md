
# TENSION Pass — Consumer Wiring Spec

Review date: 2026-05-29

## Substantive Gaps

### G1: `derive_cve_query` requires `source_image` but pipeline loop has only `component`

**Problem:** R1.3 says "derive the CVELookupQuery using
`derive_cve_query(record, source_image)`." The classification
pipeline's inner loop (`pipeline.py:115`) iterates components but
does NOT currently have access to the `source_image` (the
`FirmwareImage` that produced the manifest). The `ExtractionManifest`
carries `source_image`, but `classify_components` takes only
`Sequence[ExtractedComponent]`, not the manifest.

**Impact:** If not resolved, the pipeline cannot call
`derive_cve_query` without an API change to pass the source image.

**Options:**
- **G1-A:** Add an optional `source_image: FirmwareImage | None = None`
  kwarg to `classify_components`. When `feeds` is provided,
  `source_image` is required (raise `ClassificationConfigError` if
  `feeds` is set but `source_image` is None).
- **G1-B:** Change `derive_cve_query` to accept vendor/product/version
  strings directly (derive from the `ClassificationRecord` axis labels
  and a static version, without needing the image). This avoids the
  API surface growth but loses the firmware_version context.
- **G1-C:** Accept the full `ExtractionManifest` instead of the
  component sequence. Breaking change to v1 API — too invasive.

**Recommendation:** G1-A. The `source_image` kwarg is opt-in and
only consulted when `feeds` is set. It mirrors the analysis engine's
approach (which takes `target_image` as a parameter).

### G2: `matched_cve` selection uses "highest-CVSS" but CVSS data is not on `cve_matches`

**Problem:** R2.1 says "highest-CVSS-score CVE ID from
`cve_matches`." But `ClassificationRecord.cve_matches` is
`list[str]` (just CVE IDs, not `CVEMatch` objects). The CVSS
data lives in the `CVELookupResult.matches` (which are
`CVEMatch` dataclass instances with `cvss_v3_score`), but that
object is not persisted on the `ClassificationRecord`.

**Impact:** The analysis engine cannot pick the highest-CVSS entry
from the ID list alone without re-querying the feeds cache.

**Options:**
- **G2-A:** Change `cve_matches` from `list[str]` to a richer type
  (e.g. `list[CVEMatchSummary]` with id + score). Model-layer
  breaking change — all existing tests that assert `cve_matches=[]`
  would need updating.
- **G2-B:** Use lexicographic-first as the selection rule for v1 of
  consumer-wiring (deterministic, stable, no model change). Document
  the CVSS-based selection as a deferred improvement that requires
  either enriching `cve_matches` or giving the analysis engine its
  own feeds access.
- **G2-C:** Store the CVE list as `list[str]` but also store the
  "worst CVE ID" on the record itself as a separate field. Additional
  model-layer extension.

**Recommendation:** G2-B. Lex-first is deterministic and avoids a
model-layer breaking change. The CVSS-based improvement can land in
a future spec that enriches `cve_matches` or adds a
`worst_cve: str | None` field.

### G3: `cve_score_bump` addition to composite score may change PostureRating thresholds

**Problem:** R2.4 says "add `cve_score_bump` to the raw
Composite_Score BEFORE clamping." The PostureRating six-rule
cascade (analysis R17.5) uses composite_score thresholds:
`>= 8.0` → COMPROMISED, `>= 6.0` → AT_RISK, `>= 2.0` →
DEGRADED. A 0.5 bump could push a 7.5 finding (AT_RISK) to 8.0
(COMPROMISED). Is this the intended escalation behavior?

**Impact:** Operators may be surprised if a CVE introduction alone
pushes a finding across a posture threshold boundary.

**Options:**
- **G3-A:** Accept — this IS the intended behavior. A CVE
  introduction is a material escalation and should push findings
  upward in severity. Document the cascade interaction explicitly.
- **G3-B:** Apply the bump only to the DeviatioScore but NOT
  propagate it to the PostureRating derivation (add the bump after
  posture is computed). More complex, less intuitive.

**Recommendation:** G3-A. The whole point of the bump is to
escalate. Document the cascade interaction in the design's D4
section so operators understand the implication.

### G4: Missing `source_image` on baseline records for CVE comparison

**Problem:** R2.2 says "compare target's cve_matches against the
paired baseline record's cve_matches." But baseline records were
classified under the OLD spec (v1, where `cve_matches=[]` always).
This means every comparison will see `baseline.cve_matches=[]` for
ALL existing baselines, so `cve_introduced` will ALWAYS be `True`
whenever the target has any CVE matches.

**Impact:** Operators who reclassify against new feeds will see
every CVE match flagged as "introduced" because their baselines
don't carry CVE data.

**Options:**
- **G4-A:** Accept for v1. Document that baselines must be
  regenerated (re-classified) with feeds enabled to get meaningful
  `cve_introduced` comparisons. This is the expected bootstrap
  behavior.
- **G4-B:** Special-case the comparison: if
  `baseline.cve_matches == []`, treat it as "unknown" rather than
  "had no CVEs" and set `cve_introduced=False`. This avoids the
  bootstrap noise but loses real detection when baselines genuinely
  had zero CVEs.

**Recommendation:** G4-A. Accept the bootstrap behavior and
document it. Operators regenerate baselines with feeds-enabled
classification to get accurate comparisons. The alternative
(G4-B) swallows real introductions.

## Wording Items

### M1: R1 acceptance criterion 1 says "FeedsConfig (or a pre-constructed FeedRegistry)"

The actual API takes `FeedRegistry | None`, not `FeedsConfig`. The
parenthetical is misleading — clean up to say only `FeedRegistry`.

### M2: Design says "highest-CVSS" but implementation will use lex-first

The design section says "highest-CVSS CVE from
target_record.cve_matches" but the tasks and notes say lex-first.
Reconcile: the design should say "lexicographically-first" for v1,
with a note that CVSS-based selection is deferred per G2-B.

### M3: R6.2 says "O(1) in the size of cve_matches"

Set intersection on two lists of length N and M is O(min(N,M)),
not O(1). Should say "O(N) where N = max(len(target.cve_matches),
len(baseline.cve_matches))" — but since N is typically <= 5 in
practice, the characterization is "bounded constant for realistic
inputs."

## Summary

| Gap | Severity | Recommendation |
|-----|----------|----------------|
| G1  | HIGH — blocks implementation | G1-A: add `source_image` kwarg |
| G2  | MEDIUM — affects correctness claim | G2-B: lex-first for v1 |
| G3  | LOW — intended behavior | G3-A: accept and document |
| G4  | MEDIUM — affects usability | G4-A: accept and document bootstrap |
| M1  | Wording | Fix to say `FeedRegistry` only |
| M2  | Wording | Reconcile to lex-first |
| M3  | Wording | Fix complexity characterization |
