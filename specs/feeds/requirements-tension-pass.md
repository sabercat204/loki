

# TENSION pass — feeds requirements.md

**Date:** 2026-05-29
**Reviewed file:** `requirements.md` (1712 lines, 15 EARS requirements, P59-P65)
**Reviewer's lens:** WEAVE / Loom Tier 3 — Shuttle Protocol stage TENSION (CAST → DRAFT → **TENSION** → HARDEN → FRAY → BIND).
**Outcome:** seven substantive gaps and four wording items surfaced, all derived either from the seven Forward-threads explicitly enumerated at the tail of the DRAFT or from a fresh end-to-end walk of the 15 requirements against the existing model layer (`loki/models/{config,classification,firmware}.py`) and the four shipped subsystems' patterns. None of them justify a return to DRAFT — they are HARDEN-phase decisions for the operator.

---

## How to read this note

The DRAFT is structurally complete (15 EARS-style requirements, all with `#### Acceptance Criteria` blocks, a Forward-threads section explicitly enumerating seven deferred items, no TODO / OPEN-QUESTION markers, diagnostics-clean per the spec format checker). The TENSION pass walked the DRAFT end-to-end against:

- the existing `FeedsConfig` model in `loki/models/config.py` (four fields today: `nvd_url`, `update_interval`, `cache_path`, `implant_rules_path`);
- the upstream `ClassificationRecord.cve_matches` contract (R6 of classification-pipeline; default empty list);
- the four shipped subsystems' patterns (extraction, baseline, classification, analysis-engine, classify-cli) for typed-error hierarchies, no-leakage discipline, cooperative cancellation, and CLI exit-code taxonomy;
- the project-wide carry-forward constraints (Python 3.12, mypy strict, ruff, no `fs_write` on existing files, sequential property numbering).

The findings are split into:

- **Gaps (G1–G7):** points where the DRAFT is silent, under-specified, or where the design phase could go either way without further input. Each gap is paired with a recommended resolution and an alternative.
- **Wording (M1–M4):** points where the spec is internally consistent but a reader could be misled. These are clarifications, not changes of substance.

The recommendation at the end is: **resolve G1-G7 by amendment to `requirements.md`, then HARDEN**. M1-M4 can be folded into the same amendment or deferred to design-phase prose.

The seven Forward-threads listed at the tail of the DRAFT are reproduced in this TENSION pass with concrete-resolution options, since "the TENSION pass owns the call" was the explicit DRAFT contract. Forward-thread #6 (P59-P65 property allocation) is folded into G6 because the TENSION pass concludes the allocation is sufficient as drafted; the others map to G1-G5 and G7 directly.

---

## Gaps

### G1 — NVD trust posture: signing-vs-hash-pinning verification

**Location:** Requirement 4 (trust-anchor resolution); Requirement 5.2 (FeedsSignatureError); Requirement 8.1 (HTTPS request shape). Forward-thread #1.

**Issue:** D4-D banks "key pinning" but the DRAFT carefully phrases R4 and R5.2 to cover both a signature scheme (the embedded Trust_Anchor is a public key; bundle is verified by signature check) and a hash-pin scheme (the embedded Trust_Anchor is a SHA-256 hash root; bundle is verified by hash equality). Current NVD documentation needs checking to settle which scheme is actually published. The two schemes have meaningfully different requirements:

- **Signature scheme:** Trust_Anchor file is a PEM (or equivalent stdlib-loadable) public key. R4.4 mentions PEM as the design-phase default. Bundle verification is a cryptographic signature check over the bundle bytes; the signature lives in a sibling NVD URL fetched alongside the bundle (R2.1).
- **Hash-pin scheme:** Trust_Anchor file is a small text file carrying the expected SHA-256 hash of the bundle. Bundle verification is a hash equality check; no cryptography library beyond `hashlib`.

NVD-API-key support (currently banned by Requirement 2.7) is part of this same thread. If NVD's free-tier rate limits are tighter than the v1 working assumption (hourly / daily refresh ≤ rate limit), the TENSION pass may carve out an `Authorization` header exception for an NVD-issued API key, with the no-leakage discipline of Requirement 13 amended to permit the API-key value on outbound requests only.

**Why it matters:** Implementation footprint shrinks by ~40-60 source lines if the published trust scheme is hash-pin (no `cryptography` dependency, no PEM parsing). Conversely, if NVD signs the bundle, hand-rolling signature verification with stdlib only is non-trivial and a new dependency on `cryptography` (a heavyweight, well-maintained PyPI package) becomes the design-phase default.

**Recommended resolution (option A — settle today, amend the DRAFT):** Run a one-off check against the current NVD documentation (https://nvd.nist.gov/feeds, the data-feeds documentation page), determine which scheme is published, and amend R4.4 + R5.2 to reference the chosen scheme verbatim. The other scheme's wording stays as a fallback in case NVD changes its publication shape, but the design phase commits to the current scheme. This is the smallest-meaningful-change path.

**Recommended resolution (option B — defer to design phase):** Leave R4 and R5.2 as the dual-scheme wording they are now. Design phase commits to one scheme based on the implementer's first read of NVD documentation, and the Cache_Metadata schema records the scheme in use. R4.7's "the public-key fingerprint or the hash-pin material" already covers both cases. No requirements amendment needed.

**Alternative:** Adopt a stricter posture that requires both a hash-pin and a signature when NVD provides both. This is overkill for v1; reject.

**Operator decision queued:** option A or option B. The TENSION pass has a slight preference for option B (smaller this-round footprint; the dual-scheme wording is already in the DRAFT and is structurally honest), but option A's bias toward concrete commitment is also defensible.

---

### G2 — CPE parser: dependency vs. hand-roll

**Location:** Requirement 6 (CPE-2.3 lookup shape); Requirement 6.2 (match-shape policy "pinned at design phase against current NVD documentation"). Forward-thread #2.

**Issue:** R6 pins the CPE-2.3 lookup shape but defers the question of how the Feeds subsystem parses CPE strings on the cache-population side. Two candidates:

- **Depend on `python-cpe` from PyPI.** Lightly maintained (last release 2022 per PyPI metadata at time of the v0.6.1 CAST round); license needs verification; Python 3.12 compatibility needs verification.
- **Hand-roll a minimal CPE-2.3 parser.** About 30 fields, stable spec since 2011 (NIST IR 7695). Estimated ~150-200 source lines. Cleaner dependency footprint; more code surface to maintain.

**Why it matters:** The CPE 2.3 specification is genuinely stable and the hand-rolled parser need only handle the wfn-string and wfn-fs-string forms NVD actually publishes (probably one or two of the seven CPE-2.3 string forms). The NVD JSON 2.0 feed structures CPEs as discrete fields rather than single strings on the per-record level, which further reduces hand-roll scope. The dependency option introduces a maintenance burden (Python 3.13 readiness, license tracking) for a stable problem.

**Recommended resolution:** Hand-roll a minimal parser at `loki/feeds/cpe.py`. v1 limits scope to the (vendor, product, version) triple plus the version-range qualifiers (`versionStartIncluding`, `versionEndExcluding`, etc.) that R6 mentions; additional CPE qualifiers (update, edition, language, sw_edition, target_sw, target_hw, other) are accepted in lookup queries (R6.2 mentions them as design-phase scope) but defer their match implementation to a future revision.

**Alternative:** Use `python-cpe`. Defensible if license + Python 3.12 compatibility check out; smaller this-round footprint. Reject only if maintenance velocity is too slow.

**Operator decision queued:** hand-roll vs. depend on `python-cpe`. The TENSION pass leans hand-roll for the maintenance reasons above and the project's standing preference for stdlib-only (`sqlite3` for the cache, `urllib.request` for HTTPS, etc.).

---

### G3 — Bundled-implant-rule maintenance cadence

**Location:** Requirement 7.1 (built-in starter set inventory). Forward-thread #3.

**Issue:** Requirement 7.1 specifies the starter set "SHALL include rules covering at least the publicly-documented BlackLotus, MosaicRegressor, and LoJax implants" but does not commit to a maintenance cadence for the rule set. Three candidates:

- **A. On-demand on disclosure.** New public implant disclosure → new loki release. Highest accuracy; highest release-cadence overhead.
- **B. Quarterly review.** Project commits to reviewing the starter set every quarter. Predictable cadence; risks lagging fast-moving disclosures.
- **C. Operator-extension-only with a tiny built-in set.** v1 ships only the three implants explicitly named (BlackLotus, MosaicRegressor, LoJax) and otherwise points operators at `FeedsConfig.implant_rules_path`. Smallest maintenance burden; weakest out-of-the-box utility.

Whichever cadence is chosen, the project also needs a CONTRIBUTING-doc text that documents the maintenance policy (where rules live, how to add a new rule, the rule-file schema). Without it, the future maintainer (likely the operator themselves, per HANDOFF.md's "they're the sole technical contributor to most of these projects") has no clear guidance.

**Why it matters:** The project's release cadence to date has been operator-driven, not disclosure-driven. Committing to "on-demand on disclosure" implies an ongoing watch-the-BIOS-security-news commitment that the project may not want.

**Recommended resolution:** option C (operator-extension-only with a tiny built-in set). The starter set ships with rules covering only the three implants explicitly named in R7.1. The CONTRIBUTING-doc text amends R7 with an explicit "Maintenance" sub-clause: "The built-in starter set is reviewed at the project's discretion and is NOT maintained on a fixed cadence; operators with stricter implant-detection requirements SHALL place additional rule files in `FeedsConfig.implant_rules_path`." This honors the project's smallest-meaningful-change discipline and matches the HANDOFF.md observation that maintenance burden lands on a single contributor.

**Alternative:** option B (quarterly review). Defensible if the operator wants to pre-commit to the review cadence; rejected only if the operator's bandwidth doesn't support it.

**Operator decision queued:** A, B, or C. The TENSION pass strongly prefers C.

---

### G4 — Exit-code taxonomy for the `loki feeds refresh` CLI

**Location:** Requirement 11.7 (exit-code mapping; explicitly listed as "exact codes pinned at design phase"). Forward-thread #4.

**Issue:** R11.7 lists `{0, 2, 130}` plus "non-zero (exact codes pinned at design phase)" for the three HARD FAIL branches and the propagated network failure. The closed-set decision belongs at design phase, mirroring classify-cli's `{0, 2, 3, 4, 5, 6, 130}` pattern.

Two candidates for the closed set:

- **A. Distinct codes per failure type.** ``{0, 2, 3, 4, 5, 6, 130}``:
   - 0 success or WARN_STALE on inline-refresh path (the latter not reachable from the explicit CLI per R11.7's note).
   - 2 bad input (config file missing, unreadable, invalid CLI argument).
   - 3 FeedsSignatureError (HARD FAIL — security event).
   - 4 FeedsCacheError partial-download flavor (HARD FAIL — data integrity event).
   - 5 FeedsCacheError write-failure flavor (HARD FAIL — disk / SQLite event).
   - 6 FeedsNetworkError (explicit-refresh path; CI script knows network was the reason).
   - 130 SIGINT received and cancellation honored.
- **B. Collapsed catchall.** ``{0, 2, 4, 130}``:
   - 0 success.
   - 2 bad input.
   - 4 catchall non-zero failure (signature, cache write, partial download, network).
   - 130 SIGINT.

**Why it matters:** Option A gives CI scripts fine-grained branching at the cost of more distinct codes to remember; option B gives one error code at the cost of script authors having to parse stderr for the failure category. Option A is the more conservative "set it now" choice; option B is the more conservative "fewer surfaces to break" choice.

**Recommended resolution:** option A with the seven-code mapping above. This mirrors classify-cli's exit-code shape almost exactly (classify-cli uses `{0, 2, 3, 4, 5, 6, 130}` with different semantics per code; the feeds analog reuses the cardinality and the SIGINT code). Stable scripting surface.

**Alternative:** option B. Defensible if the operator wants the smallest possible surface area.

**Operator decision queued:** A or B. The TENSION pass leans A for the cardinality consistency with classify-cli.

---

### G5 — `FeedsConfig` model migration field name and behavior

**Location:** Requirement 4.1 (Trust_Anchor resolution); Requirement 4.3 (`FeedsConfig.signing_key_path` non-`None` branch). Forward-thread #5.

**Issue:** D4-D specifies adding `signing_key_path: str | None = None` to `FeedsConfig` (currently four fields: `nvd_url`, `update_interval`, `cache_path`, `implant_rules_path`). The DRAFT treats the field as if it already exists. Two minor sub-questions:

- **Field name:** `signing_key_path`, `trust_anchor_path`, or `verification_key_path`? The DRAFT uses `signing_key_path` throughout; this is consistent with the v0.6.1 CAST notes. But if G1 resolves toward hash-pinning rather than signature verification, "signing key" is technically a misnomer — a hash-pin file is not a signing key.
- **Behavior on empty string:** if the operator's YAML config sets `signing_key_path: ""` (empty string), should the Feeds subsystem treat that as `None` (use the package-embedded default) or as an invalid path (raise `FeedsConfigError`)? The DRAFT R4.4 implicitly handles `None` and "non-`None` invalid path" cases but is silent on the empty-string case.

**Why it matters:** The field name is renameable cheaply during this round. Renaming after implementation requires a backward-compatibility shim in `LokiConfig.from_yaml` and a deprecation cycle. The empty-string behavior is a one-line check in the resolver.

**Recommended resolution:**

- **Field name:** rename to `trust_anchor_path: str | None = None`. This is scheme-agnostic (works whether the trust anchor is a signing key, a hash pin, or a future hybrid). Amend R4 and R13.1 references throughout. Amend the Glossary's Trust_Anchor entry to note the field name.
- **Empty-string behavior:** treat `""` as equivalent to `None` (use the package-embedded default). Document in R4.4 with one additional acceptance criterion.

**Alternative (field name):** keep `signing_key_path`. Defensible if G1 resolves toward signature scheme; ambiguous if G1 resolves toward hash-pinning.

**Alternative (empty-string):** raise `FeedsConfigError` on `""`. Stricter; surfaces a YAML-level typo earlier; rejected because it punishes operators whose YAML serialization library round-trips `None` to `""`.

**Operator decision queued:** field-name rename y/n. The empty-string-as-None recommendation is non-controversial.

---

### G6 — Property numbering allocation (P59-P65) confirmed sufficient

**Location:** Requirement 15 (Property-based test contracts); Forward-thread #6.

**Issue:** Forward-thread #6 asks the TENSION pass to confirm that no important property is missing and that no two properties test the same surface redundantly. Walking R15.1 through R15.7 against the rest of the DRAFT:

- **P59 lookup determinism** (R15.1) — pinned. Tests `cve_lookup` determinism for byte-equal results across two invocations with the same query and Cache_DB.
- **P60 implant-lookup determinism** (R15.2) — pinned. Same for `implant_rule_lookup`.
- **P61 HTTPS-request leakage** (R15.3) — pinned. Tests no Forbidden_Leakage_Field_Set member appears in captured outbound requests.
- **P62 Cancel_Flag-driven cancellation contract** (R15.4) — pinned. Deterministic in-process test plus separate example-based subprocess test for SIGINT end-to-end.
- **P63 Stderr_Summary_Line emission discipline** (R15.5) — pinned. Mirrors classify-cli's P57 four-case parameterized.
- **P64 no-leakage on stderr and stdout** (R15.6) — pinned. Mirrors classify-cli's P58.
- **P65 CVE-result sort stability** (R15.7) — pinned. Tests lexicographic ascending sort.

**Candidate missing properties:**

- **Inline-refresh trigger on stale cache.** R3.4 specifies the inline trigger fires when `now() - last_refresh_at >= Update_Interval`. No P59-P65 property exercises this surface explicitly. A "P66 inline-refresh trigger" would: construct a Cache_DB with a stale `last_refresh_at`, monkey-patch the network transport to record fetch attempts, invoke `cve_lookup(allow_refresh=True)`, and assert the fetch attempt is observed. **Worth adding.**
- **Cache atomicity under failure.** R3.10 says a failed refresh leaves the Cache_DB unchanged. No property exercises this. A "P67 cache atomicity" would: populate the Cache_DB with a known set, simulate a failure mid-refresh (e.g. Trust_Anchor failure after the bundle is fetched), and assert the prior contents remain. **Worth adding.**
- **Tiered failure semantics on inline path.** R5.4 says network/server failure on the inline path WARNs and continues; signature + partial-download are HARD FAIL. No property exercises the WARN-vs-HARD path branching. A "P68 tiered inline-refresh failure" would parameterize over the three failure modes and assert the correct branch fires. **Worth adding.**

**Why it matters:** The property-based test discipline is the project's primary correctness contract. Three additional properties (P66-P68) cost ~100 test lines and pin three semantic contracts that R15 currently leaves to example-based tests.

**Recommended resolution:** extend R15 with three additional acceptance criteria — P66 inline-refresh trigger, P67 cache atomicity, P68 tiered-failure-mode branching. Property numbering for the next subsystem becomes P69 (rather than P66 as the DRAFT pre-states). Amend R15.8 to record the new starting point.

**Alternative:** leave the property allocation at P59-P65; cover the three candidates with example-based tests instead. Defensible if the operator wants a smaller property surface; rejected because property-based discipline is the project's stated bar and these three properties are clearly testable as Hypothesis strategies.

**Operator decision queued:** extend to P59-P68 (three additional properties) y/n. The TENSION pass strongly prefers extending.

---

### G7 — FULL-context audit work shape

**Location:** Requirement 8 (FULL threat-context discipline); Requirement 13 (no-leakage discipline). Forward-thread #7.

**Issue:** R8.3 + R8.4 specify a paired AST audit and dynamic request-capture audit (`test_no_request_leakage_ast.py` + `test_no_request_leakage_dynamic.py`). R13.6 specifies a paired log audit pair (`test_no_log_leakage.py` + `test_log_no_leakage.py`). Forward-thread #7 asks the TENSION pass to confirm whether v1 also needs a runtime certificate-chain validation audit to pin R8.7 (mandatory TLS verification) and whether the four audits should be gated behind the slow-marker.

**Why it matters:** Slow-marker tests are excluded from the default `pytest -q` run (per `pyproject.toml`'s `addopts = "-ra --strict-markers -m 'not slow'"`). Putting the audits behind slow-marker means they don't run in the default CI / dev loop, which weakens the FULL-context discipline. Putting them in the default suite means every dev iteration runs an HTTPS-transport monkey-patch + AST walk, which is fast in absolute terms (hundreds of milliseconds at most) but still adds to the test suite's wall-clock baseline.

**Candidate audits beyond the four already in the DRAFT:**

- **Runtime certificate-chain validation.** A test that constructs the Feeds subsystem's `ssl.SSLContext` and asserts `verify_mode == ssl.CERT_REQUIRED` and `check_hostname == True`; this pins R8.7 statically. Cheap (~20 test lines).
- **Redirect-host-match policy.** A dynamic test that simulates a cross-origin redirect (e.g. NVD URL redirects to `evil.example`) and asserts the Feeds subsystem rejects it with `FeedsNetworkError`; this pins R8.6. Cheap (~30 test lines).

**Why it matters:** R8.6 and R8.7 are FULL-context security contracts. Without explicit tests they are at risk of regression on a future implementation refactor.

**Recommended resolution:** extend R13.6 (the four-audit list) to a six-audit list:

1. `tests/feeds/test_no_log_leakage.py` (static AST audit on log records).
2. `tests/feeds/test_log_no_leakage.py` (dynamic caplog audit on log records).
3. `tests/feeds/test_no_request_leakage_ast.py` (static AST audit on outbound HTTPS requests).
4. `tests/feeds/test_no_request_leakage_dynamic.py` (dynamic request-capture audit on outbound HTTPS requests).
5. **NEW:** `tests/feeds/test_tls_verification.py` (runtime SSLContext audit pinning R8.7).
6. **NEW:** `tests/feeds/test_redirect_policy.py` (dynamic redirect-host-match audit pinning R8.6).

All six audits run in the default `pytest -q` baseline (NOT gated behind slow-marker). The dynamic-request-capture and redirect-policy audits use a synthetic local fixture (no real network); the SSL-context audit is a fixture-only test; the AST audits parse modules. None of the six need network access, real NVD endpoints, or a pre-populated Cache_DB.

**Alternative:** keep four audits; leave the TLS-verification and redirect-policy contracts to design-phase example tests. Defensible if the operator wants to keep R13.6's audit count low; rejected because R8.6 and R8.7 are exactly the FULL-context contracts the audit pair was supposed to pin.

**Operator decision queued:** extend to six audits y/n. The TENSION pass strongly prefers extending.

---

## Wording

### M1 — `FEEDS_VERSION` cross-reference in R14.5 is ambiguous

**Location:** Requirement 14.5.

**Issue:** "The ``FEEDS_VERSION`` constant SHALL appear in the Stdout_Refresh_Status JSON per Requirement 11.4 and in the ``loki feeds --version`` output (or its equivalent; the design phase pins the version-disclosure CLI surface)." The "or its equivalent" hedge is vague. classify-cli's analogous version-disclosure flag is `loki classify --help` (the program version surfaces via `argparse`'s `version` action, not via a dedicated `--version` subcommand). The DRAFT should commit to one of: `loki feeds --version`, `loki feeds version`, or "the project-wide version flag on the top-level `loki` dispatcher."

**Recommended resolution:** Replace R14.5 with: "The ``FEEDS_VERSION`` constant SHALL appear in the Stdout_Refresh_Status JSON per Requirement 11.4 and in the output of the project-wide top-level version flag on `loki` (the design phase pins the exact flag form, mirroring whatever surface classify-cli and `loki extract` use today)." Removes the false-precision "loki feeds --version" reference.

**Alternative:** leave as-is. Acceptable since "or its equivalent" is honest hedge.

---

### M2 — "v1 working-set assumption" repeated three times in R12 without a centralized note

**Location:** Requirement 12.1, 12.2, 12.3.

**Issue:** R12.1 says "up to 200,000 CVE records (a v1 working-set assumption pinned at design phase)". R12.2 says "up to 1,024 rules (a v1 working-set assumption pinned at design phase)". R12.3 says "up to 100 MiB (a v1 working-set assumption pinned at design phase)". The pattern repeats three times. A reader could miss that "design phase" owns the calibration of all three values together.

**Recommended resolution:** Add a short note at the top of R12 (before the acceptance criteria) reading: "The three working-set figures in this requirement (200,000 CVE records, 1,024 implant rules, 100 MiB bundle size) are v1 design-phase calibrations. Operators with larger working sets MAY surface a slow-marker performance regression that prompts a future revision to extend the bounds. The figures are non-normative for the lookup and refresh APIs themselves; the APIs SHALL function correctly above and below the cited bounds, but the wall-clock budgets are tied to the cited working-set sizes." Cleans up three repeated parenthetical hedges.

**Alternative:** leave as-is. Acceptable; cosmetic.

---

### M3 — `FEEDS_VERSION` strict-versioning rules in R14.1 use loose phrasing

**Location:** Requirement 14.1.

**Issue:** "Major bump on a breaking change to the FeedRegistry public API, the Cache_DB schema, or the trust-anchor format; minor bump on a backward-compatible feature addition; patch bump on a bug fix or documentation change with no API or schema effect." The phrasing is fine for SemVer but does not specify what counts as a "breaking change to the trust-anchor format." If G1 resolves toward dual-scheme support (signature + hash-pin), is adding hash-pin support after a signature-only v1 a major bump?

**Recommended resolution:** Add an inline example: "Adding a new trust-anchor scheme (e.g. extending v1's <chosen-scheme> with the alternative scheme as a fallback) is a minor bump because existing callers are unaffected. Replacing or removing v1's trust-anchor scheme entirely is a major bump."

**Alternative:** leave as-is. Acceptable; the SemVer rules are conventional.

---

### M4 — `Forbidden_Leakage_Field_Set` enumeration in R13.1 is comma-heavy

**Location:** Requirement 13.1.

**Issue:** R13.1 enumerates six Forbidden_Leakage_Field_Set members (a) through (f) in a comma-heavy single sentence. classify-cli's analogous Glossary entry is more readable as a bulleted list.

**Recommended resolution:** Reformat R13.1 as six numbered bullets (one per Forbidden_Leakage_Field_Set member). No semantic change; readability only.

**Alternative:** leave as-is. Acceptable; the enumeration is unambiguous.

---

## Recommended HARDEN amendment

The following multi-bullet edit to `requirements.md` resolves G1-G7 cleanly. M1-M4 are aesthetics-only and can be folded in or deferred. Recommended HARDEN-phase amendment:

1. **R4 + R5.2 (G1):** apply option A or B per operator decision. Option A amends R4.4 and R5.2 to reference the chosen NVD trust scheme (signature or hash-pin) verbatim. Option B leaves R4 and R5.2 as the dual-scheme wording.
2. **R6 (G2):** add a note (or extend an acceptance criterion) committing to hand-roll vs. `python-cpe`. Recommended: hand-roll, scope limited to `(vendor, product, version)` plus version-range qualifiers.
3. **R7 (G3):** apply option A, B, or C per operator decision. Recommended: option C, with an explicit "Maintenance" sub-clause amending R7.
4. **R11.7 (G4):** apply option A or B per operator decision. Option A pins the seven-code closed set `{0, 2, 3, 4, 5, 6, 130}`. Option B pins the four-code closed set `{0, 2, 4, 130}`.
5. **R4 + R13.1 + Glossary (G5):** rename `signing_key_path` to `trust_anchor_path` if the operator agrees; document `""` as equivalent to `None` in R4.4.
6. **R15 (G6):** extend with three additional acceptance criteria — P66 inline-refresh trigger, P67 cache atomicity, P68 tiered-failure-mode branching. Update R15.8's "future specs pick up at" anchor from P66 to P69.
7. **R13.6 (G7):** extend to six audits; add R8.7-anchor `test_tls_verification.py` and R8.6-anchor `test_redirect_policy.py`.
8. **(optional)** apply M1's "or its equivalent" cleanup, M2's centralized R12 note, M3's trust-anchor SemVer example, and M4's R13.1 bulletized reformat.

After these edits, the DRAFT is BIND-ready: every requirement's design-phase scope is explicit, the Forward-threads section can shrink to "all seven items resolved by the TENSION pass," and the property allocation pins three additional FULL-context contracts.

---

## What this TENSION pass did NOT find

To make the negative space explicit:

- **No conflicts** between any pair of acceptance criteria. The 15 requirements compose cleanly.
- **No missing model-layer dependencies.** Every type the spec assumes (`FeedsConfig`, `ClassificationRecord.cve_matches`, `ExtractedComponent`, `LOKI_NAMESPACE`) exists in `loki/models/` today. The one model-layer migration the DRAFT calls out (adding `signing_key_path` / `trust_anchor_path` per G5) is the only model change v1 needs.
- **No drift from the upstream subsystems' patterns.** The typed-exception hierarchy (R5.1), the cooperative-cancellation contract (R9), the `--summary-only` opt-out (R11.5), the no-leakage discipline (R13), the property-numbering convention (R15), and the SemVer commitment (R14.1) all mirror analysis-engine / classification-cli verbatim.
- **No CVE-feed entanglement with the upstream classification library.** R6.6 explicitly says the consumer takes the `CVE_Lookup_Result` and writes the CVE identifier strings into `cve_matches` per its own policy. The Feeds subsystem provides the lookup API; consumer wiring is correctly out-of-scope.
- **No fleet entanglement.** No mention of `FleetAnalysisReport` or `analyze_fleet`. The Feeds subsystem is at the right level of abstraction.
- **No persistence entanglement beyond the Cache_DB.** The Feeds subsystem owns its SQLite cache and the package-embedded trust-anchor file. Operator-supplied trust-anchor and operator-supplied implant-rules are read-only from the Feeds subsystem's perspective. No GUI, no shared state with extraction or baseline.
- **No threat-context drift.** D8-B's FULL-context discipline is encoded in R8 and R13 with paired AST + dynamic audits. The TLS verification and redirect-host-match policies are explicit (R8.6, R8.7). The pattern is internally consistent.
- **No determinism gap on the lookup paths.** R10.1, R10.2, and R10.4 cover both `cve_lookup` and `implant_rule_lookup` for the `allow_refresh=False` path; the inline-refresh path's determinism is explicitly carved out (R3.4 + R5.4) because network egress breaks pure-function semantics by definition.

---

## Operator decisions queued

For HARDEN, the operator chooses (smallest-to-largest impact):

1. **G5 — `signing_key_path` → `trust_anchor_path` rename.** Rename y/n. The empty-string-as-None policy is non-controversial; recommend yes.
2. **M1-M4 — wording cleanups.** Apply / skip, individually or as a block. Recommend "apply M1 + M4; skip M2 + M3."
3. **G3 — implant-rule maintenance cadence.** A (on-disclosure), B (quarterly), or C (operator-extension-only with tiny built-in set). Recommend C.
4. **G6 — extend property allocation P59-P65 to P59-P68.** y/n. Recommend yes.
5. **G7 — extend audit suite from four to six audits.** y/n. Recommend yes.
6. **G2 — CPE parser dependency vs. hand-roll.** dep-on-`python-cpe` or hand-roll. Recommend hand-roll.
7. **G4 — exit-code taxonomy.** option A (`{0, 2, 3, 4, 5, 6, 130}`) or option B (`{0, 2, 4, 130}`). Recommend A.
8. **G1 — NVD trust posture verification.** option A (settle today by checking NVD documentation; commit to scheme) or option B (defer to design phase; keep dual-scheme wording). Recommend B.

Once these are settled, the amended `requirements.md` is HARDEN-ready and the next session (within this conversation per operator's "top to bottom" decision) proceeds to design BIND.

---

*End of TENSION pass note.*
