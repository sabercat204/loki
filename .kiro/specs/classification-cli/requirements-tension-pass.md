
# Requirements TENSION pass — classification-cli

**Spec:** `.kiro/specs/classification-cli/requirements.md` (DRAFT, 2026-05-28)
**Pass date:** 2026-05-28
**Pass type:** End-to-end TENSION on the DRAFT before HARDEN.
**Scope:** Walk every requirement against the upstream contracts (the
classification library at `loki/classification/`, the model layer at
`loki/models/`, the upstream classification spec at
`.kiro/specs/classification-pipeline/requirements.md`, the existing CLI
patterns at `loki/cli.py`) and surface gaps, citation drift, and
spec deviations before HARDEN.

## What was checked

- The CLI spec's cross-references to the upstream
  classification-pipeline spec — every "R*N.M*" cited.
- The CLI spec's claims about the live library API
  (`classify_components`, `ProgressEvent`, `ClassificationError`,
  `ClassificationResult`, `ClassificationPipelineError` subclasses).
- The CLI spec's claims about the model layer
  (`ExtractionManifest`, `ClassificationRecord.needs_review`,
  `ClassificationRecord.timestamp`).
- The CLI spec's banked design decisions (D1-A through D12-A plus the
  two new flags) against the requirement bodies.
- Determinism, no-leakage, and exit-code totality claims.
- EARS phrasing correctness across all 13 requirements.

## Findings: substantive gaps requiring HARDEN-phase resolution

### G1 — Citation: "Requirement 13.5 of classification-pipeline" is correct in number, off in wording

The CLI spec cites "Requirement 13.5 of classification-pipeline" three
times (Reqs 7.6, 10.5, Glossary entry for `Forbidden_Leakage_Field_Set`)
as the authoritative definition of the Forbidden_Leakage_Field_Set.

**Verified.** Upstream R13.5 reads:

> THE Classification_Pipeline SHALL NOT, at any time, log any member
> of the Forbidden_Leakage_Field_Set:
> `ExtractedComponent.component_id` or its mirrored
> `ClassificationRecord.component_id`, `SignatureInfo.signer`, the
> parent `BaselineRecord.source_image_hash`, or any value carried in
> `AxisClassification.evidence`.

The CLI's Glossary entry omits one half of the upstream definition: the
mirror on `ClassificationRecord.component_id`. The CLI Glossary lists
"the `ExtractedComponent.component_id` (and its mirror on
`ClassificationRecord`)" — which reads as if `ClassificationRecord`
itself is the mirror, but the upstream phrasing is more precise:
`ClassificationRecord.component_id` is the mirrored field. Cosmetic
gap; HARDEN should track the upstream phrasing exactly.

**Recommended fix:** in the CLI Glossary's
`Forbidden_Leakage_Field_Set` entry, change
`"the ExtractedComponent.component_id (and its mirror on
ClassificationRecord)"` to `"ExtractedComponent.component_id and its
mirrored ClassificationRecord.component_id"`. Same change in Req
10.1 (which omits `ClassificationRecord.component_id` entirely from
its enumeration of forbidden fields, listing only `signer`,
`source_image_hash`, and `evidence`).

### G2 — Req 4.2's `<R>` rules-loaded count: the library DOES expose it, contrary to the spec's "if the library does not currently expose this count" hedge

The CLI's Req 4.2 introduces `<R>` (rules loaded) and includes a
fallback clause:

> if the library does not currently expose this count, the
> Classification_CLI SHALL NOT fabricate or estimate it but SHALL
> surface the integer ``0`` rather than crash, and a follow-up
> library change SHALL be tracked separately.

**The hedge is wrong.** The library does expose the rule count via
`ClassificationPipeline._rules.rules` — see
`loki/classification/pipeline.py:84` where the same count is logged
into the pipeline-construction INFO record:
`len(self._rules.rules)`. The pipeline also exposes a sibling
`self._rules.sources` (count of YAML files loaded).

But there's a real underlying tension the subagent was reaching for:
**`ClassificationPipeline` is internal to the subsystem (see
`api.py:128` "The internal coordinator … is not part of the public
surface")**, and the public free function `classify_components`
returns only `ClassificationResult` — which carries no
`rules_loaded` field. So the count exists but is not on the public
surface the CLI is contracted to consume.

Three options:

- **G2-A: Extend the public surface.** Add a `rules_loaded: int`
  field to `ClassificationResult` (the simplest extension, since
  the dataclass is the natural carrier). The CLI reads
  `result.rules_loaded` and surfaces it as `<R>`. Requires a
  library change AND a back-compatible `__init__` default. Touches
  the upstream classification spec's R10 (Result construction and
  validation) — would need a coordinated amendment.
- **G2-B: Drop `<R>` from the Stderr_Summary_Line for v1.** The
  remaining four counts (`<N>`, `<K>`, `<E>`, `<S>`) are all
  derivable from `ClassificationResult` directly. `<R>` is
  diagnostic, not contractual. Defer to a future revision when the
  rule count lives on the public surface anyway.
- **G2-C: Reach into the internal pipeline.** The CLI imports
  `ClassificationPipeline` directly and calls
  `len(pipeline._rules.rules)`. This is a layering violation —
  the upstream spec's R12.4 explicitly says the CLI surface for
  classification is a separate spec; reaching into a private
  attribute would entangle the two.

**Recommended:** G2-B for v1, with the `<R>` field deferred. The
Stderr_Summary_Line shape becomes:

`classify: <N> records (<K> need_review), <E> errors, duration=<S>s`

If/when the public surface grows a rules-loaded count (likely
alongside the analysis-engine pattern of exposing version
constants), the spec amendment is small. The hedge in the
current spec ("surface 0 rather than crash") leaves an
operationally meaningless metric in the line forever; G2-B avoids
that.

### G3 — Req 5.2's "on each invocation by the library" is correct but the spec elsewhere says "per component" — they aren't equivalent

The CLI's Req 5 talks about Progress_Line emission. Req 5.2 says:

> ... that, on each invocation by the library, writes exactly one
> Progress_Line ...

And the Glossary says:

> **Progress_Line**: One line per `ProgressEvent` written to stderr
> while `--progress` is enabled ...

These are accurate. But Req 5's User Story says:

> ... that streams one line per component to stderr ...

Pipeline implementation (`pipeline.py:213-228`) reveals: the progress
callback fires only on successfully-classified components.
Per-component error paths use `continue` and skip the progress call.
Same applies to the dual-record (R5.6) success path — that one DOES
fire progress because the record is successfully built before the
emit. But a component whose four-axis evaluation crashes never
generates a ProgressEvent.

Upstream classification spec R12.1 also says progress is invoked "at
component granularity" — this is the same imprecision baked into the
upstream contract. So the CLI is faithful to the upstream phrasing.
Still, the User Story's "one line per component" is misleading.

**Recommended fix:** in Req 5's User Story, change
`"streams one line per component to stderr"` to
`"streams one line per successfully-classified component to stderr"`,
and add a clarifying acceptance criterion (call it 5.8) that says:
"THE Classification_CLI SHALL NOT, in v1, emit a Progress_Line for
components whose classification fails (i.e. the per-component error
path that records a `ClassificationError` and continues without
producing a `ClassificationRecord`); the upstream library's
`progress` callback contract per R12.1 of classification-pipeline
fires only on records, and the Classification_CLI mirrors that
behavior without modification."

This is honest about the v1 contract and prevents downstream tools
from assuming Progress_Line count == input component count.

### G4 — Req 6.7 quotes the Cancellation_Marker's `component_id` as None — verified, but the spec adds a behavioral claim ("because cancellation is a whole-run condition") not in upstream R1.9

The CLI's Req 6.7 says:

> ... its `component_id` is `None` (because cancellation is a
> whole-run condition, not a per-component failure); the
> Classification_CLI SHALL NOT inject, mutate, or reorder this
> record.

**Verified the `component_id` is None** — `pipeline.py:120` sets
`component_id=None` on the cancellation marker. **The parenthetical
explanation, however, is the CLI spec's own commentary, not text
from upstream R1.9.** Upstream R1.9 says only that the marker has
`error_message == "classification cancelled by caller"`; it does
NOT explicitly state `component_id is None`. The implementation
sets it to None as an implementation detail.

This is a minor gap. The CLI spec is contracting against
implementation behavior rather than against an explicit upstream
guarantee. Two ways to resolve:

- **G4-A: Keep the assertion, but cite the implementation.** Change
  Req 6.7's parenthetical from "(because cancellation is a
  whole-run condition, not a per-component failure)" to
  "(consistent with the implementation's
  `component_id=None` cancellation-marker construction at
  `loki/classification/pipeline.py`)". This is honest about where
  the contract lives.
- **G4-B: Push the assertion upstream.** Open a small spec
  amendment on `classification-pipeline` adding to R1.9: "the
  marker's `component_id` SHALL be `None`". Then the CLI's Req 6.7
  becomes a faithful reflection of an upstream contract rather
  than a behavioral overlay.
- **G4-C: Soften the assertion.** Change "its `component_id` is
  `None`" to "its `component_id` value matches whatever the
  upstream library produces for cancellation markers (currently
  `None`)". Less rigid but preserves the don't-mutate clause.

**Recommended:** G4-B if the upstream spec is amendable in this
session (a one-line fix to R1.9 of classification-pipeline). G4-A
otherwise. G4-C is the weakest option.

### G5 — Req 7.3 "no handler attached at the time" is too narrow; the realistic check is "no handler that would route DEBUG records to a visible sink"

The CLI's Req 7.3 (the `--debug` flag) says:

> WHEN ``--debug`` is set and the ``loki.classification`` logger
> has no handler attached at the time the Classification_CLI is
> invoked, THE Classification_CLI SHALL attach a
> ``logging.StreamHandler`` writing to ``sys.stderr`` for the
> duration of the run and SHALL detach it after the run ...

Python logging propagation means a logger with no direct handlers
can still emit visible output: records propagate up to the root
logger, which (under default `logging.basicConfig()`) has a
StreamHandler at WARNING level. So "no handler attached" doesn't
mean "DEBUG records won't appear" — they might still surface
through the root handler at WARNING+ but not below.

The user-visible question is: did `--debug` actually surface
DEBUG-level output? The current Req 7.3 contract attaches a handler
ONLY when `loki.classification` has nothing locally; if root has a
DEBUG-level handler, attaching another would double-log; if root
has only WARNING+, DEBUG records are silently dropped.

Three options:

- **G5-A: Always attach when `--debug` is set, set propagation to
  False for the duration.** Guarantees the user sees DEBUG output
  exactly once. Cost: shadows externally-attached handlers for the
  duration.
- **G5-B: Always attach when `--debug` is set, leave propagation
  alone.** Risk of double-logging if root also has a handler at
  DEBUG level.
- **G5-C: Detect effective level via
  `logger.getEffectiveLevel()` and attach only if no upstream
  handler would catch DEBUG.** Most surgical; most complex.
- **G5-D: Keep the current contract but document the propagation
  caveat explicitly.** Lowest cost; relies on operator awareness.

**Recommended:** G5-A is the cleanest. The `--debug` flag is an
operator's explicit opt-in to DEBUG output going to stderr; the
side-effect of suppressing external handlers for one CLI run is
well-bounded. Add a Req 7.3-bis: "WHEN `--debug` is set, THE
Classification_CLI SHALL set `logger.propagate = False` on the
`loki.classification` logger for the duration of the run and SHALL
restore the previous value after the run." Combined with a
guaranteed handler attachment, the operator sees DEBUG records
exactly once.

### G6 — Req 11.1's 200ms overhead budget is unverifiable on a stub library output, and Req 11.3's 64MiB working-set budget needs a measurement plan

Req 11.1 promises ≤200ms CLI overhead at 256 components. Req 11.3
promises ≤64MiB working-set budget for the CLI layer. Both numbers
are reasonable as targets, but neither has a "how is this measured"
clause. The upstream classification spec's R11.1 (Performance
bounds, line ~621 of upstream) measures via the `slow` marker test
suite at `tests/classification/test_performance.py` against a
calibrated synthetic input.

**Gap:** the CLI spec doesn't say how `<200ms overhead beyond the
library>` is measured. Two readings:

- **Wall-clock subtraction:** total `loki classify` wall time minus
  the duration the library reports inside `ClassificationResult`.
  The library doesn't currently expose a duration on the public
  surface — only `_logger.info` carries a duration string from the
  `Stopwatch` context (see `pipeline.py:240`). So the CLI would
  need its own outer Stopwatch to measure total, and would have no
  reliable way to subtract.
- **Wrapper-only timing:** time argparse parsing + JSON load +
  Pydantic validation + JSON dump as a separate measurement, with
  the library call out of the loop. This is more surgical but
  requires explicit timing instrumentation in the test, not in the
  CLI.

**Recommended fix:** in Req 11.1, replace
`"add no more than 200 milliseconds of wall-clock overhead beyond
the time spent inside ``classify_components`` itself"` with
`"add no more than 200 milliseconds of wall-clock overhead beyond
the time spent inside ``classify_components`` itself, as measured
by a slow-marker test that times the surrounding wrapper code
explicitly (manifest read + JSON decode + Pydantic validation +
ClassificationConfig construction + Stdout_Result JSON
serialization + stderr line emission), not by subtracting the
library's internally-reported duration"`. This makes the
measurement plan part of the contract.

For Req 11.3, the working-set bound is hard to test deterministically
without `tracemalloc` or `resource.getrusage()`, neither of which
the rest of the project uses. The bound is realistic but
operationally unenforceable in v1. **Recommended:** soften 11.3 to
"THE Classification_CLI SHOULD keep peak resident memory ..." with
a "MAY be enforced by a future test" deferred note. The current
"SHALL keep" makes a contract the test suite can't verify.

### G7 — Req 1.5 uses `sys.stdin.isatty()` but the existing CLI uses argparse for I/O setup; the placement of the TTY check matters

Req 1.5 (TTY guard on stdin) says:

> IF the positional ``manifest`` value is the literal ``-`` and
> ``sys.stdin.isatty()`` returns ``True``, THEN ...

This is sensible behavior. But the CLI's main loop in
`loki/cli.py:266` is a flat dispatch: `args = parser.parse_args(...)`
followed by `handler(args)`. The `_handle_classify` function would
need to perform the `isatty()` check itself (argparse doesn't
support it natively), and would need to do so BEFORE attempting to
read stdin (otherwise an interactive operator who typed `loki
classify -` and then forgot what the `-` meant could be left waiting
for input that never comes).

This isn't really a spec gap — the requirement is correct. But the
implementation order matters: check `isatty()` immediately after
seeing `-`, before any other I/O. Worth flagging in the design phase
as an explicit ordering constraint.

**Recommended:** no change to the requirement. Add to the design
phase a note that `_handle_classify` checks `sys.stdin.isatty()`
as the first action when the positional value is `-`.

### G8 — Req 13's properties P53–P58 are sound but P55 needs an explicit concurrency caveat

P55 is the SIGINT cancellation property:

> for randomly chosen cancellation indices into a manifest of at
> least 2 components, asserts: (a) the resulting
> ``ClassificationResult.errors`` list ends with exactly one
> Cancellation_Marker ...

Two issues:

- **(i)** The property as written needs to inject SIGINT at a
  specific component index. In a Hypothesis property test that
  spawns a subprocess, timing is non-deterministic — sending
  SIGINT at "the moment between components 5 and 6" requires
  either (a) spawning the CLI as a subprocess and using
  `subprocess.send_signal()` with a sleep that's longer than
  classification of components 1-5 plus shorter than the time
  before component 6, OR (b) using a synchronous in-process
  test that monkey-patches the signal mechanism to flip the
  Cancel_Flag at a known iteration. Neither is robust as a
  Hypothesis property; both are flaky as test-suite citizens.

- **(ii)** Property tests in this project run with
  `max_examples=25` for full-pipeline properties and
  `max_examples=50` for in-memory ones (see analysis-engine's
  P49-P52 in `loki/analysis/test_properties.py`). A subprocess-
  based SIGINT property at `max_examples=25` would take
  ~30 seconds per CI run; `max_examples=50` doubles that.

**Recommended:** restructure P55 as an in-process unit test, not a
property test. The Cancel_Flag mechanism can be exercised
deterministically by passing a `cancel: Callable[[], bool]`
callback that returns True at the configured iteration; this
exercises the same cancellation contract the CLI's SIGINT handler
relies on. Replace P55 with: "P55 (Cancel_Flag-driven cancellation,
pinned by an in-process test): for the range of cancellation
indices `[1, total]`, asserts the `ClassificationResult.errors`
list ends with exactly one Cancellation_Marker with
`error_message == "classification cancelled by caller"` and
`component_id is None`, the Stdout_Result still parses as valid
JSON, and the Classification_CLI exit code is 130." The SIGINT
end-to-end behavior gets one example-based test (not a property
test) using `subprocess.Popen` + `send_signal(SIGINT)` with a
deterministic wait condition.

Properties P53, P54, P56, P57, P58 are all sound and don't need
restructuring.

## Findings: minor wording items (M*)

### M1 — Glossary's `Cancellation_Marker` entry slightly misquotes upstream R1.9

The CLI Glossary says:

> The single ``ClassificationError`` record the classification
> library writes into ``ClassificationResult.errors``
> when the Cancel_Flag is observed (per R1.9 of
> classification-pipeline: ``error_message == "classification
> cancelled by caller"``). The Classification_CLI emits the partial
> Stdout_Result containing this marker and exits 130.

Upstream R1.9 says the marker's `error_message` equals
"classification cancelled by caller" — verified literal. ✓

But the Glossary's "The single `ClassificationError` record" implies
exactly one is ever emitted; upstream R1.9 says "emit one
Classification_Error" — also verified. ✓

No change needed.

### M2 — Req 8.1 enumerates exit-code triggers with mixed phrasing

Req 8.1 lists the seven exit codes. The triggers under exit code 2
are listed as a comma-separated run-on:

> ``2``: bad input. Manifest path missing or unreadable;
> manifest JSON does not parse; manifest fails Pydantic
> strict validation; ``--rules-path`` is missing from the
> argument vector; stdin requested via ``-`` but
> ``sys.stdin.isatty()`` is ``True``.

Compare to exit code 6:

> ``6``: configuration error.
> ``ClassificationConfigError`` from ``classify_components``
> (taxonomy mismatch, Rules_Directory missing or unreadable,
> rules-file shape errors).

Code 2 lists triggers in prose; codes 4/5/6 list error class names
plus parenthetical examples. Either format is fine; mixing them in
one criterion makes the exit-code mapping look inconsistent.

**Recommended:** keep the prose form for code 2 (the triggers don't
correspond to a single error class) but re-format codes 3 and 130
to match codes 4/5/6's error-class-plus-parenthetical shape. This
makes the typed-error mapping in Req 8.2 directly auditable
against Req 8.1.

### M3 — Req 12.3's "or the equivalent argparse default" hedge is unnecessary

Req 12.3 says:

> The Classification_CLI's ``argparse`` parser SHALL set
> ``prog="loki classify"`` (or the equivalent ``argparse``
> default) so that ``--help`` ...

The argparse default for a subparser is `f"{parent_prog}
{subparser_name}"` — exactly `"loki classify"` for our case. The
"or the equivalent" hedge is true but adds noise.

**Recommended:** simplify to `SHALL set ``prog`` such that ``loki
classify --help`` shows the subcommand by its full invocation form
(``loki classify``) rather than the bare module name`. This is
behavior-focused rather than implementation-detail-focused.

## Summary

**Substantive gaps (G1-G8):** 8 items requiring HARDEN-phase
resolution. None block proceeding to design; all are tightenable
without changing the spec's structure. The most consequential are
G2 (drop `<R>` from the summary line for v1) and G5 (`--debug`
propagation handling).

**Wording items (M1-M3):** 3 items that improve readability but
don't change behavior. Optional.

**Cross-reference accuracy:** 1 minor citation tightening (G1).
Most upstream citations check out: R1.9, R5.6, R12.1-R12.2, R13.5,
R4.10, R10.5 — all real upstream criteria with the right semantics.

**Not flagged but worth a pre-HARDEN check:**

- The CLI uses Pydantic strict validation on `ExtractionManifest`
  ingestion (Req 1.3, 1.4, 1.8). The upstream extraction-pipeline
  spec doesn't promise the manifest's JSON form is stable across
  the lifetime of the project — if the model layer evolves
  (e.g. adds a required field), saved manifests on disk become
  unparseable. The CLI spec lists "Schema migration of the
  ``ExtractionManifest`` envelope" as Out_Of_Scope_Operation,
  which is fine, but the lack of a Schema_Version on the manifest
  envelope itself (compare to baseline-persistence's R4) means
  versioning is implicit. Worth tracking as a future thread:
  OT-LK-006 "ExtractionManifest schema migration" (analogous to
  OT-LK-005 for baseline schema).

- Req 6.5 says "double-Ctrl-C SHALL NOT cause the
  Classification_CLI to short-circuit". This is the right v1
  behavior, but operators conditioned on bash's
  "single-Ctrl-C-cancels-current-command, second-kills" pattern
  may find it surprising. Worth a note in the help text or
  README that double-Ctrl-C has no extra effect; the operator
  must wait for the cooperative cancellation to surface.

## Recommended HARDEN sequence

1. Apply G2-B (drop `<R>` from Stderr_Summary_Line). One-line
   change to Req 4.2; eliminates the hedge.
2. Apply G3 (Progress_Line per *successfully-classified* component).
   Tightens Req 5's User Story and adds Req 5.8.
3. Apply G5-A (`--debug` flag sets propagation to False). One-line
   addition to Req 7 (call it 7.3-bis, or renumber as 7.4 and
   bump remaining clauses).
4. Apply G6 (Req 11 measurement plan + soften 11.3 to SHOULD).
5. Apply G8 (P55 restructured: in-process unit test for the
   cancellation contract; one separate example-based subprocess
   test for SIGINT end-to-end).
6. G1, G4, G7, M1-M3 are cosmetic; apply if time permits.

After HARDEN: spec is ready for design BIND. Operator's call on
whether to do design BIND in this session or open a separate
conversation (per the project's "spec drafting is its own
conversation" rule, the natural break is here).

---

**End of TENSION pass.**


---

## HARDEN status (post-pass)

**Tagged:** 2026-05-28.

All 11 audit items applied to `requirements.md`:
- G1, G2-B, G3, G4-A, G5-A, G6, G7 (recorded in Introduction's design-phase notes), G8 — applied.
- M1 (Glossary entry was already correct on TENSION re-read; no edit needed), M2, M3 — applied.

Diagnostics-clean (`getDiagnostics` returns "No diagnostics found").

Two new tracking items surfaced and recorded in the spec's Introduction:
- OT-LK-006 — `ExtractionManifest` schema migration (analogous to OT-LK-005 for baseline).
- A future-revision opportunity to add `<R>` rules-loaded count to the Stderr_Summary_Line once the public `ClassificationResult` carries it.

Design BIND followed in the same session, against the project's "spec drafting is its own conversation" rule. Operator deviation is intentional and recorded.

`design.md` lives at `.kiro/specs/classification-cli/design.md`. Diagnostics: 2 non-blocking warnings on the Properties section (false positives — same pattern accepted on `analysis-engine/design.md`).
