# Design Document — Classification Pipeline

## Overview

The Classification Pipeline turns the `ExtractedComponent` records
produced by the extraction pipeline into validated
`ClassificationRecord` instances along the four taxonomic axes
already defined in `loki/models/enums.py`: type, vendor, security
posture, and mutability. It is the consumer of extraction's output
and the producer of the records that GLEIPNIR persists inside
`BaselineRecord.component_manifest`.

The subsystem is **synchronous**, **single-threaded**,
**deterministic** (same input + same Rule_Set ⇒ same records modulo
one explicit timestamp field), and **honest** about what it cannot
do — rule-load mistakes raise typed exceptions before any
classification runs, signature handling detects presence without
verification, CVE matching is explicitly empty in v1, and the
no-rule-fires fallback writes `UNKNOWN` at confidence `0.0` rather
than guessing.

The shape mirrors the extraction-pipeline and baseline-persistence
designs: a small public surface in `loki.classification`, a typed
exception hierarchy, a manifest-with-errors result shape, an AST
audit that pins side-channel imports, and a logging audit that
pins the Forbidden_Leakage_Field_Set out of every emitted record.
Each non-trivial design choice cites the acceptance criteria it
satisfies (e.g. `R3.7` = Requirement 3 acceptance criterion 7).

## Goals and non-goals

### Goals

- Deliver a stable, typed `classify_components` callable importable
  as `from loki.classification import classify_components`.
- Load and validate the YAML Rule_Set exactly once at pipeline
  construction (R2.3), then evaluate every input component against
  the immutable Rule_Set in input order (R8.3).
- Pick the Winning_Rule per axis deterministically (max-confidence,
  lexicographic `rule_id` tie-break — R4.4-R4.5) and fall back to
  `UNKNOWN` at confidence `0.0` when no rule fires (R4.8).
- Detect signature presence (PE32 Authenticode + UEFI
  EFI_FIRMWARE_IMAGE_AUTHENTICATION at minimum, R5.5) without
  consulting any trust root, network resource, or cert store
  (R5.7).
- Surface rule-load failures as typed exceptions and per-component
  failures as `ClassificationError` records inside
  `ClassificationResult.errors` (R9.1-R9.3).
- Stay completely independent of `loki.gui` (R1.8) and of
  `random` / `os.environ` / `socket` / network libraries (R8.5).
- Bound the matcher-evaluation phase under 30s wall time for 4096
  components × 1024 rules and the signature-detection phase under
  60s wall time for the same fleet's ≤256 MiB raw bytes, both on a
  2024-class developer laptop with a local SSD (R11.1, R11.3).

### Non-goals (explicit)

- **Signature verification.** `SignatureInfo.verified` and
  `signer` stay `False`/`None` in v1 (R5.2-R5.3). A future
  trust-root-aware spec may relax this.
- **CVE matching.** `cve_matches` stays the empty list `[]` in v1
  (R6). A future CVE-feed spec populates it.
- **Cross-axis inference.** The four axes classify independently
  in v1 (R4.3). A future spec may re-open this.
- **Persistence of `ClassificationRecord` instances.** GLEIPNIR
  already persists them inside `BaselineRecord.component_manifest`;
  this spec produces records and hands them to the caller.
- **Override records, suspicion triggers.** Both stay at the
  model-layer default `[]` for every emitted record (R10.3-R10.4).
- **CLI subcommand and GUI integration surfaces.** Both are
  separate specs (R12.4-R12.5). v1 only ships the library API.
- **Confidence-threshold gating.** `ClassificationConfig.confidence_threshold`
  is reserved for the future analysis engine; v1 SHALL NOT consume
  it (R4.10). The model layer's hard-coded `needs_review =
  composite_confidence < 0.60` invariant remains the only review
  gate.
- **Rule indexing optimization.** Linear scan is the v1 contract
  (R11.5); GUID-keyed prefilters or similar are deferred.

## Constraints carried forward

- Python 3.11+ (3.12 baseline). All new code must satisfy
  `mypy --strict`, `ruff check`, and `ruff format`.
- Pydantic v2 strict mode for every model in `loki.models`; the
  pipeline constructs `ClassificationRecord` directly so its
  validators run before the value escapes the subsystem (R10.1).
- `loki.classification` must not import from `loki.gui` (R1.8).
- Logging via the stdlib `logging` module under the logger name
  `loki.classification` (R12.3).
- No content leakage in logs at any time (R13.5-R13.6) — the
  Forbidden_Leakage_Field_Set is `component_id` (extraction's and
  classification's), `signature_info.signer`, the parent
  `BaselineRecord.source_image_hash`, and any
  `AxisClassification.evidence` string.
- Determinism: classification SHALL NOT consult environment
  variables, the random number generator, the system clock other
  than for the run-start timestamp, or any network resource for
  any decision that affects record contents (R8.4).

## Components and Interfaces

### Module layout

```
loki/classification/
├── __init__.py        # re-exports the public surface
├── api.py             # classify_components entry point + ClassificationResult
├── pipeline.py        # ClassificationPipeline (internal, single-construct site)
├── version.py         # CLASSIFICATION_VERSION constant
├── rules/
│   ├── __init__.py    # re-exports Rule, Matcher, Effect, RuleSet
│   ├── loader.py      # load_rule_set(): YAML → validated RuleSet
│   ├── schema.py      # Rule, Matcher, Effect, RuleSet typed shapes
│   └── matcher.py     # match() predicate evaluator (conjunctive)
├── classifier.py      # AxisClassifier per-axis Winning_Rule selection
├── signatures.py      # detect_signature(): PE32 + UEFI auth wrapper
├── errors.py          # typed exception hierarchy + ClassificationError record
└── timing.py          # designated module for time.monotonic() (mirrors extraction)
```

`loki/classification/__init__.py` re-exports exactly:

```python
from loki.classification.api import (
    ClassificationResult,
    classify_components,
)
from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationError,
    ClassificationPipelineError,
    ClassificationRuleError,
)
from loki.classification.rules import Effect, Matcher, Rule, RuleSet
from loki.classification.version import CLASSIFICATION_VERSION
```

The `__init__.py` module docstring documents the determinism
contract per R8.1-R8.7 ("same input + same Rule_Set ⇒ same records
modulo timestamp; preserves input ordering; round-trip through JSON
losslessly; idempotent under re-classification").

### Public API surface

#### `classify_components` (R1.1-R1.9)

```python
# loki/classification/api.py
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from loki.classification.errors import ClassificationError
from loki.models.classification import ClassificationRecord
from loki.models.config import ClassificationConfig
from loki.models.firmware import ExtractedComponent


@dataclass(frozen=True)
class ProgressEvent:
    """Structured progress event emitted at component granularity (R12.1).

    Emitted exactly once after each component's classification finishes,
    regardless of whether classification succeeded, failed, or
    encountered the missing-bytes signature-detection limitation
    (R5.6).
    """

    index: int      # 1-based position in the input sequence
    total: int      # static input-sequence length
    component_id: str  # str(component.component_id) — needed for GUI
                       # progress UI; this is the SAME field listed in
                       # the Forbidden_Leakage_Field_Set, so the
                       # callback contract MUST forbid the callback
                       # from logging it through `loki.classification`.
                       # See "Progress callback and the leakage rule"
                       # below.


# Type aliases on the public entry point.
ProgressCallback = Callable[[ProgressEvent], None]
CancellationToken = Callable[[], bool]


@dataclass(frozen=True)
class ClassificationResult:
    """Output container for one classification run (R1.1, R10.5).

    The `records` and `errors` lists partition components in v1 except
    for the missing-bytes signature-detection case (R5.6), which
    intentionally produces both a `ClassificationRecord` and a
    `ClassificationError` for the same component.
    """

    records: list[ClassificationRecord] = field(default_factory=list)
    errors: list[ClassificationError] = field(default_factory=list)


def classify_components(
    components: Sequence[ExtractedComponent],
    config: ClassificationConfig,
    *,
    progress: ProgressCallback | None = None,
    cancel: CancellationToken | None = None,
) -> ClassificationResult:
    """Classify a sequence of extracted components (R1.1-R1.9).

    Constructs a single internal `ClassificationPipeline` from
    `config` (which loads and validates the Rule_Set per
    Requirement 2), then iterates `components` in input order
    (R8.3), classifying each per Requirements 3 through 7.

    Raises only typed `ClassificationPipelineError` subclasses for
    whole-run failures (rule-load errors, configuration errors).
    Per-component failures are recorded as `ClassificationError`
    instances inside `result.errors` and never raised (R9.3).

    Runs synchronously on the calling thread and never spawns
    workers (R1.7). Progress callback, if supplied, is invoked
    from the calling thread only (R12.2).
    """
```

#### `ClassificationPipeline` (internal — R2.3, R4)

```python
# loki/classification/pipeline.py
class ClassificationPipeline:
    """Internal pipeline holding the validated Rule_Set.

    Construction loads and validates rules exactly once (R2.3).
    The pipeline instance is single-use: `classify` is called
    once per `classify_components` invocation. The pipeline
    holds no per-run mutable state beyond the run timestamp
    chosen at the start of `classify`.
    """

    def __init__(self, config: ClassificationConfig) -> None:
        """Load and validate the Rule_Set (R2.3, R2.4).

        Raises `ClassificationConfigError` on missing rules
        directory, malformed YAML, schema mismatches, taxonomy
        version mismatches, or duplicate `rule_id` values.
        Raises `ClassificationRuleError` on individual Rule /
        Matcher / Effect validation failures.
        """

    def classify(
        self,
        components: Sequence[ExtractedComponent],
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
    ) -> ClassificationResult:
        """Run classification per Requirements 3 through 13."""
```

The `ClassificationPipeline` is *internal*. The public surface is
the free function `classify_components`. This avoids inviting
callers to construct multiple pipelines from the same config or to
mutate the pipeline between calls — the rule-set-immutable-for-
lifetime contract (R2.3) is easier to defend behind a free function
that constructs and discards in one call.

#### Exception hierarchy (R9)

```
ClassificationPipelineError                  # all errors raised by this subsystem
├── ClassificationConfigError                # R2.4, R2.6, R2.7, R2.8
└── ClassificationRuleError                  # R2.9, R3.9, R4.1, R4.2
```

`ClassificationPipelineError` is the root. It subclasses
`Exception`. Both subclass it, mirroring the extraction-pipeline's
two-level hierarchy (`ExtractionPipelineError` →
`ExtractionConfigError` / `ExtractionToolError`). Specifically:

- `ClassificationConfigError` carries `path: Path` (the offending
  rules directory or rule file) and a free-form message. Used for
  whole-directory and whole-file failures: missing rules
  directory, taxonomy_version mismatch, duplicate `rule_id`.
- `ClassificationRuleError` carries `path: Path`, `rule_id: str | None`
  (None if the offending entry has no parsable `rule_id`), and a
  free-form message. Used for individual-rule schema / matcher /
  effect validation failures.

`ClassificationError` (the per-component error record, R9.3) is
**not** an exception subclass — it's a Pydantic model parallel to
`ExtractionError`:

```python
# loki/classification/errors.py
class ClassificationError(BaseModel):
    """Per-component error record (R9.3, R9.4). Parallel to ExtractionError."""

    model_config = ConfigDict(strict=True, frozen=False)

    component_id: uuid.UUID | None  # None for whole-run failures (cancel)
    error_message: str              # non-empty per validator
    timestamp: datetime             # UTC

    @field_validator("error_message")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("error_message must be non-empty")
        return v
```

### Rule schema (R2.5-R2.8, R3, R4.1-R4.2)

Rules live in YAML files at depth 1 inside
`ClassificationConfig.rules_path`. Each file has the shape:

```yaml
# example_rules.yaml
taxonomy_version: "1.0.0"
rules:
  - rule_id: intel.management-engine.firmware
    axis: type
    matcher:
      guid: "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
    effect:
      label: RUNTIME_SERVICE
      confidence: 0.95
      method: RULE
      evidence: "Intel ME firmware GUID match"

  - rule_id: ami.aptio.dxe-driver-by-name
    axis: vendor
    matcher:
      name:
        prefix: "AMI"
      component_type_hint: dxe_driver
    effect:
      label: AMI
      confidence: 0.80
      method: RULE
```

The Pydantic shapes that validate this:

```python
# loki/classification/rules/schema.py
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from loki.models.enums import ClassificationMethod


# Rule_id charset constraint (R2.7)
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class GuidPredicate(BaseModel):
    """`guid:` predicate (R3.2). Either a single UUID string or `{in: [...]}`."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    values: tuple[str, ...]  # canonical lower-case 8-4-4-4-12 form


class NamePredicate(BaseModel):
    """`name:` predicate (R3.3). Exactly one of equals/prefix/suffix/contains."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    op: Literal["equals", "prefix", "suffix", "contains"]
    value: str  # non-empty


class TypeHintPredicate(BaseModel):
    """`component_type_hint:` predicate (R3.4)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    values: tuple[str, ...]


class SizePredicate(BaseModel):
    """`size:` predicate (R3.5). One or both of min/max."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    min: int | None = None  # >= 0
    max: int | None = None  # >= 0

    @field_validator("min", "max")
    @classmethod
    def _non_negative(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("size predicate values must be non-negative")
        return v


class RawHashPredicate(BaseModel):
    """`raw_hash:` predicate (R3.6)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    values: tuple[str, ...]  # 64-char lowercase hex


class Matcher(BaseModel):
    """Conjunctive Matcher (R3.1, R3.7-R3.8). Closed key set."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    guid: GuidPredicate | None = None
    name: NamePredicate | None = None
    component_type_hint: TypeHintPredicate | None = None
    size: SizePredicate | None = None
    raw_hash: RawHashPredicate | None = None

    @field_validator("*", mode="before")
    @classmethod
    def _at_least_one_predicate(cls, v: object) -> object:
        # Validation that at least one predicate is set lives in
        # the loader after the per-field coercions complete.
        return v


class Effect(BaseModel):
    """Effect block (R4.1, R4.2)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    label: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    method: ClassificationMethod
    evidence: str | None = None  # non-empty when present (R4.7)

    @field_validator("evidence")
    @classmethod
    def _evidence_non_empty(cls, v: str | None) -> str | None:
        if v is not None and (not v or not v.strip()):
            raise ValueError("evidence, when present, must be non-empty")
        return v


class Rule(BaseModel):
    """A single Rule (R2.7)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    rule_id: str
    axis: Literal["type", "vendor", "security_posture", "mutability"]
    matcher: Matcher
    effect: Effect

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError(
                "rule_id must match ^[a-z0-9][a-z0-9._-]{0,127}$"
            )
        return v


class RuleSet(BaseModel):
    """Validated, immutable Rule_Set (R2.3)."""

    model_config = ConfigDict(strict=True, frozen=True)
    taxonomy_version: str
    rules: tuple[Rule, ...]   # tuple, not list — supports the immutability contract
    sources: tuple[Path, ...] # absolute file paths the rules came from
```

`Rule`, `Matcher`, `Effect`, and `RuleSet` re-export from
`loki/classification/rules/__init__.py` so curators of the future
CLI / GUI tooling can import them without reaching into private
modules.

### Rule-set loader (R2.1-R2.9)

```python
# loki/classification/rules/loader.py
def load_rule_set(config: ClassificationConfig) -> RuleSet:
    """Load and validate the full Rule_Set (R2).

    1. Resolve `config.rules_path` (R2.1). Raise
       `ClassificationConfigError` on missing dir / not a dir / not
       readable (R2.4).
    2. Enumerate depth-1 entries; ignore those not ending in
       `.yaml` / `.yml` (R2.2).
    3. Sort the remaining files lexicographically by path. The
       sort matters because rule-id duplicates are reported with
       both source paths in the order they were encountered, and
       lexicographic order is reproducible across filesystems.
    4. For each file:
       a. yaml.safe_load. On YAMLError raise `ClassificationConfigError`
          carrying the file path.
       b. Validate the top-level `{taxonomy_version, rules}` shape.
          Reject extra keys (R2.5).
       c. Compare `taxonomy_version` against
          `config.taxonomy_version`. On mismatch raise
          `ClassificationConfigError` (R2.6).
       d. For each entry in `rules`:
          - Pre-process predicate values into the closed shapes
            (`GuidPredicate.values`, `NamePredicate.op`/value,
            `TypeHintPredicate.values`, `SizePredicate.min/max`,
            `RawHashPredicate.values`). The YAML allows the
            sugar forms (single string vs. `{in: [...]}`); the
            pre-processor expands them into the canonical tuple
            shape so downstream code only sees one form.
          - Lower-case GUIDs to canonical form (R3.2: matching is
            case-insensitive, but normalization at load time
            keeps the matcher inner loop simple).
          - Lower-case raw_hash values; reject non-hex (R3.6).
          - Reject empty `name.value`, empty `component_type_hint`
            list, missing both `min` and `max`, etc.
          - Validate the `Rule` Pydantic model (R2.7, R3.9).
          - On any failure raise `ClassificationRuleError` carrying
            the file path and `rule_id` (or None if the failure
            was on `rule_id` itself).
    5. After every file is parsed, scan the accumulated rule list
       for duplicate `rule_id` values. On any duplicate raise
       `ClassificationConfigError` carrying both source file paths
       and the duplicated `rule_id` (R2.8).
    6. Return the immutable `RuleSet(taxonomy_version, tuple(rules), tuple(sources))`.
    """
```

A loaded `RuleSet` is **never** mutated. `ClassificationPipeline.__init__`
holds it as `self._rules: RuleSet`; the matcher and the per-axis
classifier read it but do not modify it. Callers that hold a
reference can also rely on `tuple` immutability.

### Matcher evaluator (R3)

```python
# loki/classification/rules/matcher.py
def matches(rule: Rule, component: ExtractedComponent) -> bool:
    """Conjunctive evaluation of `rule.matcher` against `component`.

    Returns True when every predicate in `rule.matcher` fires for
    `component`, False otherwise. Matchers with no predicates set
    are rejected at load time, not here.
    """
```

The matcher is a single-pass conjunctive evaluator. Each predicate
is checked in a fixed order (`guid`, `name`, `component_type_hint`,
`size`, `raw_hash`); the order doesn't affect outcome (the
conjunction is commutative) but does affect short-circuit
performance — `guid` is the cheapest predicate to evaluate, so it's
checked first.

Per R3.7, conjunction means **every** populated predicate must fire;
an unpopulated predicate is **not** "fires by default" — it's "not
checked." Per R3.2-R3.4, if the component's field that a
populated predicate targets is `None`, the predicate **does not
fire** (the matcher returns False for the rule).

Per R3.8, no regex, no glob, no code execution. The closed
predicate set in `Matcher` is the only matcher language v1
supports.

### Per-axis classifier (R4.4-R4.8)

```python
# loki/classification/classifier.py
def classify_axis(
    rules: tuple[Rule, ...],
    axis: Literal["type", "vendor", "security_posture", "mutability"],
    component: ExtractedComponent,
) -> AxisClassification:
    """Run every rule whose `axis` matches against `component`,
    pick the Winning_Rule, and return the AxisClassification.
    """
```

Algorithm:

1. Enumerate every rule in `rules` whose `rule.axis == axis`.
2. For each such rule, call `matches(rule, component)`. Collect
   the firing rules into a list.
3. If the list is empty, return the no-rule-fires fallback per
   R4.8: `AxisClassification(label=AXIS_UNKNOWN, confidence=0.0,
   method=HEURISTIC, rule_id=None, evidence=None)` where
   `AXIS_UNKNOWN` is the appropriate enum's `UNKNOWN` member
   (`ComponentTypeLabel.UNKNOWN`, `VendorLabel.UNKNOWN`,
   `SecurityPostureLabel.UNKNOWN`, `MutabilityLabel.UNKNOWN`).
4. Otherwise pick the Winning_Rule:
   `max(firing, key=lambda r: (r.effect.confidence, _neg_lex(r.rule_id)))`
   where `_neg_lex(s)` is a key whose ordering is reversed
   lexicographically so the tuple `(confidence, _neg_lex(id))`
   sorts the *smaller* `rule_id` higher when confidences tie
   (R4.5).
   In practice this is implemented as
   `min(firing, key=lambda r: (-r.effect.confidence, r.rule_id))`,
   which is simpler and avoids inventing a custom key.
5. Construct and return `AxisClassification(label=winner.effect.label,
   confidence=winner.effect.confidence, method=winner.effect.method,
   rule_id=winner.rule_id, evidence=[winner.effect.evidence] if
   winner.effect.evidence else None)` (R4.6-R4.7).

The four axes classify independently (R4.3) — `classify_axis` is
called four times per component, once per axis literal. There is
no cross-axis state in this function or in the Pipeline.

### Signature detection (R5)

```python
# loki/classification/signatures.py
def detect_signature(component: ExtractedComponent) -> tuple[bool, str | None]:
    """Detect signature presence in `component`'s raw bytes.

    Returns `(present, error_message)`. The `present` flag is True
    when the component's bytes carry a recognized code-signing
    structure (PE32 Authenticode security directory entry or UEFI
    EFI_FIRMWARE_IMAGE_AUTHENTICATION wrapper); False otherwise.

    The `error_message` is None on success and a non-empty string
    when the component's bytes were unreadable (raw_path is None
    or the file is missing / unreadable / shorter than the
    minimum recognizer prefix). Per R5.6, callers translate a
    non-None `error_message` into a `ClassificationError` while
    still emitting the `ClassificationRecord` (signature_info
    populated with `present=False`).
    """
```

Two recognizers:

- **PE32 Authenticode.** Read the first 1 MiB of `raw_path` (R11.2).
  Look for the PE32 signature `PE\\x00\\x00` at the offset stored
  in the DOS header's `e_lfanew`. From there parse the optional
  header to extract the Security data-directory entry (entry
  index 4). If the entry's `VirtualAddress` is non-zero and
  `Size > 0`, the component carries a PE32 Authenticode signature.
  We don't parse the Authenticode SignedData blob — presence is
  enough.
- **UEFI EFI_FIRMWARE_IMAGE_AUTHENTICATION.** A 24-byte
  `EFI_TIME` followed by a `WIN_CERTIFICATE_UEFI_GUID` whose
  `CertType` GUID is `EFI_CERT_TYPE_PKCS7_GUID`
  (`4aafd29d-68df-49ee-8aa9-347d375665a7`). When the component's
  `component_type_hint` is one of the UEFI capsule / firmware
  variants and the first 24 + sizeof(WIN_CERTIFICATE_UEFI_GUID) =
  ~50 bytes parse cleanly with that GUID, the component carries
  a UEFI auth wrapper.

Both recognizers operate on bounded byte ranges (≤ 1 MiB read per
component, R11.2). Streaming I/O is achieved by reading exactly
the prefix needed and closing the file; we do **not** memory-map
or load the full component (R11.4).

The recognizers do not parse certificates, do not consult any
trust root, and do not attempt verification (R5.2-R5.4, R5.7).
`SignatureInfo.signer` and `SignatureInfo.cert_expiry` are
**always** `None` in v1.

A future trust-root-aware spec replaces `detect_signature` with a
`detect_and_verify_signature` and lifts R5.2 / R5.3. The shape of
that future call (returning extra fields) is one of the reasons
this v1 spec returns the tuple `(present, error_message)` rather
than a richer dataclass — keeping the v1 surface narrow makes the
v2 surface change cheap.

### Progress callback and the leakage rule

`ProgressEvent.component_id` is a `str` form of the same
`uuid.UUID` carried in `ExtractedComponent.component_id` and
`ClassificationRecord.component_id`. Per R13.5 the **logger**
`loki.classification` SHALL NOT emit `component_id` — but the
**progress callback** is *caller-supplied code*, and the GUI's
status-bar rendering needs *some* identifier to display per
component. The choice in this design:

- The progress callback receives `component_id` as a plain string
  (R12.1's "current component index, total component count" minimum
  is met; a stable per-component identifier is added on top).
- The progress callback contract documents that callers SHALL NOT
  forward this value into the `loki.classification` logger.
- The Forbidden_Leakage_Field_Set audit (R13.5) walks
  `loki/classification/` for `logger.{info,warning,error,debug}`
  call sites and verifies none of them format `component_id`,
  `signer`, `source_image_hash`, or `evidence`. Caller-supplied
  callbacks are out of scope for the audit (the caller's choice
  to log is the caller's responsibility).
- The `loki.gui` and CLI subsystems, when they ship, will get
  their own log-no-leakage audits. Until then, R13's contract is
  scoped to `loki.classification` only.

This is the one place where the requirements' Forbidden_Leakage_Field_Set
(`component_id` is on the list) is in tension with R12's
"structured progress events" minimum. The resolution above is a
*judgment call* — a stricter reading of R13.5 would forbid
`component_id` even on the progress callback, in which case
`ProgressEvent.component_id` would have to be removed and the GUI
would have to display "component 137 of 4096" rather than
"component 137 of 4096 (uuid prefix abcdef…)". The judgment call
here favors observable progress; if the user prefers the stricter
read, the `component_id` field on `ProgressEvent` is the cheap
revert.


## Data Models

This subsystem produces `ClassificationRecord` (already defined in
`loki/models/classification.py`) and consumes
`ExtractedComponent` (already defined in `loki/models/firmware.py`)
plus `ClassificationConfig` (already defined in
`loki/models/config.py`). It introduces no new model-layer
Pydantic types.

It introduces these internal types (purely in-process; not
persisted; live in `loki.classification` rather than `loki.models`
because they are not part of the long-term data contract that
other subsystems consume):

| Type                   | Module                               | Used as                                              |
|------------------------|--------------------------------------|------------------------------------------------------|
| `RuleSet`              | `loki.classification.rules.schema`   | Validated, immutable rule collection                 |
| `Rule`                 | `loki.classification.rules.schema`   | One row of `RuleSet.rules`                           |
| `Matcher`              | `loki.classification.rules.schema`   | Conjunctive predicate block                          |
| `Effect`               | `loki.classification.rules.schema`   | Output assertion block                               |
| `GuidPredicate`        | `loki.classification.rules.schema`   | Normalized GUID match predicate                      |
| `NamePredicate`        | `loki.classification.rules.schema`   | `equals`/`prefix`/`suffix`/`contains` over `name`    |
| `TypeHintPredicate`    | `loki.classification.rules.schema`   | `component_type_hint` membership                     |
| `SizePredicate`        | `loki.classification.rules.schema`   | `min`/`max` byte-size bounds                         |
| `RawHashPredicate`     | `loki.classification.rules.schema`   | `raw_hash` membership                                |
| `ProgressEvent`        | `loki.classification.api`            | Progress callback payload                            |
| `ClassificationResult` | `loki.classification.api`            | `classify_components` return container               |
| `ClassificationError`  | `loki.classification.errors`         | Per-component error record                           |

It introduces two type aliases on the public entry point:

- `ProgressCallback = Callable[[ProgressEvent], None]`
- `CancellationToken = Callable[[], bool]`

These don't ship in `loki.models` because they're not part of the
persisted data contract.

## Error Handling

This section consolidates the error story already touched on in
"Components and Interfaces."

### What gets raised

Three exception classes leave the subsystem boundary:

- `ClassificationPipelineError` — root parent.
- `ClassificationConfigError` — whole-directory or whole-file
  failures: missing rules directory, taxonomy_version mismatch,
  duplicate `rule_id` (R2.4, R2.6, R2.8). Carries `path: Path`.
- `ClassificationRuleError` — individual-rule schema / matcher /
  effect validation failures (R2.7, R3.9, R4.1, R4.2). Carries
  `path: Path`, `rule_id: str | None`.

### What gets recorded as ClassificationError (not raised)

Per R9.3, per-component failures are recorded as
`ClassificationError` records inside `ClassificationResult.errors`
and never raised:

| Error message form                                        | Cause                                                   |
|-----------------------------------------------------------|---------------------------------------------------------|
| `signature detection failed: raw_path missing`            | `component.raw_path` is None (R5.6)                     |
| `signature detection failed: file unreadable: {errno}`    | `os.open` returned EACCES / ENOENT / EIO (R5.6)         |
| `rule evaluation crashed: {exception class name}`         | An exception bubbled out of `matches()` for some rule   |
| `record validation failed: {pydantic message summary}`    | `ClassificationRecord` validator rejected the build     |
| `classification cancelled by caller`                      | `cancel()` returned True between components (R1.9)      |

Per R9.3 the per-component path **never** raises out of the entry
point. Per R9.5 the `errors` list is empty when every component
classifies successfully.

### The R5.6 dual-record contract

R5.6 carves out **one** explicit case where a single component
appears in *both* `records` and `errors`: when the component's
bytes are unreadable, `signature_info.present` is `False`, all
four axes classify normally per Requirements 3 and 4, and the
record is emitted alongside a `ClassificationError` describing the
missing-bytes condition. This is the only contracted v1 case
where the partition between `records` and `errors` is broken;
downstream consumers SHALL treat the pairing as "rule-only
classification with a known signature-detection limitation"
(R5.6 normative phrasing).

### Pre/post-condition contract

| Condition                                              | Behavior                                                                          |
|--------------------------------------------------------|-----------------------------------------------------------------------------------|
| `config.rules_path` missing / not a dir / unreadable   | Raise `ClassificationConfigError` (R2.4)                                          |
| Empty `*.yaml` files in `rules_path`                   | Skip each empty file with a `ClassificationRuleError`                             |
| Two rule files share a `rule_id`                       | Raise `ClassificationConfigError` after every file is parsed (R2.8)               |
| Empty input sequence                                   | Return `ClassificationResult([], [])` (R1.3)                                      |
| Input contains an Inner_Component                      | Classify identically to outer components (R7.1-R7.2)                              |
| `component.raw_path` is `None`                         | Emit dual record + error per R5.6                                                 |
| `component.raw_path` exists but file missing           | Emit dual record + error per R5.6                                                 |
| Caller-supplied `cancel()` returns True between calls  | Stop further classification, append "classification cancelled by caller" error,    |
|                                                        | return partial `ClassificationResult` (R1.9)                                      |
| Per-component evaluation raises an exception           | Catch, record `ClassificationError`, continue (R9.3)                              |
| Pydantic rejects a built `ClassificationRecord`        | Catch, record `ClassificationError`, do not emit the record (R9.3)                |

## Architecture

### Pipeline construction (`ClassificationPipeline.__init__`)

Satisfies R2 and R13.1.

```
ClassificationPipeline.__init__(config)
  │
  ├── 1. self._rules = load_rule_set(config)                       (R2.3)
  │       └── on any failure: raise ClassificationConfigError
  │           or ClassificationRuleError; no partial pipeline      (R2.4-R2.9)
  │
  ├── 2. self._taxonomy_version = config.taxonomy_version
  │
  ├── 3. self._classification_version = CLASSIFICATION_VERSION
  │
  └── 4. logger.info("classification pipeline ready
         rules_path=%s files=%d rules=%d
         taxonomy_version=%s classification_version=%s")           (R13.1)
```

The construction phase is the **only** place rule-loading happens.
After construction, `self._rules` is a `RuleSet` — a frozen
Pydantic model holding a tuple of frozen `Rule` instances —
guaranteed immutable for the lifetime of the pipeline (R2.3).

### Classify flow (`ClassificationPipeline.classify`)

Satisfies R1, R3-R5, R7-R10, R13.

```
ClassificationPipeline.classify(components, *, progress=None, cancel=None)
  │
  ├── 1. run_started_at = datetime.now(tz=UTC)                     (R1.6)
  │   t0 = time.monotonic()                                        (timing module only)
  │
  ├── 2. records: list[ClassificationRecord] = []
  │   errors: list[ClassificationError] = []
  │
  ├── 3. logger.info("classification run starting components=%d
  │     classification_version=%s")                                (R13.2)
  │
  ├── 4. For each (index, component) in enumerate(components, start=1):
  │     a. cancel() check; on True →
  │        errors.append(ClassificationError(
  │            component_id=None,
  │            error_message="classification cancelled by caller",
  │            timestamp=datetime.now(tz=UTC)))
  │        break the loop                                           (R1.9)
  │
  │     b. Build the four axis classifications:
  │        type_axis = classify_axis(rules, "type", component)
  │        vendor_axis = classify_axis(rules, "vendor", component)
  │        security_axis = classify_axis(rules, "security_posture", component)
  │        mutability_axis = classify_axis(rules, "mutability", component)
  │
  │        On any exception inside classify_axis:
  │          axes_classified = number of axes successfully built
  │          errors.append(ClassificationError(
  │              component_id=component.component_id,
  │              error_message=f"rule evaluation crashed: {type(e).__name__}",
  │              timestamp=datetime.now(tz=UTC)))
  │          logger.warning("classification per-component failure
  │              axes_classified=%d", axes_classified)              (R13.4)
  │          continue to next component
  │
  │     c. Signature detection:
  │        present, sig_error = detect_signature(component)
  │        signature_info = SignatureInfo(
  │            present=present, verified=False,
  │            signer=None, cert_expiry=None)                       (R5.1-R5.4)
  │        if sig_error:
  │            errors.append(ClassificationError(
  │                component_id=component.component_id,
  │                error_message=sig_error,
  │                timestamp=datetime.now(tz=UTC)))                 (R5.6 first half)
  │            # Continue past this — record still gets emitted.
  │
  │     d. Build the record:
  │        try:
  │            record = ClassificationRecord(
  │                component_id=component.component_id,
  │                source_image_id=component.source_image_id,       (R7.3, R10.2)
  │                extraction_offset=component.offset,
  │                timestamp=run_started_at,                        (R1.6, R8.1)
  │                type_axis=type_axis,
  │                vendor_axis=vendor_axis,
  │                security_axis=security_axis,
  │                mutability_axis=mutability_axis,
  │                signature_info=signature_info,
  │                cve_matches=[],                                  (R6, R10)
  │                suspicion_triggers=[],                           (R10.4)
  │                composite_confidence=0.0,                        (set by model)
  │                needs_review=True,                               (set by model)
  │                classification_version=self._classification_version,  (R1.5)
  │                overrides=[])                                    (R10.3)
  │            records.append(record)
  │        except pydantic.ValidationError as e:
  │            errors.append(ClassificationError(
  │                component_id=component.component_id,
  │                error_message=f"record validation failed: {summarize(e)}",
  │                timestamp=datetime.now(tz=UTC)))                 (R9.3)
  │            logger.warning("classification per-component failure
  │                axes_classified=4")                              (R13.4)
  │            continue
  │
  │     e. progress() callback if supplied:
  │        progress(ProgressEvent(
  │            index=index, total=len(components),
  │            component_id=str(component.component_id)))           (R12.1, R12.2)
  │
  ├── 5. duration_ms = (time.monotonic() - t0) * 1000.0
  │
  ├── 6. logger.info("classification run finished
  │     records=%d errors=%d duration=%.1fms")                       (R13.3)
  │
  └── 7. Return ClassificationResult(records=records, errors=errors)
```

The classify flow is **single-pass**, **synchronous**, and
**ordered** — components classify in input order, and the emitted
`records` list preserves that order (R8.3, R10.5). No ranking,
no batching, no concurrency.

### Per-axis evaluation (`classify_axis`)

Already covered above. The function holds no state beyond its
arguments. Calling it four times per component (one per axis)
costs O(R) per call where R is the count of rules whose `axis`
matches; the total per-component cost is O(R_total). For 4096
components and 1024 rules that is at most 4096 × 1024 = 4.2M
matcher evaluations, well inside R11.1's 30-second budget on
any 2024-class CPU (matcher evaluation is dominated by string
comparisons; ≥ 10M comparisons per second is conservative).

R11.5 explicitly defers a rule-indexing optimization (e.g.
GUID-keyed prefilter, dispatching to a
`dict[uuid.UUID, list[Rule]]` keyed by `rule.matcher.guid.values`).
A future revision MAY add such an index without changing the
public surface.

### Signature-detection I/O budget

Per R11.2 every read is bounded to ≤ 1 MiB chunks. Per R11.3 the
total signature-detection wall time over a 4096-component fleet
whose total `raw_path` byte footprint is ≤ 256 MiB SHALL stay
under 60 seconds. Sequential reads of 256 MiB on a local SSD
take ~1 second; the remaining ~59 seconds covers per-file `open` /
`stat` / parse overhead.

When `raw_path` is `None` or the file is missing, `detect_signature`
returns `(False, error_message)` immediately without performing
I/O. This is the path R5.6 carves out for the dual-record case.

### Determinism contract

The classify flow consults exactly two non-deterministic sources:

1. `datetime.now(tz=UTC)` — for `run_started_at` (R1.6) and for
   each error's `timestamp` field (R9.4).
2. `time.monotonic()` — for the duration measurement, only inside
   `loki/classification/timing.py`, mirroring the extraction
   pipeline's pattern (R8.5).

It does **not** consult:

- `os.environ` (R8.5)
- `random` / `secrets` / `os.urandom` (R8.5)
- `socket` / `urllib` / `requests` / `httpx` (R8.5)
- The filesystem outside `config.rules_path` and
  `component.raw_path` (R5.7)
- Any clock other than via the timing module

R8 is enforced *at source* (no offending imports), *at audit*
(`tests/classification/test_no_side_channels.py` AST-walks
`loki/classification/` for forbidden imports and timing calls),
and *at property test* (Hypothesis runs the same input twice and
compares records modulo timestamp).

The `timestamp` field is the **only** source of variance permitted
between two equivalent runs on the same input. R8.1's
`model_dump(mode="json")` equality after stripping `timestamp`
is the determinism property.

### Inner-component handling (R7)

The classify flow does not branch on whether a component is an
Inner_Component or an outer component (R7.1). The Pipeline reads
`component.source_image_id` exactly once, when constructing the
emitted `ClassificationRecord` (R7.3); whether that UUID derives
from `FirmwareImage.image_id` (outer) or from
`uuid5(LOKI_NAMESPACE, decompressed_hash)` (inner) is invisible
to classification.

The matcher language has no `inner_component` predicate (R7.5).
Curators that need to write inner-only or outer-only rules
express the distinction through the existing predicates over
fields the extraction pipeline records — typically via the parent
volume's `component_type_hint` (e.g. matching
`component_type_hint: "decompressed_section"` if the extraction
pipeline tags inner components that way) or through GUID
matching.

R7.4 is satisfied by construction: the classify flow never reads
`component` raw bytes for any purpose other than signature
detection on the component's own `raw_path`. It does not walk
inner buffers, does not decompress, does not chase
parent-component pointers.


## Correctness Properties

This section enumerates the invariants the classification subsystem
guarantees. Numbering continues from baseline-persistence's 23-32,
so the model layer owns 1-11, extraction owns 12-22,
baseline-persistence owns 23-32, and classification starts at 33.

### Property 33: Emitted ClassificationRecord is Pydantic-validated on return

For every component that survives classification, the
`ClassificationRecord` instance present in
`ClassificationResult.records` was constructed by direct
`ClassificationRecord(...)` instantiation (R10.1) and therefore
passed Pydantic v2 strict validation. Any caller can use the
record without re-validating.

**Validates: Requirements 9.3, 10.1**

### Property 34: Per-axis Winning_Rule selection is deterministic

For every component and every axis, given the same firing-rules
list, the Winning_Rule is the rule with the maximum
`effect.confidence` and, on ties, the lexicographically smallest
`rule_id`. Verified by Hypothesis property: generate two random
permutations of the same firing rules, run `classify_axis`
against the same component, assert identical
`AxisClassification.rule_id`.

**Validates: Requirements 4.4, 4.5**

### Property 35: Two runs on the same input produce equal records modulo timestamp

For every input component sequence and every fixed Rule_Set, two
invocations of `classify_components` produce two
`ClassificationResult` values whose `records` lists are equal
under `model_dump(mode="json")` after stripping the `timestamp`
field on every record. The equality includes the auto-computed
`composite_confidence` and `needs_review` fields, which derive
deterministically from the four axis confidences via the model
layer's invariants (R4.9).

**Validates: Requirements 8.1, 8.2**

### Property 36: Input order is preserved in the records list

For every input sequence `[c0, c1, ..., cn]`, the emitted
`ClassificationResult.records` list — restricted to entries with
non-`None` `component_id` — is a subsequence of `[c0, c1, ..., cn]`
(by `component_id`). The pipeline never reorders components.

**Validates: Requirements 8.3, 10.5**

### Property 37: ClassificationRecord round-trips through JSON losslessly

For every emitted `ClassificationRecord` `r`,
`ClassificationRecord.model_validate_json(r.model_dump_json())`
returns a record `r'` such that `r.model_dump(mode="json") ==
r'.model_dump(mode="json")`. Verified by Hypothesis property over
synthetic records.

**Validates: Requirements 8.6**

### Property 38: Re-classification is idempotent

For every input component sequence and every fixed Rule_Set, the
records produced by `classify_components(components, config)` and
the records produced by `classify_components(components, config)`
on the second invocation are equal under `model_dump(mode="json")`
modulo the `timestamp` field. Equivalent in spirit to Property 35
but emphasizes that calling the entry point repeatedly does not
accumulate state in the rule set or matcher.

**Validates: Requirements 8.7**

### Property 39: No-rule-fires fallback is exact

For every component on every axis where no rule fires, the
emitted `AxisClassification` has exactly:
`label = AXIS_UNKNOWN, confidence = 0.0, method = HEURISTIC,
rule_id = None, evidence = None`. The four `AXIS_UNKNOWN` values
are `ComponentTypeLabel.UNKNOWN`, `VendorLabel.UNKNOWN`,
`SecurityPostureLabel.UNKNOWN`, `MutabilityLabel.UNKNOWN`.

**Validates: Requirements 4.8**

### Property 40: Forbidden_Leakage_Field_Set is never logged

`loki.classification` does not log any of: extraction's
`component_id`, classification's mirrored `component_id`,
`SignatureInfo.signer`, the parent
`BaselineRecord.source_image_hash`, or any
`AxisClassification.evidence` string. Enforced by:

- AST audit at `tests/classification/test_no_log_leakage.py`
  walking `loki/classification/__path__` for `logger.{info,
  warning, error, debug}` call sites and asserting that no
  format string or argument expression references the forbidden
  fields by attribute path.
- Dynamic capture in `tests/classification/test_log_no_leakage.py`
  (note: separate file from the AST audit, mirroring the
  extraction pattern): use `caplog` to capture every message
  emitted during a curated classification run + a curated
  per-component-failure run, and assert no captured message
  contains the test fixture's `component_id` UUID, `source_image_hash`,
  or `evidence` string substrings.

**Validates: Requirements 13.5, 13.6**

### Property 41: No environmental side channels

`loki.classification` does not consult environment variables, the
random number generator, the network, or any clock other than
`datetime.now(tz=UTC)` (for `timestamp` fields permitted by
R1.6 and R9.4) and `time.monotonic()` (for duration measurement,
isolated to `loki/classification/timing.py`). Enforced by an AST
audit test (`tests/classification/test_no_side_channels.py`)
that walks `loki.classification.__path__` for forbidden imports
and forbidden time calls, mirroring extraction's Property 22 and
baseline-persistence's Property 32.

**Validates: Requirements 8.4, 8.5**

### Property 42: R5.6 dual-record contract holds

For every component whose `raw_path` is `None` or whose `raw_path`
file is missing or unreadable: the emitted result contains both
(a) one `ClassificationRecord` for the component with
`signature_info.present == False` and four axes classified per
Requirements 3 and 4, and (b) one `ClassificationError` with the
component's `component_id` and an error message identifying the
missing-bytes condition. Verified by a directed test, not
Hypothesis (the property is too narrow for shrinking to add
value).

**Validates: Requirements 5.6**

## Logging strategy

Satisfies R13.

- Logger name: `loki.classification` (R12.3, R13.5).
- Loggers in submodules use `logging.getLogger(f"loki.classification.{modname}")`.
- The subsystem never installs handlers, never sets levels, never
  logs to stdout/stderr directly.

INFO records:

- Pipeline construction: `"classification pipeline ready
  rules_path=%s files=%d rules=%d taxonomy_version=%s
  classification_version=%s"` (R13.1)
- Run start: `"classification run starting components=%d
  classification_version=%s"` (R13.2)
- Run end: `"classification run finished records=%d errors=%d
  duration=%.1fms"` (R13.3)

WARNING records:

- Per-component failure: `"classification per-component failure
  axes_classified=%d"` where `%d` is in `[0, 4]` (R13.4).
  **Notably absent**: the failed component's `component_id`,
  `source_image_id`, and any `evidence` string. The error
  message itself is also absent from the WARNING record — it
  lives only in the `ClassificationError.error_message` field
  in the result. R13.4 is normative on this; the rationale is
  that error messages may incidentally embed component
  identifying substrings (e.g. a vendor name from a parsed
  PE32 path) and the WARNING-record audit can't easily prove
  the message is leak-free.

ERROR records:

- On `ClassificationConfigError` and `ClassificationRuleError`
  raised from pipeline construction. The ERROR record includes
  the rules-directory path and the rule_id (when available)
  but never any component data — these are pre-classification
  errors.

R13.5 ("never log Forbidden_Leakage_Field_Set members") is
enforced by:

- **At source.** No log message in `loki.classification` references
  `component.component_id`, `record.component_id`,
  `signature_info.signer`, `record.source_image_id`, or any
  `axis.evidence` string directly. Reviewer-checkable.
- **At audit.** `tests/classification/test_no_log_leakage.py`
  AST-walks every Python file in `loki/classification/` and
  asserts no `logger.{info,warning,error,debug}` call's format
  string or argument expression references the forbidden field
  paths by `Attribute` access.
- **At test (dynamic).** `tests/classification/test_log_no_leakage.py`
  captures every emitted record during a curated run and asserts
  no captured message contains the test fixture's
  `component_id` UUID hex, `source_image_hash` hex, or evidence
  substrings.

R13.6 ("never log raw component bytes or per-axis evidence at any
time including idle / init / shutdown") follows from R13.5 and
the pipeline's stateless design — there is no idle state or
shutdown phase to leak from.

## Testing Strategy

Test layout mirrors source:

```
tests/classification/
├── __init__.py
├── conftest.py                    # fixtures: ClassificationConfig, scratch dirs, valid rule files
├── fixtures/
│   ├── __init__.py
│   ├── synthetic_components.py    # builds deterministic ExtractedComponent sequences
│   ├── synthetic_rules.py         # builds deterministic Rule / RuleSet objects + YAML files
│   └── golden/
│       ├── canonical_rules_v1.yaml         # one committed rule file for round-trip
│       └── canonical_classifications.json  # the expected classification output for the curated input
├── rules/
│   ├── __init__.py
│   ├── test_loader.py             # R2 (file enumeration, taxonomy version, duplicate rule_id)
│   ├── test_schema.py             # R2.7, R3 (Matcher/Effect Pydantic validators)
│   └── test_matcher.py            # R3.1-R3.8 (every predicate variant + conjunctive semantics)
├── test_classifier.py             # R4 (Winning_Rule, tie-break, no-rule-fires fallback)
├── test_signatures.py             # R5 (PE32 + UEFI auth wrapper recognizers, R5.6 missing-bytes)
├── test_pipeline.py               # R1, R7-R10 (entry point, inner components, errors, result construction)
├── test_pipeline_errors.py        # R9 (typed exceptions + per-component error rows)
├── test_pipeline_progress.py      # R12.1-R12.2 (progress callback contract)
├── test_pipeline_cancel.py        # R1.9 (cooperative cancellation)
├── test_determinism.py            # Properties 35-38 (Hypothesis)
├── test_no_side_channels.py       # Property 41 (AST audit)
├── test_no_log_leakage.py         # Property 40 (AST audit on logger calls)
├── test_log_no_leakage.py         # R13.5-R13.6 (dynamic capture)
├── test_performance.py            # R11.1, R11.3 (slow-marked, ≥4096 components scale)
└── test_golden.py                 # R8.6 (round-trip the canonical_classifications.json)
```

Plus integration tests that *don't* live under `tests/classification/`:

```
tests/test_classification_smoke.py  # one end-to-end run via classify_components against demo workspace
```

(Not in `tests/classification/` because the smoke test exercises
the full extract → classify path, importing both subsystems.)

### Synthetic fixture

`tests/classification/fixtures/synthetic_components.py` exports a
`build_components(*, count, source_image_id=None,
include_inner=False)` function that returns a deterministic
sequence of `ExtractedComponent` instances. Component
`component_id` values use fixed `uuid.uuid5` seeds so the
resulting sequence is byte-identical across runs.

`tests/classification/fixtures/synthetic_rules.py` exports
`build_rule_set(*, rules_dir, axis_distribution=...)` that writes
deterministic YAML rule files into `rules_dir` and returns the
expected `RuleSet`. Used by `test_loader.py` (rule files written
to a `tmp_path`) and by `test_pipeline.py` (full classification
runs).

### Golden-file regression

`tests/classification/fixtures/golden/canonical_rules_v1.yaml` is
committed and regenerated only when the schema or the synthetic
builder changes (mirroring the extraction-pipeline and
baseline-persistence approaches). The test re-runs classification
against the committed rule file with a curated input sequence
and compares the emitted records against
`canonical_classifications.json` modulo the timestamp field.

### Hypothesis budget

Per the project's existing convention (model layer uses
`max_examples=50`; baseline persistence uses `max_examples=25`
because each example saves and reads a YAML file), classification
property tests use `max_examples=50` for matcher / classifier
properties (in-memory) and `max_examples=25` for full-pipeline
properties (which read rule files and emit records). Both set
`suppress_health_check=[HealthCheck.too_slow]`.

### Performance tests (slow-marked)

Per the existing `slow` marker convention, `test_performance.py`
runs are excluded from the default `pytest -q` invocation:

- `pytest.mark.slow` — 4096-component × 1024-rule run, asserts
  total wall time < 30s (R11.1).
- `pytest.mark.slow` — 4096-component signature detection over
  ≤ 256 MiB of scratch raw bytes, asserts wall time < 60s (R11.3).

The slow marker is consistent with extraction's
`tests/extraction/test_performance.py` and persistence's
`tests/baseline/test_performance.py`.

### What's deliberately not tested

- Real-world vendor firmware classifications — no public corpus
  of curated rules exists, and curated rules are downstream
  work. Future spec.
- Network behavior — the subsystem doesn't have any.
- CVE feed integration — explicitly out of scope (R6).
- Signature verification — explicitly out of scope (R5.2-R5.3).
- GUI integration on real workspaces — covered by a future GUI
  classification spec; v1 ships only the library API.
- CLI subcommand — covered by a future CLI classification spec.

## Deferred decisions and open questions

Tracked here so future sessions don't re-derive answers.

1. **Rule indexing optimization.** R11.5 explicitly defers a
   GUID-keyed prefilter (or any other rule indexing). The v1
   contract is linear scan over `RuleSet.rules` for each axis.
   If real-world rule sets approach the 1024-rule cap and the
   30-second budget gets uncomfortably close, a future revision
   adds a `dict[uuid.UUID, list[Rule]]` index keyed by
   `rule.matcher.guid.values` (the cheapest predicate to index)
   and falls back to linear scan for rules without a `guid`
   predicate. The change is internal to `classifier.py` and
   does not affect the public surface.
2. **Disjunctive matchers.** R3.7 forbids disjunction at the
   Matcher level; curators write multiple Rules with the same
   axis to express OR. If this proves too verbose for real
   rule sets, a future revision adds an `any_of:` block at the
   Matcher level. Until then, every `axis: vendor` rule that
   wants to match (Intel OR AMD) writes two rules with the same
   `effect.label`.
3. **Regex / glob predicates.** R3.8 forbids both. If real-world
   rules need pattern matching on `name` beyond
   `equals/prefix/suffix/contains`, a future revision adds a
   `regex:` operator with a fixed Python regex engine.
4. **Cross-axis inference.** R4.3 forbids it. If, say, a
   `type=MICROCODE` classification ought to *imply*
   `vendor=INTEL` on certain GUIDs, that's a v2 feature.
5. **Signature verification.** R5.2 sets `verified=False` in v1.
   A future trust-root-aware spec replaces `detect_signature`
   with `detect_and_verify_signature`, accepts a `TrustRoot`
   argument, and lifts R5.2-R5.4. The `SignatureInfo` model
   already has `signer: str | None` and `cert_expiry: datetime |
   None` fields ready to populate.
6. **CVE feed integration.** R6 stubs `cve_matches` to `[]`. A
   future CVE-feed spec defines an NVD ingestion subsystem that
   maps `(component, classification)` pairs to CVE entries via
   CPE-style keys.
7. **Cancellation event payload.** R1.9 records cancellation as
   a single `ClassificationError(component_id=None, ...)`. The
   index in the input sequence at which cancellation happened
   is **not** captured in v1. If diagnostics need it, the
   future revision can add it to the error message string
   without changing the `ClassificationError` Pydantic shape.
8. **Progress callback `component_id` leakage.** Documented
   above under "Progress callback and the leakage rule."
   `ProgressEvent.component_id` is the one place the
   Forbidden_Leakage_Field_Set's `component_id` is exposed
   outside the result records. The judgment call favors
   observable progress; if a stricter read of R13.5 is desired,
   the field is the cheap revert.
9. **CLI surface.** R12.4 defers `loki classify` to a separate
   spec. The library API (R1.2's
   `from loki.classification import classify_components`) is
   the v1 contract; a future `classification-cli` spec defines
   `loki classify run`, `loki classify show`, etc.
10. **GUI classification view.** R12.5 defers this to a separate
    spec. The v1 library API doesn't depend on Qt and runs
    headless.

## Traceability matrix

| Requirement   | Design section(s)                                                                  |
|---------------|------------------------------------------------------------------------------------|
| R1.1-R1.9     | "Public API surface — `classify_components`", "Classify flow"                      |
| R2.1-R2.9     | "Module layout", "Rule schema", "Rule-set loader (`load_rule_set`)"                |
| R3.1-R3.9     | "Rule schema", "Matcher evaluator (`matches`)"                                     |
| R4.1-R4.10    | "Per-axis classifier (`classify_axis`)", "Classify flow"                           |
| R5.1-R5.7     | "Signature detection (`detect_signature`)", "The R5.6 dual-record contract"        |
| R6            | "Goals and non-goals — Non-goals", "Classify flow step 4d"                         |
| R7.1-R7.5     | "Inner-component handling (R7)"                                                    |
| R8.1-R8.7     | "Determinism contract", Properties 35-38, 41                                       |
| R9.1-R9.5     | "Public API surface — Exception hierarchy", "Error Handling"                       |
| R10.1-R10.5   | "Public API surface — `classify_components`", "Classify flow step 4d"              |
| R11.1-R11.5   | "Per-axis evaluation", "Signature-detection I/O budget", "Performance tests"       |
| R12.1-R12.5   | "Progress callback and the leakage rule", "Goals and non-goals — Non-goals"        |
| R13.1-R13.6   | "Logging strategy", Property 40                                                    |

Every acceptance criterion has at least one design section it maps
to, and every design section cites at least one acceptance criterion
it satisfies.
