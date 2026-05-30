
# Design Document — Analysis Engine

## Overview

The Analysis Engine turns a sequence of `ClassificationRecord` instances produced by the classification pipeline, plus a `BaselineRegistry` loaded by GLEIPNIR, plus a `FirmwareImage` describing the target, plus an `AnalysisConfig`, into a validated `ImageAnalysisReport`. It pairs target records with baseline records by `component_id`, emits one or more `FindingRecord` instances per pair (or per unpaired record on either side) along the six v1 finding categories, computes per-pair `DeviationScore` instances for `classification_mismatch` findings, and assembles the report with a deterministic `posture_rating` derived from the closed mapping in requirements.md R17.5.

The subsystem is **synchronous**, **single-threaded**, **deterministic** (same Target_Records + same Matched_Baseline + same `AnalysisConfig` + same Analysis_Engine version ⇒ bit-equal report modulo the explicit `ImageAnalysisReport.timestamp` and the cooperative-cancellation `evidence.raw_indicators[0]` value), and **honest** about what it cannot do — config / lookup / input failures raise typed exceptions before any finding emission, signature handling reads `signature_info.present` without verifying signers, CVE matching is explicitly out of scope (`cve_matches` carried into the engine is always empty per classification R6 and v1 of this engine never populates `evidence.matched_cve`), persistence is the caller's responsibility, and the analysis CLI / GUI integration surfaces are reserved for separate specs.

The shape mirrors `extraction-pipeline`, `baseline-persistence`, and `classification-pipeline`: a small public surface in `loki.analysis`, a typed exception hierarchy at `loki/analysis/errors.py`, an `AnalysisProgressEvent` dataclass, an AST audit pinning side-channel imports, a logging audit pinning the Forbidden_Leakage_Field_Set, and a designated timing module insulating `time.monotonic()` access from determinism checks. Each non-trivial design choice cites the acceptance criteria it satisfies (e.g. `R7.4` = Requirement 7 acceptance criterion 4 from `.kiro/specs/analysis-engine/requirements.md`).

## Goals and non-goals

### Goals

- Deliver a stable, typed `analyze_image` callable importable as `from loki.analysis import analyze_image` (R1.1, R1.2, R19.1).
- Resolve the Matched_Baseline per the three Match_Strategy values (`EXPLICIT`, `AUTO`, `EXPLICIT_OR_AUTO`), raising typed `BaselineNotFoundError` on lookup failure and typed `AnalysisConfigError` on strategy/config errors (R2, R16.2-R16.3).
- Pair Target_Records with Baseline_Manifest records by `component_id` only, raising typed `AnalysisInputError` on duplicate-id inputs on either side (R3, R16.4).
- Emit findings in the closed v1 set of six categories: `classification_mismatch`, `signature_regression`, `unexpected_component`, `missing_required_component`, `classification_gap`, `analysis_cancelled` (R4-R8, R10).
- Compute four `Axis_Score` values per paired component, sum them under `AnalysisConfig.severity_weights`, scale to `Composite_Score` in `[0.0, 10.0]`, and embed a `DeviationScore` on every `classification_mismatch` finding via the new optional `FindingEvidence.deviation_score` field (R9).
- Emit `analysis_cancelled` (the Cancellation_Marker) exactly once per cancelled run, as the last entry of `findings`, with deterministic sentinel `component_id` and `finding_id`, with the cancellation index recorded in `evidence.raw_indicators[0]` only (never logged) (R7).
- Construct a Pydantic-validated `ImageAnalysisReport` per R17, including a `BaselineComparison` whose `comparison_timestamp` equals the report's `timestamp` (R17.4 post-HARDEN amendment), and a `posture_rating` per the six-rule closed mapping including the v1 escalation of `classification_mismatch: CRITICAL` to `COMPROMISED` (R17.5 post-HARDEN amendment).
- Stay completely independent of `loki.gui` (R1.9).
- Stay free of `os.environ` / `random` / `secrets` / `socket` / network-library imports outside the designated timing module (R15.4).
- Bound a 1024-component target × 1024-component baseline run under 5 seconds wall time and under 64 MiB peak working set on a 2024-class developer laptop with a local SSD (R18.1, R18.3).

### Non-goals (explicit)

- **CVE matching.** `FindingEvidence.matched_cve` stays `None` for every emitted finding in v1 (R9.9, intro non-goals). `feeds` subsystem (OT-LK-002) populates this in a future spec.
- **Signature verification.** v1 reads `signature_info.present` only; it does not parse signer identity, certificate validity, or trust roots (R5.5 + classification R5.2-R5.3).
- **Fleet analysis.** `analyze_fleet` is reserved for a future spec; v1 exposes only `analyze_image` (R19.7).
- **Persistence of `ImageAnalysisReport`.** v1 returns the report; on-disk storage is a separate future spec.
- **Analyst overrides on findings.** The model layer's `OverrideRecord` is consumed by classification only; analysis v1 does not produce or consume overrides.
- **CLI subcommand surface.** `loki analyze run/show/...` is a future spec (R19.5).
- **GUI integration surface.** The Analysis tab in the GUI scaffold remains a placeholder; wiring it to this engine is a separate future spec (R19.6).
- **Filtering by `default_severity_threshold`.** v1 reads but does not consume the field for any control flow (R14.5); consumers apply the threshold at presentation time.
- **`recommended_actions` generation.** v1 leaves the list `[]` (R17.3); a future revision generates remediation actions.
- **Per-axis indexing optimization.** v1 builds a single `dict[uuid.UUID, ClassificationRecord]` keyed by `component_id` for pairing (R18.2). Per-axis indexing is deferred.

## Constraints carried forward

- Python 3.11+ (3.12 baseline). All new code must satisfy `mypy --strict`, `ruff check`, and `ruff format`.
- Pydantic v2 strict mode for every model in `loki.models`. The engine constructs `FindingRecord`, `DeviationScore`, `BaselineComparison`, and `ImageAnalysisReport` directly so their validators run before the value escapes the subsystem (R17.1).
- `loki.analysis` must not import from `loki.gui` (R1.9).
- Logging via the stdlib `logging` module under the logger name `loki.analysis` (R19.4, R20.6).
- No content leakage in logs at any time (R20.5). The Forbidden_Leakage_Field_Set inherits classification's `{component_id, signature_info.signer, BaselineRecord.source_image_hash, AxisClassification.evidence}` and adds `FindingEvidence.matched_rule`, `FindingEvidence.matched_cve`, `FindingEvidence.matched_signature`, `FindingEvidence.raw_indicators`, `FindingRecord.title`, and `FindingRecord.description`.
- Determinism: the engine SHALL NOT consult environment variables, the random number generator, the system clock other than for the run-start timestamp, or any network resource for any decision that affects report contents (R15.3).
- Property numbering picks up at **P43** per the platform-wide convention recorded in `loki/HANDOFF.md` (model layer 1-11, extraction 12-22, baseline-persistence 23-32, classification 33-42, analysis 43-52).


## Components and Interfaces

This section catalogues the public surface, internal pipeline, and exception hierarchy. The module layout in §Architecture below shows where each component lives. The Components and Interfaces material is consolidated here as a single top-level section to match the project's spec-format conventions; the Architecture subsection that follows expands the same content with code-shaped detail.

The four interface families are:

1. **Public surface** (`loki.analysis.api`): `analyze_image`, `AnalysisProgressEvent`, `AnalysisProgressCallback`, `AnalysisCancellationToken`. All consumers (future CLI, future GUI, tests) import from `loki.analysis`.
2. **Internal pipeline** (`loki.analysis.pipeline`): `AnalysisPipeline` class. Holds the resolved Matched_Baseline; constructed once per `analyze_image` call; not part of the public surface (D1 default).
3. **Per-category emitters** (`loki.analysis.findings`): `emit_classification_mismatch`, `emit_signature_regression`, `emit_unexpected_component`, `emit_missing_required_component`, `emit_classification_gap`, `make_cancellation_marker`, `derive_finding_id`. Pure functions; no side effects beyond their return values.
4. **Exception hierarchy** (`loki.analysis.errors`): `AnalysisError` root + four subclasses (`AnalysisConfigError`, `BaselineNotFoundError`, `AnalysisInputError`, `AnalysisReportConstructionError`). Standard `Exception` subclasses; module at `loki/analysis/errors.py` per D2 default.

The detailed code-shape for each family follows under `## Architecture`.

## Architecture

### Module layout

```
loki/analysis/
├── __init__.py        # re-exports the public surface
├── api.py             # analyze_image entry point + AnalysisProgressEvent
├── pipeline.py        # AnalysisPipeline (internal, single-construct site)
├── version.py         # ANALYSIS_VERSION constant
├── matching.py        # Match_Strategy resolution → Matched_Baseline
├── pairing.py         # Component_Pairing logic over (Target_Records, Baseline_Manifest)
├── findings.py        # per-category finding emitters (R4-R8, R10)
├── scoring.py         # Axis_Score + Composite_Score + DeviationScore construction (R9)
├── posture.py         # PostureRating closed-mapping evaluator (R17.5)
├── report.py          # ImageAnalysisReport assembly + BaselineComparison construction (R17)
├── errors.py          # typed exception hierarchy (D2 default — mirrors baseline / classification)
└── timing.py          # designated module for time.monotonic() (mirrors classification)
```

`loki/analysis/__init__.py` re-exports exactly:

```python
from loki.analysis.api import (
    AnalysisProgressEvent,
    analyze_image,
)
from loki.analysis.errors import (
    AnalysisConfigError,
    AnalysisError,
    AnalysisInputError,
    AnalysisReportConstructionError,
    BaselineNotFoundError,
)
from loki.analysis.version import ANALYSIS_VERSION
```

The `__init__.py` module docstring documents the determinism contract per R15.1-R15.8 ("same Target_Records + same Matched_Baseline + same `AnalysisConfig` + same Analysis_Engine version ⇒ bit-equal report modulo `ImageAnalysisReport.timestamp` and, for cancelled runs, the Cancellation_Marker's `evidence.raw_indicators`; preserves input ordering of Target_Records; round-trips through JSON losslessly; idempotent under re-analysis").

### Public API surface

#### `analyze_image` (R1.1-R1.11, R19.1-R19.4)

```python
# loki/analysis/api.py
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from loki.models.baseline import BaselineRegistry
from loki.models.classification import ClassificationRecord
from loki.models.config import AnalysisConfig
from loki.models.firmware import FirmwareImage
from loki.models.reports import ImageAnalysisReport


@dataclass(frozen=True)
class AnalysisProgressEvent:
    """Structured progress event emitted at component granularity (R19.2).

    Emitted exactly once at the start of each Target_Record's per-pair
    evaluation. Strips ``component_id`` deliberately (D6 default) so
    that the progress callback contract cannot leak any value in the
    Forbidden_Leakage_Field_Set; the GUI / CLI consumer can render
    "component N of total" without knowing the UUID.

    See "Progress callback and the leakage rule" below.
    """

    index: int   # 1-based position in the input sequence
    total: int   # static input-sequence length captured at run start


# Type aliases on the public entry point.
AnalysisProgressCallback = Callable[[AnalysisProgressEvent], None]
AnalysisCancellationToken = Callable[[], bool]


def analyze_image(
    target_records: Sequence[ClassificationRecord],
    registry: BaselineRegistry,
    target_image: FirmwareImage,
    config: AnalysisConfig,
    *,
    progress: AnalysisProgressCallback | None = None,
    cancel: AnalysisCancellationToken | None = None,
) -> ImageAnalysisReport:
    """Analyze a target firmware image against a matched baseline (R1.1-R1.11).

    Constructs a single internal ``AnalysisPipeline`` from the four
    inputs, resolves the Matched_Baseline per ``config.match_strategy``
    (R2), pairs Target_Records with the Baseline_Manifest by
    ``component_id`` (R3), emits findings per Requirements 4 through 10,
    computes ``DeviationScore`` instances for ``classification_mismatch``
    findings (R9), and assembles a Pydantic-validated
    ``ImageAnalysisReport`` per Requirement 17.

    Raises only typed ``AnalysisError`` subclasses for whole-run
    failures (config errors, baseline lookup failures, duplicate-id
    inputs, final-report construction failures). Cooperative
    cancellation produces a partial report carrying an
    ``analysis_cancelled`` finding and SHALL NOT raise (R1.10, R7,
    R16.6).

    Runs synchronously on the calling thread and never spawns workers
    (R1.8). Progress callback, if supplied, is invoked from the
    calling thread only (R19.3).
    """
```

#### `AnalysisPipeline` (internal — R2.3, R3, R4-R10, R17)

```python
# loki/analysis/pipeline.py
class AnalysisPipeline:
    """Internal pipeline holding the resolved Matched_Baseline.

    Construction validates ``config`` against Requirement 14, resolves
    the Matched_Baseline per Requirement 2, and validates pairing
    inputs per Requirement 3. The pipeline instance is single-use:
    ``run`` is called once per ``analyze_image`` invocation. The
    pipeline holds no per-run mutable state beyond the run timestamp
    chosen at the start of ``run``.
    """

    def __init__(
        self,
        target_records: Sequence[ClassificationRecord],
        registry: BaselineRegistry,
        target_image: FirmwareImage,
        config: AnalysisConfig,
    ) -> None:
        """Validate config (R14), resolve Matched_Baseline (R2),
        and check pairing pre-conditions (R3.6, R3.7).

        Raises ``AnalysisConfigError`` on any Requirement 14 violation.
        Raises ``BaselineNotFoundError`` on Requirement 2 lookup
        failure. Raises ``AnalysisInputError`` on duplicate
        ``component_id`` values in either ``target_records`` or
        ``Matched_Baseline.component_manifest``.
        """

    def run(
        self,
        *,
        progress: AnalysisProgressCallback | None = None,
        cancel: AnalysisCancellationToken | None = None,
    ) -> ImageAnalysisReport:
        """Run analysis per Requirements 3 through 17.

        Returns a Pydantic-validated ``ImageAnalysisReport`` on
        success. On cooperative cancellation, returns a partial
        ``ImageAnalysisReport`` carrying an ``analysis_cancelled``
        Cancellation_Marker as the last entry of ``findings``
        (R7.6).

        Raises ``AnalysisReportConstructionError`` if final report
        construction fails Pydantic validation (R16.5).
        """
```

The `AnalysisPipeline` is **internal** (D1 default — free function `analyze_image` is the public surface). This avoids inviting callers to construct multiple pipelines from the same config, mutate the pipeline between calls, or spread analysis state across calls. The Matched_Baseline-resolved-once contract (R2) is easier to defend behind a free function that constructs and discards in one call. Mirrors the classification-pipeline shape exactly.

### Exception hierarchy (R16, D2 default — module at `loki/analysis/errors.py`)

```
AnalysisError                                # all errors raised by this subsystem
├── AnalysisConfigError                      # R16.2 (Requirement 14 violations)
├── BaselineNotFoundError                    # R16.3 (Requirement 2 lookup failure)
├── AnalysisInputError                       # R16.4 (duplicate component_id on either side)
└── AnalysisReportConstructionError          # R16.5 (Pydantic final-validation failure)
```

`AnalysisError` is the root. It subclasses `Exception`. Four subclasses, one per failure mode. Each carries enough structured context to identify the offending input without leaking any value in the Forbidden_Leakage_Field_Set.

```python
# loki/analysis/errors.py
import uuid
from collections.abc import Iterable

__all__ = [
    "AnalysisConfigError",
    "AnalysisError",
    "AnalysisInputError",
    "AnalysisReportConstructionError",
    "BaselineNotFoundError",
]


class AnalysisError(Exception):
    """Root of the analysis-engine exception hierarchy (R16.1)."""


class AnalysisConfigError(AnalysisError):
    """Raised when AnalysisConfig violates Requirement 14 (R16.2).

    Carries the offending field name and a redacted message. SHALL NOT
    carry any field value derived from Target_Records or
    Matched_Baseline contents.
    """

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(f"{field_name}: {message}")
        self.field_name = field_name


class BaselineNotFoundError(AnalysisError):
    """Raised when baseline matching fails per Requirement 2 (R16.3).

    Carries either the offending baseline_id (EXPLICIT path) or the
    offending (vendor, model, firmware_version) tuple (AUTO /
    EXPLICIT_OR_AUTO fallback path).
    """

    def __init__(
        self,
        *,
        baseline_id: uuid.UUID | None = None,
        vendor_model_version: tuple[str, str, str] | None = None,
    ) -> None:
        if baseline_id is not None and vendor_model_version is None:
            super().__init__(f"baseline not found by id: {baseline_id}")
        elif vendor_model_version is not None and baseline_id is None:
            v, m, fw = vendor_model_version
            super().__init__(f"baseline not found by vendor/model/version: ({v!r}, {m!r}, {fw!r})")
        else:
            raise ValueError(
                "BaselineNotFoundError requires exactly one of baseline_id or vendor_model_version"
            )
        self.baseline_id = baseline_id
        self.vendor_model_version = vendor_model_version


class AnalysisInputError(AnalysisError):
    """Raised on duplicate component_id values in inputs per Requirement 3 (R16.4)."""

    def __init__(
        self,
        *,
        side: str,                                  # "target" or "baseline"
        duplicates: Iterable[uuid.UUID],
        baseline_id: uuid.UUID | None = None,       # only set when side == "baseline"
    ) -> None:
        ids_str = ", ".join(str(d) for d in duplicates)
        if side == "baseline":
            super().__init__(
                f"duplicate component_id in baseline {baseline_id}: [{ids_str}]"
            )
        else:
            super().__init__(f"duplicate component_id in target_records: [{ids_str}]")
        self.side = side
        self.duplicates = list(duplicates)
        self.baseline_id = baseline_id


class AnalysisReportConstructionError(AnalysisError):
    """Raised when final ImageAnalysisReport construction fails Pydantic validation (R16.5).

    Carries the offending Pydantic ``loc`` path and the Pydantic
    error message. SHALL NOT carry any value from the
    Forbidden_Leakage_Field_Set.
    """

    def __init__(self, loc: tuple[int | str, ...], message: str) -> None:
        loc_str = ".".join(str(p) for p in loc)
        super().__init__(f"{loc_str}: {message}")
        self.loc = loc
```

Observations:

- `AnalysisInputError` carries the duplicate `component_id` values verbatim. `component_id` is in the Forbidden_Leakage_Field_Set per the no-leakage rule (R20.5), but the rule applies to *log records*, not to *exception messages raised to the caller*. The caller is responsible for choosing whether to log the exception verbatim. The classification-pipeline pattern is identical: `ClassificationRuleError` carries `rule_id`, which is in the matched-rule leakage set, but the exception itself raises to the caller.
- `BaselineNotFoundError`'s `vendor_model_version` is **not** in the Forbidden_Leakage_Field_Set. `vendor`, `model`, and `firmware_version` are public metadata describing the firmware image; they are explicitly included in the run-start INFO log per R20.1. Safe to include in the exception message.
- `AnalysisReportConstructionError.loc` is the Pydantic field path; values are excluded from the message. The Pydantic exception's full detail is never wrapped — only the `loc` path and a sanitized message.

### Cancellation_Marker (R7)

The `analysis_cancelled` finding is constructed by a single helper in `loki/analysis/findings.py`:

```python
# loki/analysis/findings.py
import uuid
from loki.models.firmware import LOKI_NAMESPACE
from loki.models.analysis import FindingEvidence, FindingRecord
from loki.models.enums import SeverityLevel

# Module constant — derived once at import time, fixed across runs (R7.2).
ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID: uuid.UUID = uuid.uuid5(
    LOKI_NAMESPACE, "analysis-cancelled"
)


def make_cancellation_marker(
    *,
    baseline_id: uuid.UUID,
    cancelled_at_index: int,
) -> FindingRecord:
    """Construct the Cancellation_Marker finding (R7.1-R7.8).

    Called exactly once per cancelled run, after partial findings
    have already been emitted. The 1-based ``cancelled_at_index``
    is the position of the Target_Record that was about to be
    processed when the cancellation token returned True; it is
    embedded in ``evidence.raw_indicators[0]`` only and SHALL
    NOT appear in any log record (R7.4, R20.5).
    """
    finding_id = derive_finding_id(
        baseline_id=baseline_id,
        finding_category="analysis_cancelled",
        target_component_id=ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
    )
    return FindingRecord(
        finding_id=finding_id,
        component_id=ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID,
        severity=SeverityLevel.INFO,
        category="analysis_cancelled",
        title="analysis cancelled",
        description="cooperative cancellation observed; partial findings returned",
        evidence=FindingEvidence(
            classification_record=None,
            matched_rule=None,
            matched_cve=None,
            matched_signature=None,
            raw_indicators=[f"cancelled-at-index={cancelled_at_index}"],
            deviation_score=None,
        ),
        recommended_action="",  # v1: no recommended actions per R17.3
    )
```


## Data Models

This subsystem extends three model-layer files. Each extension is backwards-compatible: existing call sites continue to construct the affected models with the same argument shape they used before.

#### `MatchStrategy` enum (D5 default — added to `loki/models/enums.py`)

```python
# loki/models/enums.py — appended

class MatchStrategy(StrEnum):
    """Match strategy for resolving the Matched_Baseline (R2.1)."""

    EXPLICIT = "EXPLICIT"
    AUTO = "AUTO"
    EXPLICIT_OR_AUTO = "EXPLICIT_OR_AUTO"
```

The enum joins the project's 14 existing StrEnums; this matches the R2.1 wording ("v1 defines as one of exactly three string values: `EXPLICIT`, `AUTO`, and `EXPLICIT_OR_AUTO`") and the project's serialization-friendly StrEnum pattern.

#### `AnalysisConfig` extension (R14, D4 default — direct add to `loki/models/config.py`)

```python
# loki/models/config.py — AnalysisConfig amended

import uuid
from pydantic import Field
from loki.models.enums import MatchStrategy


class AnalysisConfig(BaseModel):
    """Configuration for the analysis engine.

    ``severity_weights`` values must sum to 1.0 within floating-point tolerance.
    """

    model_config = ConfigDict(strict=True, frozen=False)

    _WEIGHT_SUM_TOLERANCE: ClassVar[float] = 1e-6

    severity_weights: dict[str, float]
    default_severity_threshold: SeverityLevel
    report_template: str | None = None

    # NEW (R14.2, R14.3, R14.4):
    match_strategy: MatchStrategy = MatchStrategy.AUTO
    confidence_gap_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    baseline_id: uuid.UUID | None = None

    # ... existing severity_weights validator unchanged ...
```

Three new fields, each with a default that preserves the existing call-site contract:

- `match_strategy` defaults to `AUTO` (the most common case — auto-match by `(vendor, model, firmware_version)`). Existing `AnalysisConfig` constructions that omit the field get `AUTO` and the engine's auto-match path.
- `confidence_gap_threshold` defaults to `0.6` (matches the model layer's hard-coded `needs_review = composite_confidence < 0.60` invariant on `ClassificationRecord`, so a `classification_gap` finding fires under the same condition that already flagged `needs_review`).
- `baseline_id` defaults to `None`. Required when `match_strategy=EXPLICIT`; ignored when `match_strategy=AUTO`; consulted-then-fallback when `match_strategy=EXPLICIT_OR_AUTO` (R2.4).

The engine's R14 validator enforces the four-key set on `severity_weights` (`{"type", "vendor", "security_posture", "mutability"}`) at the start of every run. The model-layer's existing sum-to-1.0 validator catches the weight total at construction time. Any failure of either check raises `AnalysisConfigError` per R16.2.

The model layer's R14.5/R14.6 reservations stand: `default_severity_threshold` and `report_template` are still read by the model and serialized to YAML, but the engine never branches on either field in v1.

#### `FindingEvidence.deviation_score` extension (R9.1, D3 default — direct add to `loki/models/analysis.py`)

```python
# loki/models/analysis.py — FindingEvidence amended

class FindingEvidence(BaseModel):
    """Structured evidence supporting an analysis finding."""

    model_config = ConfigDict(strict=True, frozen=False)

    classification_record: ClassificationRecord | None = None
    matched_rule: str | None = None
    matched_cve: str | None = None
    matched_signature: str | None = None
    raw_indicators: list[str] = []

    # NEW (R9.1):
    deviation_score: DeviationScore | None = None
```

Single optional field, defaulting to `None`. Existing call sites that construct `FindingEvidence` (none in v0.1.0 — the model is consumed only via `FindingRecord`) keep the same call shape. The Pydantic strict-mode validator covers the new field automatically; no custom validator is needed because `DeviationScore` already validates its own range invariants on construction.

The R9.1 wording ("backwards-compatible because every existing call site treats `FindingEvidence` as a constructed-once value with a small set of populated fields") is honored: the new field never appears in serialized YAML or JSON unless a `classification_mismatch` finding's caller populated it. JSON / YAML round-trip stays bit-equal for any `FindingEvidence` whose `deviation_score` is `None`.

The serialized form, when populated, looks like:

```yaml
evidence:
  classification_record: { ... full record ... }
  matched_rule: null
  matched_cve: null
  matched_signature: null
  raw_indicators: []
  deviation_score:
    base_severity: HIGH
    component_criticality: 0.85
    security_direction: DEGRADED
    signature_delta: NONE
    cve_introduced: false
    mutability_change: NONE
    composite_score: 6.4
    priority_rank: 1
```

All eight `DeviationScore` fields appear when populated; the Pydantic strict-mode validators enforce the bounds (`composite_score` in `[0.0, 10.0]`, `component_criticality` in `[0.0, 1.0]`, `priority_rank >= 1`) that the model layer already pins.


## Sequence walkthrough

The end-to-end sequence of a successful `analyze_image` call:

```
analyze_image(target_records, registry, target_image, config, *, progress=None, cancel=None)
│
├─ AnalysisPipeline.__init__(...)
│  ├─ validate_config(config)                          # R14 keyset + already-Pydantic-validated bounds
│  │  └─ raise AnalysisConfigError on violation        # R16.2
│  ├─ resolve_matched_baseline(config, registry, target_image)
│  │  ├─ EXPLICIT path:           registry.get_by_id(config.baseline_id)
│  │  ├─ AUTO path:               registry.get_by_vendor_model_version(...)
│  │  └─ EXPLICIT_OR_AUTO path:   try EXPLICIT (if baseline_id set), else AUTO
│  │     └─ raise BaselineNotFoundError on miss        # R16.3
│  └─ check_pairing_preconditions(target_records, matched_baseline)
│     └─ raise AnalysisInputError on duplicate component_ids   # R16.4
│
├─ AnalysisPipeline.run(progress, cancel)
│  ├─ run_started_at = datetime.now(UTC)               # single timestamp anchors run (R1.6)
│  ├─ INFO log: matched-baseline tuple, target count, match_strategy   # R20.1
│  ├─ start = time.monotonic()                         # via timing module
│  │
│  ├─ pair components by component_id                  # R3.1, R18.2 (single dict)
│  │  baseline_index = {r.component_id: r for r in matched_baseline.component_manifest}
│  │
│  ├─ for index, target in enumerate(target_records, start=1):
│  │     ├─ if cancel and cancel():                    # R1.10, R7
│  │     │     emit Cancellation_Marker (R7.1-R7.5)
│  │     │     break
│  │     ├─ if progress: progress(AnalysisProgressEvent(index=index, total=N))   # R19.2
│  │     ├─ baseline = baseline_index.get(target.component_id)
│  │     │
│  │     ├─ if baseline is None:                       # unpaired Target_Record
│  │     │     emit unexpected_component finding       # R6
│  │     │     # No classification_mismatch / signature_regression for unpaired (R6.6)
│  │     │
│  │     ├─ else:                                      # paired (target, baseline)
│  │     │     if axis labels disagree on any of the 4 axes:
│  │     │         compute Axis_Score per axis         # R9.2-R9.3
│  │     │         compute Composite_Score             # R9.4
│  │     │         derive base_severity from Composite_Score   # R10.7
│  │     │         construct DeviationScore            # R9.6-R9.10 (priority_rank pass 2)
│  │     │         emit classification_mismatch finding    # R4
│  │     │     if signature_info.present differs (both non-None):
│  │     │         emit signature_regression finding   # R5
│  │     │
│  │     └─ if target.composite_confidence < config.confidence_gap_threshold:
│  │           emit classification_gap finding         # R10.1, R10.6
│  │
│  ├─ for baseline_only in baselines_unpaired:
│  │     emit missing_required_component finding       # R8 (sorted by ascending component_id per R3.4)
│  │
│  ├─ assign priority_rank to classification_mismatch findings   # R9.10, second pass
│  │  (sort by descending Composite_Score, ascending component_id; rank starts at 1)
│  │
│  ├─ derive PostureRating from finding categories + scores      # R17.5 (six-rule cascade)
│  │
│  ├─ construct BaselineComparison(
│  │      baseline_id=matched_baseline.baseline_id,
│  │      target_image_id=target_image.image_id,
│  │      comparison_timestamp=run_started_at,        # R17.4 post-HARDEN
│  │      deviations=[],                              # R17.4
│  │  )
│  │
│  ├─ construct ImageAnalysisReport(...)              # R17.1
│  │  └─ raise AnalysisReportConstructionError on Pydantic failure   # R16.5
│  │
│  ├─ duration_ms = int((time.monotonic() - start) * 1000)
│  ├─ INFO log: duration_ms, per-category counts     # R20.2
│  └─ return report
```

Eleven design points worth calling out from the walkthrough:

1. **Single run-timestamp anchors everything.** `run_started_at = datetime.now(UTC)` is captured once at the top of `run` and used for both `ImageAnalysisReport.timestamp` (R1.6) and `BaselineComparison.comparison_timestamp` (R17.4 post-HARDEN). The two timestamps move in lockstep, so the determinism property in R15.1 strips a single value.

2. **Cancellation check happens BEFORE progress emission and BEFORE finding emission for the current index.** `cancel()` returning True at the top of the loop body means index N is "the one that was about to be processed but never got there"; the Cancellation_Marker's `evidence.raw_indicators[0]` carries `cancelled-at-index=N` for that index (R7.4). The progress callback is not invoked for that index because the work for it never started.

3. **Pairing uses a single `dict[uuid.UUID, ClassificationRecord]`.** Built once before the loop. Linear time in the size of the union (R18.2). The dict carries the baseline records keyed by `component_id`; the loop pops or marks-consumed each match, and the final unpaired-baseline pass iterates whatever didn't get popped. (The actual implementation may use a set of consumed ids alongside the dict; the design contract is just "linear in the union of inputs, dict-keyed by component_id, no per-axis indexing.")

4. **Classification_mismatch and signature_regression are not mutually exclusive.** Per R4.8 + R5.1, a paired component whose axis labels disagree AND whose `signature_info.present` differs gets two findings. Each carries its own severity per its own rule (mismatch from Composite_Score table; regression flat per R5.6). Same `component_id`, distinct `finding_id` (because the category string differs in the R15.7 derivation tuple).

5. **Classification_gap fires regardless of pairing.** R10.2 is explicit: an unpaired Target_Record can also receive a `classification_gap` finding when `composite_confidence < threshold`. The `classification_gap` finding does not depend on a baseline counterpart.

6. **Priority_rank is assigned in a second pass.** Per R9.10, `priority_rank` is the 1-based ordinal position of a `classification_mismatch` finding when all such findings are sorted by descending `Composite_Score` with ties broken by ascending `component_id`. The first-pass loop doesn't know the global ranking until every paired component is processed. The pipeline holds the un-ranked findings, completes the loop, then computes a ranking and constructs `DeviationScore` instances with the resolved `priority_rank`. Reverse ordering (highest score = rank 1) per R9.10. Mutated `FindingEvidence.deviation_score` references the constructed `DeviationScore`.

7. **Missing_required_component findings are appended after the loop.** Per R3.4, after every Target_Record is processed, the engine iterates the unpaired baseline records in **ascending `component_id` order** and emits one `missing_required_component` finding each. This ordering is deterministic and matches the input-order discipline carried forward from extraction / classification.

8. **PostureRating is derived from the finished finding list.** Per R17.5, after every finding is emitted (including the optional Cancellation_Marker per R7.8), `posture.derive_posture_rating(findings)` walks the closed-mapping cascade and returns one of the five v1 `PostureRating` values. The Cancellation_Marker (severity INFO, category `analysis_cancelled`) does not trigger any of the COMPROMISED / AT_RISK / DEGRADED rules; a cancelled run with no other findings posture-rates as BASELINE per R7.8 (the marker counts as a finding for the catch-all rule, so the posture is DEGRADED if and only if the marker is the only finding emitted — see Posture-rating section below).

9. **BaselineComparison.deviations is the empty list.** Per R17.4, v1 carries deviation information through `FindingRecord` plus the embedded `DeviationScore`, not through `BaselineComparison.deviations`. The latter is reserved for a future BaselineComparison subsystem. The model-layer `summary` field is auto-computed from the empty list and carries an empty `dict[DeltaType, int]`.

10. **The progress callback is invoked from the calling thread only (R19.3).** No threading, no asyncio. Callbacks run synchronously inside the loop body; long-running callbacks block the analysis run. The classification-pipeline's `ProgressCallback` discipline is preserved here.

11. **The R14 validator runs once at pipeline construction.** `severity_weights.keys() == {"type", "vendor", "security_posture", "mutability"}`; the model layer's existing `_weights_must_sum_to_one` already enforces the sum-to-1.0 invariant. `confidence_gap_threshold` is range-checked by the Pydantic field validator at construction. `match_strategy` is StrEnum-checked by Pydantic. `baseline_id` is UUID-typed by Pydantic. Three of the four R14 fields self-validate via the model layer; only the keyset check needs a separate engine-side check.


## Per-category finding emitters (R4-R8, R10)

Each category has a dedicated emitter in `loki/analysis/findings.py`. All emitters share a common contract: they accept the inputs they need, return a `FindingRecord` constructed with a deterministic `finding_id`, and never log. The pipeline orchestrates emitter calls; the emitters themselves are pure functions of their inputs.

### `derive_finding_id` helper (R15.7)

```python
# loki/analysis/findings.py
import uuid
from loki.models.firmware import LOKI_NAMESPACE


def derive_finding_id(
    *,
    baseline_id: uuid.UUID,
    finding_category: str,
    target_component_id: uuid.UUID,
) -> uuid.UUID:
    """Deterministically derive a FindingRecord.finding_id (R15.7).

    Same baseline + same category + same target/baseline component_id
    always produces the same finding_id across runs and across hosts.
    The third tuple element is the target Target_Record's component_id
    for paired and unpaired-target findings, the unpaired
    Baseline_Manifest record's component_id for missing_required
    findings, and the deterministic sentinel UUID for the
    Cancellation_Marker (R7.7).

    The naming retained from R15.7 ("target_component_id") is technically
    a slight misnomer for the missing_required and Cancellation_Marker
    cases, where the value is sourced from the baseline manifest or
    a fixed sentinel respectively. The deferred wording fix M1 from
    the TENSION pass is cosmetic; the math is correct as-is.
    """
    name = f"{baseline_id}:{finding_category}:{target_component_id}"
    return uuid.uuid5(LOKI_NAMESPACE, name)
```

### `classification_mismatch` emitter (R4)

```python
def emit_classification_mismatch(
    *,
    target: ClassificationRecord,
    baseline: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
    severity_weights: dict[str, float],
) -> FindingRecord:
    """Emit a classification_mismatch finding (R4.1-R4.8).

    Computes the four Axis_Score values (R9.2-R9.3), the Composite_Score
    (R9.4), the base_severity from R10.7's closed mapping, and the
    DeviationScore (with priority_rank=0 placeholder; the pipeline
    fills in the real rank in a second pass per R9.10).

    Returns a FindingRecord with the embedded DeviationScore on
    evidence.deviation_score. Title and description are templated
    strings; both are in the Forbidden_Leakage_Field_Set and never
    appear in any log record (R20.5).
    """
```

The internal scoring helpers in `loki/analysis/scoring.py`:

```python
# loki/analysis/scoring.py

def axis_score(target_axis: AxisClassification, baseline_axis: AxisClassification) -> float:
    """Compute one Axis_Score (R9.3).

    Returns 0.0 if labels agree. Otherwise returns the product of the
    two axis confidences. The result lies in [0.0, 1.0] because both
    confidences are constrained to [0.0, 1.0] by the model layer.
    """
    if target_axis.label == baseline_axis.label:
        return 0.0
    return target_axis.confidence * baseline_axis.confidence


def composite_score(
    *,
    type_score: float,
    vendor_score: float,
    security_score: float,
    mutability_score: float,
    severity_weights: dict[str, float],
) -> float:
    """Compute the Composite_Score (R9.4).

    composite_score = 10.0 * (
        w_type * s_type
        + w_vendor * s_vendor
        + w_security_posture * s_security
        + w_mutability * s_mutability
    )

    severity_weights is validated by the engine to have exactly the
    four keys {"type", "vendor", "security_posture", "mutability"}
    (R9.5, R14.1). The weights sum to 1.0 (model layer validator),
    so the maximum composite is 10.0 when every axis disagrees at
    full confidence on both sides.
    """


def base_severity_from_composite(score: float) -> SeverityLevel:
    """Derive base_severity from Composite_Score per R10.7's closed mapping.

    composite_score >= 8.0 -> CRITICAL
    6.0 <= composite_score < 8.0 -> HIGH
    4.0 <= composite_score < 6.0 -> MEDIUM
    2.0 <= composite_score < 4.0 -> LOW
    composite_score < 2.0 -> INFO
    """


def security_direction(
    target: SecurityPostureLabel,
    baseline: SecurityPostureLabel,
) -> SecurityDirection:
    """Compute SecurityDirection per R11.

    DEGRADED: target=VULNERABLE, baseline=SECURE
    IMPROVED: target=SECURE, baseline=VULNERABLE
    UNCHANGED: every other case (including any UNKNOWN)
    """


def signature_delta(
    target: SignatureInfo | None,
    baseline: SignatureInfo | None,
) -> SignatureDelta:
    """Compute SignatureDelta per R12.

    LOST:    baseline.present=True,  target.present=False
    GAINED:  baseline.present=False, target.present=True
    NONE:    every other case (including either side None)
    CHANGED: reserved for future revision; not emitted in v1 (R12.3)
    """


def mutability_change(
    target: MutabilityLabel,
    baseline: MutabilityLabel,
) -> MutabilityChange:
    """Compute MutabilityChange per R13.

    BECAME_MUTABLE:  baseline=READONLY, target=MUTABLE
    BECAME_READONLY: baseline=MUTABLE,  target=READONLY
    NONE:            every other case (including any UNKNOWN)
    """
```

### `signature_regression` emitter (R5)

```python
def emit_signature_regression(
    *,
    target: ClassificationRecord,
    baseline: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit a signature_regression finding (R5.1-R5.6).

    Pre-conditions enforced by the caller: both target.signature_info
    and baseline.signature_info are non-None and their .present
    fields differ.

    severity = HIGH if baseline-signed/target-unsigned, MEDIUM if reverse.
    evidence.matched_signature = "BASELINE_SIGNED" or "TARGET_SIGNED".
    No DeviationScore (R9.11).
    """
```

### `unexpected_component` emitter (R6)

```python
def emit_unexpected_component(
    *,
    target: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit an unexpected_component finding (R6.1-R6.7).

    severity = MEDIUM (R6.5; flat per v1).
    evidence.classification_record = target (the unpaired record itself).
    No DeviationScore (R9.11).
    """
```

### `missing_required_component` emitter (R8)

```python
def emit_missing_required_component(
    *,
    baseline: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit a missing_required_component finding (R8.1-R8.6).

    severity = HIGH (R8.5; flat per v1).
    component_id = baseline.component_id (per R8.3 — the field is
    non-optional on FindingRecord; the value comes from the baseline
    manifest because no target record exists with this id).
    evidence.classification_record = baseline (the unpaired baseline record).
    No DeviationScore (R9.11).
    """
```

### `classification_gap` emitter (R10.1-R10.6)

```python
def emit_classification_gap(
    *,
    target: ClassificationRecord,
    matched_baseline_id: uuid.UUID,
) -> FindingRecord:
    """Emit a classification_gap finding (R10.1-R10.6).

    Pre-condition: target.composite_confidence < config.confidence_gap_threshold.
    severity = LOW (R10.6; flat per v1; gaps are diagnostic, not threats).
    evidence.classification_record = target.
    No DeviationScore (R9.11).
    """
```

## PostureRating derivation (R17.5)

The post-HARDEN closed mapping evaluates as a six-rule cascade:

```python
# loki/analysis/posture.py
def derive_posture_rating(findings: Sequence[FindingRecord]) -> PostureRating:
    """Derive PostureRating from the finding list per R17.5 (post-HARDEN amendment).

    Rule cascade (top wins; first match returns):

    1. COMPROMISED if any:
       - signature_regression with severity HIGH, OR
       - missing_required_component (any severity; v1 always HIGH), OR
       - classification_mismatch with composite_score >= 8.0 (severity CRITICAL).
    2. AT_RISK if any classification_mismatch with composite_score >= 6.0.
    3. DEGRADED if any classification_mismatch with composite_score >= 2.0.
    4. DEGRADED if any finding of any category is emitted (catch-all per G3-A).
    5. BASELINE if no findings are emitted at all.
    6. HARDENED is reserved for a future revision (R17.5; never emitted by v1).

    Note that rules 3 and 4 both return DEGRADED but for different
    reasons. Rule 3 is the historical case (a mismatch with low-but-
    nonzero composite). Rule 4 is the G3-A catch-all that handles runs
    whose only findings are unexpected_component, signature_regression
    (severity MEDIUM only), classification_gap, or analysis_cancelled.
    """
```

The cascade implementation walks the finding list once, collecting the booleans needed for the cascade, then returns the matching rating:

```python
def derive_posture_rating(findings: Sequence[FindingRecord]) -> PostureRating:
    if not findings:
        return PostureRating.BASELINE

    has_signature_regression_high = False
    has_missing_required = False
    has_classification_mismatch_critical = False
    max_classification_mismatch_score = 0.0
    has_any_finding = bool(findings)

    for f in findings:
        if f.category == "signature_regression" and f.severity == SeverityLevel.HIGH:
            has_signature_regression_high = True
        elif f.category == "missing_required_component":
            has_missing_required = True
        elif f.category == "classification_mismatch":
            if f.evidence.deviation_score is not None:
                score = f.evidence.deviation_score.composite_score
                if score > max_classification_mismatch_score:
                    max_classification_mismatch_score = score
                if score >= 8.0:
                    has_classification_mismatch_critical = True

    if has_signature_regression_high or has_missing_required or has_classification_mismatch_critical:
        return PostureRating.COMPROMISED
    if max_classification_mismatch_score >= 6.0:
        return PostureRating.AT_RISK
    if max_classification_mismatch_score >= 2.0:
        return PostureRating.DEGRADED
    if has_any_finding:
        return PostureRating.DEGRADED
    return PostureRating.BASELINE
```

The `has_any_finding` branch is reachable when the only findings are `unexpected_component`, `signature_regression: MEDIUM`, `classification_gap`, or `analysis_cancelled` — none of which trigger the COMPROMISED / AT_RISK / DEGRADED-by-score branches. This is exactly the G3-A catch-all behavior.


## Determinism

The engine is deterministic in the strong sense: same Target_Records, same `BaselineRegistry`, same `target_image`, same `AnalysisConfig`, same `ANALYSIS_VERSION` ⇒ bit-equal `ImageAnalysisReport` modulo two explicit fields:

- `ImageAnalysisReport.timestamp` (and the lockstep `BaselineComparison.comparison_timestamp` per R17.4 post-HARDEN). The two fields move together; stripping one strips both.
- `findings[-1].evidence.raw_indicators` on cancelled runs only — the `cancelled-at-index=N` value depends on when the cancellation token returned True (R15.1 post-HARDEN amendment, R7.4).

Determinism is enforced through five disciplines:

1. **No environmental side-channels.** The engine SHALL NOT consult `os.environ`, `random`, `secrets`, `socket`, `urllib`, `requests`, `httpx`, or `time.time()` / `time.monotonic()` outside the designated `loki.analysis.timing` module (R15.4). Pinned by an AST audit at `tests/analysis/test_no_side_channels.py` mirroring the extraction / classification pattern.

2. **Deterministic UUID derivation.**
   - `FindingRecord.finding_id` is derived as `uuid5(LOKI_NAMESPACE, f"{baseline_id}:{finding_category}:{target_component_id}")` (R15.7).
   - `ImageAnalysisReport.report_id` is derived as `uuid5(LOKI_NAMESPACE, f"{target_image.image_id}:{baseline_id}:{ANALYSIS_VERSION}")` (R15.8).
   - The Cancellation_Marker's `component_id` is the fixed sentinel `uuid5(LOKI_NAMESPACE, "analysis-cancelled")` (R7.2).

3. **Deterministic ordering.** Per-target findings appear in target-input order. Missing-required findings appear after, sorted by ascending baseline `component_id`. The Cancellation_Marker, when present, is the last entry of `findings` (R7.6, R15.2). Within a single target/baseline pair, the per-category emission order is fixed: classification_mismatch first, then signature_regression, then classification_gap. (Unpaired Target_Records emit unexpected_component first, then classification_gap if applicable.)

4. **Single timestamp anchor.** `run_started_at = datetime.now(UTC)` is captured once at the top of `pipeline.run`. Every place a timestamp would otherwise leak (the report's `timestamp`, the BaselineComparison's `comparison_timestamp`) reads from this single value.

5. **Idempotence.** A second run on identical inputs produces an `ImageAnalysisReport` equal to the first under `model_dump(mode="json")` modulo `timestamp` (R15.6). The model-layer auto-computed fields (`ImageAnalysisReport.summary` from `findings`, `BaselineComparison.summary` from the empty `deviations` list) are deterministic functions of their inputs, so the round-trip property in R15.5 holds for every emitted report.

## Error handling

Errors fall into two classes:

### Whole-run errors (raised; never partial report)

Per R16.1, every whole-run failure raises an `AnalysisError` subclass and the engine SHALL NOT return a partially constructed report:

| Failure mode | Exception | Trigger |
|---|---|---|
| Config violates Requirement 14 | `AnalysisConfigError` | severity_weights keyset wrong, confidence_gap_threshold out of range, baseline_id required but unset |
| Baseline lookup failure | `BaselineNotFoundError` | EXPLICIT lookup miss, AUTO lookup miss, EXPLICIT_OR_AUTO fallback miss |
| Duplicate component_id in inputs | `AnalysisInputError` | duplicate ids in target_records or baseline_manifest |
| Final report Pydantic failure | `AnalysisReportConstructionError` | model-layer invariant violation at construction time (defensive — should not fire in normal operation given v1's input discipline) |

### Cooperative cancellation (NOT raised; partial report returned)

Per R1.10 + R7 + R16.6, cancellation is the one case where the engine returns rather than raises. The returned `ImageAnalysisReport` carries every finding emitted before cancellation plus exactly one `analysis_cancelled` Cancellation_Marker as the last entry of `findings`. The `posture_rating` is derived from the partial finding list including the marker. The typed exception hierarchy carries no `AnalysisCancelledError` member; cancellation is a return-path, not a throw-path.

This is the same partial-result-with-marker contract the classification pipeline ships in v1 (its `ClassificationResult` carries `errors` alongside `records`; cancellation produces a partial result rather than raising).

### Per-component error swallowing — explicitly NOT permitted

Per R16.7, the engine SHALL NOT silently drop findings on internal exceptions. The matching rules in Requirements 4 through 13 produce zero findings for a paired component **only when those rules explicitly produce zero** (e.g. R4.2: every axis label agrees and signature presence agrees). Any internal exception during finding construction propagates as an `AnalysisError` subclass. There is no per-component try/except wrapping; the v1 contract is "construct the FindingRecord directly, let Pydantic raise, wrap it as `AnalysisReportConstructionError` only at the top-level construction site."

## Performance and resource use

Per R18:

- **Wall time bound:** 1024 × 1024 components under 5 seconds on a 2024-class developer laptop with a local SSD, exclusive of progress callback overhead (R18.1). The pairing pass is O(N) on a single dict (R18.2). The per-pair finding-emission pass is O(N). The priority_rank assignment is O(M log M) where M is the number of classification_mismatch findings (typically a small fraction of N). Total: O(N + M log M) per run, dominated by N.

- **Memory bound:** peak resident memory attributable to analysis under 64 MiB plus the size of inputs (R18.3). The engine builds one `dict[uuid.UUID, ClassificationRecord]` of size at most |Baseline_Manifest|, holds one in-progress finding list, and constructs one `ImageAnalysisReport` at the end. v1 does not cache the full BaselineRegistry — only the resolved Matched_Baseline.

- **Synchronous, single-threaded:** R1.8, R18.4. No threading, no asyncio, no process pools. The classification pipeline's discipline is preserved; the GUI wires this onto a `QThread` the same way it wires extraction and classification.

A performance test at `tests/analysis/test_performance.py` validates R18.1 with the `slow` marker (mirrors `tests/classification/test_performance.py`). Like the classification slow test, this is excluded from the default `pytest -q` run; operators run it locally with `pytest -m slow tests/analysis/test_performance.py` before declaring a release.

## No-leakage audits

Two complementary audits enforce R20:

### Static AST audit (`tests/analysis/test_no_log_leakage.py`)

AST-walks every Python file in `loki/analysis/` and asserts that no `logging.Logger.{debug,info,warning,error,exception}` call has a `format`-style or `%`-style argument referencing any field in the Forbidden_Leakage_Field_Set:

- `component_id` (target's, baseline's, sentinel's)
- `signature_info.signer`
- `BaselineRecord.source_image_hash`
- `AxisClassification.evidence`
- `FindingEvidence.matched_rule`
- `FindingEvidence.matched_cve`
- `FindingEvidence.matched_signature`
- `FindingEvidence.raw_indicators`
- `FindingRecord.title`
- `FindingRecord.description`

Mirrors `tests/classification/test_no_log_leakage.py`. Catch-time is reviewer-checkable.

### Dynamic caplog audit (`tests/analysis/test_log_no_leakage.py`)

Pytest fixture captures every log record emitted during a curated set of analysis runs (paired-disagreement, signature-regression, unexpected-component, missing-required-component, classification-gap, cancellation) and asserts that no record's formatted message contains any value derived from the Forbidden_Leakage_Field_Set. Mirrors `tests/extraction/test_log_no_leakage.py`, `tests/baseline/test_log_no_leakage.py`, and `tests/classification/test_log_no_leakage.py`.

### What the audits permit

The two run-summary log records (R20.1, R20.2) are explicitly permitted:

- `R20.1 INFO`: matched-baseline tuple `(vendor, model, firmware_version, baseline_version)`, target count, configured `match_strategy`. No `baseline_id`, no `source_image_hash`.
- `R20.2 INFO`: wall-clock duration in milliseconds, per-category finding counts: `classification_mismatch=N1, signature_regression=N2, unexpected_component=N3, missing_required_component=N4, classification_gap=N5, analysis_cancelled=N6`. The `analysis_cancelled` count is 0 for every completed run and 1 for every cancelled run.
- `R20.4 WARNING`: typed-exception class name + redacted message on internal failure paths. No field values from the Forbidden_Leakage_Field_Set.

No per-finding log record is emitted in v1 (R20.3); the run-finish summary is sufficient.

## Progress callback and the leakage rule

`AnalysisProgressEvent` deliberately strips `component_id` (D6 default). The classification pipeline shipped its `ProgressEvent` with `component_id` as a deliberate exception to its leakage discipline, documented in classification's design Deferred-decisions section as a judgment call. Analysis takes the stricter side: the GUI / CLI consumer can render "component N of total" without knowing the UUID.

The rationale:

1. **The leakage rule's spirit is broader than its letter.** R20.5 forbids logging values in the set; the progress callback is not a log record but it's adjacent (consumers commonly funnel progress events into log streams during debugging).
2. **The GUI doesn't actually need `component_id` to render progress.** "Component 5 of 100" is a sufficient progress UX. Showing the UUID adds noise.
3. **The CLI doesn't need `component_id` either.** A progress bar with "5/100" is more useful than `"component_id=fa3b8e7c-..." 5/100`.
4. **Future log forwarding is safer.** A future GUI revision that pipes progress events into the log stream cannot accidentally leak `component_id` because the field doesn't exist on the event.

If a future revision needs `component_id` exposed on the event (e.g. for a "show in workspace" jump-to-component button), it can extend `AnalysisProgressEvent` with an optional field at that time and revisit the leakage discipline as a deliberate amendment.


## Correctness Properties

The classification pipeline established the convention that the design document carries the formal correctness properties. Analysis adds **Properties 43 through 52**, picking up where classification left off (model layer 1-11, extraction 12-22, baseline-persistence 23-32, classification 33-42, analysis 43-52).

These ten properties are validated by Hypothesis-based property tests at `tests/analysis/test_properties.py`. Per the project convention (see `loki/HANDOFF.md` Test Infrastructure section), in-memory matcher / scorer properties use `max_examples=50` and full-pipeline properties use `max_examples=25`; both set `suppress_health_check=[HealthCheck.too_slow]`.

### Property 43: Emitted ImageAnalysisReport is Pydantic-validated on return

For every `analyze_image` call that returns successfully, the returned `ImageAnalysisReport` SHALL satisfy every Pydantic v2 strict validator on `ImageAnalysisReport`, `BaselineComparison`, every `FindingRecord` in `findings`, every `FindingEvidence` and `DeviationScore` embedded therein, and `ReportSummary`. Validation runs at construction time inside the engine; the value is never returned partially constructed.

**Validates: Requirements 16.5, 17.1, 17.2**

### Property 44: Baseline matching is deterministic per Match_Strategy

For every `(BaselineRegistry, AnalysisConfig)` pair where the strategy resolves successfully, two `analyze_image` calls with the same `target_records`, `target_image`, and `config` produce two reports whose `baseline_comparison.baseline_id` values are equal.

For every `(BaselineRegistry, AnalysisConfig)` pair where the strategy resolves to a miss, both calls raise `BaselineNotFoundError` carrying the same offending lookup tuple.

**Validates: Requirements 2.1-2.6**

### Property 45: Component_Pairing is a bijection-with-defects keyed by component_id

For every `(target_records, baseline_manifest)` pair (with no duplicate `component_id` on either side), the engine partitions the union of `component_id` values into three disjoint sets: paired (in both), target-only (in target_records, not in baseline_manifest), and baseline-only (in baseline_manifest, not in target_records). Every paired target_record produces zero or more findings concerning that paired component_id; every target-only target_record produces exactly one `unexpected_component` finding plus zero or one `classification_gap` finding; every baseline-only baseline_manifest record produces exactly one `missing_required_component` finding.

**Validates: Requirements 3.1-3.4, 6.1, 8.1**

### Property 46: Per-axis Axis_Score and Composite_Score are deterministic functions of inputs

For every `(target_record, baseline_record, severity_weights)` tuple where `target_record.component_id == baseline_record.component_id`, two computations of `(type_score, vendor_score, security_score, mutability_score, composite_score)` produce equal values. Furthermore, the result satisfies:

- Each `axis_score` is `0.0` when labels agree, `target_axis.confidence * baseline_axis.confidence` when they disagree.
- `composite_score = 10.0 * (sum of w_i * s_i)` where `w_i` are the four `severity_weights` values and `s_i` are the four `axis_score` values.
- `composite_score` lies in `[0.0, 10.0]`.
- `base_severity_from_composite(composite_score)` agrees with R10.7's closed mapping.

**Validates: Requirements 9.2-9.4, 10.7**

### Property 47: Two runs on the same input produce equal reports modulo timestamp (and modulo cancellation_at_index)

For every input combination `(target_records, registry, target_image, config)` that resolves to the same Matched_Baseline twice, two `analyze_image` calls produce reports whose `findings`, `summary`, `posture_rating`, `report_id`, and embedded `DeviationScore` values are equal under `model_dump(mode="json")` after stripping `timestamp` (and, for cancelled runs, the Cancellation_Marker's `evidence.raw_indicators` per R15.1 post-HARDEN). The equality includes the order of findings in the `findings` list.

**Validates: Requirements 15.1, 15.2**

### Property 48: ImageAnalysisReport round-trips through JSON losslessly

For every emitted `ImageAnalysisReport` `r`, `model_validate_json(r.model_dump_json()) == r` under `model_dump(mode="json")` equality. The same round-trip holds through YAML via `model_validate(yaml.safe_load(yaml.safe_dump(r.model_dump())))` (R17.6).

**Validates: Requirements 15.5, 17.6**

### Property 49: PostureRating is a closed function of the finding list

For every finished finding list, `derive_posture_rating(findings)` returns exactly one of `{COMPROMISED, AT_RISK, DEGRADED, BASELINE}` per the R17.5 post-HARDEN cascade. `HARDENED` is never returned by v1. The function is total: every input list maps to a defined rating.

The cascade is monotone in the COMPROMISED direction: adding any `signature_regression: HIGH`, `missing_required_component`, or `classification_mismatch` with `composite_score >= 8.0` finding to a non-COMPROMISED report transitions the rating to COMPROMISED. (Adding any finding to an empty list transitions BASELINE to either COMPROMISED, AT_RISK, or DEGRADED depending on the finding's category and composite score.)

**Validates: Requirements 17.5 (post-HARDEN amendment)**

### Property 50: Forbidden_Leakage_Field_Set is never logged

`loki.analysis` does not log any of: `component_id` (target / baseline / sentinel), `signature_info.signer`, `BaselineRecord.source_image_hash`, any `AxisClassification.evidence` string, `FindingEvidence.matched_rule`, `FindingEvidence.matched_cve`, `FindingEvidence.matched_signature`, `FindingEvidence.raw_indicators`, `FindingRecord.title`, or `FindingRecord.description`. This holds across every Hypothesis-generated input combination, including paired-disagreement runs, signature-regression runs, missing-required runs, classification-gap runs, and cancelled runs.

The static AST audit at `tests/analysis/test_no_log_leakage.py` and the dynamic `caplog` audit at `tests/analysis/test_log_no_leakage.py` together enforce this property; the `caplog` audit is the Hypothesis-driven side.

**Validates: Requirements 20.3, 20.4, 20.5**

### Property 51: No environmental side channels

`loki.analysis` does not consult environment variables, the random number generator, the system clock other than for the run-start `datetime.now(UTC)` and the duration-measurement `time.monotonic()` in the designated timing module, or any network resource for any decision that affects report contents. Pinned by an AST audit at `tests/analysis/test_no_side_channels.py` enforcing the import discipline of R15.4: no `os.environ`, `random`, `secrets`, `socket`, `urllib`, `requests`, `httpx`, or `time.time()` outside `loki/analysis/timing.py`.

**Validates: Requirements 15.3, 15.4**

### Property 52: Cancellation_Marker contract holds

For every cancelled run (every input where the cancellation token returns True at some index N in `[1, len(target_records)]`):

- The returned `findings` list has at least one entry, and the LAST entry has `category == "analysis_cancelled"`.
- The Cancellation_Marker carries `severity == SeverityLevel.INFO`, `component_id == uuid5(LOKI_NAMESPACE, "analysis-cancelled")`, `title == "analysis cancelled"`, `description == "cooperative cancellation observed; partial findings returned"`, and `evidence.raw_indicators == ["cancelled-at-index=N"]`.
- The Cancellation_Marker's `finding_id` is `uuid5(LOKI_NAMESPACE, f"{baseline_id}:analysis_cancelled:{sentinel_component_id}")`.
- No other entry in `findings` has `category == "analysis_cancelled"`.
- The cancellation index N does not appear in any log record.
- For every uncancelled run (cancellation token always False or omitted), no entry in `findings` has `category == "analysis_cancelled"`.

**Validates: Requirements 1.10, 7.1-7.9**

## Testing Strategy

Test layout mirrors source. New tests live under `tests/analysis/`:

```
tests/analysis/
├── __init__.py
├── conftest.py                       # Hypothesis strategies for AnalysisConfig, target_records, baselines
├── test_api.py                       # public surface smoke + happy-path
├── test_matching.py                  # R2 — three Match_Strategy paths, all error cases
├── test_pairing.py                   # R3 — bijection-with-defects, duplicate-id raises
├── test_findings_classification_mismatch.py  # R4
├── test_findings_signature_regression.py     # R5
├── test_findings_unexpected_component.py     # R6
├── test_findings_missing_required.py         # R8
├── test_findings_classification_gap.py       # R10
├── test_cancellation.py              # R7 — Cancellation_Marker contract
├── test_scoring.py                   # R9 — Axis_Score, Composite_Score, DeviationScore
├── test_posture.py                   # R17.5 — six-rule cascade
├── test_report.py                    # R17 — report assembly + BaselineComparison
├── test_errors.py                    # R16 — typed exception hierarchy
├── test_determinism.py               # R15 — two-run equality, idempotence
├── test_round_trip.py                # R15.5, R17.6 — JSON + YAML round-trip
├── test_no_side_channels.py          # R15.4 — AST audit pinning import discipline
├── test_no_log_leakage.py            # R20.5 — AST audit pinning logger calls (Property 50, static)
├── test_log_no_leakage.py            # R20.5 — caplog audit pinning runtime emissions (Property 50, dynamic)
├── test_properties.py                # P43–P52 Hypothesis property tests
└── test_performance.py               # R18.1 — slow marker; 1024x1024 under 5s
```

End-to-end smoke at `tests/test_analysis_smoke.py` runs the extract → classify → analyze chain against a curated firmware fixture, mirroring `tests/test_classification_smoke.py`. The smoke covers the happy path with a non-empty baseline registry, validating that the engine integrates cleanly with the upstream three subsystems.

Existing test infrastructure carries forward unchanged:

- `pytest-timeout` (`--timeout=30 --timeout-method=signal`) on any GUI-touching test (none in this subsystem; `loki.analysis` is gui-free per R1.9).
- Hypothesis settings: `max_examples=50` for in-memory matcher / scorer / pairing properties; `max_examples=25` for full-pipeline properties; `suppress_health_check=[HealthCheck.too_slow]` on both.
- `slow` marker for `test_performance.py`; excluded from the default `pytest -q` run via the project's existing `addopts = "-ra --strict-markers -m 'not slow'"`.
- `filterwarnings = ["error"]` carried forward; any new `DeprecationWarning` triggers the same pattern (upgrade pin or add narrow `filterwarnings("ignore", ...)` in the affected test module's conftest with a documented rationale).

Test counts after analysis-engine implementation: existing 897 + estimated 80–120 new analysis tests. Property tests (P43–P52) account for ~20 of those; per-category emitter tests + matching + pairing + posture + scoring tests account for the bulk; the AST + caplog audits and the smoke account for the remainder. Final count is implementation-dependent and the design does not commit to a precise number.

## Deferred decisions and open questions

Tracked here so future sessions don't re-derive answers. These are decisions made during the v1 design pass that future revisions may revisit.

### D1 (default) — Engine module shape: free function, not class

`analyze_image` is exposed as a free function from `loki.analysis`, with `AnalysisPipeline` kept internal. Mirrors classification's `classify_components` shape.

**Why this could change:** if a future revision wants to expose the pipeline for testing without re-running the matching/pairing pre-conditions (e.g. a test harness that wants to inject a pre-computed `Matched_Baseline`), it could promote `AnalysisPipeline` to public surface. v1 does not need this and the smaller surface is easier to defend.

### D2 (default) — Exception hierarchy at `loki/analysis/errors.py`

Mirrors baseline's `loki/baseline/errors.py` and classification's `loki/classification/errors.py`. Single module, four exception classes, each with structured fields.

**Why this could change:** if the analysis engine ever grows a per-component error record analogous to classification's `ClassificationError` (Pydantic model, not exception subclass), the module would also house that record. v1 does not need one — internal exceptions during finding construction propagate as `AnalysisError` subclasses per R16.7.

### D3 (default) — `FindingEvidence.deviation_score` is a direct model-layer extension

Added to `loki/models/analysis.py` as `deviation_score: DeviationScore | None = None`. Backwards-compatible because the model's existing call sites construct `FindingEvidence` once with a small set of named fields.

**Why this could change:** if a future revision adds many more optional fields to `FindingEvidence`, the model could split into a base + analyst-extension sub-model. v1's single optional field doesn't justify that.

### D4 (default) — `AnalysisConfig` extensions are direct model-layer additions

`match_strategy: MatchStrategy = MatchStrategy.AUTO`, `confidence_gap_threshold: float = 0.6`, and `baseline_id: uuid.UUID | None = None` are added directly to `loki/models/config.py`'s `AnalysisConfig`. Defaults are chosen so existing call sites (none in v0.1.0) keep their construction shape.

**Why this could change:** if a future analysis-CLI subsystem wants its own analysis-specific config layer (e.g. `AnalyzeRunConfig` carrying CLI-only fields like `output_format`), the new fields would live on that subsystem-local model. v1 does not need a separate layer.

### D5 (default) — `MatchStrategy` is a `StrEnum`

Added to `loki/models/enums.py` alongside the project's 14 existing StrEnums. R2.1's wording ("v1 defines as one of exactly three string values") and the project's serialization-friendly StrEnum pattern both argue for this.

**Why this could change:** if a future revision adds a fourth strategy (e.g. `EXPLICIT_THEN_AUTO_THEN_FUZZY`), the enum extends naturally. The closed v1 set is intentional; future strategies are explicit additions.

### D6 (default) — `AnalysisProgressEvent` strips `component_id`

Carries only `index: int` and `total: int`. The classification pipeline's `ProgressEvent.component_id` was a deliberate exception to its leakage discipline; analysis takes the stricter side.

**Why this could change:** if a future GUI revision adds a "show in workspace" jump-to-component button that needs the UUID, the event can extend with an optional `component_id: uuid.UUID | None = None` field at that time. The leakage discipline would need a deliberate amendment with a documented rationale at that point.

### D7 (default) — Property numbering: P43–P52

Ten properties, picking up from classification's P33–P42. Matches the project's sequential discipline (model layer 1-11, extraction 12-22, baseline-persistence 23-32, classification 33-42, analysis 43-52). The next subsystem to ship a Tier 3 spec triple (currently `feeds` per OT-LK-002) picks up at P53.

### D8 — Multi-paragraph Property descriptions accepted

Five Property descriptions (P44, P45, P46, P49, P52) use multi-paragraph or bullet-list structure between the property header and the `**Validates: Requirements ...**` line. The Kiro Spec Format checker emits five non-blocking warnings for this; the classification pipeline's design.md uses single-paragraph descriptions throughout and emits no warnings.

**Why retained:** the structure makes the contract clearer at a glance. P44's two paragraphs cover the success-resolution case and the miss-resolution case as parallel bullets. P46's bulleted post-conditions enumerate the four invariants the scoring helpers must satisfy; collapsing them into prose would obscure them. P49's monotonicity-clause is a substantive second paragraph, not a stylistic flourish. P52's seven-bullet list of Cancellation_Marker fields is the cleanest way to enumerate the contract.

**Why this could change:** if the warnings ever trip CI or the format checker hardens the rule into an error, each warned property can be flattened into a single paragraph in a cosmetic amendment without changing the contract.

### Locked-in v1 contracts that future revisions can revisit

These are not "deferred" in the sense of "we'll address them in v1.1"; they are choices made for v1 with reasonable upgrade paths if operational experience suggests revisiting:

- **`SignatureDelta.CHANGED` is reserved.** R12.3 says the value exists in the model but v1 doesn't emit it because v1 doesn't parse signer identity. A future revision that adds signer-or-cert-expiry comparison (probably as part of the `feeds` subsystem or its successor) will start emitting `CHANGED`. The model-layer enum carries the value already.

- **`unexpected_component` severity is flat MEDIUM.** R6.5 says future revisions MAY weight unexpected components by axis-specific risk. v1's flat MEDIUM is the conservative default.

- **`missing_required_component` severity is flat HIGH.** R8.5 says v1 does not infer "intentionally removed" versus "stripped by an attacker"; both produce the same finding category at the same severity. A future revision that adds an "expected-removal" annotation (perhaps via a new `BaselineRecord.expected_removed_components` field) could lower severity to MEDIUM or INFO for annotated removals.

- **`recommended_actions` is empty.** R17.3 leaves this to a future revision. The model layer already validates the field; the analysis subsystem does not populate it.

- **`default_severity_threshold` is read but not consumed.** R14.5 reserves engine-side filtering for a future revision; v1 leaves filtering to consumers (CLI, GUI, future report renderer) at presentation time.

- **M1 wording fix on `target_component_id` in R15.7.** The third tuple element is technically a slight misnomer for `missing_required_component` and Cancellation_Marker findings (where the value comes from the baseline manifest or a fixed sentinel respectively). The math is correct as-is; a future requirements amendment may rename the parameter to `finding_subject_component_id` or similar without changing the implementation.

- **M2 wording fix on "highest-priority" in R17.5.** The phrase reduces to "max Composite_Score across all classification_mismatch findings" via R9.10's priority_rank definition. Reads cleanly as-is; a future amendment may make the wording explicit.

## Out-of-scope explicit list

Confirming the introduction's non-goals are honored throughout the design:

- **CVE matching:** `FindingEvidence.matched_cve` is `None` for every emitted finding in v1. The `feeds` subsystem (OT-LK-002) populates this in a future spec.
- **Signature verification:** v1 reads `signature_info.present` only.
- **Fleet analysis:** `analyze_fleet` is reserved.
- **Persistence of `ImageAnalysisReport`:** v1 returns the report; on-disk storage is future.
- **Analyst overrides on findings:** out of scope.
- **CLI subcommand surface:** future spec.
- **GUI integration surface:** future spec.

---

*End of design.md. tasks.md is the next session per HANDOFF.md's spec-drafting-is-its-own-conversation rule; the implementation phase is the session after that.*
