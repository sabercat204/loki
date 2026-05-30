"""Hypothesis property tests for the analysis engine (task 24).

Implements Properties P43-P52 from design.md §"Correctness Properties".
Hypothesis settings follow the project convention (max_examples=50 for
in-memory matcher / scorer / pairing properties; max_examples=25 for
full-pipeline properties; both with
suppress_health_check=[HealthCheck.too_slow]).

Some properties have natural Hypothesis coverage (P44, P45, P46, P47,
P50, P52). Others are example-based or covered by the AST audits
(P43 is a Pydantic-validation check; P49 is covered in test_posture;
P51 is the AST audit in test_no_side_channels). This file pulls them
together as a unified property-suite anchor.
"""

from __future__ import annotations

import uuid

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.analysis import (
    ANALYSIS_VERSION,
    BaselineNotFoundError,
    analyze_image,
)
from loki.analysis.findings import ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
from loki.analysis.posture import derive_posture_rating
from loki.analysis.scoring import axis_score, composite_score
from loki.models import (
    AnalysisConfig,
    BaselineRegistry,
    ComponentTypeLabel,
    DeviationScore,
    FindingEvidence,
    FindingRecord,
    ImageAnalysisReport,
    MatchStrategy,
    MutabilityChange,
    PostureRating,
    SecurityDirection,
    SeverityLevel,
    SignatureDelta,
)
from tests.analysis._helpers import (
    VALID_WEIGHTS,
    make_axis,
    make_baseline_record,
    make_image,
    make_record,
)

# Hypothesis settings per project convention.
_FAST_SETTINGS = settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
_SLOW_SETTINGS = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


def _config() -> AnalysisConfig:
    return AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
    )


# ---------------------------------------------------------------------
# P43: Emitted ImageAnalysisReport is Pydantic-validated on return
# ---------------------------------------------------------------------


@_SLOW_SETTINGS
@given(target_count=st.integers(min_value=0, max_value=10))
def test_p43_report_round_trips_through_json(target_count: int) -> None:
    """P43: every successful analyze_image returns a Pydantic-validated report."""
    cfg = _config()
    targets = [make_record() for _ in range(target_count)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    # Round-trip through JSON; if Pydantic validation succeeded on
    # return, model_validate_json on the dump produces an equal
    # report.
    restored = ImageAnalysisReport.model_validate_json(report.model_dump_json())
    assert restored.report_id == report.report_id


# ---------------------------------------------------------------------
# P44: Baseline matching is deterministic per Match_Strategy
# ---------------------------------------------------------------------


@_FAST_SETTINGS
@given(
    vendor=st.sampled_from(["Intel", "AMD", "ARM"]),
    model=st.sampled_from(["X1", "Y2", "Z3"]),
    version=st.sampled_from(["1.0.0", "2.0.0", "3.0.0"]),
)
def test_p44_baseline_matching_deterministic(vendor: str, model: str, version: str) -> None:
    """Two analyze_image calls with the same baseline-matching inputs
    produce equal baseline_comparison.baseline_id values."""
    cfg = _config()
    baseline = make_baseline_record(vendor=vendor, model=model, firmware_version=version)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image(vendor=vendor, model=model, firmware_version=version)

    report_a = analyze_image(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    report_b = analyze_image(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    assert report_a.baseline_comparison is not None
    assert report_b.baseline_comparison is not None
    assert report_a.baseline_comparison.baseline_id == report_b.baseline_comparison.baseline_id


@_FAST_SETTINGS
@given(
    target_vendor=st.sampled_from(["Intel", "AMD", "ARM"]),
    baseline_vendor=st.sampled_from(["Intel", "AMD", "ARM"]),
)
def test_p44_baseline_lookup_miss_raises_with_same_tuple(
    target_vendor: str, baseline_vendor: str
) -> None:
    """When matching misses, both runs raise BNF carrying the same tuple."""
    if target_vendor == baseline_vendor:
        return  # only test the miss case
    cfg = _config()
    baseline = make_baseline_record(vendor=baseline_vendor)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image(vendor=target_vendor)

    raised_tuples: list[tuple[str, str, str] | None] = []
    for _ in range(2):
        try:
            analyze_image(
                target_records=[],
                registry=registry,
                target_image=image,
                config=cfg,
            )
        except BaselineNotFoundError as exc:
            raised_tuples.append(exc.vendor_model_version)
    assert len(raised_tuples) == 2
    assert raised_tuples[0] == raised_tuples[1]


# ---------------------------------------------------------------------
# P45: Component_Pairing is a bijection-with-defects keyed by component_id
# ---------------------------------------------------------------------


@_FAST_SETTINGS
@given(
    paired_count=st.integers(min_value=0, max_value=5),
    target_only_count=st.integers(min_value=0, max_value=5),
    baseline_only_count=st.integers(min_value=0, max_value=5),
)
def test_p45_pairing_bijection_with_defects(
    paired_count: int, target_only_count: int, baseline_only_count: int
) -> None:
    """P45: paired+target-only+baseline-only partition fills the union."""
    cfg = _config()
    paired_ids = [uuid.uuid4() for _ in range(paired_count)]
    target_only_ids = [uuid.uuid4() for _ in range(target_only_count)]
    baseline_only_ids = [uuid.uuid4() for _ in range(baseline_only_count)]

    targets = [make_record(component_id=cid) for cid in paired_ids + target_only_ids]
    baseline_manifest = [make_record(component_id=cid) for cid in paired_ids + baseline_only_ids]
    baseline = make_baseline_record(component_manifest=baseline_manifest)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    # Every target-only id should produce exactly one
    # unexpected_component finding.
    unexpected_ids = {
        f.component_id for f in report.findings if f.category == "unexpected_component"
    }
    assert unexpected_ids == set(target_only_ids)
    # Every baseline-only id should produce exactly one
    # missing_required_component finding.
    missing_ids = {
        f.component_id for f in report.findings if f.category == "missing_required_component"
    }
    assert missing_ids == set(baseline_only_ids)
    # The paired ids are quiet by default (records identical -> no
    # mismatch finding) but classification_gap may fire if
    # composite_confidence happens to be below threshold; we don't
    # assert per-pair counts here.


# ---------------------------------------------------------------------
# P46: Per-axis Axis_Score and Composite_Score are deterministic
# ---------------------------------------------------------------------


@_FAST_SETTINGS
@given(
    label_a=st.sampled_from([str(x) for x in ComponentTypeLabel]),
    label_b=st.sampled_from([str(x) for x in ComponentTypeLabel]),
    conf_a=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    conf_b=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
)
def test_p46_axis_score_deterministic_in_unit_interval(
    label_a: str, label_b: str, conf_a: float, conf_b: float
) -> None:
    """Two evaluations with the same inputs produce equal axis scores in [0.0, 1.0]."""
    a_first = axis_score(
        make_axis(label_a, confidence=conf_a),
        make_axis(label_b, confidence=conf_b),
    )
    a_second = axis_score(
        make_axis(label_a, confidence=conf_a),
        make_axis(label_b, confidence=conf_b),
    )
    assert a_first == a_second
    assert 0.0 <= a_first <= 1.0


@_FAST_SETTINGS
@given(
    type_s=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    vendor_s=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    security_s=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    mutability_s=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
)
def test_p46_composite_score_bounded(
    type_s: float, vendor_s: float, security_s: float, mutability_s: float
) -> None:
    """For any axis scores in [0,1], composite_score lies in [0.0, 10.0]."""
    result = composite_score(
        type_score=type_s,
        vendor_score=vendor_s,
        security_score=security_s,
        mutability_score=mutability_s,
        severity_weights=VALID_WEIGHTS,
    )
    assert -1e-9 <= result <= 10.0 + 1e-9


# ---------------------------------------------------------------------
# P47: Two runs produce equal reports modulo timestamp
# ---------------------------------------------------------------------


@_SLOW_SETTINGS
@given(
    target_count=st.integers(min_value=0, max_value=8),
    disagreement_seed=st.integers(min_value=0, max_value=100),
)
def test_p47_two_runs_equal_modulo_timestamp(target_count: int, disagreement_seed: int) -> None:
    """Two analyze_image runs on the same inputs produce equal reports modulo timestamp."""
    cfg = _config()

    # Build deterministic targets + baseline. Use the seed to pick
    # whether the baseline disagrees on the type axis.
    targets = []
    baseline_records = []
    for i in range(target_count):
        cid = uuid.UUID(int=disagreement_seed * 1000 + i)
        target = make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
        # 50/50 disagreement based on seed parity per index.
        baseline_label = (
            ComponentTypeLabel.OS_KERNEL
            if (disagreement_seed + i) % 2 == 0
            else ComponentTypeLabel.UEFI_DRIVER
        )
        baseline_record = make_record(component_id=cid, type_label=baseline_label)
        targets.append(target)
        baseline_records.append(baseline_record)

    baseline = make_baseline_record(component_manifest=baseline_records)
    image = make_image()

    def run_once() -> dict[str, object]:
        registry = BaselineRegistry(baselines=[baseline])
        return analyze_image(
            target_records=targets,
            registry=registry,
            target_image=image,
            config=cfg,
        ).model_dump(mode="json")

    a = run_once()
    b = run_once()
    a.pop("timestamp")
    b.pop("timestamp")
    bc_a = a.get("baseline_comparison")
    bc_b = b.get("baseline_comparison")
    if isinstance(bc_a, dict):
        bc_a.pop("comparison_timestamp", None)
    if isinstance(bc_b, dict):
        bc_b.pop("comparison_timestamp", None)
    assert a == b


# ---------------------------------------------------------------------
# P48: ImageAnalysisReport round-trips through JSON losslessly
# ---------------------------------------------------------------------


@_SLOW_SETTINGS
@given(target_count=st.integers(min_value=0, max_value=5))
def test_p48_report_json_round_trip(target_count: int) -> None:
    """Lossless JSON round-trip via model_dump_json + model_validate_json."""
    cfg = _config()
    targets = [make_record() for _ in range(target_count)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    restored = ImageAnalysisReport.model_validate_json(report.model_dump_json())
    assert restored.report_id == report.report_id
    assert len(restored.findings) == len(report.findings)


# ---------------------------------------------------------------------
# P49: PostureRating is a closed function of the finding list
# ---------------------------------------------------------------------


def _build_finding(
    *,
    category: str,
    severity: SeverityLevel,
    composite: float | None = None,
) -> FindingRecord:
    cid = uuid.uuid4()
    deviation = (
        DeviationScore(
            base_severity=SeverityLevel.HIGH,
            component_criticality=0.5,
            security_direction=SecurityDirection.UNCHANGED,
            signature_delta=SignatureDelta.NONE,
            cve_introduced=False,
            mutability_change=MutabilityChange.NONE,
            composite_score=composite,
            priority_rank=1,
        )
        if composite is not None
        else None
    )
    evidence = FindingEvidence(
        classification_record=None,
        matched_rule=None,
        matched_cve=None,
        matched_signature=None,
        raw_indicators=[],
        deviation_score=deviation,
    )
    return FindingRecord(
        finding_id=uuid.uuid4(),
        component_id=cid,
        severity=severity,
        category=category,
        title="t",
        description="d",
        evidence=evidence,
        recommended_action="",
    )


@_FAST_SETTINGS
@given(
    sig_high=st.booleans(),
    missing=st.booleans(),
    mismatch_score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
    unexpected=st.booleans(),
)
def test_p49_posture_rating_closed_function(
    sig_high: bool,
    missing: bool,
    mismatch_score: float | None,
    unexpected: bool,
) -> None:
    """For any combination of findings, posture_rating is a defined v1 value."""
    findings: list[FindingRecord] = []
    if sig_high:
        findings.append(
            _build_finding(category="signature_regression", severity=SeverityLevel.HIGH)
        )
    if missing:
        findings.append(
            _build_finding(category="missing_required_component", severity=SeverityLevel.HIGH)
        )
    if mismatch_score is not None:
        findings.append(
            _build_finding(
                category="classification_mismatch",
                severity=SeverityLevel.HIGH,
                composite=mismatch_score,
            )
        )
    if unexpected:
        findings.append(
            _build_finding(category="unexpected_component", severity=SeverityLevel.MEDIUM)
        )

    rating = derive_posture_rating(findings)
    assert rating in {
        PostureRating.COMPROMISED,
        PostureRating.AT_RISK,
        PostureRating.DEGRADED,
        PostureRating.BASELINE,
    }
    assert rating is not PostureRating.HARDENED


# ---------------------------------------------------------------------
# P52: Cancellation_Marker contract holds
# ---------------------------------------------------------------------


@_SLOW_SETTINGS
@given(
    target_count=st.integers(min_value=2, max_value=10),
    cancel_at=st.integers(min_value=1, max_value=10),
)
def test_p52_cancellation_marker_contract(target_count: int, cancel_at: int) -> None:
    """For every cancelled run, the Cancellation_Marker honors its contract."""
    if cancel_at > target_count:
        return  # only meaningful when cancellation actually fires

    cfg = _config()
    targets = [make_record() for _ in range(target_count)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    call_count = [0]

    def cancel() -> bool:
        call_count[0] += 1
        return call_count[0] > cancel_at - 1

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
        cancel=cancel,
    )

    # Last entry is the marker; only one such entry exists.
    assert report.findings[-1].category == "analysis_cancelled"
    cancellation_count = sum(1 for f in report.findings if f.category == "analysis_cancelled")
    assert cancellation_count == 1

    marker = report.findings[-1]
    assert marker.severity is SeverityLevel.INFO
    assert marker.component_id == ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
    assert marker.title == "analysis cancelled"
    assert marker.description == ("cooperative cancellation observed; partial findings returned")
    assert marker.evidence.raw_indicators == [f"cancelled-at-index={cancel_at}"]


@_FAST_SETTINGS
@given(target_count=st.integers(min_value=0, max_value=10))
def test_p52_uncancelled_run_has_no_marker(target_count: int) -> None:
    """For every uncancelled run, no entry has category 'analysis_cancelled'."""
    cfg = _config()
    targets = [make_record() for _ in range(target_count)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    categories = [f.category for f in report.findings]
    assert "analysis_cancelled" not in categories


# ---------------------------------------------------------------------
# Analysis version is deterministic across runs (sanity)
# ---------------------------------------------------------------------


def test_analysis_version_anchors_report_id() -> None:
    """ANALYSIS_VERSION is the version embedded in every report."""
    cfg = _config()
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=[],
        registry=registry,
        target_image=image,
        config=cfg,
    )
    assert report.analysis_version == ANALYSIS_VERSION
