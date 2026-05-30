"""End-to-end smoke test for the analysis engine (task 26).

Exercises a lightweight version of the extract → classify → analyze
chain by constructing classification records directly (matching the
shape ``classify_components`` produces) and feeding them through
``analyze_image``. Validates that the cross-subsystem path works and
that all six finding categories can be triggered in a single
controlled run.

Lives under ``tests/`` rather than ``tests/analysis/`` because the
test spans subsystems (it consumes the ``classification`` subsystem's
output shape and validates against the ``baseline`` subsystem's
``BaselineRegistry``).

Mirrors :mod:`tests.test_classification_smoke`.
"""

from __future__ import annotations

import uuid

from loki.analysis import (
    ANALYSIS_VERSION,
    AnalysisProgressEvent,
    analyze_image,
)
from loki.models import (
    AnalysisConfig,
    BaselineRegistry,
    ComponentTypeLabel,
    ImageAnalysisReport,
    MatchStrategy,
    PostureRating,
    SeverityLevel,
)
from tests.analysis._helpers import (
    VALID_WEIGHTS,
    make_baseline_record,
    make_image,
    make_record,
    make_signature_info,
)


def test_end_to_end_chain_smoke() -> None:
    """Construct a controlled fleet that triggers all six finding categories.

    Five components in the matched baseline:
      - ``cid_match``: pair with a target that disagrees on the type axis.
        Triggers ``classification_mismatch``.
      - ``cid_sig``: pair with a target whose signature is lost.
        Triggers ``signature_regression``.
      - ``cid_gap``: pair with a target whose composite_confidence is
        below threshold. Triggers ``classification_gap``.
      - ``cid_missing``: no target counterpart. Triggers
        ``missing_required_component``.
      - ``cid_paired_clean``: pair with an identical target (no findings).

    Two extra targets:
      - ``cid_unexpected``: not in the baseline. Triggers
        ``unexpected_component``.
      - ``cid_paired_clean``: paired above; quiet.

    The sixth category ``analysis_cancelled`` is exercised in a
    separate cancellation smoke below.
    """
    cfg = AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
        confidence_gap_threshold=0.6,
    )

    cid_match = uuid.uuid4()
    cid_sig = uuid.uuid4()
    cid_gap = uuid.uuid4()
    cid_missing = uuid.uuid4()
    cid_paired_clean = uuid.uuid4()
    cid_unexpected = uuid.uuid4()

    # Targets: 5 of the 6 component_ids above (cid_missing is absent).
    targets = [
        make_record(component_id=cid_match, type_label=ComponentTypeLabel.UEFI_DRIVER),
        make_record(
            component_id=cid_sig,
            signature_info=make_signature_info(present=False),
        ),
        make_record(component_id=cid_gap, confidence=0.4),  # below threshold
        make_record(component_id=cid_paired_clean),
        make_record(component_id=cid_unexpected),
    ]

    # Baseline manifest: 5 of the 6 component_ids (cid_unexpected absent).
    baseline_manifest = [
        make_record(component_id=cid_match, type_label=ComponentTypeLabel.OS_KERNEL),
        make_record(
            component_id=cid_sig,
            signature_info=make_signature_info(present=True),
        ),
        make_record(component_id=cid_gap, confidence=1.0),
        make_record(component_id=cid_missing),
        make_record(component_id=cid_paired_clean),
    ]
    baseline = make_baseline_record(component_manifest=baseline_manifest)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
    )

    # Verify: report shape is correct.
    assert isinstance(report, ImageAnalysisReport)
    assert report.analysis_version == ANALYSIS_VERSION
    assert report.image_id == image.image_id
    assert report.baseline_comparison is not None
    assert report.baseline_comparison.baseline_id == baseline.baseline_id

    # Verify: all five non-cancellation finding categories appear.
    categories = {f.category for f in report.findings}
    assert "classification_mismatch" in categories
    assert "signature_regression" in categories
    assert "unexpected_component" in categories
    assert "missing_required_component" in categories
    assert "classification_gap" in categories
    assert "analysis_cancelled" not in categories  # uncancelled run

    # Verify: posture rating is COMPROMISED (missing_required + sig_regression
    # both trigger rule 1).
    assert report.posture_rating is PostureRating.COMPROMISED

    # Verify: missing_required's component_id is the BASELINE record's id,
    # not any target's id (R8.3).
    missing_findings = [f for f in report.findings if f.category == "missing_required_component"]
    assert len(missing_findings) == 1
    assert missing_findings[0].component_id == cid_missing

    # Verify: round-trip through JSON.
    restored = ImageAnalysisReport.model_validate_json(report.model_dump_json())
    assert restored.report_id == report.report_id
    assert len(restored.findings) == len(report.findings)


def test_end_to_end_cancellation_smoke() -> None:
    """A cancelled run produces a partial report with the Cancellation_Marker."""
    cfg = AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
    )
    targets = [make_record() for _ in range(10)]
    baseline = make_baseline_record(component_manifest=[])
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    seen_progress: list[AnalysisProgressEvent] = []

    def progress(event: AnalysisProgressEvent) -> None:
        seen_progress.append(event)

    call_count = [0]

    def cancel() -> bool:
        call_count[0] += 1
        return call_count[0] > 4  # cancel on 5th check

    report = analyze_image(
        target_records=targets,
        registry=registry,
        target_image=image,
        config=cfg,
        progress=progress,
        cancel=cancel,
    )

    # Cancellation_Marker is the LAST entry.
    assert report.findings[-1].category == "analysis_cancelled"
    assert report.findings[-1].evidence.raw_indicators == ["cancelled-at-index=5"]

    # Progress was invoked for indices 1-4 (cancellation fires before
    # progress emission for index 5).
    assert [event.index for event in seen_progress] == [1, 2, 3, 4]


def test_end_to_end_public_api_imports() -> None:
    """The public surface from ``loki.analysis`` works as documented."""
    from loki.analysis import (  # noqa: F401
        ANALYSIS_VERSION,
        AnalysisCancellationToken,
        AnalysisConfigError,
        AnalysisError,
        AnalysisInputError,
        AnalysisProgressCallback,
        AnalysisProgressEvent,
        AnalysisReportConstructionError,
        BaselineNotFoundError,
        analyze_image,
    )

    assert callable(analyze_image)
    assert isinstance(ANALYSIS_VERSION, str)
