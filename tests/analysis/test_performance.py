"""Performance smoke test for the analysis engine (task 25).

Marked ``slow``, skipped on CI by default. Run locally with
``pytest -m slow tests/analysis/test_performance.py``.

R18.1 budget: 1024 components x 1024 baseline manifest records,
analyze_image completes in under 5 seconds on a 2024-class
developer laptop with a local SSD, exclusive of progress-callback
overhead. Mirrors the slow-marker pattern used in
:mod:`tests.classification.test_performance`,
:mod:`tests.extraction.test_performance`, and
:mod:`tests.baseline.test_performance`.

The 5-second budget is generous; the engine should complete
~1024+1024 pairing + finding emission in well under a second on
the operator's reference machine.
"""

from __future__ import annotations

import time
import uuid

import pytest

from loki.analysis import analyze_image
from loki.models import (
    AnalysisConfig,
    BaselineRegistry,
    ComponentTypeLabel,
    MatchStrategy,
    SeverityLevel,
)
from tests.analysis._helpers import (
    VALID_WEIGHTS,
    make_baseline_record,
    make_image,
    make_record,
)

# R18.1 budget: under 5 seconds wall time on a 2024-class
# developer laptop.
_R18_1_BUDGET_SECONDS: float = 5.0

# 1024 components on each side per R18.1.
_COMPONENT_COUNT: int = 1024


@pytest.mark.slow
def test_r18_1_analysis_budget() -> None:
    """1024-component target x 1024-component baseline analysis under 5 seconds.

    Build matched pairs with identical classifications so the
    happy path runs cleanly (no findings emitted; the pipeline
    still walks every pair and constructs the index). This is
    the lower-bound timing test; runs with mismatches generate
    more findings but the loop body remains O(1) per pair.
    """
    cfg = AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
    )

    # Pre-build all the records up-front so the timing window
    # captures the analyze_image call only.
    target_records = []
    baseline_records = []
    for i in range(_COMPONENT_COUNT):
        cid = uuid.UUID(int=i + 1)
        target_records.append(
            make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
        )
        baseline_records.append(
            make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
        )

    baseline = make_baseline_record(component_manifest=baseline_records)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    start = time.monotonic()
    report = analyze_image(
        target_records=target_records,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    elapsed = time.monotonic() - start

    assert elapsed < _R18_1_BUDGET_SECONDS, (
        f"R18.1 budget exceeded: {elapsed:.2f}s > {_R18_1_BUDGET_SECONDS}s"
    )
    # Every pair matches identically -> no findings, BASELINE rating.
    assert report.findings == []


@pytest.mark.slow
def test_r18_1_analysis_with_mismatches_under_budget() -> None:
    """Same 1024+1024 fleet but with universal type-axis disagreement.

    Every paired component now produces a classification_mismatch
    finding (1024 findings total). The pipeline's second-pass
    priority_rank assignment is O(N log N); the budget should
    still hold comfortably.
    """
    cfg = AnalysisConfig(
        severity_weights=dict(VALID_WEIGHTS),
        default_severity_threshold=SeverityLevel.MEDIUM,
        match_strategy=MatchStrategy.AUTO,
    )

    target_records = []
    baseline_records = []
    for i in range(_COMPONENT_COUNT):
        cid = uuid.UUID(int=i + 1)
        target_records.append(
            make_record(component_id=cid, type_label=ComponentTypeLabel.UEFI_DRIVER)
        )
        baseline_records.append(
            make_record(component_id=cid, type_label=ComponentTypeLabel.OS_KERNEL)
        )

    baseline = make_baseline_record(component_manifest=baseline_records)
    registry = BaselineRegistry(baselines=[baseline])
    image = make_image()

    start = time.monotonic()
    report = analyze_image(
        target_records=target_records,
        registry=registry,
        target_image=image,
        config=cfg,
    )
    elapsed = time.monotonic() - start

    assert elapsed < _R18_1_BUDGET_SECONDS, (
        f"R18.1 budget exceeded: {elapsed:.2f}s > {_R18_1_BUDGET_SECONDS}s"
    )
    # Every pair disagrees on type -> 1024 classification_mismatch findings.
    mismatches = [f for f in report.findings if f.category == "classification_mismatch"]
    assert len(mismatches) == _COMPONENT_COUNT
    # priority_ranks are assigned 1..1024.
    ranks = sorted(
        f.evidence.deviation_score.priority_rank
        for f in mismatches
        if f.evidence.deviation_score is not None
    )
    assert ranks == list(range(1, _COMPONENT_COUNT + 1))
