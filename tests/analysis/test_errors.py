"""Tests for the typed exception hierarchy at ``loki.analysis.errors``.

Covers task 6 acceptance: every exception class is constructible with
the documented kwargs; all four subclasses are subclasses of
``AnalysisError``; ``BaselineNotFoundError`` enforces the exactly-one-of
constraint; ``AnalysisInputError`` formats the side and duplicates
correctly; ``AnalysisReportConstructionError`` formats the loc path;
``AnalysisConfigError`` formats the field name.
"""

from __future__ import annotations

import uuid

import pytest

from loki.analysis import (
    AnalysisConfigError,
    AnalysisError,
    AnalysisInputError,
    AnalysisReportConstructionError,
    BaselineNotFoundError,
)

# --- AnalysisError root ---


def test_analysis_error_subclasses_exception() -> None:
    assert issubclass(AnalysisError, Exception)


def test_all_four_subclasses_inherit_from_analysis_error() -> None:
    assert issubclass(AnalysisConfigError, AnalysisError)
    assert issubclass(BaselineNotFoundError, AnalysisError)
    assert issubclass(AnalysisInputError, AnalysisError)
    assert issubclass(AnalysisReportConstructionError, AnalysisError)


# --- AnalysisConfigError ---


def test_analysis_config_error_constructs() -> None:
    err = AnalysisConfigError("severity_weights", "missing keys: type")
    assert err.field_name == "severity_weights"
    assert "severity_weights" in str(err)
    assert "missing keys: type" in str(err)


def test_analysis_config_error_is_analysis_error() -> None:
    err = AnalysisConfigError("match_strategy", "EXPLICIT requires baseline_id")
    assert isinstance(err, AnalysisError)


# --- BaselineNotFoundError ---


def test_baseline_not_found_by_id() -> None:
    target = uuid.uuid4()
    err = BaselineNotFoundError(baseline_id=target)
    assert err.baseline_id == target
    assert err.vendor_model_version is None
    assert str(target) in str(err)


def test_baseline_not_found_by_vendor_model_version() -> None:
    err = BaselineNotFoundError(vendor_model_version=("Intel", "X1", "1.2.3"))
    assert err.baseline_id is None
    assert err.vendor_model_version == ("Intel", "X1", "1.2.3")
    assert "Intel" in str(err)
    assert "X1" in str(err)
    assert "1.2.3" in str(err)


def test_baseline_not_found_rejects_both_set() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        BaselineNotFoundError(
            baseline_id=uuid.uuid4(),
            vendor_model_version=("V", "M", "1.0.0"),
        )


def test_baseline_not_found_rejects_both_unset() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        BaselineNotFoundError()


# --- AnalysisInputError ---


def test_analysis_input_error_target_side() -> None:
    dup = uuid.uuid4()
    err = AnalysisInputError(side="target", duplicates=[dup])
    assert err.side == "target"
    assert err.duplicates == [dup]
    assert err.baseline_id is None
    assert "target_records" in str(err)
    assert str(dup) in str(err)


def test_analysis_input_error_baseline_side() -> None:
    dup1 = uuid.uuid4()
    dup2 = uuid.uuid4()
    bid = uuid.uuid4()
    err = AnalysisInputError(side="baseline", duplicates=[dup1, dup2], baseline_id=bid)
    assert err.side == "baseline"
    assert err.duplicates == [dup1, dup2]
    assert err.baseline_id == bid
    assert "baseline" in str(err)
    assert str(bid) in str(err)
    assert str(dup1) in str(err)
    assert str(dup2) in str(err)


def test_analysis_input_error_rejects_unknown_side() -> None:
    with pytest.raises(ValueError, match="side must be"):
        AnalysisInputError(side="invalid", duplicates=[uuid.uuid4()])


def test_analysis_input_error_accepts_iterable_duplicates() -> None:
    """The constructor accepts any Iterable, not just list."""
    duplicates = (uuid.uuid4() for _ in range(3))  # generator
    err = AnalysisInputError(side="target", duplicates=duplicates)
    assert len(err.duplicates) == 3


# --- AnalysisReportConstructionError ---


def test_analysis_report_construction_error_constructs() -> None:
    err = AnalysisReportConstructionError(
        loc=("findings", 0, "evidence", "deviation_score", "composite_score"),
        message="value out of range",
    )
    assert err.loc == ("findings", 0, "evidence", "deviation_score", "composite_score")
    assert "findings.0.evidence.deviation_score.composite_score" in str(err)
    assert "value out of range" in str(err)


def test_analysis_report_construction_error_handles_empty_loc() -> None:
    err = AnalysisReportConstructionError(loc=(), message="model-level invariant")
    assert err.loc == ()
    assert "model-level invariant" in str(err)


# --- Re-export surface ---


def test_all_five_classes_importable_from_loki_analysis() -> None:
    """The package re-exports every exception type per the design's public surface."""
    from loki.analysis import (  # noqa: F401
        AnalysisConfigError,
        AnalysisError,
        AnalysisInputError,
        AnalysisReportConstructionError,
        BaselineNotFoundError,
    )
