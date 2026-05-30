"""Internal ``AnalysisPipeline`` orchestrating one ``analyze_image`` run.

Per design D1, the pipeline is internal; the free-function
``analyze_image`` in ``loki.analysis.api`` is the public surface.

The pipeline holds the resolved Matched_Baseline and the validated
``AnalysisConfig``. Construction validates the config (R14), resolves
the Matched_Baseline (R2), and checks pairing pre-conditions (R3.6,
R3.7). The single ``run`` method orchestrates the sequence walkthrough
documented in design.md §"Sequence walkthrough" — pair components,
emit per-pair findings, emit unpaired-target findings, emit unpaired-
baseline findings, assign priority ranks, derive posture rating,
construct and validate the final ``ImageAnalysisReport``.

The pipeline is single-use: ``run`` is called exactly once per
``analyze_image`` invocation, and the calling thread is the only
thread the pipeline ever uses (R1.8 + R18.4).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loki.analysis.findings import (
    emit_classification_gap,
    emit_classification_mismatch,
    emit_signature_expired,
    emit_signature_regression,
    emit_unexpected_component,
    make_cancellation_marker,
)
from loki.analysis.findings import (
    emit_missing_required_component as _emit_missing_required_component,
)
from loki.analysis.matching import (
    resolve_matched_baseline,
    validate_analysis_config,
)
from loki.analysis.pairing import (
    build_baseline_index,
    check_pairing_preconditions,
    unpaired_baselines,
)
from loki.analysis.posture import derive_posture_rating
from loki.analysis.report import assemble_report, assign_priority_ranks
from loki.analysis.timing import Stopwatch
from loki.analysis.version import ANALYSIS_VERSION

if TYPE_CHECKING:
    import uuid

    from loki.models.analysis import FindingRecord
    from loki.models.baseline import BaselineRecord, BaselineRegistry
    from loki.models.classification import ClassificationRecord
    from loki.models.config import AnalysisConfig
    from loki.models.firmware import FirmwareImage
    from loki.models.reports import ImageAnalysisReport

__all__ = ["AnalysisPipeline"]

_LOGGER = logging.getLogger("loki.analysis")


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
        validate_analysis_config(config)
        self._matched_baseline: BaselineRecord = resolve_matched_baseline(
            config, registry, target_image
        )
        check_pairing_preconditions(
            target_records,
            self._matched_baseline.component_manifest,
            self._matched_baseline.baseline_id,
        )
        self._target_records = target_records
        self._target_image = target_image
        self._config = config

    def run(
        self,
        *,
        progress: Callable[[int, int], None] | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> ImageAnalysisReport:
        """Run analysis per Requirements 3 through 17.

        The progress callback signature matches the public surface's
        ``AnalysisProgressCallback``: it receives ``(index_1based,
        total)`` and is invoked at the start of each Target_Record's
        per-pair evaluation (R19.2). Both arguments are optional;
        callbacks (when supplied) run on the calling thread (R19.3).

        On cooperative cancellation (R1.10, R7), the pipeline emits
        the Cancellation_Marker as the LAST entry of ``findings`` and
        returns the partial report; it does NOT raise (R16.6).
        """
        run_started_at = datetime.now(UTC)
        total = len(self._target_records)

        # R20.1: run-start INFO log. Forbidden_Leakage_Field_Set
        # excludes baseline_id and source_image_hash; we log the
        # (vendor, model, firmware_version, baseline_version) tuple
        # plus target count and configured match_strategy.
        _LOGGER.info(
            "analysis run starting: baseline=(%r, %r, %r, %r) target_count=%d match_strategy=%s",
            self._matched_baseline.vendor,
            self._matched_baseline.model,
            self._matched_baseline.firmware_version,
            self._matched_baseline.baseline_version,
            total,
            self._config.match_strategy.value,
        )

        baseline_index = build_baseline_index(self._matched_baseline.component_manifest)
        consumed_ids: set[uuid.UUID] = set()
        findings: list[FindingRecord] = []
        cancelled = False
        cancelled_at_index = 0

        with Stopwatch() as stopwatch:
            for index_zero_based, target in enumerate(self._target_records):
                index = index_zero_based + 1  # 1-based per R7.4 + R19.2

                # Cancellation check happens BEFORE progress emission
                # and BEFORE per-pair finding emission (design.md
                # §"Sequence walkthrough" point 2).
                if cancel is not None and cancel():
                    cancelled = True
                    cancelled_at_index = index
                    break

                if progress is not None:
                    progress(index, total)

                paired_baseline = baseline_index.get(target.component_id)
                if paired_baseline is None:
                    findings.append(
                        emit_unexpected_component(
                            target=target,
                            matched_baseline_id=self._matched_baseline.baseline_id,
                        )
                    )
                else:
                    consumed_ids.add(target.component_id)
                    self._emit_paired_findings(
                        target=target,
                        baseline=paired_baseline,
                        findings=findings,
                    )

                # R10.1: classification_gap fires regardless of pairing.
                if target.composite_confidence < self._config.confidence_gap_threshold:
                    findings.append(
                        emit_classification_gap(
                            target=target,
                            matched_baseline_id=self._matched_baseline.baseline_id,
                        )
                    )

                # Signature expiry: fires when cert is verified but expired.
                if (
                    target.signature_info is not None
                    and target.signature_info.verified
                    and target.signature_info.cert_expiry is not None
                    and target.signature_info.cert_expiry < run_started_at
                ):
                    findings.append(
                        emit_signature_expired(
                            target=target,
                            matched_baseline_id=self._matched_baseline.baseline_id,
                            expiry_iso=target.signature_info.cert_expiry.isoformat(),
                        )
                    )

            # Post-loop: missing_required_component findings appear
            # after every per-target finding, sorted by ascending
            # baseline component_id (R3.4). On cancellation, we skip
            # this pass per R7.1.
            if not cancelled:
                for unpaired in unpaired_baselines(baseline_index, consumed_ids):
                    findings.append(
                        _emit_missing_required_component(
                            baseline=unpaired,
                            matched_baseline_id=self._matched_baseline.baseline_id,
                        )
                    )

            # Cancellation_Marker is the LAST entry of findings (R7.6).
            if cancelled:
                findings.append(
                    make_cancellation_marker(
                        baseline_id=self._matched_baseline.baseline_id,
                        cancelled_at_index=cancelled_at_index,
                    )
                )

            # R9.10: priority_rank second pass. Mutates embedded
            # DeviationScore values on classification_mismatch findings
            # in place; non-mismatch findings are untouched.
            assign_priority_ranks(findings)

            posture_rating = derive_posture_rating(findings)

            report = assemble_report(
                target_image=self._target_image,
                matched_baseline=self._matched_baseline,
                findings=findings,
                run_started_at=run_started_at,
                posture_rating=posture_rating,
                analysis_version=ANALYSIS_VERSION,
            )

        # R20.2: run-finish INFO log. Per-category counts; the
        # analysis_cancelled count is 0 for completed runs and 1 for
        # cancelled runs.
        counts = _per_category_counts(findings)
        _LOGGER.info(
            "analysis run finished: duration_ms=%d "
            "classification_mismatch=%d signature_regression=%d "
            "unexpected_component=%d missing_required_component=%d "
            "classification_gap=%d signature_expired=%d analysis_cancelled=%d",
            int(stopwatch.duration_ms),
            counts["classification_mismatch"],
            counts["signature_regression"],
            counts["unexpected_component"],
            counts["missing_required_component"],
            counts["classification_gap"],
            counts["signature_expired"],
            counts["analysis_cancelled"],
        )

        return report

    def _emit_paired_findings(
        self,
        *,
        target: ClassificationRecord,
        baseline: ClassificationRecord,
        findings: list[FindingRecord],
    ) -> None:
        """Emit per-pair findings for a paired (target, baseline) pair.

        Per R4.8 + R5.1, classification_mismatch and signature_regression
        are NOT mutually exclusive: a paired component whose axes
        disagree AND whose signature_info.present differs produces
        two findings, both with the same component_id but distinct
        finding_id values.
        """
        if _any_axis_disagrees(target=target, baseline=baseline):
            findings.append(
                emit_classification_mismatch(
                    target=target,
                    baseline=baseline,
                    matched_baseline_id=self._matched_baseline.baseline_id,
                    severity_weights=self._config.severity_weights,
                    cve_score_bump=self._config.cve_score_bump,
                )
            )

        # signature_regression fires only when both signature_info
        # values are non-None and their .present fields differ
        # (R5.1, R5.2).
        if (
            target.signature_info is not None
            and baseline.signature_info is not None
            and target.signature_info.present != baseline.signature_info.present
        ):
            findings.append(
                emit_signature_regression(
                    target=target,
                    baseline=baseline,
                    matched_baseline_id=self._matched_baseline.baseline_id,
                )
            )


def _any_axis_disagrees(
    *,
    target: ClassificationRecord,
    baseline: ClassificationRecord,
) -> bool:
    """Return True if any of the four axis labels differ (R4.1)."""
    return (
        target.type_axis.label != baseline.type_axis.label
        or target.vendor_axis.label != baseline.vendor_axis.label
        or target.security_axis.label != baseline.security_axis.label
        or target.mutability_axis.label != baseline.mutability_axis.label
    )


def _per_category_counts(findings: Sequence[FindingRecord]) -> dict[str, int]:
    """Count findings per category for the R20.2 finish-line log record."""
    counts: dict[str, int] = {
        "classification_mismatch": 0,
        "signature_regression": 0,
        "unexpected_component": 0,
        "missing_required_component": 0,
        "classification_gap": 0,
        "signature_expired": 0,
        "analysis_cancelled": 0,
    }
    for finding in findings:
        if finding.category in counts:
            counts[finding.category] += 1
    return counts
