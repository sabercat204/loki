"""Analysis-engine semantic version constant.

The constant ``ANALYSIS_VERSION`` is contracted by R1.5 to be a semver
string in ``^\\d+\\.\\d+\\.\\d+$`` form. R15.8 derives every
``ImageAnalysisReport.report_id`` as
``uuid.uuid5(LOKI_NAMESPACE, f"{target_image.image_id}:{baseline.baseline_id}:{ANALYSIS_VERSION}")``,
so a bump to this value changes every emitted ``report_id`` while leaving
``finding_id`` values stable (the ``finding_id`` derivation in R15.7 is
keyed on ``(baseline_id, finding_category, target_component_id)`` only).

A minor bump is required when any finding-emission or scoring behaviour
changes (currently a manual discipline; future work could enforce via a
property test that snapshots the version on every test run).
"""

__all__ = ["ANALYSIS_VERSION"]

ANALYSIS_VERSION: str = "1.0.0"
