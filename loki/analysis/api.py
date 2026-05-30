"""Public API surface for the analysis engine.

Exposes the ``analyze_image`` free-function entry point and the
``AnalysisProgressEvent`` dataclass per design D1 + D6. The dataclass
deliberately strips ``component_id`` from the progress event payload
to take the stricter side of the no-leakage discipline; the GUI / CLI
consumer can render "component N of total" without knowing the UUID.

The public surface is intentionally minimal: one entry-point callable
plus the progress-event dataclass and two type aliases. Internal
state (the ``AnalysisPipeline``, the matching/pairing/scoring/posture
modules) is not re-exported.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from loki.analysis.pipeline import AnalysisPipeline

if TYPE_CHECKING:
    from loki.models.baseline import BaselineRegistry
    from loki.models.classification import ClassificationRecord
    from loki.models.config import AnalysisConfig
    from loki.models.firmware import FirmwareImage
    from loki.models.reports import ImageAnalysisReport

__all__ = [
    "AnalysisCancellationToken",
    "AnalysisProgressCallback",
    "AnalysisProgressEvent",
    "analyze_image",
]


@dataclass(frozen=True)
class AnalysisProgressEvent:
    """Structured progress event emitted at component granularity (R19.2).

    Emitted exactly once at the start of each Target_Record's per-pair
    evaluation. Per design D6, this dataclass deliberately strips
    ``component_id``: the GUI / CLI consumer renders "component N of
    total" without knowing the UUID, taking the stricter side of the
    no-leakage discipline (the leakage rule's spirit is broader than
    its letter; the progress callback is callback-adjacent to log
    streams in production GUIs).
    """

    index: int  # 1-based position in the input sequence
    total: int  # static input-sequence length captured at run start


# Type aliases on the public entry point.
AnalysisProgressCallback = Callable[["AnalysisProgressEvent"], None]
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
    """Analyze a target firmware image against a matched baseline (R1).

    Constructs a single internal ``AnalysisPipeline`` from the four
    inputs (which validates ``config``, resolves the Matched_Baseline,
    and checks pairing pre-conditions), then runs the pipeline and
    returns a Pydantic-validated ``ImageAnalysisReport``.

    Raises only typed ``AnalysisError`` subclasses for whole-run
    failures:

    - ``AnalysisConfigError``: ``config`` violates Requirement 14
      (missing weight key, unknown match strategy, out-of-range
      ``confidence_gap_threshold``, etc.).
    - ``BaselineNotFoundError``: baseline matching fails per
      Requirement 2 (lookup miss).
    - ``AnalysisInputError``: ``target_records`` or the matched
      baseline's manifest contains duplicate ``component_id`` values
      per Requirement 3.
    - ``AnalysisReportConstructionError``: final-report Pydantic
      validation fails per Requirement 17.

    Cooperative cancellation is a return-path, not a throw-path
    (R16.6): when the supplied ``cancel`` token returns ``True``, the
    pipeline emits the Cancellation_Marker as the LAST entry of
    ``findings`` and returns the partial report without raising.

    Runs synchronously on the calling thread and never spawns workers
    (R1.8 + R18.4). The progress callback, if supplied, is invoked
    from the calling thread only (R19.3).
    """
    # The pipeline takes (index, total) ints rather than the public
    # AnalysisProgressEvent dataclass directly; adapt the public
    # callback shape to the internal one.
    internal_progress: Callable[[int, int], None] | None
    if progress is None:
        internal_progress = None
    else:
        callback = progress  # local alias for the closure

        def internal_progress(index: int, total: int) -> None:
            callback(AnalysisProgressEvent(index=index, total=total))

    pipeline = AnalysisPipeline(
        target_records=target_records,
        registry=registry,
        target_image=target_image,
        config=config,
    )
    return pipeline.run(progress=internal_progress, cancel=cancel)
