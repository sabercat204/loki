"""Public API surface for the classification pipeline.

Exposes the free function ``classify_components`` along with the
``ClassificationResult`` container, the ``ProgressEvent``
dataclass, and the ``ProgressCallback`` / ``CancellationToken``
type aliases. Internal coordination lives in
``loki.classification.pipeline``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from loki.classification.errors import ClassificationError
from loki.models import ExtractedComponent
from loki.models.classification import ClassificationRecord
from loki.models.config import ClassificationConfig

if TYPE_CHECKING:
    from loki.feeds.registry import FeedRegistry
    from loki.models.firmware import FirmwareImage
    from loki.verification import TrustStore

__all__ = [
    "CancellationToken",
    "ClassificationResult",
    "ProgressCallback",
    "ProgressEvent",
    "classify_components",
]


@dataclass(frozen=True)
class ProgressEvent:
    """Structured progress event emitted at component granularity (R12.1).

    Emitted exactly once after each component's classification
    finishes (whether via record construction, the
    R5.6 dual-record path, or per-component failure recording).

    Carries:

    - ``index``: 1-based position in the input sequence.
    - ``total``: static input-sequence length, computed once
      at the start of the run.
    - ``component_id``: ``str(component.component_id)``,
      provided so GUI status bars can display a stable
      per-component identifier. Note: this is the same field
      listed in the design's Forbidden_Leakage_Field_Set, so
      callers SHALL NOT forward this value into the
      ``loki.classification`` logger. Caller-supplied callbacks
      are out of scope for the no-leakage audit (Property 40).
    """

    index: int
    total: int
    component_id: str


@dataclass(frozen=True)
class ClassificationResult:
    """Output container for one classification run (R1.1, R10.5).

    The ``records`` and ``errors`` lists partition components in
    v1 except for the missing-bytes signature-detection case
    (R5.6), which intentionally produces both a
    ``ClassificationRecord`` and a ``ClassificationError`` for
    the same component.
    """

    records: list[ClassificationRecord] = field(default_factory=list)
    errors: list[ClassificationError] = field(default_factory=list)


# Type aliases on the public entry point.
ProgressCallback = Callable[[ProgressEvent], None]
CancellationToken = Callable[[], bool]


def classify_components(
    components: Sequence[ExtractedComponent],
    config: ClassificationConfig,
    *,
    progress: ProgressCallback | None = None,
    cancel: CancellationToken | None = None,
    feeds: FeedRegistry | None = None,
    source_image: FirmwareImage | None = None,
    trust_store: TrustStore | None = None,
) -> ClassificationResult:
    """Classify a sequence of extracted components (R1.1-R1.9).

    Constructs a single internal ``ClassificationPipeline`` from
    ``config`` (which loads and validates the Rule_Set per
    Requirement 2), then iterates ``components`` in input order
    (R8.3), classifying each per Requirements 3 through 7.

    The pipeline is constructed *unconditionally* (even for
    empty input sequences) so that rule-load errors surface
    eagerly as exceptions rather than getting swallowed when
    nothing has been classified.

    Raises only typed ``ClassificationPipelineError`` subclasses
    for whole-run failures (rule-load errors, configuration
    errors). Per-component failures are recorded as
    ``ClassificationError`` instances inside ``result.errors``
    and never raised (R9.3).

    Runs synchronously on the calling thread and never spawns
    workers (R1.7). The optional ``progress`` callback, if
    supplied, is invoked from the calling thread only (R12.2).

    Args:
        components: A sequence of ``ExtractedComponent`` records
            from the extraction pipeline.
        config: ``ClassificationConfig`` carrying
            ``taxonomy_version`` and ``rules_path``. The
            ``confidence_threshold`` field is reserved for the
            future analysis engine; v1 does not consume it
            (R4.10).
        progress: Optional ``ProgressCallback`` invoked once per
            component on the calling thread (R12.1, R12.2).
        cancel: Optional ``CancellationToken`` polled between
            components; returning ``True`` stops further
            classification and records a cancellation
            ``ClassificationError`` per R1.9.
        feeds: Optional ``FeedRegistry`` for CVE lookup. When
            supplied, each classified record gets ``cve_matches``
            populated from the feeds cache. Requires
            ``source_image`` to be non-None.
        source_image: Optional ``FirmwareImage`` providing the
            firmware version for CVE query derivation. Required
            when ``feeds`` is not None.
        trust_store: Optional ``TrustStore`` for signature chain
            verification. When supplied, components with detected
            signatures are verified against this trust store and
            ``SignatureInfo.verified/signer/cert_expiry`` are
            populated. When None, verified stays False (v1 default).

    Returns:
        A ``ClassificationResult`` carrying the validated
        ``ClassificationRecord`` list and the
        ``ClassificationError`` list.
    """
    # Imported lazily to avoid the circular dependency at module
    # import time (pipeline.py imports ProgressEvent /
    # ClassificationResult from this module).
    from loki.classification.pipeline import ClassificationPipeline

    pipeline = ClassificationPipeline(
        config, feeds=feeds, source_image=source_image, trust_store=trust_store
    )
    return pipeline.classify(components, progress=progress, cancel=cancel)
