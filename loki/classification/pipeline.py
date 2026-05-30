"""Internal ``ClassificationPipeline`` coordinator.

Loads the Rule_Set at construction time (delegating to
``loki.classification.rules.loader``), then iterates input
components in order, invoking the per-axis classifier and the
signature detector and emitting validated
``ClassificationRecord`` instances. Per-component failures are
recorded as ``ClassificationError`` records inside the returned
``ClassificationResult``.

The pipeline is internal to the subsystem; callers use the free
function ``classify_components`` from
``loki.classification.api`` instead.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import ValidationError

from loki.classification.api import (
    CancellationToken,
    ClassificationResult,
    ProgressCallback,
    ProgressEvent,
)
from loki.classification.classifier import classify_axis
from loki.classification.errors import ClassificationConfigError, ClassificationError
from loki.classification.rules.loader import load_rule_set
from loki.classification.rules.schema import RuleSet
from loki.classification.signatures import detect_signature
from loki.classification.timing import Stopwatch
from loki.classification.version import CLASSIFICATION_VERSION
from loki.models import ExtractedComponent
from loki.models.classification import (
    AxisClassification,
    ClassificationRecord,
    SignatureInfo,
)
from loki.models.config import ClassificationConfig

if TYPE_CHECKING:
    from loki.feeds.registry import FeedRegistry
    from loki.models.firmware import FirmwareImage
    from loki.verification import TrustStore

__all__ = ["ClassificationPipeline"]

# The four axes the pipeline classifies, in fixed order
# (R4.3 four-axis independence + the model layer's positional
# field order on ClassificationRecord).
_AXES: tuple[str, ...] = ("type", "vendor", "security_posture", "mutability")

_logger = logging.getLogger("loki.classification.pipeline")


class ClassificationPipeline:
    """Internal pipeline holding the validated Rule_Set.

    Construction loads and validates the Rule_Set exactly once
    (R2.3). The pipeline holds no per-run mutable state beyond
    the run timestamp chosen at the start of ``classify``.
    Callers use the free function ``classify_components`` rather
    than constructing the pipeline directly.
    """

    def __init__(
        self,
        config: ClassificationConfig,
        *,
        feeds: FeedRegistry | None = None,
        source_image: FirmwareImage | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        """Load and validate the Rule_Set (R2.3, R2.4).

        Raises ``ClassificationConfigError`` on missing rules
        directory, malformed YAML, schema mismatches, taxonomy
        version mismatches, or duplicate ``rule_id`` values.
        Raises ``ClassificationRuleError`` on individual Rule /
        Matcher / Effect validation failures.
        """
        if feeds is not None and source_image is None:
            raise ClassificationConfigError(
                config.rules_path,
                "source_image is required when feeds is provided",
            )

        self._rules: RuleSet = load_rule_set(config)
        self._taxonomy_version: str = config.taxonomy_version
        self._classification_version: str = CLASSIFICATION_VERSION
        self._feeds: FeedRegistry | None = feeds
        self._source_image: FirmwareImage | None = source_image
        self._trust_store: TrustStore | None = trust_store

        # R13.1: pipeline-construction summary INFO record.
        _logger.info(
            "classification pipeline ready rules_path=%s files=%d rules=%d "
            "taxonomy_version=%s classification_version=%s",
            config.rules_path,
            len(self._rules.sources),
            len(self._rules.rules),
            self._taxonomy_version,
            self._classification_version,
        )

    def classify(
        self,
        components: Sequence[ExtractedComponent],
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
    ) -> ClassificationResult:
        """Run classification per Requirements 3 through 13."""

        # R1.6 + R8.1: single run-start timestamp, copied into
        # every emitted record.
        run_started_at = datetime.now(tz=UTC)
        stopwatch = Stopwatch()
        stopwatch.start()

        records: list[ClassificationRecord] = []
        errors: list[ClassificationError] = []
        total = len(components)

        # R13.2: run-start INFO record.
        _logger.info(
            "classification run starting components=%d classification_version=%s",
            total,
            self._classification_version,
        )

        for index, component in enumerate(components, start=1):
            # R1.9: cooperative cancellation.
            if cancel is not None and cancel():
                errors.append(
                    ClassificationError(
                        component_id=None,
                        error_message="classification cancelled by caller",
                        timestamp=datetime.now(tz=UTC),
                    )
                )
                break

            # Build the four axis classifications. Wrap the
            # per-axis evaluation in try/except so a crash on one
            # axis doesn't prevent the other axes from being
            # built — but R9.3's contract is that the *whole*
            # component fails when any axis evaluation crashes,
            # so on the first exception we record an error and
            # skip the component.
            axes: list[AxisClassification] = []
            axis_crashed = False
            for axis_name in _AXES:
                try:
                    axes.append(classify_axis(self._rules.rules, axis_name, component))
                except Exception as exc:
                    axes_classified = len(axes)
                    errors.append(
                        ClassificationError(
                            component_id=component.component_id,
                            error_message=f"rule evaluation crashed: {type(exc).__name__}",
                            timestamp=datetime.now(tz=UTC),
                        )
                    )
                    # R13.4: WARNING with axes_classified only.
                    # No component_id, no error message string.
                    _logger.warning(
                        "classification per-component failure axes_classified=%d",
                        axes_classified,
                    )
                    axis_crashed = True
                    break

            if axis_crashed:
                continue

            # Signature detection (R5.1-R5.4 + R5.6).
            present, sig_error = detect_signature(component)
            verified = False
            signer: str | None = None
            cert_expiry: datetime | None = None

            if present and sig_error is None and self._trust_store is not None:
                if component.raw_path is not None:
                    from pathlib import Path

                    from loki.verification import verify_signature

                    vr = verify_signature(Path(component.raw_path), self._trust_store)
                    verified = vr.verified
                    signer = vr.signer
                    cert_expiry = vr.cert_expiry

            signature_info = SignatureInfo(
                present=present,
                verified=verified,
                signer=signer,
                cert_expiry=cert_expiry,
            )

            # R5.6 dual-record contract: if signature detection
            # returned an error, record it but continue past to
            # build the record. The component appears in BOTH
            # records and errors lists.
            if sig_error is not None:
                errors.append(
                    ClassificationError(
                        component_id=component.component_id,
                        error_message=sig_error,
                        timestamp=datetime.now(tz=UTC),
                    )
                )

            # Build the ClassificationRecord. The four axes were
            # appended in _AXES order; unpack positionally.
            type_axis, vendor_axis, security_axis, mutability_axis = axes
            try:
                record = ClassificationRecord(
                    component_id=component.component_id,
                    source_image_id=component.source_image_id,
                    extraction_offset=component.offset,
                    timestamp=run_started_at,
                    type_axis=type_axis,
                    vendor_axis=vendor_axis,
                    security_axis=security_axis,
                    mutability_axis=mutability_axis,
                    signature_info=signature_info,
                    cve_matches=[],
                    suspicion_triggers=[],
                    classification_version=self._classification_version,
                    overrides=[],
                )
            except ValidationError as exc:
                errors.append(
                    ClassificationError(
                        component_id=component.component_id,
                        error_message=f"record validation failed: {_summarize(exc)}",
                        timestamp=datetime.now(tz=UTC),
                    )
                )
                # R13.4: WARNING with axes_classified=4 since all
                # four axes were built; the failure is in the
                # final record construction.
                _logger.warning(
                    "classification per-component failure axes_classified=%d",
                    4,
                )
                continue

            if self._feeds is not None:
                record.cve_matches = self._populate_cve_matches(record)

            records.append(record)

            # R12.1 + R12.2: progress callback on the calling thread.
            if progress is not None:
                progress(
                    ProgressEvent(
                        index=index,
                        total=total,
                        component_id=str(component.component_id),
                    )
                )

        duration_ms = stopwatch.stop()

        # R13.3: run-end INFO record.
        _logger.info(
            "classification run finished records=%d errors=%d duration=%.1fms",
            len(records),
            len(errors),
            duration_ms,
        )

        return ClassificationResult(records=records, errors=errors)

    def _populate_cve_matches(self, record: ClassificationRecord) -> list[str]:
        """Derive and execute a CVE lookup for a classified record.

        Returns a sorted, deduplicated list of CVE ID strings.
        On any error, logs a WARNING and returns [].
        """
        if self._feeds is None or self._source_image is None:
            return []
        try:
            from loki.feeds.models import CVELookupQuery
            from loki.feeds.registry import derive_cve_query

            query: CVELookupQuery = derive_cve_query(record, self._source_image)
            result = self._feeds.cve_lookup(query, allow_refresh=False)
            cve_ids = sorted(set(m.cve_id for m in result.matches))
            return cve_ids
        except Exception as exc:
            _logger.warning("feeds cve_lookup failed: %s", type(exc).__name__)
            return []


def _summarize(exc: ValidationError) -> str:
    """Render a ``ValidationError`` as a single-line summary.

    Keeps the summary small to avoid accidental leakage of
    field values into the error message. The full Pydantic
    rendering can include arbitrary input values, which may
    include identifiers from the Forbidden_Leakage_Field_Set;
    the summary is bounded to the error count plus the first
    error's location and message.
    """
    error_count = exc.error_count()
    errors = exc.errors()
    if not errors:
        return f"validation failed ({error_count} errors)"
    first = errors[0]
    loc = ".".join(str(part) for part in first.get("loc", ()))
    msg = first.get("msg", "validation error")
    return f"{error_count} error(s); first at {loc!r}: {msg}"
