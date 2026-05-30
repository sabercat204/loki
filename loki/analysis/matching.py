"""Match_Strategy resolution → Matched_Baseline.

Implements Requirement 2 (baseline matching) and Requirement 14.1's
engine-side keyset check on ``AnalysisConfig.severity_weights``. The two
functions in this module are pure (no logging, no side effects beyond
their return values + raised exceptions); the pipeline orchestrates
them at construction time before any finding emission begins.

The model layer's existing validators on ``AnalysisConfig`` already
enforce sum-to-1.0 on ``severity_weights``, the range check on
``confidence_gap_threshold``, the StrEnum check on ``match_strategy``,
and the UUID-or-None check on ``baseline_id``. This module adds only
the engine-specific keyset rule (R14.1's
``{"type", "vendor", "security_posture", "mutability"}``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loki.analysis.errors import AnalysisConfigError, BaselineNotFoundError
from loki.models.enums import MatchStrategy

if TYPE_CHECKING:
    from loki.models.baseline import BaselineRecord, BaselineRegistry
    from loki.models.config import AnalysisConfig
    from loki.models.firmware import FirmwareImage

__all__ = [
    "REQUIRED_SEVERITY_WEIGHT_KEYS",
    "resolve_matched_baseline",
    "validate_analysis_config",
]

#: The closed v1 keyset for ``AnalysisConfig.severity_weights`` per R14.1.
#: The four keys correspond to the four taxonomic axes the analysis
#: engine scores against (R9.4): type, vendor, security_posture,
#: mutability.
REQUIRED_SEVERITY_WEIGHT_KEYS: frozenset[str] = frozenset(
    {"type", "vendor", "security_posture", "mutability"}
)


def validate_analysis_config(config: AnalysisConfig) -> None:
    """Enforce R14.1's keyset check on ``severity_weights``.

    Raises ``AnalysisConfigError`` when the keys of
    ``config.severity_weights`` differ from the closed v1 set
    ``{"type", "vendor", "security_posture", "mutability"}``. The
    model layer's existing sum-to-1.0 validator runs at
    ``AnalysisConfig`` construction time and is not re-checked here.

    The function is pure: no logging, no I/O, no return value other
    than ``None`` on success.
    """
    keys = set(config.severity_weights.keys())
    if keys != set(REQUIRED_SEVERITY_WEIGHT_KEYS):
        missing = sorted(REQUIRED_SEVERITY_WEIGHT_KEYS - keys)
        extra = sorted(keys - REQUIRED_SEVERITY_WEIGHT_KEYS)
        parts: list[str] = []
        if missing:
            parts.append(f"missing keys: {missing}")
        if extra:
            parts.append(f"extra keys: {extra}")
        msg = (
            "severity_weights must carry exactly the four keys "
            f"{sorted(REQUIRED_SEVERITY_WEIGHT_KEYS)}; " + "; ".join(parts)
        )
        raise AnalysisConfigError("severity_weights", msg)


def resolve_matched_baseline(
    config: AnalysisConfig,
    registry: BaselineRegistry,
    target_image: FirmwareImage,
) -> BaselineRecord:
    """Resolve the Matched_Baseline per ``config.match_strategy`` (R2).

    Three strategies (R2.1):

    - ``EXPLICIT``: lookup by ``config.baseline_id`` only. Raises
      ``AnalysisConfigError`` if ``baseline_id`` is unset (R2.2).
      Raises ``BaselineNotFoundError(baseline_id=...)`` on lookup miss
      (R2.5).
    - ``AUTO``: lookup by ``(target.vendor, target.model,
      target.firmware_version)`` only. Raises
      ``BaselineNotFoundError(vendor_model_version=...)`` on lookup
      miss (R2.3).
    - ``EXPLICIT_OR_AUTO``: try explicit first if ``baseline_id`` is
      set; otherwise fall back to auto-match. A mid-flight explicit
      miss when ``baseline_id`` is set raises (R2.5; no silent
      fallback).

    The function does not mutate the registry or any record it
    contains (R2.8).
    """
    strategy = config.match_strategy

    if strategy is MatchStrategy.EXPLICIT:
        return _resolve_explicit(config, registry)

    if strategy is MatchStrategy.AUTO:
        return _resolve_auto(registry, target_image)

    if strategy is MatchStrategy.EXPLICIT_OR_AUTO:
        if config.baseline_id is not None:
            return _resolve_explicit(config, registry)
        return _resolve_auto(registry, target_image)

    # Defensive: the StrEnum constraint on AnalysisConfig.match_strategy
    # should prevent any other value from reaching this point. If it
    # ever does, surface it as an AnalysisConfigError naming the field.
    msg = f"unknown match_strategy: {strategy!r}"
    raise AnalysisConfigError("match_strategy", msg)


def _resolve_explicit(
    config: AnalysisConfig,
    registry: BaselineRegistry,
) -> BaselineRecord:
    """EXPLICIT and EXPLICIT_OR_AUTO-with-baseline_id_set path (R2.2 / R2.5)."""
    if config.baseline_id is None:
        raise AnalysisConfigError(
            "baseline_id",
            "EXPLICIT match_strategy requires baseline_id to be set",
        )
    record = registry.get_by_id(config.baseline_id)
    if record is None:
        raise BaselineNotFoundError(baseline_id=config.baseline_id)
    return record


def _resolve_auto(
    registry: BaselineRegistry,
    target_image: FirmwareImage,
) -> BaselineRecord:
    """AUTO and EXPLICIT_OR_AUTO-fallback path (R2.3).

    The lookup requires non-None ``vendor``, ``model``, and
    ``firmware_version`` on the target image. If any is ``None``, the
    lookup cannot succeed; raise ``BaselineNotFoundError`` carrying the
    offending tuple verbatim (the model layer permits ``None`` on these
    fields, but the registry's lookup method does not — and a baseline
    record with ``None`` for any of them is not constructible at all
    because ``BaselineRecord`` requires non-None strings).
    """
    vendor = target_image.vendor
    model = target_image.model
    firmware_version = target_image.firmware_version
    if vendor is None or model is None or firmware_version is None:
        # Surface the mismatch as a not-found error carrying the literal
        # ``"<unset>"`` for the missing fields so the message is
        # readable. The vendor_model_version tuple itself uses the
        # actual values passed (post-coercion to non-None) so the
        # exception message is unambiguous.
        coerced = (
            vendor if vendor is not None else "<unset>",
            model if model is not None else "<unset>",
            firmware_version if firmware_version is not None else "<unset>",
        )
        raise BaselineNotFoundError(vendor_model_version=coerced)
    record = registry.get_by_vendor_model_version(vendor, model, firmware_version)
    if record is None:
        raise BaselineNotFoundError(vendor_model_version=(vendor, model, firmware_version))
    return record
