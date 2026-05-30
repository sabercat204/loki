"""Tests for ``loki.analysis.matching``.

Covers task 8 acceptance: ``validate_analysis_config`` enforces the R14.1
keyset rule on ``severity_weights``; ``resolve_matched_baseline`` resolves
the Matched_Baseline per all three Match_Strategy paths with the correct
exception classes raised on each documented failure mode.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from loki.analysis import (
    AnalysisConfigError,
    BaselineNotFoundError,
)
from loki.analysis.matching import (
    REQUIRED_SEVERITY_WEIGHT_KEYS,
    resolve_matched_baseline,
    validate_analysis_config,
)
from loki.models import (
    AnalysisConfig,
    AxisClassification,
    BaselineRecord,
    BaselineRegistry,
    ClassificationMethod,
    ClassificationRecord,
    ComponentTypeLabel,
    FirmwareImage,
    MatchStrategy,
    MutabilityLabel,
    SecurityPostureLabel,
    SeverityLevel,
    VendorLabel,
)

# --- Test fixture helpers ---


_VALID_WEIGHTS = {
    "type": 0.4,
    "vendor": 0.2,
    "security_posture": 0.3,
    "mutability": 0.1,
}


def _make_config(**overrides: Any) -> AnalysisConfig:
    base: dict[str, Any] = {
        "severity_weights": _VALID_WEIGHTS,
        "default_severity_threshold": SeverityLevel.MEDIUM,
    }
    base.update(overrides)
    return AnalysisConfig(**base)


def _axis(label: str, *, confidence: float = 1.0) -> AxisClassification:
    return AxisClassification(
        label=label,
        confidence=confidence,
        method=ClassificationMethod.RULE,
    )


def _make_record(*, component_id: uuid.UUID | None = None) -> ClassificationRecord:
    return ClassificationRecord(
        component_id=component_id or uuid.uuid4(),
        source_image_id=uuid.uuid4(),
        extraction_offset="0x00",
        timestamp=datetime.now(UTC),
        type_axis=_axis(ComponentTypeLabel.UEFI_DRIVER),
        vendor_axis=_axis(VendorLabel.INTEL),
        security_axis=_axis(SecurityPostureLabel.SECURE),
        mutability_axis=_axis(MutabilityLabel.READONLY),
        classification_version="1.0.0",
    )


def _make_baseline(
    *,
    baseline_id: uuid.UUID | None = None,
    vendor: str = "Intel",
    model: str = "X1",
    firmware_version: str = "1.0.0",
) -> BaselineRecord:
    return BaselineRecord(
        baseline_id=baseline_id or uuid.uuid4(),
        name="test-baseline",
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
        created_timestamp=datetime.now(UTC),
        component_manifest=[_make_record()],
        source_image_hash="0" * 64,
        baseline_version="1.0.0",
    )


def _make_image(
    *,
    vendor: str = "Intel",
    model: str = "X1",
    firmware_version: str = "1.0.0",
) -> FirmwareImage:
    return FirmwareImage(
        file_path="/tmp/test.bin",
        file_hash="0" * 64,
        file_size=1024,
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
    )


# --- validate_analysis_config ---


def test_validate_accepts_canonical_keyset() -> None:
    cfg = _make_config()
    validate_analysis_config(cfg)  # no raise


def test_validate_rejects_missing_type_key() -> None:
    cfg = _make_config(severity_weights={"vendor": 0.4, "security_posture": 0.3, "mutability": 0.3})
    with pytest.raises(AnalysisConfigError) as excinfo:
        validate_analysis_config(cfg)
    assert excinfo.value.field_name == "severity_weights"
    assert "missing keys" in str(excinfo.value)
    assert "type" in str(excinfo.value)


def test_validate_rejects_extra_axis_key() -> None:
    cfg = _make_config(
        severity_weights={
            "type": 0.3,
            "vendor": 0.2,
            "security_posture": 0.2,
            "mutability": 0.1,
            "extra_axis": 0.2,
        }
    )
    with pytest.raises(AnalysisConfigError) as excinfo:
        validate_analysis_config(cfg)
    assert "extra keys" in str(excinfo.value)
    assert "extra_axis" in str(excinfo.value)


def test_validate_rejects_renamed_key() -> None:
    """A near-miss like ``severity_posture`` instead of ``security_posture`` raises."""
    cfg = _make_config(
        severity_weights={
            "type": 0.4,
            "vendor": 0.2,
            "severity_posture": 0.3,  # typo
            "mutability": 0.1,
        }
    )
    with pytest.raises(AnalysisConfigError) as excinfo:
        validate_analysis_config(cfg)
    msg = str(excinfo.value)
    assert "missing keys" in msg
    assert "extra keys" in msg
    assert "security_posture" in msg
    assert "severity_posture" in msg


def test_required_keyset_is_immutable() -> None:
    """The exported constant is a frozenset (no in-place mutation)."""
    assert isinstance(REQUIRED_SEVERITY_WEIGHT_KEYS, frozenset)
    assert REQUIRED_SEVERITY_WEIGHT_KEYS == frozenset(
        {"type", "vendor", "security_posture", "mutability"}
    )


# --- resolve_matched_baseline: EXPLICIT ---


def test_explicit_strategy_hit_returns_record() -> None:
    target_id = uuid.uuid4()
    baseline = _make_baseline(baseline_id=target_id)
    registry = BaselineRegistry(baselines=[baseline])
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT, baseline_id=target_id)
    image = _make_image()
    result = resolve_matched_baseline(cfg, registry, image)
    assert result.baseline_id == target_id


def test_explicit_strategy_miss_raises_baseline_not_found_with_id() -> None:
    """A baseline_id that doesn't appear in the registry raises with the offending id."""
    missing_id = uuid.uuid4()
    other_baseline = _make_baseline()  # different baseline_id
    registry = BaselineRegistry(baselines=[other_baseline])
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT, baseline_id=missing_id)
    image = _make_image()
    with pytest.raises(BaselineNotFoundError) as excinfo:
        resolve_matched_baseline(cfg, registry, image)
    assert excinfo.value.baseline_id == missing_id
    assert excinfo.value.vendor_model_version is None


def test_explicit_strategy_unset_baseline_id_raises_config_error() -> None:
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT, baseline_id=None)
    registry = BaselineRegistry(baselines=[_make_baseline()])
    image = _make_image()
    with pytest.raises(AnalysisConfigError) as excinfo:
        resolve_matched_baseline(cfg, registry, image)
    assert excinfo.value.field_name == "baseline_id"
    assert "EXPLICIT" in str(excinfo.value)


# --- resolve_matched_baseline: AUTO ---


def test_auto_strategy_hit_returns_record() -> None:
    baseline = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[baseline])
    cfg = _make_config(match_strategy=MatchStrategy.AUTO)
    image = _make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    result = resolve_matched_baseline(cfg, registry, image)
    assert result.baseline_id == baseline.baseline_id


def test_auto_strategy_miss_raises_baseline_not_found_with_tuple() -> None:
    baseline = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[baseline])
    cfg = _make_config(match_strategy=MatchStrategy.AUTO)
    image = _make_image(vendor="AMD", model="Z9", firmware_version="2.5.0")
    with pytest.raises(BaselineNotFoundError) as excinfo:
        resolve_matched_baseline(cfg, registry, image)
    assert excinfo.value.baseline_id is None
    assert excinfo.value.vendor_model_version == ("AMD", "Z9", "2.5.0")


def test_auto_strategy_baseline_id_ignored_on_match() -> None:
    """When match_strategy is AUTO, baseline_id is ignored (R2.3 explicit)."""
    auto_match = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[auto_match])
    spurious_id = uuid.uuid4()  # not in registry; should be ignored
    cfg = _make_config(match_strategy=MatchStrategy.AUTO, baseline_id=spurious_id)
    image = _make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    result = resolve_matched_baseline(cfg, registry, image)
    assert result.baseline_id == auto_match.baseline_id


def test_auto_strategy_with_none_vendor_raises_baseline_not_found() -> None:
    """A FirmwareImage with vendor=None cannot auto-match; raises BNF with <unset>."""
    baseline = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[baseline])
    cfg = _make_config(match_strategy=MatchStrategy.AUTO)
    # FirmwareImage permits vendor=None at the model level; the engine
    # surfaces it cleanly via BaselineNotFoundError rather than passing
    # None to the registry's strict-typed lookup method.
    image = FirmwareImage(
        file_path="/tmp/test.bin",
        file_hash="0" * 64,
        file_size=1024,
        vendor=None,
        model=None,
        firmware_version=None,
    )
    with pytest.raises(BaselineNotFoundError) as excinfo:
        resolve_matched_baseline(cfg, registry, image)
    assert excinfo.value.vendor_model_version == ("<unset>", "<unset>", "<unset>")


# --- resolve_matched_baseline: EXPLICIT_OR_AUTO ---


def test_explicit_or_auto_with_explicit_hit_returns_explicit() -> None:
    target_id = uuid.uuid4()
    explicit = _make_baseline(baseline_id=target_id)
    auto_match = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[explicit, auto_match])
    cfg = _make_config(
        match_strategy=MatchStrategy.EXPLICIT_OR_AUTO,
        baseline_id=target_id,
    )
    image = _make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    result = resolve_matched_baseline(cfg, registry, image)
    # Explicit wins when baseline_id is set, even if auto would also match.
    assert result.baseline_id == target_id


def test_explicit_or_auto_with_explicit_miss_raises_no_silent_fallback() -> None:
    """R2.5: explicit miss with baseline_id set raises; does not fall back to AUTO."""
    missing_id = uuid.uuid4()
    auto_match = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[auto_match])
    cfg = _make_config(
        match_strategy=MatchStrategy.EXPLICIT_OR_AUTO,
        baseline_id=missing_id,
    )
    image = _make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    with pytest.raises(BaselineNotFoundError) as excinfo:
        resolve_matched_baseline(cfg, registry, image)
    assert excinfo.value.baseline_id == missing_id


def test_explicit_or_auto_unset_baseline_id_falls_back_to_auto_match() -> None:
    auto_match = _make_baseline(vendor="Intel", model="X1", firmware_version="1.0.0")
    registry = BaselineRegistry(baselines=[auto_match])
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT_OR_AUTO, baseline_id=None)
    image = _make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    result = resolve_matched_baseline(cfg, registry, image)
    assert result.baseline_id == auto_match.baseline_id


def test_explicit_or_auto_unset_baseline_id_auto_miss_raises() -> None:
    """No explicit + no auto-match -> raises with the auto-lookup tuple."""
    other = _make_baseline(vendor="Other", model="M", firmware_version="9.9.9")
    registry = BaselineRegistry(baselines=[other])
    cfg = _make_config(match_strategy=MatchStrategy.EXPLICIT_OR_AUTO, baseline_id=None)
    image = _make_image(vendor="Intel", model="X1", firmware_version="1.0.0")
    with pytest.raises(BaselineNotFoundError) as excinfo:
        resolve_matched_baseline(cfg, registry, image)
    assert excinfo.value.vendor_model_version == ("Intel", "X1", "1.0.0")


# --- Read-only registry contract (R2.8) ---


def test_resolver_does_not_mutate_registry() -> None:
    baseline = _make_baseline()
    registry = BaselineRegistry(baselines=[baseline])
    cfg = _make_config(match_strategy=MatchStrategy.AUTO)
    image = _make_image()
    snapshot_before = registry.model_dump(mode="json")
    resolve_matched_baseline(cfg, registry, image)
    snapshot_after = registry.model_dump(mode="json")
    assert snapshot_before == snapshot_after


def test_resolver_does_not_mutate_returned_record() -> None:
    baseline = _make_baseline()
    registry = BaselineRegistry(baselines=[baseline])
    cfg = _make_config(match_strategy=MatchStrategy.AUTO)
    image = _make_image()
    result = resolve_matched_baseline(cfg, registry, image)
    snapshot_before = result.model_dump(mode="json")
    # Re-call; the resolver must not have stashed state that mutates the record.
    resolve_matched_baseline(cfg, registry, image)
    snapshot_after = result.model_dump(mode="json")
    assert snapshot_before == snapshot_after
