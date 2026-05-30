"""Smoke + example tests for the LOKI model layer.

Verifies that:
- the package imports cleanly without circular-import errors
- every public model + enum is reachable from ``loki.models``
- ``LokiConfig.from_yaml`` reads a valid YAML file
- enums serialize to plain strings
- a few representative invalid inputs are rejected
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from loki import models as loki_models


def test_public_api_exports_complete() -> None:
    """Every name promised in __all__ resolves on the package."""
    assert hasattr(loki_models, "__all__")
    for name in loki_models.__all__:
        assert hasattr(loki_models, name), f"{name} missing from loki.models"


def test_no_circular_imports() -> None:
    """from loki.models import * loads cleanly."""
    namespace: dict[str, object] = {}
    exec("from loki.models import *", namespace)
    # spot-check a representative subset
    for name in [
        "FirmwareImage",
        "ClassificationRecord",
        "BaselineRegistry",
        "ImageAnalysisReport",
        "LokiConfig",
        "DeltaType",
        "SeverityLevel",
    ]:
        assert name in namespace, f"{name} missing after wildcard import"


def test_enum_serializes_to_string() -> None:
    payload = json.dumps(loki_models.SeverityLevel.HIGH)
    assert payload == '"HIGH"'


def test_firmware_image_round_trip_simple() -> None:
    image = loki_models.FirmwareImage(
        file_path="/tmp/x.bin",
        file_hash="a" * 64,
        file_size=1024,
        vendor="INTEL",
    )
    rebuilt = loki_models.FirmwareImage.model_validate_json(image.model_dump_json())
    assert rebuilt == image


def test_invalid_offset_rejected() -> None:
    with pytest.raises(ValidationError):
        loki_models.ExtractedComponent(
            component_id=uuid.uuid4(),
            source_image_id=uuid.uuid4(),
            offset="not-a-hex-offset",
            size=42,
            raw_hash="b" * 64,
        )


def test_override_record_empty_justification_rejected() -> None:
    with pytest.raises(ValidationError):
        loki_models.OverrideRecord(
            original_label="OLD",
            override_label="NEW",
            analyst="alice",
            timestamp=datetime.now(tz=UTC),
            justification="   ",
        )


def test_loki_config_from_yaml(tmp_path: Path) -> None:
    """End-to-end: write a YAML file, load it, validate the structure."""
    cfg_path = tmp_path / "loki.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "general": {
                    "default_output_format": "HUMAN",
                    "color": "AUTO",
                    "verbosity": 1,
                    "log_level": "INFO",
                },
                "extraction": {
                    "default_output_dir": "/tmp/loki-extracted",
                    "max_component_size": 50_000_000,
                    "timeout_per_component": 60,
                },
                "classification": {
                    "taxonomy_version": "1.0.0",
                    "confidence_threshold": 0.6,
                    "rules_path": "/tmp/loki-rules",
                },
                "analysis": {
                    "severity_weights": {
                        "critical": 0.5,
                        "high": 0.3,
                        "medium": 0.15,
                        "low": 0.05,
                    },
                    "default_severity_threshold": "MEDIUM",
                    "report_template": None,
                },
                "baseline": {
                    "storage_path": "/tmp/loki-baselines",
                    "auto_match": True,
                },
                "feeds": {
                    "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "update_interval": 3600,
                    "cache_path": "/tmp/loki-cache",
                    "implant_rules_path": "/tmp/loki-implants",
                },
                "fleet": {
                    "default_severity_threshold": "MEDIUM",
                    "storage_path": "/tmp/loki-fleet",
                },
            }
        )
    )
    cfg = loki_models.LokiConfig.from_yaml(cfg_path)
    assert cfg.general.default_output_format == loki_models.OutputFormat.HUMAN
    assert cfg.classification.confidence_threshold == 0.6


def test_loki_config_from_yaml_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        loki_models.LokiConfig.from_yaml(tmp_path / "does-not-exist.yaml")


def test_loki_config_from_yaml_invalid_weights(tmp_path: Path) -> None:
    """Severity weights summing to ≠ 1.0 should fail validation at load time."""
    cfg_path = tmp_path / "loki-bad.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "general": {
                    "default_output_format": "HUMAN",
                    "color": "AUTO",
                    "verbosity": 0,
                    "log_level": "INFO",
                },
                "extraction": {
                    "default_output_dir": "/tmp/x",
                    "max_component_size": 1,
                    "timeout_per_component": 1,
                },
                "classification": {
                    "taxonomy_version": "1.0.0",
                    "confidence_threshold": 0.5,
                    "rules_path": "/tmp/x",
                },
                "analysis": {
                    "severity_weights": {"a": 0.5, "b": 0.6},  # sums to 1.1
                    "default_severity_threshold": "MEDIUM",
                    "report_template": None,
                },
                "baseline": {"storage_path": "/tmp/x", "auto_match": False},
                "feeds": {
                    "nvd_url": "https://x",
                    "update_interval": 1,
                    "cache_path": "/tmp/x",
                    "implant_rules_path": "/tmp/x",
                },
                "fleet": {
                    "default_severity_threshold": "MEDIUM",
                    "storage_path": "/tmp/x",
                },
            }
        )
    )
    with pytest.raises(ValidationError):
        loki_models.LokiConfig.from_yaml(cfg_path)
