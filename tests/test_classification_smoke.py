"""End-to-end smoke test for the classification pipeline (task 23).

Exercises the full extract → classify path: builds the
synthetic UEFI volume fixture, runs extract_firmware, builds a
minimal rule file pointing at one of the extracted components'
GUIDs, runs classify_components, and asserts the result
demonstrates both code paths (rule fired, UNKNOWN fallback) and
round-trips through JSON.

Lives under ``tests/`` rather than ``tests/classification/``
because the test spans the extraction and classification
subsystems.
"""

from __future__ import annotations

from pathlib import Path

from loki.classification import classify_components
from loki.classification.rules.loader import load_rule_set
from loki.classification.rules.schema import RuleSet
from loki.extraction import extract_firmware
from loki.extraction.extractors.base import clear_registry
from loki.models import ExtractionConfig
from loki.models.classification import ClassificationRecord
from loki.models.config import ClassificationConfig
from tests.extraction.fixtures import synthetic_uefi_volume


def test_extract_then_classify_smoke(tmp_path: Path) -> None:
    """Build → extract → classify on the synthetic UEFI volume.

    Asserts the cross-subsystem path works and that both
    classifier code paths (rule fired, UNKNOWN fallback) are
    exercised in a single run.
    """
    clear_registry()

    binary = synthetic_uefi_volume.build(tmp_path)
    config = ExtractionConfig(
        default_output_dir="",
        max_component_size=10_000_000,
        timeout_per_component=30,
    )
    extraction_result = extract_firmware(binary, config)
    components = extraction_result.manifest.components
    assert len(components) > 0, "extraction produced no components"

    target_guid = components[0].guid
    assert target_guid is not None, (
        "synthetic fixture should produce at least one GUID-bearing component"
    )

    # Build a minimal rule file targeting the first component's
    # GUID. Rule fires on component 0, leaving every other axis
    # on every component to fall through to the UNKNOWN fallback.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_yaml = f"""\
taxonomy_version: "1.0.0"
rules:
  - rule_id: smoke.type.000
    axis: type
    matcher:
      guid: {target_guid.lower()}
    effect:
      label: UEFI_DRIVER
      confidence: 0.85
      method: RULE
      evidence: smoke test rule
"""
    (rules_dir / "smoke.yaml").write_text(rule_yaml)

    classification_config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )
    classification_result = classify_components(components, classification_config)

    # Assert at least one rule fires across the whole result.
    fired_rule_ids = {
        record.type_axis.rule_id
        for record in classification_result.records
        if record.type_axis.rule_id is not None
    }
    assert "smoke.type.000" in fired_rule_ids, f"smoke rule never fired; saw {fired_rule_ids}"

    # Assert at least one UNKNOWN fallback emerges (axes the
    # smoke rule doesn't target).
    unknown_axis_seen = False
    for record in classification_result.records:
        if record.vendor_axis.label == "UNKNOWN":
            unknown_axis_seen = True
            break
    assert unknown_axis_seen, "no UNKNOWN fallback observed in any record"

    # Assert every record round-trips through JSON.
    for record in classification_result.records:
        payload = record.model_dump_json()
        restored = ClassificationRecord.model_validate_json(payload)
        assert restored.model_dump() == record.model_dump()


def test_canonical_rules_yaml_loads_via_loader(tmp_path: Path) -> None:
    """The committed canonical rules YAML loads cleanly via
    ``load_rule_set``. Belt-and-braces complement to the golden
    test: if the canonical YAML drifts from the loader's
    schema, this test fails before the golden test runs."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    canonical = (
        Path(__file__).parent / "classification" / "fixtures" / "golden" / "canonical_rules_v1.yaml"
    )
    (rules_dir / "canonical.yaml").write_text(canonical.read_text(encoding="utf-8"))

    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )
    rule_set = load_rule_set(config)
    assert isinstance(rule_set, RuleSet)
    assert len(rule_set.rules) == 4
