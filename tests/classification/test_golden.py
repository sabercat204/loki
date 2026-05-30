"""Golden-file regression test for classification (task 21).

Pins the classify_components output against a committed JSON
snapshot. Any change to the rule schema, classifier, signature
detector, or pipeline that affects record contents will cause
this test to fail loudly. Regeneration procedure is documented
in ``tests/classification/fixtures/README.md``.

Implements R8.6 round-trip determinism at the snapshot level.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from loki.classification import classify_components
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_components

_GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"
_CANONICAL_RULES = _GOLDEN_DIR / "canonical_rules_v1.yaml"
_CANONICAL_CLASSIFICATIONS = _GOLDEN_DIR / "canonical_classifications_v1.json"


def _strip_volatile(record_dump: dict[str, Any]) -> dict[str, Any]:
    """Remove fields that vary between runs (timestamps)."""
    return {k: v for k, v in record_dump.items() if k != "timestamp"}


def test_canonical_rules_yaml_exists() -> None:
    """Pin the existence of the committed rule file."""
    assert _CANONICAL_RULES.exists(), (
        "canonical rules YAML missing from tests/classification/fixtures/golden/. "
        "See tests/classification/fixtures/README.md for regeneration."
    )


def test_canonical_classifications_json_exists() -> None:
    """Pin the existence of the committed expected-output JSON."""
    assert _CANONICAL_CLASSIFICATIONS.exists(), (
        "canonical classifications JSON missing from "
        "tests/classification/fixtures/golden/. "
        "See tests/classification/fixtures/README.md for regeneration."
    )


def test_classify_components_matches_golden_snapshot(tmp_path: Path) -> None:
    """Run classify_components against the canonical inputs and
    compare every emitted record against the committed JSON
    snapshot (modulo timestamp).
    """
    # Stage the canonical YAML in a tmp_path/rules dir per the
    # loader's depth-1 enumeration contract.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    shutil.copy(_CANONICAL_RULES, rules_dir / "canonical.yaml")

    components = build_components(count=4)
    config = ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )
    result = classify_components(components, config)

    actual_dumps = [_strip_volatile(r.model_dump(mode="json")) for r in result.records]

    expected_text = _CANONICAL_CLASSIFICATIONS.read_text(encoding="utf-8")
    expected_dumps = json.loads(expected_text)

    assert actual_dumps == expected_dumps, (
        "classify_components output diverged from canonical snapshot. "
        "If this is intentional, regenerate the snapshot per "
        "tests/classification/fixtures/README.md."
    )
