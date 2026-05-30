"""Inner-component handling tests for the classification pipeline.

Covers Requirement 7: inner components (those produced by the
extraction pipeline from decompressed UEFI sections, identified
by a synthetic ``source_image_id`` derived from a decompressed
hash) classify identically to outer components. The pipeline
does not branch on ``source_image_id``, applies the full
Rule_Set without filtering, and does not read bytes outside
each component's own ``raw_path``.
"""

from __future__ import annotations

import builtins
import uuid
from pathlib import Path
from typing import Any

import pytest

from loki.classification import classify_components
from loki.models import LOKI_NAMESPACE, ExtractedComponent
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_components


def _config(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


# ---------------------------------------------------------------------------
# Inner components classify the same as outer components (R7.1, R7.2)
# ---------------------------------------------------------------------------


def test_inner_components_classify_identically_to_outer_components(
    synthetic_rules_dir: Path,
    synthetic_components_with_inner: list[ExtractedComponent],
) -> None:
    """R7.1: inner and outer components go through the same
    code path. Every component in the input produces one
    record (modulo R5.6 dual-record on missing bytes — which
    the synthetic fixture's None raw_path triggers
    universally)."""
    config = _config(synthetic_rules_dir)
    result = classify_components(synthetic_components_with_inner, config)
    # Every component produces a record, regardless of inner/outer status.
    assert len(result.records) == len(synthetic_components_with_inner)


def test_pipeline_does_not_branch_on_source_image_id(
    synthetic_rules_dir: Path,
) -> None:
    """R7.1 second clause: classification of an inner component
    produces the same axis selections as the equivalent outer
    component. Build two components that differ ONLY in
    ``source_image_id``; assert the resulting axis
    classifications are identical."""

    outer_image_id = uuid.uuid5(LOKI_NAMESPACE, "outer-image")
    # Inner image_id derived as uuid5(LOKI_NAMESPACE, decompressed_hash)
    # per the extraction pipeline's contract.
    decompressed_hash = "f" * 64
    inner_image_id = uuid.uuid5(LOKI_NAMESPACE, decompressed_hash)

    common_kwargs = {
        "component_id": uuid.uuid5(LOKI_NAMESPACE, "shared-component"),
        "offset": "0x1000",
        "size": 4096,
        "raw_hash": "0" * 64,
        "component_type_hint": "dxe_driver",
        "guid": str(uuid.uuid5(LOKI_NAMESPACE, "shared-guid")),
        "name": "SHARED_COMP",
        "raw_path": None,
    }
    outer = ExtractedComponent(source_image_id=outer_image_id, **common_kwargs)  # type: ignore[arg-type]
    inner = ExtractedComponent(source_image_id=inner_image_id, **common_kwargs)  # type: ignore[arg-type]

    config = _config(synthetic_rules_dir)
    outer_result = classify_components([outer], config)
    inner_result = classify_components([inner], config)

    # Both produce records.
    assert len(outer_result.records) == 1
    assert len(inner_result.records) == 1

    outer_record = outer_result.records[0]
    inner_record = inner_result.records[0]

    # Axis classifications are identical (same labels, same
    # rule_ids, same confidences) — the pipeline did not
    # consult source_image_id when classifying.
    for axis_name in ("type_axis", "vendor_axis", "security_axis", "mutability_axis"):
        outer_axis = getattr(outer_record, axis_name)
        inner_axis = getattr(inner_record, axis_name)
        assert outer_axis.label == inner_axis.label
        assert outer_axis.confidence == inner_axis.confidence
        assert outer_axis.rule_id == inner_axis.rule_id


def test_inner_components_get_full_rule_set(
    synthetic_rules_dir: Path,
) -> None:
    """R7.2: the full Rule_Set applies to inner components
    without filtering. If a rule fires on an outer component
    with the same matchable attributes, it also fires on the
    inner component."""

    decompressed_hash = "e" * 64
    inner_source_image_id = uuid.uuid5(LOKI_NAMESPACE, decompressed_hash)

    # Use the same GUID a synthetic rule fires on (rule
    # synthetic.type.000 matches component-guid-0).
    fixture_namespace = uuid.uuid5(LOKI_NAMESPACE, "tests.classification.fixtures")
    matching_guid = str(uuid.uuid5(fixture_namespace, "comp-guid-0"))

    inner_component = ExtractedComponent(
        component_id=uuid.uuid5(LOKI_NAMESPACE, "inner-test"),
        source_image_id=inner_source_image_id,
        offset="0x0",
        size=4096,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=matching_guid,
        name="INNER_COMP",
        raw_path=None,
    )

    config = _config(synthetic_rules_dir)
    result = classify_components([inner_component], config)

    assert len(result.records) == 1
    record = result.records[0]
    # The synthetic.type.000 rule should have fired on this
    # inner component (it matches by GUID).
    assert record.type_axis.rule_id == "synthetic.type.000"


# ---------------------------------------------------------------------------
# source_image_id preserved verbatim (R7.3)
# ---------------------------------------------------------------------------


def test_inner_component_source_image_id_preserved_verbatim(
    synthetic_rules_dir: Path,
) -> None:
    """R7.3: ``ClassificationRecord.source_image_id`` for an
    inner component matches the input component's
    ``source_image_id`` byte-for-byte (preserving the
    synthetic-UUID derivation chosen by the extraction
    pipeline)."""

    decompressed_hash = "d" * 64
    inner_source_image_id = uuid.uuid5(LOKI_NAMESPACE, decompressed_hash)

    inner_component = ExtractedComponent(
        component_id=uuid.uuid5(LOKI_NAMESPACE, "preserved-source-image-id"),
        source_image_id=inner_source_image_id,
        offset="0x0",
        size=4096,
        raw_hash="0" * 64,
        component_type_hint="dxe_driver",
        guid=str(uuid.uuid5(LOKI_NAMESPACE, "preserved-guid")),
        name="PRESERVED",
        raw_path=None,
    )

    config = _config(synthetic_rules_dir)
    result = classify_components([inner_component], config)

    assert len(result.records) == 1
    assert result.records[0].source_image_id == inner_source_image_id


def test_inner_and_outer_components_in_same_run_preserve_their_ids(
    synthetic_rules_dir: Path,
    synthetic_components_with_inner: list[ExtractedComponent],
) -> None:
    """When inner and outer components are mixed in the same
    run, each emitted record carries its input component's
    ``source_image_id`` verbatim."""
    config = _config(synthetic_rules_dir)
    result = classify_components(synthetic_components_with_inner, config)

    assert len(result.records) == len(synthetic_components_with_inner)
    for component, record in zip(synthetic_components_with_inner, result.records, strict=True):
        assert record.source_image_id == component.source_image_id


# ---------------------------------------------------------------------------
# No bytes read outside component.raw_path (R7.4)
# ---------------------------------------------------------------------------


def test_pipeline_only_reads_component_raw_paths(
    synthetic_rules_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R7.4: the pipeline does not, for any component, read
    bytes outside the component's own ``raw_path``. We verify
    by capturing every ``builtins.open`` call during a
    classification run and asserting all paths are the
    expected ``raw_path`` values."""

    # Build two components with real raw_path files so signature
    # detection actually opens something. Use distinct file paths
    # so we can verify the pipeline only opens those exact paths.
    raw_files: list[Path] = []
    components: list[ExtractedComponent] = []
    for i in range(2):
        raw_file = tmp_path / f"comp-{i}.bin"
        raw_file.write_bytes(b"\x00" * 64)
        raw_files.append(raw_file)
        components.append(
            ExtractedComponent(
                component_id=uuid.uuid5(LOKI_NAMESPACE, f"audit-test-{i}"),
                source_image_id=uuid.uuid5(LOKI_NAMESPACE, f"audit-image-{i}"),
                offset=f"0x{i * 0x1000:x}",
                size=64,
                raw_hash="0" * 64,
                component_type_hint="dxe_driver",
                guid=str(uuid.uuid5(LOKI_NAMESPACE, f"audit-guid-{i}")),
                name=f"AUDIT_{i}",
                raw_path=str(raw_file),
            )
        )

    # Capture every open() call. Note: rule loading uses Path.open
    # rather than builtins.open, so the rules-dir reads aren't
    # captured here. The signature detector uses Path.open
    # internally (which delegates to io.open / builtins.open),
    # so those reads ARE captured.
    opened_paths: list[str] = []
    real_open = builtins.open

    def tracking_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        opened_paths.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", tracking_open)

    config = _config(synthetic_rules_dir)
    classify_components(components, config)

    # Every captured open call against a real file path is
    # either a rule file (under synthetic_rules_dir) or one of
    # the components' raw_path files. Nothing else should be
    # read.
    expected_raw_paths = {str(rf) for rf in raw_files}
    rules_dir_str = str(synthetic_rules_dir)
    for opened in opened_paths:
        is_rule_file = opened.startswith(rules_dir_str)
        is_component_raw = opened in expected_raw_paths
        assert is_rule_file or is_component_raw, f"Pipeline opened unexpected path: {opened!r}"


# ---------------------------------------------------------------------------
# Inner components don't accept the inner_component matcher key (R7.5)
# ---------------------------------------------------------------------------


def test_pipeline_rejects_inner_component_matcher_key(
    tmp_path: Path,
) -> None:
    """R7.5: v1 SHALL NOT accept an ``inner_component`` key in
    any Matcher mapping. Rule loading rejects it."""

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    bad_rule_yaml = """\
taxonomy_version: "1.0.0"
rules:
  - rule_id: "tries.inner.component"
    axis: type
    matcher:
      inner_component: true
    effect:
      label: UEFI_DRIVER
      confidence: 0.5
      method: RULE
"""
    (rules_dir / "bad.yaml").write_text(bad_rule_yaml)

    from loki.classification.errors import ClassificationRuleError

    with pytest.raises(ClassificationRuleError, match="unknown predicate keys"):
        classify_components([], _config(rules_dir))


# ---------------------------------------------------------------------------
# Sanity: synthetic_components_with_inner has both kinds (fixture invariant)
# ---------------------------------------------------------------------------


def test_synthetic_components_with_inner_has_both_kinds() -> None:
    """Pin the fixture invariant: the
    ``synthetic_components_with_inner`` fixture returns
    components with at least two distinct ``source_image_id``
    values (one outer, one inner)."""
    components = build_components(count=4, include_inner=True)
    distinct_image_ids = {c.source_image_id for c in components}
    assert len(distinct_image_ids) >= 2
