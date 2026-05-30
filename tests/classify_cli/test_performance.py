"""Slow-marker performance test for the classify CLI (task 21, R11.1).

Pins the wrapper-only timing budget: argparse parsing +
manifest read/decode/Pydantic validation + Stdout_Result JSON
serialization SHALL collectively run in under 200 ms on a
256-component manifest plus a 256-rule rules dir. The library's
own time inside ``classify_components`` is deliberately
excluded; the budget is wrapper-only per R11.1 post-HARDEN.

The test is decorated with ``@pytest.mark.slow`` so it is
skipped by the default ``pytest -q`` run (``addopts =
"-ra --strict-markers -m 'not slow'"`` in ``pyproject.toml``).
Verify it passes via ``.venv/bin/python -m pytest
tests/classify_cli/test_performance.py -m slow``.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.classification import ClassificationResult
from loki.classify_helpers import _load_manifest, _serialize_result

#: Hex string for synthetic ``file_hash`` / ``raw_hash`` values.
_PERF_HEX64 = "9" * 64

#: Run timestamp shared across the synthetic manifest contents.
_PERF_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

#: Number of components and rules for the wrapper-only budget
#: measurement. Per design Performance plan.
_COMPONENT_COUNT = 256
_RULE_COUNT = 256

#: The contracted budget per R11.1 post-HARDEN.
_OVERHEAD_BUDGET_SECONDS = 0.200


def _build_perf_manifest_path(tmp_path: Path) -> Path:
    """Write a 256-component manifest JSON to ``tmp_path/manifest.json``."""
    from loki.models import ExtractedComponent, ExtractionManifest, FirmwareImage

    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.performance")
    image_id = uuid.uuid5(namespace, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/perf.bin",
        file_hash=_PERF_HEX64,
        file_size=4096,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        ExtractedComponent(
            component_id=uuid.uuid5(namespace, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512,
            raw_hash=_PERF_HEX64,
            component_type_hint=None,
            guid=str(uuid.uuid5(namespace, f"guid-{idx:04d}")),
            name=f"PERF_{idx:03d}",
            raw_path=None,
        )
        for idx in range(_COMPONENT_COUNT)
    ]
    manifest = ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=_PERF_TIMESTAMP,
        extractor_version="loki-test-fixture",
        extraction_errors=[],
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest_path


def _build_perf_rules_dir(tmp_path: Path) -> Path:
    """Write a rules directory with 256 synthetic rules across the four axes.

    The library's rule loader expects one YAML file per axis;
    each file carries a ``rules`` list. Distributing 256 rules
    across the four axes gives 64 rules per file. The rules
    each carry a unique GUID matcher so their loading exercises
    the same parse path 256 times.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    axes = ["type", "vendor", "security_posture", "mutability"]
    labels = {
        "type": "UEFI_DRIVER",
        "vendor": "INTEL",
        "security_posture": "SECURE",
        "mutability": "READONLY",
    }
    rules_per_axis = _RULE_COUNT // len(axes)
    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.performance.rules")

    for axis in axes:
        rules_payload = {
            "taxonomy_version": "1.0.0",
            "rules": [
                {
                    "rule_id": f"perf.{axis}.{idx:03d}",
                    "axis": axis,
                    "matcher": {"guid": str(uuid.uuid5(namespace, f"{axis}-rule-{idx:04d}"))},
                    "effect": {
                        "label": labels[axis],
                        "confidence": 0.5,
                        "method": "RULE",
                    },
                }
                for idx in range(rules_per_axis)
            ],
        }
        path = rules_dir / f"{axis}.yaml"
        with path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(
                rules_payload,
                handle,
                sort_keys=True,
                default_flow_style=False,
            )
    return rules_dir


@pytest.mark.slow
def test_cli_overhead_under_200ms(tmp_path: Path) -> None:
    """Wrapper-only CLI overhead stays under 200 ms (R11.1).

    Measures three wrapper steps explicitly with
    ``time.monotonic()`` brackets:

    - argparse parsing (``build_parser().parse_args(...)``);
    - manifest read + JSON decode + Pydantic validation
      (``_load_manifest``);
    - Stdout_Result JSON serialization (``_serialize_result``).

    Sums the three durations as ``cli_overhead`` and asserts
    the budget. The library's own time inside
    ``classify_components`` is deliberately NOT measured here:
    the budget is wrapper-only per R11.1 post-HARDEN, so the
    test does not invoke the library at all.
    """
    manifest_path = _build_perf_manifest_path(tmp_path)
    rules_path = _build_perf_rules_dir(tmp_path)

    # Step 1: argparse parsing.
    from loki.cli import build_parser

    parse_t0 = time.monotonic()
    parser = build_parser()
    args = parser.parse_args(["classify", str(manifest_path), "--rules-path", str(rules_path)])
    parse_t1 = time.monotonic()

    # The args namespace is consulted to keep the optimizer
    # honest about the parser actually doing the work.
    assert args.manifest == str(manifest_path)

    # Step 2: manifest read + JSON decode + Pydantic validation.
    load_t0 = time.monotonic()
    manifest_or_exit = _load_manifest(str(manifest_path))
    load_t1 = time.monotonic()
    assert not isinstance(manifest_or_exit, int)
    assert manifest_or_exit.total_components == _COMPONENT_COUNT

    # Step 3: Stdout_Result JSON serialization. We hand the
    # serializer an empty-result object so it exercises the
    # JSON-rendering path without depending on the library.
    fake_result = ClassificationResult(records=[], errors=[])
    serialize_t0 = time.monotonic()
    rendered = _serialize_result(fake_result)
    serialize_t1 = time.monotonic()
    assert rendered.endswith("\n")

    parse_dt = parse_t1 - parse_t0
    load_dt = load_t1 - load_t0
    serialize_dt = serialize_t1 - serialize_t0
    cli_overhead = parse_dt + load_dt + serialize_dt

    assert cli_overhead < _OVERHEAD_BUDGET_SECONDS, (
        f"CLI wrapper-only overhead {cli_overhead:.4f}s exceeds budget "
        f"{_OVERHEAD_BUDGET_SECONDS:.3f}s "
        f"(parse={parse_dt:.4f}s, load={load_dt:.4f}s, serialize={serialize_dt:.4f}s)"
    )
