"""Tests for the loki analyze CLI subcommand."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.cli import build_parser
from loki.models.firmware import FirmwareImage


def _make_manifest_json(tmp_path: Path) -> Path:
    """Create a minimal ExtractionManifest JSON file."""
    from loki.models.firmware import ExtractedComponent, ExtractionManifest

    image = FirmwareImage(
        file_path="/firmware/test.bin",
        file_hash="a" * 64,
        file_size=1024,
    )
    assert image.image_id is not None
    component = ExtractedComponent(
        component_id=uuid.uuid4(),
        source_image_id=image.image_id,
        offset="0x1000",
        size=512,
        raw_hash="b" * 64,
    )
    manifest = ExtractionManifest(
        source_image=image,
        components=[component],
        extraction_timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        extractor_version="1.0.0",
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return path


def _make_rules_dir(tmp_path: Path) -> Path:
    """Create a minimal rules directory with one catch-all rule."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "default.yaml"
    rule_data = {
        "taxonomy_version": "1.0.0",
        "rules": [
            {
                "rule_id": "type.unknown.fallback",
                "axis": "type",
                "matcher": {"size": {"min": 0}},
                "effect": {
                    "label": "UNKNOWN",
                    "confidence": 0.1,
                    "method": "HEURISTIC",
                    "evidence": "fallback rule",
                },
            },
        ],
    }
    rule_file.write_text(yaml.dump(rule_data), encoding="utf-8")
    return rules_dir


def _make_baseline_dir(tmp_path: Path) -> Path:
    """Create an empty baseline directory."""
    baseline_dir = tmp_path / "baselines"
    baseline_dir.mkdir()
    return baseline_dir


class TestAnalyzeCli:
    def test_help_exits_zero(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["analyze", "--help"])
        assert exc_info.value.code == 0

    def test_missing_manifest_exits_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rules_dir = _make_rules_dir(tmp_path)
        baseline_dir = _make_baseline_dir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(
            [
                "analyze",
                str(tmp_path / "no-such-manifest.json"),
                "--baseline-path",
                str(baseline_dir),
                "--rules-path",
                str(rules_dir),
            ]
        )
        exit_code = args.handler(args)
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "manifest not found" in captured.err

    def test_missing_baseline_dir_exits_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest_path = _make_manifest_json(tmp_path)
        rules_dir = _make_rules_dir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(
            [
                "analyze",
                str(manifest_path),
                "--baseline-path",
                str(tmp_path / "no-such-dir"),
                "--rules-path",
                str(rules_dir),
            ]
        )
        exit_code = args.handler(args)
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "baseline directory not found" in captured.err

    def test_analysis_runs_with_empty_baseline(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """With no matching baseline, analysis raises BaselineNotFoundError -> exit 5."""
        manifest_path = _make_manifest_json(tmp_path)
        rules_dir = _make_rules_dir(tmp_path)
        baseline_dir = _make_baseline_dir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(
            [
                "analyze",
                str(manifest_path),
                "--baseline-path",
                str(baseline_dir),
                "--rules-path",
                str(rules_dir),
            ]
        )
        exit_code = args.handler(args)
        assert exit_code == 5
        captured = capsys.readouterr()
        assert "analysis error" in captured.err

    def test_summary_only_suppresses_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--summary-only should suppress stdout even on error paths."""
        manifest_path = _make_manifest_json(tmp_path)
        rules_dir = _make_rules_dir(tmp_path)
        baseline_dir = _make_baseline_dir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(
            [
                "analyze",
                str(manifest_path),
                "--baseline-path",
                str(baseline_dir),
                "--rules-path",
                str(rules_dir),
                "--summary-only",
            ]
        )
        args.handler(args)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_invalid_manifest_json_exits_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad_manifest = tmp_path / "bad.json"
        bad_manifest.write_text("{}", encoding="utf-8")
        rules_dir = _make_rules_dir(tmp_path)
        baseline_dir = _make_baseline_dir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(
            [
                "analyze",
                str(bad_manifest),
                "--baseline-path",
                str(baseline_dir),
                "--rules-path",
                str(rules_dir),
            ]
        )
        exit_code = args.handler(args)
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "invalid manifest" in captured.err

    def test_success_path_with_matching_baseline(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Full pipeline: manifest -> classify -> analyze -> report JSON."""
        from loki.baseline import BaselineStore
        from loki.models import BaselineConfig
        from loki.models.baseline import BaselineRecord
        from loki.models.classification import (
            AxisClassification,
            ClassificationRecord,
        )
        from loki.models.enums import ClassificationMethod
        from loki.models.firmware import ExtractedComponent, ExtractionManifest

        image = FirmwareImage(
            file_path="/firmware/test.bin",
            file_hash="a" * 64,
            file_size=1024,
            vendor="TESTVENDOR",
            model="MODEL-X",
            firmware_version="1.0.0",
        )
        assert image.image_id is not None
        comp = ExtractedComponent(
            component_id=uuid.uuid4(),
            source_image_id=image.image_id,
            offset="0x1000",
            size=512,
            raw_hash="b" * 64,
        )
        manifest = ExtractionManifest(
            source_image=image,
            components=[comp],
            extraction_timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            extractor_version="1.0.0",
        )
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

        axis = AxisClassification(
            label="UNKNOWN",
            confidence=0.5,
            method=ClassificationMethod.HEURISTIC,
        )
        baseline_record = BaselineRecord(
            baseline_id=uuid.uuid4(),
            name="test-baseline",
            vendor="TESTVENDOR",
            model="MODEL-X",
            firmware_version="1.0.0",
            created_timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            component_manifest=[
                ClassificationRecord(
                    component_id=comp.component_id,
                    source_image_id=image.image_id,
                    extraction_offset="0x1000",
                    timestamp=datetime(2025, 1, 1, tzinfo=UTC),
                    type_axis=axis,
                    vendor_axis=axis,
                    security_axis=axis,
                    mutability_axis=axis,
                    classification_version="1.0.0",
                )
            ],
            source_image_hash="a" * 64,
            baseline_version="1.0.0",
        )

        baseline_dir = tmp_path / "baselines"
        baseline_dir.mkdir()
        store = BaselineStore(BaselineConfig(storage_path=str(baseline_dir), auto_match=True))
        store.save(baseline_record)

        rules_dir = _make_rules_dir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(
            [
                "analyze",
                str(manifest_path),
                "--baseline-path",
                str(baseline_dir),
                "--rules-path",
                str(rules_dir),
            ]
        )
        exit_code = args.handler(args)

        assert exit_code == 0
        captured = capsys.readouterr()
        report_data = json.loads(captured.out)
        assert "posture_rating" in report_data
        assert "findings" in report_data
        assert "analyze:" in captured.err
        assert "posture=" in captured.err
