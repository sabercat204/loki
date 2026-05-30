"""Tests for the fleet CLI subcommand."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.cli import build_parser
from loki.models.enums import PostureRating
from loki.models.firmware import FirmwareImage
from loki.models.reports import ImageAnalysisReport


def _make_report(*, posture: PostureRating = PostureRating.BASELINE) -> ImageAnalysisReport:
    file_hash = uuid.uuid4().hex + uuid.uuid4().hex[:32]
    image = FirmwareImage(
        file_path="/firmware/test.bin",
        file_hash=file_hash,
        file_size=1024,
    )
    assert image.image_id is not None
    return ImageAnalysisReport(
        report_id=uuid.uuid4(),
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        analysis_version="1.0.0",
        image_id=image.image_id,
        image_metadata=image,
        posture_rating=posture,
        findings=[],
    )


def _write_report(path: Path, report: ImageAnalysisReport) -> None:
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _setup_config(tmp_path: Path) -> Path:
    """Create a valid fleet config with two reports."""
    r1 = _make_report()
    r2 = _make_report(posture=PostureRating.DEGRADED)
    _write_report(tmp_path / "a.json", r1)
    _write_report(tmp_path / "b.json", r2)

    config_path = tmp_path / "fleet.yaml"
    data = {
        "fleet_id": "cli-test-fleet",
        "reports": [
            {"path": str(tmp_path / "a.json")},
            {"path": str(tmp_path / "b.json")},
        ],
    }
    config_path.write_text(yaml.dump(data), encoding="utf-8")
    return config_path


class TestFleetCli:
    def test_help_exits_zero(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["fleet", "analyze", "--help"])
        assert exc_info.value.code == 0

    def test_missing_args_exits_two(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["fleet", "analyze"])
        assert exc_info.value.code == 2

    def test_config_mode_stdout_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_path = _setup_config(tmp_path)
        parser = build_parser()
        args = parser.parse_args(["fleet", "analyze", "--config", str(config_path)])
        exit_code = args.handler(args)

        assert exit_code == 0
        captured = capsys.readouterr()
        report_data = json.loads(captured.out)
        assert report_data["fleet_id"] == "cli-test-fleet"
        assert report_data["image_count"] == 2
        assert "fleet:" in captured.err

    def test_dir_mode_stdout_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        r1 = _make_report()
        r2 = _make_report()
        _write_report(tmp_path / "img1.json", r1)
        _write_report(tmp_path / "img2.json", r2)

        parser = build_parser()
        args = parser.parse_args(["fleet", "analyze", "--dir", str(tmp_path)])
        exit_code = args.handler(args)

        assert exit_code == 0
        captured = capsys.readouterr()
        report_data = json.loads(captured.out)
        assert report_data["image_count"] == 2
        assert report_data["fleet_id"] == tmp_path.name

    def test_fleet_id_override(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        r1 = _make_report()
        _write_report(tmp_path / "img.json", r1)

        parser = build_parser()
        args = parser.parse_args(
            ["fleet", "analyze", "--dir", str(tmp_path), "--fleet-id", "custom"]
        )
        exit_code = args.handler(args)

        assert exit_code == 0
        captured = capsys.readouterr()
        report_data = json.loads(captured.out)
        assert report_data["fleet_id"] == "custom"

    def test_missing_config_exits_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        parser = build_parser()
        args = parser.parse_args(["fleet", "analyze", "--config", str(tmp_path / "nope.yaml")])
        exit_code = args.handler(args)
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "loki fleet analyze:" in captured.err

    def test_stderr_summary_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_path = _setup_config(tmp_path)
        parser = build_parser()
        args = parser.parse_args(["fleet", "analyze", "--config", str(config_path)])
        args.handler(args)

        captured = capsys.readouterr()
        assert "images" in captured.err
        assert "posture=" in captured.err
        assert "outliers" in captured.err
        assert "common findings" in captured.err
