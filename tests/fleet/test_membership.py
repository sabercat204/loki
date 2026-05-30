"""Tests for fleet membership loading — config-driven and directory-scan modes."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.fleet.errors import FleetConfigError, FleetInputError
from loki.fleet.membership import load_from_config, load_from_directory
from loki.models.enums import PostureRating
from loki.models.firmware import FirmwareImage
from loki.models.reports import ImageAnalysisReport


def _make_report(*, posture: PostureRating = PostureRating.BASELINE) -> ImageAnalysisReport:
    """Create a minimal valid ImageAnalysisReport for testing."""
    image = FirmwareImage(
        file_path="/firmware/test.bin",
        file_hash="a" * 64,
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
    """Serialize a report to a JSON file."""
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _write_config(path: Path, fleet_id: str, report_paths: list[Path]) -> None:
    """Write a fleet YAML config file."""
    import yaml

    data = {
        "fleet_id": fleet_id,
        "reports": [{"path": str(p)} for p in report_paths],
    }
    path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")


# --------------------------------------------------------------------------
# Config-driven mode (load_from_config)
# --------------------------------------------------------------------------


class TestLoadFromConfig:
    """Tests for config-driven fleet membership loading."""

    def test_valid_config_loads_reports(self, tmp_path: Path) -> None:
        report_a = _make_report()
        report_b = _make_report(posture=PostureRating.DEGRADED)

        path_a = tmp_path / "a.json"
        path_b = tmp_path / "b.json"
        _write_report(path_a, report_a)
        _write_report(path_b, report_b)

        config_path = tmp_path / "fleet.yaml"
        _write_config(config_path, "test-fleet", [path_a, path_b])

        fleet_id, reports = load_from_config(config_path)
        assert fleet_id == "test-fleet"
        assert len(reports) == 2
        assert reports[0].report_id == report_a.report_id
        assert reports[1].report_id == report_b.report_id

    def test_relative_paths_resolved_from_config_dir(self, tmp_path: Path) -> None:
        report = _make_report()
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        _write_report(reports_dir / "img.json", report)

        config_path = tmp_path / "fleet.yaml"
        import yaml

        data = {
            "fleet_id": "relative-fleet",
            "reports": [{"path": "reports/img.json"}],
        }
        config_path.write_text(yaml.dump(data), encoding="utf-8")

        fleet_id, reports = load_from_config(config_path)
        assert fleet_id == "relative-fleet"
        assert len(reports) == 1

    def test_missing_config_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FleetInputError, match="Config file not found"):
            load_from_config(tmp_path / "nonexistent.yaml")

    def test_missing_report_file_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "fleet.yaml"
        _write_config(config_path, "bad-fleet", [tmp_path / "missing.json"])

        with pytest.raises(FleetInputError, match="Report file not found"):
            load_from_config(config_path)

    def test_invalid_report_json_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{not valid json", encoding="utf-8")

        config_path = tmp_path / "fleet.yaml"
        _write_config(config_path, "bad-fleet", [bad_file])

        with pytest.raises(FleetInputError, match="Invalid report"):
            load_from_config(config_path)

    def test_empty_reports_list_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "fleet.yaml"
        import yaml

        data = {"fleet_id": "empty-fleet", "reports": []}
        config_path.write_text(yaml.dump(data), encoding="utf-8")

        with pytest.raises(FleetConfigError, match="empty or missing"):
            load_from_config(config_path)

    def test_missing_fleet_id_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "fleet.yaml"
        import yaml

        data = {"reports": [{"path": "/foo.json"}]}
        config_path.write_text(yaml.dump(data), encoding="utf-8")

        with pytest.raises(FleetConfigError, match="fleet_id"):
            load_from_config(config_path)

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "fleet.yaml"
        config_path.write_text(":\n  :\n  - [invalid", encoding="utf-8")

        with pytest.raises(FleetInputError, match="Invalid YAML"):
            load_from_config(config_path)


# --------------------------------------------------------------------------
# Directory-scan mode (load_from_directory)
# --------------------------------------------------------------------------


class TestLoadFromDirectory:
    """Tests for directory-scan fleet membership loading."""

    def test_valid_directory_loads_reports(self, tmp_path: Path) -> None:
        report_a = _make_report()
        report_b = _make_report(posture=PostureRating.AT_RISK)
        _write_report(tmp_path / "alpha.json", report_a)
        _write_report(tmp_path / "beta.json", report_b)

        fleet_id, reports = load_from_directory(tmp_path)
        assert fleet_id == tmp_path.name
        assert len(reports) == 2

    def test_invalid_files_skipped_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        report = _make_report()
        _write_report(tmp_path / "good.json", report)
        (tmp_path / "bad.json").write_text("not json at all", encoding="utf-8")
        (tmp_path / "incomplete.json").write_text(
            json.dumps({"report_id": str(uuid.uuid4())}), encoding="utf-8"
        )

        with caplog.at_level(logging.WARNING, logger="loki.fleet.membership"):
            _fleet_id, reports = load_from_directory(tmp_path)

        assert len(reports) == 1
        assert reports[0].report_id == report.report_id
        assert len(caplog.records) == 2

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FleetConfigError, match="No valid reports"):
            load_from_directory(tmp_path)

    def test_all_invalid_files_raises(self, tmp_path: Path) -> None:
        (tmp_path / "bad1.json").write_text("{}", encoding="utf-8")
        (tmp_path / "bad2.json").write_text("[]", encoding="utf-8")

        with pytest.raises(FleetConfigError, match="No valid reports"):
            load_from_directory(tmp_path)

    def test_fleet_id_override(self, tmp_path: Path) -> None:
        report = _make_report()
        _write_report(tmp_path / "img.json", report)

        fleet_id, reports = load_from_directory(tmp_path, fleet_id_override="custom-id")
        assert fleet_id == "custom-id"
        assert len(reports) == 1

    def test_nonexistent_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FleetInputError, match="Directory not found"):
            load_from_directory(tmp_path / "no-such-dir")

    def test_non_json_files_ignored(self, tmp_path: Path) -> None:
        report = _make_report()
        _write_report(tmp_path / "valid.json", report)
        (tmp_path / "readme.txt").write_text("hello", encoding="utf-8")
        (tmp_path / "data.yaml").write_text("key: value", encoding="utf-8")

        _fleet_id, reports = load_from_directory(tmp_path)
        assert len(reports) == 1

    def test_fleet_id_defaults_to_dir_name(self, tmp_path: Path) -> None:
        subdir = tmp_path / "my-fleet-name"
        subdir.mkdir()
        report = _make_report()
        _write_report(subdir / "r.json", report)

        fleet_id, _reports = load_from_directory(subdir)
        assert fleet_id == "my-fleet-name"
