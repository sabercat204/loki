"""Fleet membership loading — config-driven and directory-scan modes."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from loki.fleet.errors import FleetConfigError, FleetInputError
from loki.models.reports import ImageAnalysisReport

__all__: list[str] = ["load_from_config", "load_from_directory"]

_logger = logging.getLogger(__name__)


def load_from_config(config_path: Path) -> tuple[str, list[ImageAnalysisReport]]:
    """Load fleet membership from a YAML config file.

    The config must have structure:
        fleet_id: "some-fleet"
        reports:
          - path: /data/reports/image-a.json
          - path: /data/reports/image-b.json

    Returns (fleet_id, list of validated reports).
    """
    if not config_path.exists():
        raise FleetInputError(f"Config file not found: {config_path}")

    text = config_path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise FleetInputError(f"Invalid YAML in config: {config_path}") from exc

    if not isinstance(data, dict):
        raise FleetConfigError(f"Config must be a YAML mapping: {config_path}")

    fleet_id = data.get("fleet_id")
    if not fleet_id or not isinstance(fleet_id, str):
        raise FleetConfigError(f"Config missing 'fleet_id' string: {config_path}")

    reports_list = data.get("reports")
    if not isinstance(reports_list, list) or len(reports_list) == 0:
        raise FleetConfigError(f"Config has empty or missing 'reports' list: {config_path}")

    reports: list[ImageAnalysisReport] = []
    for entry in reports_list:
        if not isinstance(entry, dict) or "path" not in entry:
            raise FleetConfigError(f"Each report entry must have a 'path' key: {config_path}")
        report_path = Path(entry["path"])
        if not report_path.is_absolute():
            report_path = config_path.parent / report_path

        if not report_path.exists():
            raise FleetInputError(f"Report file not found: {report_path}")

        report_text = report_path.read_text(encoding="utf-8")
        try:
            report = ImageAnalysisReport.model_validate_json(report_text)
        except ValidationError as exc:
            raise FleetInputError(
                f"Invalid report at {report_path}: {exc.error_count()} validation errors"
            ) from exc

        reports.append(report)

    return fleet_id, reports


def load_from_directory(
    dir_path: Path, fleet_id_override: str | None = None
) -> tuple[str, list[ImageAnalysisReport]]:
    """Load fleet membership by scanning a directory for JSON report files.

    Globs *.json at depth 1. Invalid files are logged as WARNING and
    skipped. Empty directory (after filtering) raises FleetConfigError.

    Returns (fleet_id, list of validated reports).
    """
    if not dir_path.is_dir():
        raise FleetInputError(f"Directory not found: {dir_path}")

    fleet_id = fleet_id_override if fleet_id_override else dir_path.name
    json_files = sorted(dir_path.glob("*.json"))

    reports: list[ImageAnalysisReport] = []
    for json_file in json_files:
        report_text = json_file.read_text(encoding="utf-8")
        try:
            report = ImageAnalysisReport.model_validate_json(report_text)
        except (ValidationError, ValueError) as exc:
            _logger.warning("Skipping invalid report %s: %s", json_file, exc)
            continue

        reports.append(report)

    if not reports:
        raise FleetConfigError(f"No valid reports found in directory: {dir_path}")

    return fleet_id, reports
