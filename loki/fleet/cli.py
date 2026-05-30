"""CLI surface for the fleet analysis engine."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from loki.fleet.api import analyze_fleet
from loki.fleet.errors import FleetConfigError, FleetInputError
from loki.fleet.membership import load_from_config, load_from_directory

__all__: list[str] = ["register_fleet_subcommand"]


def register_fleet_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register 'fleet' subcommand group on the top-level loki dispatcher."""
    fleet_parser = sub.add_parser(
        "fleet",
        help="Fleet-level firmware analysis.",
        description="Subcommands for fleet-level firmware analysis and aggregation.",
    )
    fleet_sub = fleet_parser.add_subparsers(
        dest="fleet_command",
        required=True,
        metavar="SUBCOMMAND",
    )

    analyze_parser = fleet_sub.add_parser(
        "analyze",
        help="Aggregate per-image reports into a fleet analysis report.",
        description=(
            "Load per-image ImageAnalysisReport files and produce a "
            "FleetAnalysisReport aggregating posture distribution, "
            "common findings, CVE rollup, outlier detection, and "
            "worst-image ranking."
        ),
    )

    group = analyze_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to fleet YAML config defining membership.",
    )
    group.add_argument(
        "--dir",
        type=Path,
        default=None,
        help="Directory to scan for *.json ImageAnalysisReport files.",
    )
    analyze_parser.add_argument(
        "--fleet-id",
        type=str,
        default=None,
        help="Override the fleet ID (default: from config or directory name).",
    )
    analyze_parser.set_defaults(handler=_handle_fleet_analyze)


def _handle_fleet_analyze(args: argparse.Namespace) -> int:
    """Execute fleet analysis from CLI arguments."""
    try:
        if args.config is not None:
            fleet_id, reports = load_from_config(args.config)
        else:
            fleet_id, reports = load_from_directory(args.dir, fleet_id_override=args.fleet_id)

        if args.fleet_id is not None:
            fleet_id = args.fleet_id

        report = analyze_fleet(reports=reports, fleet_id=fleet_id)

        sys.stdout.write(report.model_dump_json(indent=2))
        sys.stdout.write("\n")

        dominant_rating = max(
            report.fleet_posture,
            key=lambda r: report.fleet_posture[r],
        )
        summary = (
            f"fleet: {report.image_count} images, "
            f"posture={dominant_rating.value}, "
            f"{len(report.outlier_images)} outliers, "
            f"{len(report.common_findings)} common findings"
        )
        print(summary, file=sys.stderr)
        return 0

    except (FleetConfigError, FleetInputError) as exc:
        print(f"loki fleet analyze: {exc.message}", file=sys.stderr)
        return 2
