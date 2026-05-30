
# Implementation Plan — Fleet Analysis Engine

## Overview

Implements the fleet analysis engine per the requirements and
design. 18 tasks across 5 waves. Property numbering: P72-P76.

## Pre-flight checklist

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m ruff check
.venv/bin/python -m ruff format --check
```

Current checkpoint: **1583 passed, 12 deselected**, mypy clean
across **283 source files**.

## Tasks

- [x] 1. Scaffold the `loki/fleet/` package

  - Create `loki/fleet/__init__.py`, `api.py`, `aggregation.py`, `membership.py`, `models.py`, `errors.py`, `version.py`, `cli.py` as empty modules with docstrings + `__all__: list[str] = []`.
  - Create `tests/fleet/__init__.py` and `tests/fleet/conftest.py`.
  - Verify: `.venv/bin/python -c "import loki.fleet"` works.
  - Run verification gates; test count unchanged.
  - _Requirements: none — scaffolding_
  - _Design: Module layout_

- [x] 2. Implement `FLEET_VERSION` and exception hierarchy

  - In `loki/fleet/version.py`: `FLEET_VERSION: str = "1.0.0"`.
  - In `loki/fleet/errors.py`: `FleetError(Exception)` root with `message: str`, `FleetConfigError(FleetError)`, `FleetInputError(FleetError)`.
  - Re-export from `loki/fleet/__init__.py`.
  - Add `tests/fleet/test_errors.py` covering constructibility, inheritance, message attribute.
  - _Requirements: R9.1-R9.2_
  - _Design: Error handling_

- [x] 3. Implement config-driven membership loading

  - In `loki/fleet/membership.py`: `load_from_config(config_path: Path) -> tuple[str, list[ImageAnalysisReport]]`.
  - Parse YAML: `fleet_id` + `reports[].path`.
  - Load each path via `ImageAnalysisReport.model_validate_json(text)`.
  - Missing file -> `FleetInputError`. Invalid JSON -> `FleetInputError`. Empty reports list -> `FleetConfigError`.
  - Add `tests/fleet/test_membership.py` covering: valid config, missing file, invalid JSON, empty list.
  - _Requirements: R2.1-R2.5_
  - _Design: Membership loading — config-driven_

- [x] 4. Implement directory-scan membership loading

  - In `loki/fleet/membership.py`: `load_from_directory(dir_path: Path, fleet_id_override: str | None = None) -> tuple[str, list[ImageAnalysisReport]]`.
  - Glob `*.json` at depth 1. Attempt to load each. Invalid -> WARNING + skip. Empty after filter -> `FleetConfigError`.
  - `fleet_id` = `dir_path.name` unless overridden.
  - Add tests covering: valid dir, invalid files skipped, empty dir, override fleet_id.
  - _Requirements: R3.1-R3.4_
  - _Design: Membership loading — directory-scan_

- [x] 5. Implement posture distribution

  - In `loki/fleet/aggregation.py`: `compute_posture_distribution(reports: Sequence[ImageAnalysisReport]) -> dict[PostureRating, int]`.
  - Fill all PostureRating enum values with 0, then count.
  - Add `tests/fleet/test_aggregation.py` (posture section) covering: all ratings present, sum equals image_count, single-image fleet.
  - _Requirements: R4.1-R4.3_
  - _Design: Posture distribution_

- [x] 6. Implement common findings aggregation

  - In `loki/fleet/aggregation.py`: `compute_common_findings(reports: Sequence[ImageAnalysisReport]) -> list[FindingRecord]`.
  - Normalize titles (replace UUID patterns with `<component>`).
  - Group by `(category, severity, normalized_title)`.
  - Filter count >= 2. Sort descending count, then descending severity.
  - Attach `fleet_count=N` to `raw_indicators`.
  - Add tests covering: no common findings, one common, sorting, normalization.
  - _Requirements: R5.1-R5.3_
  - _Design: Common findings_

- [x] 7. Implement CVE rollup

  - In `loki/fleet/aggregation.py`: `compute_cve_rollup(reports: Sequence[ImageAnalysisReport]) -> list[str]`.
  - Collect `evidence.matched_cve` across all findings. Group by CVE ID, count distinct images.
  - Filter 2+ images. Format as `"CVE-XXXX-YYYY affects N images"`.
  - Sort descending count, then lex CVE ID.
  - Add tests covering: no CVEs, single CVE in multiple images, multiple CVEs.
  - _Requirements: R5.4_
  - _Design: CVE rollup_

- [x] 8. Implement outlier detection

  - In `loki/fleet/aggregation.py`: `detect_outliers(reports: Sequence[ImageAnalysisReport], fleet_posture: dict[PostureRating, int]) -> list[uuid.UUID]`.
  - Compute median posture via ordinal. Flag images worse than median.
  - Skip if < 3 images. Sort by descending severity, then lex image_id.
  - Add tests covering: outlier detected, no outliers (all same), < 3 images skips, sorting.
  - _Requirements: R6.1-R6.4_
  - _Design: Outlier detection; D4_

- [x] 9. Implement worst-image ranking

  - In `loki/fleet/aggregation.py`: `compute_risk_ranking(reports: Sequence[ImageAnalysisReport]) -> list[ActionRecord]`.
  - Per image: `risk_score = sum(mismatch composite_scores) + 10 * count(CRITICAL findings)`.
  - Sort descending. Surface top 3 as ActionRecord.
  - Add tests covering: ranking order, top-3 limit, ties broken deterministically.
  - _Requirements: R7.1-R7.3_
  - _Design: Worst-image ranking; D5_

- [x] 10. Implement `analyze_fleet` entry point

  - In `loki/fleet/api.py`: wire all aggregation functions into `analyze_fleet`.
  - Generate `report_id` via `uuid5(LOKI_NAMESPACE, f"{fleet_id}:{timestamp}")`.
  - Validate: empty reports -> `FleetConfigError`.
  - Construct `FleetAnalysisReport` with all computed fields.
  - Re-export from `loki/fleet/__init__.py`.
  - Add `tests/fleet/test_api.py` covering: success path, empty fleet error, single-image, determinism.
  - _Requirements: R1.1-R1.7_
  - _Design: Public API_

- [x] 11. Implement CLI surface

  - In `loki/fleet/cli.py`: `register_fleet_subcommand` and `run_fleet_analyze`.
  - Register on top-level dispatcher in `loki/cli.py`.
  - Flags: `--config` / `--dir` (mutually exclusive), `--fleet-id`.
  - Stdout JSON, stderr summary, exit codes.
  - Add `tests/fleet/test_cli.py` covering: both modes, help exits 0, missing args exits 2, stdout JSON shape, stderr summary.
  - _Requirements: R8.1-R8.6_
  - _Design: CLI_

- [x] 12. Implement internal FleetRiskScore model

  - In `loki/fleet/models.py`: `FleetRiskScore` frozen dataclass with `image_id`, `risk_score`, `finding_count`.
  - Used internally by `compute_risk_ranking`; not exported publicly.
  - _Requirements: R7.1 (internal)_
  - _Design: Module layout_

- [x] 13. Add Hypothesis property tests (P72-P76)

  - Create `tests/fleet/test_properties.py`:
    - P72: determinism (max_examples=25)
    - P73: posture distribution totality (max_examples=50)
    - P74: outlier subset (max_examples=25)
    - P75: common finding threshold (max_examples=25)
    - P76: risk-score ordering stability (max_examples=25)
  - _Requirements: R11.2_
  - _Design: Properties P72-P76_

- [x] 14. Add performance test

  - Create `tests/fleet/test_performance.py`: slow-marker test.
  - 100 synthetic ImageAnalysisReports x 1000 findings each.
  - Assert completion under 10 seconds.
  - _Requirements: R10.2_
  - _Design: Performance_

- [x] 15. Add end-to-end smoke test

  - Create `tests/fleet/test_smoke.py`:
  - Build 5 synthetic ImageAnalysisReports with varying postures and findings.
  - Run `analyze_fleet`. Assert: posture_distribution correct, common_findings populated, outliers detected, recommended_actions present.
  - _Requirements: R11.4_
  - _Design: Testing Strategy_

- [x] 16. Add determinism and backward-compat tests

  - Create `tests/fleet/test_determinism.py`:
  - Two runs with same inputs produce equal output modulo timestamp.
  - Fleet with all-empty findings produces valid report with zeroed fields.
  - _Requirements: R10.1, R1.7_
  - _Design: D1_

- [x] 17. Update README, STATE, loom-loki

  - Add `## Fleet analysis` section to README.
  - Update STATE.md next-steps.
  - Bump loom-loki to v1.0.0 with fleet-analysis entry.
  - _Requirements: none — documentation_

- [x] 18. Final verification gate

  - Run all four gates. Confirm test count increase.
  - Confirm: `from loki.fleet import analyze_fleet, FLEET_VERSION` works.
  - Confirm: `loki fleet analyze --help` works.
  - Record final counts.
  - _Requirements: all_

## Wave plan

- **Wave 1 (tasks 1-2).** Scaffold + exceptions. Pure structure.
- **Wave 2 (tasks 3-4).** Membership loading (both modes). File I/O only.
- **Wave 3 (tasks 5-9, 12).** All five aggregation functions + internal model. Core logic.
- **Wave 4 (tasks 10-11).** Public API + CLI. Subsystem becomes callable end-to-end.
- **Wave 5 (tasks 13-18).** Properties, performance, smoke, docs, final gate.

## Notes

- **No `loki.feeds` or `loki.analysis` import at runtime.** The fleet engine reads model types only.
- **The `FleetAnalysisReport` model already exists.** No model-layer changes needed — just produce valid instances.
- **Property numbering: P72-P76.** Next subsystem picks up at P77.
- **Threat context: STANDARD.** No network egress, no credential handling. File reads only.
