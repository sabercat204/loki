
# Requirements — Fleet Analysis Engine

## Introduction

The Fleet Analysis Engine aggregates per-image
`ImageAnalysisReport` instances across an operator-defined fleet
of firmware images, producing a `FleetAnalysisReport` that
surfaces cross-image patterns, outliers, systemic risks, and
fleet-wide posture distribution.

The existing `FleetAnalysisReport` model (in
`loki/models/reports.py`) defines the output contract: `report_id`,
`timestamp`, `fleet_id`, `image_count`, `fleet_posture` (posture
distribution), `common_findings`, `outlier_images`,
`systemic_risks`, and `recommended_actions`. This spec defines the
engine that produces instances of that model.

### Scope

- Library API: `from loki.fleet import analyze_fleet`
- Two fleet membership modes: config-driven (named YAML) and
  directory-scan (all `*.json` ImageAnalysisReport files in a dir)
- Full rollup outputs: CVE rollup, posture distribution,
  per-category finding counts, outlier detection, worst-image
  ranking
- CLI surface: `loki fleet analyze [--config | --dir]`

### Non-goals (explicit)

- Re-running per-image analysis. The fleet engine consumes
  already-produced `ImageAnalysisReport` instances; it does NOT
  invoke `analyze_image`.
- Real-time fleet monitoring. v1 is a batch operation.
- Fleet membership persistence. The membership is defined at
  invocation time via config or directory scan.
- GUI integration. A future spec.
- Cross-fleet comparison. v1 analyzes one fleet at a time.
- Implant-rule fleet rollup. Deferred until the implant-lookup
  consumer wiring lands.

## Requirements

### Requirement 1: Library API surface

**User Story:** As a developer integrating fleet analysis into
workflows, I want a single entry point that accepts a collection
of per-image reports and returns a validated fleet report.

#### Acceptance Criteria

1. THE fleet engine SHALL expose a public free function
   `analyze_fleet` importable as
   `from loki.fleet import analyze_fleet`.
2. THE function SHALL accept:
   - `reports: Sequence[ImageAnalysisReport]` — the per-image
     reports to aggregate.
   - `fleet_id: str` — operator-supplied fleet identifier.
   - `config: FleetConfig` — fleet analysis configuration.
3. THE function SHALL return a validated `FleetAnalysisReport`
   instance.
4. THE function SHALL raise `FleetConfigError` when `reports`
   is empty (no images to analyze).
5. THE function SHALL raise `FleetInputError` when any report
   in the sequence fails Pydantic validation.
6. THE function SHALL be synchronous and single-threaded.
7. THE function SHALL be deterministic: same input reports +
   same config produce a bit-equal report modulo the
   `timestamp` field.

### Requirement 2: Fleet membership — config-driven mode

**User Story:** As an operator managing named fleets, I want to
define fleet membership in a YAML config file listing the image
reports by path.

#### Acceptance Criteria

1. THE fleet engine SHALL accept a YAML config with structure:
   ```yaml
   fleet_id: "corporate-laptops"
   reports:
     - path: /data/reports/laptop-a.json
     - path: /data/reports/laptop-b.json
   ```
2. EACH entry SHALL reference a JSON file containing a
   serialized `ImageAnalysisReport`.
3. THE engine SHALL validate each loaded report against the
   Pydantic model; invalid files SHALL raise `FleetInputError`
   with the offending path.
4. THE fleet_id from the config SHALL be passed through to the
   output report.
5. Missing files SHALL raise `FleetInputError` (not silently
   skip).

### Requirement 3: Fleet membership — directory-scan mode

**User Story:** As an operator who stores all reports in one
directory, I want to point the fleet engine at that directory
and have it aggregate everything inside.

#### Acceptance Criteria

1. THE fleet engine SHALL accept a directory path and load
   every `*.json` file at depth 1 as an `ImageAnalysisReport`.
2. Non-JSON files and files that fail Pydantic validation
   SHALL be logged as WARNING and skipped (not abort).
3. THE fleet_id SHALL be derived from the directory name
   unless overridden by the caller.
4. AN empty directory (after filtering) SHALL raise
   `FleetConfigError`.

### Requirement 4: Posture distribution

**User Story:** As a security manager reviewing fleet health, I
want to see how many images are at each posture rating.

#### Acceptance Criteria

1. THE `fleet_posture` field SHALL be a dict mapping each
   `PostureRating` to the count of images at that rating.
2. ALL `PostureRating` values SHALL be present as keys (with
   count 0 for ratings that have no images).
3. THE sum of all values SHALL equal `image_count`.

### Requirement 5: Common findings and CVE rollup

**User Story:** As a firmware analyst, I want to see which
findings appear across multiple images so I can prioritize
fleet-wide issues.

#### Acceptance Criteria

1. THE `common_findings` list SHALL contain findings that
   appear in at least 2 images (matched by `category` +
   severity + normalized title).
2. EACH common finding SHALL carry a `raw_indicators` entry
   noting the count of images it appears in (e.g.
   `"fleet_count=5"`).
3. THE list SHALL be sorted by descending fleet count, then
   descending severity.
4. CVE rollup: WHEN findings carry `evidence.matched_cve`,
   THE engine SHALL aggregate CVE IDs across the fleet.
   `systemic_risks` SHALL contain one entry per CVE that
   appears in 2+ images, formatted as
   `"CVE-XXXX-YYYY affects N images"`.

### Requirement 6: Outlier detection

**User Story:** As an operator, I want to know which images
deviate significantly from the fleet norm so I can
investigate.

#### Acceptance Criteria

1. AN image SHALL be flagged as an outlier WHEN its
   `posture_rating` is strictly worse than the fleet median.
2. THE `outlier_images` list SHALL contain the `image_id`
   UUIDs of outlier images.
3. THE list SHALL be sorted by descending severity (worst
   first), then lexicographic `image_id`.
4. WHEN the fleet has fewer than 3 images, outlier detection
   SHALL be skipped (all images could be outliers; not useful).

### Requirement 7: Worst-image ranking

**User Story:** As a triage analyst, I want images ranked by
risk so I can focus remediation on the worst first.

#### Acceptance Criteria

1. THE engine SHALL compute a fleet-risk-score per image
   as: `sum(finding.evidence.deviation_score.composite_score
   for each classification_mismatch finding)` + `10 * count
   of CRITICAL findings`.
2. THE `recommended_actions` list SHALL contain one
   `ActionRecord` per image, ordered by descending
   fleet-risk-score, with `action_type="INVESTIGATE"` and
   `description="Image {image_id}: risk_score={score}"`.
3. TOP-3 images by risk_score SHALL be surfaced; the
   remainder are available on the full per-image reports.

### Requirement 8: CLI surface

**User Story:** As an operator, I want to run fleet analysis
from the terminal.

#### Acceptance Criteria

1. THE CLI SHALL register `loki fleet analyze` as a subcommand.
2. FLAGS: `--config PATH` (config-driven mode) OR
   `--dir PATH` (directory-scan mode). Exactly one required.
3. STDOUT: the `FleetAnalysisReport` as indented JSON.
4. STDERR: a one-line summary
   `"fleet: {image_count} images, posture={dominant_rating},
   {outlier_count} outliers, {common_count} common findings"`.
5. EXIT CODES: 0 (success), 2 (config/input error).
6. `--help` SHALL work without config.

### Requirement 9: Error handling

**User Story:** As an operator, I want clear error messages
when fleet analysis fails.

#### Acceptance Criteria

1. THE engine SHALL define a typed exception hierarchy:
   `FleetError(Exception)` root, `FleetConfigError(FleetError)`,
   `FleetInputError(FleetError)`.
2. EACH exception SHALL carry a `message: str` attribute.
3. THE CLI SHALL map exceptions to exit codes:
   `FleetConfigError` -> 2, `FleetInputError` -> 2.

### Requirement 10: Determinism and performance

**User Story:** As a developer, I want fleet analysis to be
reproducible and complete in reasonable time.

#### Acceptance Criteria

1. THE engine SHALL be deterministic: same input reports +
   same config produce the same output modulo `timestamp`.
2. THE engine SHALL process 100 images x 1000 findings each
   in under 10 seconds on a 2024-class developer laptop.
3. THE engine SHALL NOT access the network.
4. Property numbering picks up at **P72** per the platform
   convention (consumer-wiring ended at P71).

### Requirement 11: Testing

**User Story:** As a developer, I want comprehensive test
coverage for fleet analysis.

#### Acceptance Criteria

1. AT LEAST one test per requirement.
2. Hypothesis property tests P72-P76:
   - P72: determinism (same inputs = same output modulo timestamp)
   - P73: posture distribution sums to image_count
   - P74: outlier images are a subset of input image IDs
   - P75: common findings appear in 2+ images
   - P76: fleet-risk-score ordering is stable
3. One slow-marker performance test (R10.2 budget).
4. One end-to-end smoke test.
