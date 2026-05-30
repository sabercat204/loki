
# Design Document — Fleet Analysis Engine

## Overview

The Fleet Analysis Engine aggregates pre-produced
`ImageAnalysisReport` instances into a `FleetAnalysisReport`. It is
a batch, synchronous, single-threaded, deterministic engine that
reads already-produced per-image reports (never re-runs analysis)
and produces cross-image rollups: posture distribution, common
findings, CVE rollup, outlier detection, and worst-image ranking.

The engine mirrors the project's subsystem pattern: a small public
surface at `loki.fleet`, a typed exception hierarchy, a free
function entry point, a CLI subcommand, and Hypothesis property
tests.

## Architecture

### Module layout

```
loki/fleet/
    __init__.py          # public re-exports
    api.py               # analyze_fleet free function
    aggregation.py       # core rollup logic (posture, common, CVE, outliers, ranking)
    membership.py        # config-driven + dir-scan fleet loaders
    models.py            # FleetMembership, FleetRiskScore (internal)
    errors.py            # FleetError, FleetConfigError, FleetInputError
    version.py           # FLEET_VERSION = "1.0.0"
    cli.py               # register_fleet_subcommand, run_fleet_analyze
```

### Public API

```python
from loki.fleet import analyze_fleet, FLEET_VERSION

report: FleetAnalysisReport = analyze_fleet(
    reports=per_image_reports,
    fleet_id="corporate-laptops",
    config=fleet_config,
)
```

### Data flow

```
[Operator]
    |
    v
loki fleet analyze --config fleet.yaml
    |   OR
loki fleet analyze --dir /data/reports/
    |
    v
membership.py: load_from_config(path) or load_from_directory(path)
    |
    v (list[ImageAnalysisReport])
    |
    v
analyze_fleet(reports, fleet_id, config)
    |
    |--- aggregation.py:
    |       compute_posture_distribution(reports)
    |       compute_common_findings(reports)
    |       compute_cve_rollup(reports)
    |       detect_outliers(reports, fleet_posture)
    |       compute_risk_ranking(reports)
    |
    v
FleetAnalysisReport (validated Pydantic model)
```

### Membership loading

**Config-driven** (`membership.load_from_config`):
- Reads a YAML file with `fleet_id` and `reports[].path`
- Loads each path as `ImageAnalysisReport.model_validate_json(text)`
- Missing file -> `FleetInputError`
- Invalid JSON / Pydantic failure -> `FleetInputError`

**Directory-scan** (`membership.load_from_directory`):
- Globs `*.json` at depth 1
- Attempts to load each as `ImageAnalysisReport`
- Invalid files -> WARNING logged, skipped
- Empty after filtering -> `FleetConfigError`
- `fleet_id` = directory basename unless caller overrides

### Aggregation logic

**Posture distribution** (R4):
- Count images per PostureRating
- Fill all PostureRating enum values with 0 for missing keys
- Verify sum == image_count

**Common findings** (R5):
- Group findings across all images by `(category, severity, normalized_title)`
- "Normalized title" = title stripped of image-specific identifiers (component_id UUIDs replaced with placeholder)
- Filter to groups with count >= 2
- Sort by descending count, then descending severity
- Attach `fleet_count=N` to `raw_indicators`

**CVE rollup** (R5.4):
- Collect all `evidence.matched_cve` values across all findings
- Group by CVE ID, count distinct images
- Filter to CVEs appearing in 2+ images
- Format as `systemic_risks` entries: `"CVE-XXXX-YYYY affects N images"`
- Sort by descending image count, then lex CVE ID

**Outlier detection** (R6):
- Compute fleet median posture (by ordinal: BASELINE < DEGRADED < AT_RISK < COMPROMISED)
- Flag images whose posture is strictly worse than the median
- Skip if fleet has < 3 images
- Sort outliers by descending posture severity, then lex image_id

**Worst-image ranking** (R7):
- Per image: `risk_score = sum(mismatch composite_scores) + 10 * count(CRITICAL findings)`
- Sort descending by risk_score
- Surface top 3 as `ActionRecord` entries with `action_type="INVESTIGATE"`

### Error handling

```python
class FleetError(Exception):
    message: str

class FleetConfigError(FleetError): ...   # empty fleet, missing config
class FleetInputError(FleetError): ...    # bad report file, validation failure
```

### CLI

Registered on the top-level dispatcher as `loki fleet analyze`:
- `--config PATH` or `--dir PATH` (mutually exclusive, one required)
- `--fleet-id ID` (optional override for dir-scan mode)
- Stdout: `FleetAnalysisReport.model_dump_json(indent=2)`
- Stderr: summary line
- Exit codes: 0 (success), 2 (FleetConfigError or FleetInputError)

## Design decisions

### D1: Free function, not class

Mirrors `analyze_image` and `classify_components`. The fleet engine
has no mutable state across calls.

### D2: Consumes reports, never re-runs analysis

The fleet engine is a pure aggregator. It does not import
`loki.analysis` or `loki.classification` at runtime — only
`loki.models`.

### D3: Normalized title for common-finding grouping

Component UUIDs in finding titles make every title unique per
image. Normalization replaces UUID patterns with `<component>`
placeholder so semantically-identical findings group together.

### D4: Posture ordinal for median calculation

`BASELINE=0, DEGRADED=1, AT_RISK=2, COMPROMISED=3`. The median is
computed on ordinals; ties go to the better (lower) rating.

### D5: Top-3 for recommended_actions

Surfaces the three worst images. The full ranking is implicit in
the per-image reports. Keeps the fleet report concise.

### D6: No network, no feeds import

The fleet engine reads from pre-produced report files only. CVE
data is already embedded in the findings' `evidence.matched_cve`
field.

## Correctness Properties

### Property 72: Determinism

Same input reports + same config produce a bit-equal
`FleetAnalysisReport` modulo `timestamp`.

**Validates: R1.7, R10.1**

### Property 73: Posture distribution totality

`sum(fleet_posture.values()) == image_count` for all valid inputs.

**Validates: R4.3**

### Property 74: Outlier subset

Every UUID in `outlier_images` appears in the input report set.

**Validates: R6.2**

### Property 75: Common finding threshold

Every entry in `common_findings` has a `fleet_count` >= 2.

**Validates: R5.1**

### Property 76: Risk-score ordering stability

`recommended_actions` is sorted by descending risk_score and the
order is stable across runs.

**Validates: R7.2, R10.1**

## Testing Strategy

Tests at `tests/fleet/`:

- `test_api.py` — public surface, empty-fleet error, single-image edge case
- `test_membership.py` — config load, dir scan, error cases
- `test_aggregation.py` — posture, common findings, CVE rollup, outliers, ranking
- `test_cli.py` — both modes, exit codes, stdout/stderr shape
- `test_properties.py` — Hypothesis P72-P76
- `test_performance.py` — slow marker, R10.2 budget
- `test_errors.py` — exception hierarchy
- `test_smoke.py` — end-to-end with synthetic multi-image fleet

## Performance

The fleet engine is CPU-bound (no I/O beyond initial file reads).
For 100 images x 1000 findings each (100k total findings), the
aggregation logic is O(N) in total findings for each rollup pass.
Five passes (posture, common, CVE, outlier, ranking) make the total
O(5N) = O(N). Target: under 10 seconds for 100k findings.
