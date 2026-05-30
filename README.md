# Loki

**Firmware analysis platform.** Extracts firmware images, classifies components along four taxonomic axes, compares against named baselines, scores deviations, detects and verifies code signatures, queries CVE feeds, and aggregates results across device fleets.

## At a Glance

| Metric | Value |
|--------|-------|
| Language | Python 3.12 |
| Source files | 116 modules (~17.8k lines) |
| Test files | 197 modules (~39k lines) |
| Test count | 1678 passing |
| Type safety | `mypy --strict` clean (314 files) |
| Lint | `ruff check` + `ruff format` clean |
| Packaging | macOS `.app` + DMG, Windows, Linux AppImage |

## Subsystems

| Subsystem | Description | CLI |
|-----------|-------------|-----|
| **Models** | Pydantic v2 data layer (14 enums, 20+ models) | - |
| **Extraction** | Firmware binary -> component manifest (UEFI PI, IFD, capsule, option ROM, microcode) | `loki extract` |
| **Baseline** | YAML-on-disk persistence for named firmware baselines | `loki baseline` |
| **Classification** | Four-axis classifier (type, vendor, security, mutability) with YAML rules | `loki classify` |
| **Analysis** | Deviation scoring, seven finding categories, posture rating | `loki analyze` |
| **Feeds** | NVD CVE cache + implant-rule signatures | `loki feeds` |
| **Fleet** | Cross-image aggregation: posture distribution, outliers, CVE rollup | `loki fleet` |
| **Verification** | Authenticode + UEFI signature chain verification against trust stores | via `--trust-store` |
| **GUI** | PyQt6 desktop app with extraction, analysis, and fleet views | `loki gui` |

## Quick Start

```bash
# Clone and set up
git clone <your-repo-url> loki
cd loki
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Verify installation
.venv/bin/python -c "from loki.models import FirmwareImage; print('ok')"

# Run the test suite
.venv/bin/python -m pytest -q

# Launch the GUI
.venv/bin/python -m loki gui
```

## CLI Reference

### Extract firmware components

```bash
loki extract /path/to/firmware.bin \
  --output-dir /tmp/components \
  --max-component-size 50000000 \
  --progress
```

### Classify components

```bash
loki classify manifest.json \
  --rules-path /path/to/rules/ \
  --trust-store /path/to/trusted-cas/ \
  --progress
```

### Run analysis

```bash
loki analyze manifest.json \
  --baseline-path /path/to/baselines/ \
  --rules-path /path/to/rules/ \
  --trust-store /path/to/trusted-cas/
```

### Manage baselines

```bash
loki baseline --storage-path ./baselines list
loki baseline --storage-path ./baselines show <uuid>
loki baseline --storage-path ./baselines import /path/to/baseline.yaml
loki baseline --storage-path ./baselines export <uuid> /tmp/out.yaml
loki baseline --storage-path ./baselines delete --yes <uuid>
```

### Refresh CVE feeds

```bash
loki feeds refresh --config loki.yaml
loki feeds status --config loki.yaml
```

### Fleet analysis

```bash
# Config-driven (YAML listing report paths)
loki fleet analyze --config fleet.yaml

# Directory scan (all *.json reports in a directory)
loki fleet analyze --dir /data/reports/ --fleet-id corporate-laptops
```

## Architecture

```
Operator
  |
  v
loki extract -> ExtractionManifest (JSON)
  |
  v
loki classify -> ClassificationResult (JSON)
  |               + SignatureInfo (verified/signer/expiry via --trust-store)
  |               + cve_matches (via --feeds-config)
  v
loki analyze -> ImageAnalysisReport (JSON)
  |               7 finding categories, posture rating
  v
loki fleet analyze -> FleetAnalysisReport (JSON)
                        posture distribution, outliers, CVE rollup
```

## Configuration

Loki uses a YAML config file for feeds, baseline paths, and analysis weights:

```yaml
general:
  default_output_format: HUMAN
  color: AUTO
  verbosity: 1
  log_level: INFO
extraction:
  default_output_dir: /tmp/loki-extracted
  max_component_size: 50000000
  timeout_per_component: 60
classification:
  taxonomy_version: "1.0.0"
  confidence_threshold: 0.6
  rules_path: /path/to/rules
analysis:
  severity_weights:
    type: 0.25
    vendor: 0.25
    security_posture: 0.30
    mutability: 0.20
  default_severity_threshold: MEDIUM
baseline:
  storage_path: ~/.local/share/loki/baselines
  auto_match: true
feeds:
  nvd_url: https://services.nvd.nist.gov/rest/json/cves/2.0
  update_interval: 3600
  cache_path: /tmp/loki-cache
  implant_rules_path: /tmp/loki-implants
fleet:
  default_severity_threshold: MEDIUM
  storage_path: /tmp/loki-fleet
```

## Building Native Packages

Requires the `package` extra: `pip install -e ".[package]"`

```bash
# macOS DMG (ad-hoc signed for local testing)
./scripts/build_app.sh

# macOS DMG (developer-signed for distribution)
./scripts/build_app.sh --sign

# Windows (run on Windows)
./scripts/build_app.sh --platform windows

# Linux AppImage (run on Linux)
./scripts/build_app.sh --platform linux
```

## Development

```bash
# Run all four verification gates
.venv/bin/python -m ruff check loki tests scripts
.venv/bin/python -m ruff format --check loki tests scripts
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m pytest -q

# Run performance tests (excluded by default)
.venv/bin/python -m pytest -m slow

# GUI smoke test (offscreen)
QT_QPA_PLATFORM=offscreen .venv/bin/python -c "import sys; sys.path.insert(0,'.'); exec(open('scripts/smoke_gui.py').read())"
```

## License

Proprietary. See `LICENSE`.
