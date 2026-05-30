# How-To Guide

Practical recipes for common Loki workflows.

## Setting Up a New Firmware Analysis

### 1. Extract the firmware

```bash
loki extract /path/to/bios-image.bin --output-dir ./extracted --progress
```

This produces a JSON `ExtractionManifest` on stdout. Save it:

```bash
loki extract firmware.bin --output-dir ./extracted > manifest.json
```

### 2. Create classification rules

Create a rules directory with YAML files:

```yaml
# rules/vendor-intel.yaml
taxonomy_version: "1.0.0"
rules:
  - rule_id: vendor.intel.guids
    axis: vendor
    matcher:
      guid:
        in:
          - "4aafd29d-68df-49ee-8aa9-347d375665a7"
          - "a7d8d9a6-6ab0-4ae7-ad8f-90fa7d3f0b1d"
    effect:
      label: INTEL
      confidence: 0.95
      method: SIGNATURE
      evidence: "matched canonical Intel platform GUIDs"
```

### 3. Classify the components

```bash
loki classify manifest.json --rules-path ./rules > classification.json
```

### 4. Set up a baseline

Import an existing baseline from a known-good firmware image:

```bash
# First, extract and classify the known-good image
loki extract known-good.bin --output-dir ./baseline-extracted > baseline-manifest.json
loki classify baseline-manifest.json --rules-path ./rules > baseline-classification.json

# Import into the baseline store
loki baseline --storage-path ./baselines import baseline.yaml
```

### 5. Run analysis

```bash
loki analyze manifest.json \
  --baseline-path ./baselines \
  --rules-path ./rules > report.json
```

### 6. Review findings

The report JSON contains:
- `posture_rating`: overall security posture (BASELINE, DEGRADED, AT_RISK, COMPROMISED)
- `findings`: list of deviations with severity, category, and recommended actions
- `summary.findings_by_severity`: counts per severity level

---

## Running Fleet Analysis

### Option A: Config-driven

Create a `fleet.yaml`:

```yaml
fleet_id: corporate-laptops
reports:
  - path: /data/reports/laptop-001.json
  - path: /data/reports/laptop-002.json
  - path: /data/reports/laptop-003.json
```

```bash
loki fleet analyze --config fleet.yaml > fleet-report.json
```

### Option B: Directory scan

Put all per-image `ImageAnalysisReport` JSON files in one directory:

```bash
loki fleet analyze --dir /data/reports/ --fleet-id corporate-laptops
```

### Interpreting fleet results

The fleet report surfaces:
- **Posture distribution**: how many devices at each rating
- **Common findings**: issues appearing in 2+ devices (fleet-wide problems)
- **Systemic risks**: CVEs affecting multiple devices
- **Outlier images**: devices significantly worse than the fleet median
- **Recommended actions**: top-3 worst devices to investigate first

---

## Verifying Code Signatures

### Set up a trust store

Create a directory with PEM-encoded root CA certificates:

```bash
mkdir trusted-cas/
# Add your organization's firmware signing CA
cp /path/to/firmware-ca.pem trusted-cas/
# Or use individual vendor CAs
cp /path/to/intel-signing-ca.pem trusted-cas/
cp /path/to/ami-signing-ca.pem trusted-cas/
```

### Run classification with verification

```bash
loki classify manifest.json \
  --rules-path ./rules \
  --trust-store ./trusted-cas/ > classified.json
```

Components with valid, trusted signatures will have:
- `signature_info.present = true`
- `signature_info.verified = true`
- `signature_info.signer = "Intel Corporation"` (the CN)
- `signature_info.cert_expiry = "2027-01-15T00:00:00Z"`

### Using the system trust store (Python API)

```python
from loki.verification import TrustStore, verify_signature
from pathlib import Path

store = TrustStore.system_store()  # loads macOS/Windows/Linux system CAs
result = verify_signature(Path("component.efi"), store)
print(result.verified, result.signer, result.cert_expiry)
```

---

## CVE Feed Integration

### Initial setup

Create a config with feeds section:

```yaml
feeds:
  nvd_url: https://services.nvd.nist.gov/rest/json/cves/2.0
  update_interval: 3600
  cache_path: ~/.local/share/loki/feeds
  implant_rules_path: ~/.local/share/loki/implants
```

### Refresh the CVE cache

```bash
loki feeds refresh --config loki.yaml
loki feeds status --config loki.yaml
```

### Classify with CVE lookup

```bash
loki classify manifest.json \
  --rules-path ./rules \
  --feeds-config loki.yaml > classified-with-cves.json
```

Components matching known CVEs will have populated `cve_matches` lists.

---

## Using the GUI

```bash
loki gui
```

### Workflow

1. **File -> Open Firmware Image** (Ctrl+O): loads a firmware binary
2. **View -> Extract Firmware Components** (Ctrl+E): runs extraction on a background thread
3. **View -> Run Analysis** (Ctrl+A): prompts for baseline and rules directories, runs analysis
4. **View -> Load Fleet Report**: opens a saved fleet report JSON
5. **View -> Load Demo Data**: populates with synthetic data for exploration

### Baselines in the GUI

The GUI automatically loads baselines from `~/.local/share/loki/baselines/` on startup. Use **View -> Open Baseline Registry** to load from a different location, and **View -> Save Baseline** to persist the active baseline.

---

## Building and Distributing

### Prerequisites

```bash
pip install -e ".[package]"  # installs Briefcase
```

### Build a macOS .app

```bash
./scripts/build_app.sh
# Output: dist/Loki-0.1.0.dmg
```

### Build for other platforms

```bash
# Windows (run on Windows)
./scripts/build_app.sh --platform windows

# Linux (run on Linux)
./scripts/build_app.sh --platform linux
```

### CI/CD

Push to GitHub. The `.github/workflows/ci.yml` runs:
- Lint + format + type check + test on every push/PR (Ubuntu, macOS, Windows)
- Packages DMG + MSI + AppImage on tagged releases (`git tag v0.1.0`)

---

## Writing Custom Classification Rules

Rules are YAML files in a directory. Each file has:

```yaml
taxonomy_version: "1.0.0"
rules:
  - rule_id: unique.rule.identifier
    axis: type | vendor | security_posture | mutability
    matcher:
      # All predicates are conjunctive (AND)
      guid:
        in: ["uuid-1", "uuid-2"]        # match any GUID
      name:
        prefix: "Dxe"                    # match component name
      size:
        min: 1024
        max: 1048576
      raw_hash: "abcdef..."              # exact hash match
    effect:
      label: UEFI_DRIVER                 # must be a valid enum value
      confidence: 0.9                    # 0.0 - 1.0
      method: SIGNATURE | RULE | HEURISTIC
      evidence: "human-readable reason"
```

Rules are evaluated per-axis. The highest-confidence matching rule wins. When no rule matches, the axis defaults to `UNKNOWN` with confidence 0.0.

---

## Python API Usage

### Full pipeline in code

```python
from pathlib import Path
from loki.extraction import extract_firmware
from loki.classification import classify_components
from loki.analysis import analyze_image
from loki.baseline import BaselineStore
from loki.verification import TrustStore
from loki.models import ExtractionConfig, ClassificationConfig, BaselineConfig

# Extract
config = ExtractionConfig(default_output_dir="/tmp/out", max_component_size=50_000_000, timeout_per_component=60)
result = extract_firmware(Path("firmware.bin"), config)

# Classify with signature verification
trust_store = TrustStore.from_directory(Path("/path/to/trusted-cas"))
cls_config = ClassificationConfig(taxonomy_version="1.0.0", confidence_threshold=0.6, rules_path="/path/to/rules")
cls_result = classify_components(result.manifest.components, cls_config, trust_store=trust_store)

# Analyze
store = BaselineStore(BaselineConfig(storage_path="/path/to/baselines", auto_match=True))
registry = store.load().registry
report = analyze_image(
    target_records=cls_result.records,
    registry=registry,
    target_image=result.manifest.source_image,
    config=AnalysisConfig(severity_weights={"type": 0.25, "vendor": 0.25, "security_posture": 0.3, "mutability": 0.2}, default_severity_threshold="MEDIUM"),
)
print(report.posture_rating, len(report.findings), "findings")
```

### Fleet analysis in code

```python
from loki.fleet import analyze_fleet
from loki.fleet.membership import load_from_directory

fleet_id, reports = load_from_directory(Path("/data/reports/"))
fleet_report = analyze_fleet(reports=reports, fleet_id=fleet_id)
print(f"{fleet_report.image_count} images, {len(fleet_report.outlier_images)} outliers")
```
