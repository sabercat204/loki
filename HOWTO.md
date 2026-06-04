# Loki — How To

A use-case-driven guide for end users (firmware analysts, security
engineers, fleet operators). For library API documentation, read the
public exports from `loki/extraction/__init__.py`,
`loki/baseline/__init__.py`, etc. For developer setup and CI, see
`README.md`.

---

## What Loki is for

You have firmware images — UEFI BIOSes, microcode bundles, option
ROMs, embedded-controller blobs, capsule updates — and you need to
know:

1. **What's in this image?** (extraction + classification)
2. **How does it differ from a known-good baseline?** (analysis)
3. **Are any of its components vulnerable to published CVEs?** (feeds)
4. **What's the security posture of every device in my fleet?** (fleet)

Loki answers those four questions, in order, through a CLI pipeline
plus a desktop GUI. The CLI is the canonical interface for
automation; the GUI is for one-off inspections and demos.

---

## Setup

### Option A — Install the pre-built native package (recommended for end users)

Each `v*` tag publishes three native installers as workflow artifacts.
See `README.md` § *Installing Pre-built Packages* for the platform-specific
download and bypass instructions (macOS Gatekeeper, Windows
SmartScreen, Linux AppImage permission bit).

After install, launch the GUI from your applications menu. The CLI is
**not** included in the native package — for CLI use, install from
source via Option B.

### Option B — Install from source (CLI + GUI, both)

```bash
git clone https://github.com/sabercat204/loki.git
cd loki
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Confirm
.venv/bin/loki --version
.venv/bin/loki --help
```

For the rest of this document, `loki` means `.venv/bin/loki` (or
whatever your shell resolves it to after activating the venv).

---

## The four-stage pipeline

Every CLI workflow is a composition of four stages. Each stage reads
the previous stage's JSON, so you can pipe them or save intermediate
artifacts to disk.

```
firmware.bin
   │
   ▼  loki extract                                  → ExtractionManifest (JSON)
   │   "what components are in this binary?"
   │
   ▼  loki classify --rules-path …                  → ClassificationRecords (JSON)
   │   "what is each component? (type/vendor/security/mutability)"
   │
   ▼  loki analyze --baseline-path … --rules-path …  → ImageAnalysisReport (JSON)
   │   "how does this image deviate from baseline? what findings?"
   │
   ▼  loki fleet analyze --dir reports/             → FleetAnalysisReport (JSON)
       "across all images in my fleet, what's the posture?"
```

Each stage emits **JSON to stdout** and a **one-line human summary to
stderr**. Errors use distinct exit codes per the per-subcommand spec.

---

## Use case 1 — "I just got a firmware image. What's in it?"

You've downloaded a vendor BIOS update or pulled an SPI image off a
device with `flashrom`. You want a manifest of every detectable
component before you trust it.

```bash
loki extract /path/to/firmware.bin \
  --output-dir /tmp/loki/components \
  --progress \
  > /tmp/loki/manifest.json
```

What you get:

- `manifest.json` — a validated `ExtractionManifest` with every
  detected component (UEFI PI files, IFD regions, capsule headers,
  option ROMs, microcode blobs), each with a deterministic
  `component_id`, byte offset, raw hash, and detected type hints.
- `/tmp/loki/components/` — one file per component named
  `0x{offset:x}-{raw_hash}.bin` so you can inspect raw bytes.
- A stderr summary like:
  `extract: 47 components in 1.8s (4 errors quarantined)`.

Quick eyeball pass:

```bash
jq '.components | length' /tmp/loki/manifest.json
jq '[.components[] | .raw_size] | add' /tmp/loki/manifest.json   # total bytes
jq '.errors | length' /tmp/loki/manifest.json                    # quarantined regions
```

If you don't care about the raw bytes, drop `--output-dir`. Loki then
produces only the manifest, with `raw_path: null` on every component.

---

## Use case 2 — "Is this image's component mix what I expect?"

You have a manifest and a directory of classification rules (YAML
files mapping component signatures to type/vendor/posture/mutability
labels). You want every component classified along the four taxonomic
axes.

```bash
loki classify /tmp/loki/manifest.json \
  --rules-path /path/to/rules \
  --progress \
  > /tmp/loki/classified.json
```

Or piped directly:

```bash
loki extract /path/to/firmware.bin \
  | loki classify - --rules-path /path/to/rules \
  > /tmp/loki/classified.json
```

What you get: a JSON object `{records, errors}` where each record
carries:

- `component_id` linking back to the manifest
- four `AxisClassification` decisions (type, vendor, security_posture,
  mutability), each with a confidence score and the rule/heuristic
  that produced it
- a derived `composite_confidence` and a `needs_review` flag set when
  the composite drops below `confidence_threshold`

Triage examples:

```bash
# Components needing manual review:
jq '[.records[] | select(.needs_review)] | length' /tmp/loki/classified.json

# Anything classified as VULNERABLE security_posture:
jq '.records[] | select(.security_posture.label == "VULNERABLE") | .component_id' \
  /tmp/loki/classified.json

# Distribution across component types:
jq '[.records[] | .component_type.label] | group_by(.) | map({key: .[0], n: length})' \
  /tmp/loki/classified.json
```

---

## Use case 3 — "How does this image differ from the known-good build?"

You have a baseline directory containing reference images for a
specific (vendor, model, firmware_version) tuple. You want to know
exactly what's added, removed, modified, or reclassified relative to
that baseline.

First, capture the known-good as a baseline (one-time per
vendor+model+version):

```bash
# Build a Baseline_File from a trusted image (offline workflow).
loki extract trusted_v1.0.0.bin \
  --output-dir /tmp/loki/v1-components \
  > /tmp/loki/v1-manifest.json

# … then construct a BaselineRecord pointing at v1-manifest.json
# (the schema is documented in specs/baseline-persistence/) and
# import it:
loki baseline --storage-path ~/loki-baselines import baseline-v1.yaml
```

Now analyze a candidate image against that storage:

```bash
loki analyze /tmp/loki/manifest.json \
  --baseline-path ~/loki-baselines \
  --rules-path /path/to/rules \
  > /tmp/loki/report.json
```

You get an `ImageAnalysisReport` with:

- `posture_rating` — one of `HARDENED`, `BASELINE`, `DEGRADED`,
  `AT_RISK`, `COMPROMISED`
- `baseline_comparison` — for each component: `ADDED`, `REMOVED`,
  `MODIFIED`, `RECLASSIFIED`, or `UNCHANGED` plus a per-axis
  deviation score
- `findings` — a list of `FindingRecord` entries, each with severity
  (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`), evidence, and
  classification axes
- `recommended_actions` — concrete actions ranked by severity
- `summary` — counts by severity and by `DeltaType`

Get the headline at a glance:

```bash
jq '.posture_rating' /tmp/loki/report.json
jq '.summary' /tmp/loki/report.json
jq '[.findings[] | select(.severity == "CRITICAL")]' /tmp/loki/report.json
```

---

## Use case 4 — "Are any components in this image affected by published CVEs?"

You want NVD CVE matches surfaced alongside classification. This
requires a feeds cache, kept fresh via `loki feeds`.

Refresh the cache (network egress; signature-verified against the
package's embedded trust anchor):

```bash
loki feeds refresh --config loki.yaml
loki feeds status --config loki.yaml
```

Now classify with `--feeds-config` to populate `cve_matches` on every
classification record:

```bash
loki classify /tmp/loki/manifest.json \
  --rules-path /path/to/rules \
  --feeds-config loki.yaml \
  > /tmp/loki/classified-with-cves.json
```

Triage examples:

```bash
# Every component with at least one CVE match:
jq '.records[] | select(.cve_matches | length > 0) | {id: .component_id, cves: [.cve_matches[].cve_id]}' \
  /tmp/loki/classified-with-cves.json

# Distinct CVE IDs across the entire image:
jq '[.records[].cve_matches[].cve_id] | unique' /tmp/loki/classified-with-cves.json
```

`loki analyze` does its own classification internally and folds CVE
matches into findings when the analysis config points at a feeds
cache.

---

## Use case 5 — "Verify component signatures against my organization's trust store"

If you have a directory of trusted root CA certificates (PEM/CRT),
you can have Loki verify Authenticode and UEFI-signed components
during classification. Verified components get
`SignatureInfo.verified=true` and the chain's signer name + cert
expiry populated.

```bash
loki classify /tmp/loki/manifest.json \
  --rules-path /path/to/rules \
  --trust-store /path/to/trusted-roots/ \
  > /tmp/loki/classified-verified.json
```

Find anything signed by an unknown CA or with an expired cert:

```bash
jq '.records[] | select(.signature_info != null and .signature_info.verified == false) | .component_id' \
  /tmp/loki/classified-verified.json
```

Same `--trust-store` flag is accepted by `loki analyze` and gets
threaded into its internal classification step.

---

## Use case 6 — "Roll up my entire device fleet into a posture distribution"

You've run `loki analyze` on every image from every device in your
fleet and you have a directory of `*.json` reports. You want one
aggregate view: how many devices are `HARDENED` vs. `COMPROMISED`,
which CVEs cover the most devices, which devices are outliers.

```bash
loki fleet analyze \
  --dir /data/loki/reports/ \
  --fleet-id corporate-laptops-2026Q2 \
  > /tmp/loki/fleet.json
```

Or with a YAML config that explicitly lists report paths (so the
fleet membership is reproducible across runs):

```yaml
# fleet.yaml
fleet_id: corporate-laptops-2026Q2
reports:
  - /data/loki/reports/laptop-001.json
  - /data/loki/reports/laptop-002.json
  - /data/loki/reports/laptop-003.json
```

```bash
loki fleet analyze --config fleet.yaml > /tmp/loki/fleet.json
```

You get a `FleetAnalysisReport` with:

- `posture_distribution` — count of devices in each `PostureRating`
  bucket
- `cve_rollup` — every CVE seen across the fleet, ranked by how many
  devices it affects
- `outliers` — devices whose finding profile is statistically distinct
  from the fleet median (operator review-priority)
- `worst_image_ranking` — top-N devices by aggregate severity
- `recommended_actions` — fleet-level actions

```bash
jq '.posture_distribution' /tmp/loki/fleet.json
jq '.cve_rollup[:10]' /tmp/loki/fleet.json
jq '.outliers' /tmp/loki/fleet.json
```

---

## Use case 7 — "I just want a GUI to click through one image"

```bash
loki gui                  # via the CLI subcommand
python -m loki            # equivalent — calls loki/__main__.py
```

Or launch the installed native app from your applications menu.

The GUI's menu surface is three top-level menus — **File**, **View**,
and **Help**:

- **File → Open Firmware Image…** — opens a file picker; the
  selected image is hashed and added to the **Firmware Images**
  group in the navigation pane, and an *Image* tab opens.
- **View → Extract Firmware Components…** — runs `loki extract` on
  the currently-selected image in a `QThread` worker and opens an
  *Extraction* tab. A status-bar progress line updates per
  component.
- **View → Run Analysis…** — runs the full classify+analyze
  pipeline against the current baseline store; opens an *Analysis*
  tab with all of: per-axis deviation scoring, baseline-comparison
  summary, full per-finding evidence (classification axes, deviation
  scores, matched rules / CVEs / signatures, raw indicators), and
  recommended actions.
- **View → Load Fleet Report…** — loads a `FleetAnalysisReport`
  JSON from disk and renders posture distribution, outliers, CVE
  rollup, and recommended actions.
- **View → Open Baseline Registry…** / **Save Baseline…** —
  point the GUI at a baseline storage directory; the registry shows
  in the **Baselines** group of the navigation pane.
- **View → Cancel Baseline Load** / *(implicit cancellation while
  any worker is running)* — cooperative cancellation is wired
  through every long-running task. Long extractions and analyses
  stay responsive because every pipeline runs on a `QThread` worker
  with a `threading.Event` cancellation primitive.
- **View → Load Demo Data** — populates the workspace with a
  synthetic firmware image, baseline, analysis report, and fleet
  report so you can see what every view renders without supplying
  real input. Useful for first-run orientation.
- **View → Reset Workspace** — closes every open tab and clears the
  navigation pane.
- **Help → About Loki** — version + license info.

The GUI is read-only by design. There is no per-view export, no
preferences dialog, and no in-GUI baseline curation in v1 — those are
forward-tracked. The CLI is the canonical surface for everything that
mutates state.

---

## Configuration

Most CLI flags can also live in a YAML config you reference by path
(e.g., `--config loki.yaml`, `--feeds-config loki.yaml`):

```yaml
# loki.yaml
general:
  default_output_format: HUMAN
  color: AUTO
  verbosity: 1
  log_level: INFO
extraction:
  default_output_dir: /var/loki/extracted
  max_component_size: 50000000
  timeout_per_component: 60
classification:
  taxonomy_version: "1.0.0"
  confidence_threshold: 0.6
  rules_path: /etc/loki/rules
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
  cache_path: /var/loki/cache
  implant_rules_path: /etc/loki/implants
fleet:
  default_severity_threshold: MEDIUM
  storage_path: /var/loki/fleet
```

CLI flags always override config values when both are present.

---

## Common pitfalls

- **`loki classify` and `loki analyze` need a rules directory.**
  Loki does not ship default classification rules. You build them for
  your environment (vendor allowlists, known-good signatures,
  organization-specific component fingerprints). The schema is
  documented in `specs/classification-pipeline/`.
- **`loki feeds refresh` performs network egress.** It's the only
  Loki subcommand that does. The downloaded NVD bundle is verified
  against a package-embedded trust anchor; you can rotate the anchor
  via `FeedsConfig.signing_key_path` if your organization
  re-signs.
- **Baselines are scoped by `(vendor, model, firmware_version)`.**
  `loki analyze` against a baseline directory will use the closest
  match per the auto-match policy — there's no implicit fuzzy match
  across versions. Curate the baselines you import.
- **Quarantined files are NOT a fatal error.** When `loki extract`
  hits a region it can't parse, it writes an `ExtractionError` entry
  to the manifest and keeps going. Treat the error count in the
  stderr summary as a quality signal, not a failure.
- **Cancellation is cooperative, not instantaneous.** Both the GUI's
  Cancel menu items and the CLI's `Ctrl-C` complete the in-flight
  component before exiting. For multi-hundred-megabyte binaries,
  expect up to one component's worth of latency.

---

## Where to go next

- **GUI views formal spec:** `specs/gui-views/requirements.md` (1725
  lines, EARS format) — read this if you want to extend or audit the
  GUI's behavior contract.
- **Per-subsystem specs:** `specs/{extraction-pipeline, baseline-persistence, classification-pipeline, analysis-engine, feeds, fleet-analysis}/`
- **CHANGELOG:** `CHANGELOG.md` for release-by-release behavior changes.
- **CLI subcommand help:** `loki <subcommand> --help` for the
  authoritative flag list (this document is hand-curated and may
  lag).
