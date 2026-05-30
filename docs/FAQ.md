# Frequently Asked Questions

## General

### What is Loki?

Loki is a firmware analysis platform that extracts firmware images, classifies their components, compares them against known-good baselines, and reports security deviations. It's designed for operators managing fleets of devices with firmware that needs monitoring for tampering, unauthorized changes, or known vulnerabilities.

### What firmware formats does Loki support?

v1 supports:
- Intel Flash Descriptor (full-flash images)
- UEFI PI firmware volumes
- Raw FFS (Firmware File System) blobs
- UEFI capsules
- PCI option ROMs
- Intel CPU microcode update blobs

Deferred: Coreboot CBFS, ARM Trusted Firmware, Apple iBoot, Android boot images, vendor-private capsule wrappers.

### What Python version do I need?

Python 3.11 or newer. Python 3.12 is recommended and tested in CI.

### Does Loki need network access?

Only the feeds subsystem (`loki feeds refresh`) makes network calls to fetch the NVD CVE database. All other subsystems operate entirely offline. The feeds subsystem uses TLS with certificate verification and a same-host redirect policy.

---

## Installation

### How do I install Loki?

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

For just the runtime (no test/lint tools): `.venv/bin/pip install -e .`

### I get `ModuleNotFoundError: No module named 'uefi_firmware'`

The `uefi_firmware` package requires a C compiler. On macOS:
```bash
xcode-select --install
pip install uefi_firmware
```

On Ubuntu/Debian:
```bash
sudo apt-get install build-essential python3-dev
pip install uefi_firmware
```

### The `.venv/bin/loki` script doesn't work

The venv shebangs may be stale if you moved the directory. Use:
```bash
.venv/bin/python -m loki <subcommand>
```

Or rebuild the venv:
```bash
rm -rf .venv
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

---

## Classification

### What are the four classification axes?

1. **Type**: what kind of component (UEFI_DRIVER, BOOTLOADER, OS_KERNEL, SMM_MODULE, etc.)
2. **Vendor**: who made it (INTEL, AMD, AMI, INSYDE, etc.)
3. **Security posture**: is it SECURE, VULNERABLE, or UNKNOWN?
4. **Mutability**: is it READONLY, MUTABLE, or UNKNOWN?

### How do classification rules work?

Rules are YAML files in a directory. Each rule targets one axis and contains a matcher (conditions that must all be true) and an effect (the label, confidence, and method to apply). The highest-confidence matching rule wins per axis. See `docs/HOWTO.md` for the full rule schema.

### What does `needs_review = True` mean?

A classification record has `needs_review = True` when its `composite_confidence` (the mean of all four axis confidences) falls below 0.60. This means the automated classification is uncertain and an analyst should review it.

### What is `cve_matches`?

When you pass `--feeds-config` to `loki classify`, the platform looks up each classified component against the NVD CVE database (by vendor + firmware version). Matching CVE IDs are listed in the `cve_matches` field of the classification record.

---

## Analysis

### What are the seven finding categories?

1. **`classification_mismatch`**: a component's classification differs from its baseline counterpart. Carries a composite deviation score (0-10).
2. **`signature_regression`**: a component was signed in the baseline but unsigned in the target (or vice versa). HIGH severity for lost signatures.
3. **`unexpected_component`**: a component exists in the target but not in the baseline.
4. **`missing_required_component`**: a component exists in the baseline but is absent from the target.
5. **`classification_gap`**: a component's classification confidence is too low to trust. LOW severity.
6. **`signature_expired`**: a component has a valid but expired signing certificate. MEDIUM severity.
7. **`analysis_cancelled`**: the run was interrupted by cooperative cancellation.

### How is `posture_rating` determined?

The posture is derived from findings using a six-rule cascade:
1. **COMPROMISED** if any: signature lost, required component missing, or critical mismatch (score >= 8.0)
2. **AT_RISK** if any mismatch with score >= 6.0
3. **DEGRADED** if any mismatch with score >= 2.0
4. **DEGRADED** (catch-all) if any finding was emitted
5. **BASELINE** if no findings at all
6. **HARDENED** is reserved for future use

### What does `composite_score` mean in a mismatch finding?

It's a weighted sum of per-axis deviation scores (0.0 to 10.0), using the `severity_weights` from your analysis config. Higher = more concerning. The weights default to: type 0.25, vendor 0.25, security_posture 0.30, mutability 0.20.

### Can I cancel an analysis mid-run?

Yes. Send SIGINT (Ctrl+C) during a CLI run, or pass a `cancel` callback to the Python API. The engine emits partial results with a cancellation marker.

---

## Signature Verification

### What does `--trust-store` do?

It points to a directory of PEM-encoded root CA certificates. When provided, Loki:
1. Extracts the PKCS#7 signature from PE32 Authenticode or UEFI auth wrappers
2. Parses the X.509 certificate chain
3. Verifies each link in the chain cryptographically
4. Checks that the chain terminates at one of your trusted roots

Only then does `signature_info.verified` become `True`.

### Why is `verified` always False without `--trust-store`?

By design. Without a trust store, Loki can detect signature *presence* but cannot verify *validity*. You must explicitly provide trusted roots for verification to occur.

### Can I use the system CA bundle?

In the Python API, yes:
```python
from loki.verification import TrustStore
store = TrustStore.system_store()
```

The CLI currently requires a directory path. Using the system store via CLI is a future enhancement.

### Does Loki check certificate revocation (CRL/OCSP)?

Not in v1. The chain verifier checks signatures and expiry but does not query revocation servers. This is tracked as a future enhancement.

---

## Fleet Analysis

### How many images can fleet analysis handle?

The engine processes 100 images with 1000 findings each in about 2 seconds. It's O(N) in total findings across all five aggregation passes. Practical limit is memory, not CPU.

### What is an "outlier"?

An image whose posture rating is strictly worse than the fleet median. If most devices are BASELINE and one is COMPROMISED, that's an outlier. Outlier detection is skipped for fleets with fewer than 3 images.

### What are "systemic risks"?

CVEs that appear in 2 or more images in the fleet. These are fleet-wide vulnerabilities that likely require a coordinated firmware update rather than per-device investigation.

---

## GUI

### How do I launch the GUI?

```bash
loki gui
# or
.venv/bin/python -c "from loki.gui import run; run()"
```

### The GUI crashes on Linux with `qt.qpa.plugin: Could not load the Qt platform plugin`

Install the Qt platform dependencies:
```bash
sudo apt-get install libxcb-xinerama0 libxkbcommon-x11-0
```

Or run headless for testing:
```bash
QT_QPA_PLATFORM=offscreen loki gui
```

### Can I run analysis from the GUI?

Yes. After extracting components (View -> Extract), use View -> Run Analysis (Ctrl+A). It prompts for baseline and rules directories, then runs classification + analysis on a background thread.

---

## Packaging and Distribution

### How do I build a distributable .app?

```bash
pip install -e ".[package]"
./scripts/build_app.sh
```

This produces `dist/Loki-0.1.0.dmg` (ad-hoc signed, runs locally but can't be distributed to other machines without Gatekeeper warnings).

### How do I sign for distribution?

You need an Apple Developer ID certificate. Then:
```bash
./scripts/build_app.sh --sign
```

Briefcase will prompt for your signing identity and produce a signed DMG. For notarization, use `briefcase package macOS app` without `--no-notarize`.

### What about Windows and Linux?

The Briefcase config supports all three platforms. Run the build script on the target OS:
- Windows: `./scripts/build_app.sh --platform windows` (produces MSI)
- Linux: `./scripts/build_app.sh --platform linux` (produces AppImage)

CI builds all three automatically on tagged releases.

---

## Troubleshooting

### `pytest` failures with `filterwarnings = ["error"]`

Loki promotes all warnings to errors in tests. If a dependency emits a deprecation warning, the test fails. Pin the dependency version or add a specific `filterwarnings` ignore in `pyproject.toml`.

### `mypy` errors after adding new code

Run `mypy --strict loki tests scripts`. Common issues:
- Missing type annotations on function parameters
- Using `dict` instead of the specific enum type (Pydantic strict mode)
- Forgetting `from __future__ import annotations` at the top of new files

### Analysis says "BaselineNotFoundError"

The analysis engine can't find a matching baseline. Check:
- The baseline storage directory contains at least one `.yaml` file
- The baseline's `(vendor, model, firmware_version)` matches the target image's metadata
- The `FirmwareImage` has `vendor`, `model`, and `firmware_version` fields set

### Classification produces all UNKNOWN labels

Your rules directory is empty or the rules don't match any components. Check:
- The `--rules-path` directory exists and contains `.yaml` files
- Each rule file has `taxonomy_version: "1.0.0"` (must match `--taxonomy-version`)
- Rule matchers actually fire against your components (try a permissive `size: {min: 0}` catch-all)

### Fleet analysis: "No valid reports found in directory"

The directory must contain `.json` files that are valid `ImageAnalysisReport` instances. Check that you're pointing at analysis *output* files (from `loki analyze`), not extraction manifests or classification results.
