# Changelog

All notable changes to Loki are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-02

First v1 release. Loki ships nine spec-triple subsystems at IMPLEMENTED + APPROVED, three AD_HOC subsystems at IMPLEMENTED, a complete CLI surface, a desktop GUI (AD_HOC; spec triple in flight as OT-LK-004), and a Briefcase-built macOS .app + DMG. The platform extracts firmware images, classifies their components along four taxonomic axes, persists named baselines via GLEIPNIR, compares against those baselines, scores deviations, queries CVE feeds with signed-trust verification, and aggregates findings across device fleets.

### Subsystems shipping at v1.0.0

| Subsystem | Spec status | Lifecycle | Public surface |
|---|---|---|---|
| `models` | APPROVED | IMPLEMENTED | Pydantic v2 data layer (14 enums, 20+ models) |
| `extraction` | APPROVED | IMPLEMENTED | `loki extract` + `from loki.extraction import extract_firmware` |
| `baseline` (GLEIPNIR) | APPROVED | IMPLEMENTED | `loki baseline` + `from loki.baseline import BaselineStore` |
| `classification` | APPROVED | IMPLEMENTED | `loki classify` + `from loki.classification import classify_components` |
| `analysis-engine` | APPROVED | IMPLEMENTED | `loki analyze` + `from loki.analysis import analyze_image` |
| `classify-cli` | APPROVED | IMPLEMENTED | `loki classify` subcommand contract |
| `feeds` | APPROVED | IMPLEMENTED | `loki feeds refresh/status` + `from loki.feeds import FeedRegistry` |
| `consumer-wiring` | APPROVED | IMPLEMENTED | feeds → classification / analysis integration |
| `fleet-analysis` | APPROVED | IMPLEMENTED | `loki fleet analyze` + `from loki.fleet import analyze_fleet` |
| `gui` | AD_HOC | IMPLEMENTED | `loki gui` + `loki.gui.app.run()` (PyQt6; ~1879 LOC; 7 views) |
| `cli` | AD_HOC | IMPLEMENTED | `loki` console-script entry point |
| `scripts` | AD_HOC | IMPLEMENTED | `scripts/smoke_gui.py`, `scripts/build_app.sh` |

### Verification at release

- `pytest -q`: **1678 passed / 13 deselected** (slow-marker performance tests run separately).
- `mypy --strict loki`: 0 errors across 116 source files (package-only).
- `mypy --strict loki tests scripts`: 0 errors across 314 source files (full repo).
- `ruff check` + `ruff format --check loki tests scripts`: clean.
- `QT_QPA_PLATFORM=offscreen python scripts/smoke_gui.py`: clean.
- `pytest -m slow`: 13 performance tests (R11.1, R11.3, R12.1-R12.3, R18.1, fleet R10.2, plus extraction-pipeline gates).

### Threat-context posture

- Default `STANDARD` (untrusted firmware-image input is the primary risk surface).
- `models`, `scripts`: `MINIMAL_EXPOSURE` (pure data / smoke harness).
- `feeds`: **`FULL`** — first subsystem with outbound network egress + signature/trust verification (NVD CVE bundle; package-embedded default trust anchor with `FeedsConfig.signing_key_path` rotation override).

### Release artifacts

- **macOS DMG** — `Loki-macOS-dmg` (161 MB), built via Briefcase ad-hoc signed; uploaded as a workflow artifact on the v1.0.0 tag-triggered CI run. Notarization not yet wired (deferred — needs an Apple Developer ID).
- **Windows installer** — `Loki-Windows-installer` (81 MB), built via Briefcase ad-hoc signed; uploaded as a workflow artifact.
- **Linux AppImage** — NOT shipped in v1.0.0. Briefcase's manylinux container build path fails on PyQt6's sip/qmake from-source build (`PyProjectOptionException: 'qmake'`). Tracked as Step 6 follow-on; tentative fix is to switch the Linux target from AppImage to a debian/rpm package, or install Qt6 dev tools in the AppImage build container.

### Known follow-on threads (post-v1)

- **OT-LK-004 (LOW)** — formalize the GUI views spec triple so `gui` transitions from AD_HOC → APPROVED. The implementation is substantial and clean (1879 LOC, all seven views, smoke-clean); the spec triple is the missing artifact.
- **OT-LK-005 (LOW)** — baseline schema migration tool. Not blocking until a second `Schema_Version` exists; until then the quarantine path is the right contract.
- **OT-LK-006 (LOW)** — `ExtractionManifest` schema migration. Symmetric with OT-LK-005; not blocking until the model layer changes shape.
- Native packaging completion — Outstanding: Apple developer-cert codesigning + `xcrun notarytool` notarization for the macOS DMG; equivalent Authenticode code-signing for the Windows installer; resolution of the Linux AppImage Briefcase/PyQt6/qmake build gap.

[1.0.0]: https://github.com/sabercat204/loki/releases/tag/v1.0.0
