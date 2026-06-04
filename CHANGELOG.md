# Changelog

All notable changes to Loki are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-02 (tag retargeted through 2026-06-03)

First v1 release. Loki ships **ten** spec-triple subsystems at IMPLEMENTED + APPROVED (the `gui` subsystem ratified mid-release via OT-LK-004), two AD_HOC subsystems at IMPLEMENTED, a complete CLI surface, a desktop GUI, and Briefcase-built native installers for macOS, Windows, and Linux. The platform extracts firmware images, classifies their components along four taxonomic axes, persists named baselines via GLEIPNIR, compares against those baselines, scores deviations, queries CVE feeds with signed-trust verification, and aggregates findings across device fleets.

The `v1.0.0` tag was retargeted across five commits during the release arc as cross-platform CI gaps and packaging bugs were resolved; it now points at `1a19bd5` ("Fix Briefcase launcher: add loki/__main__.py"), which is the first commit at which all three native installers boot cleanly on a target machine.

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
| `gui` | APPROVED | IMPLEMENTED | `loki gui` + `loki.gui.app.run()` (PyQt6; ~1879 LOC; 6 views) — ratified via `specs/gui-views/` (OT-LK-004) |
| `cli` | AD_HOC | IMPLEMENTED | `loki` console-script entry point |
| `scripts` | AD_HOC | IMPLEMENTED | `scripts/smoke_gui.py`, `scripts/build_app.sh`, `scripts/codesign_local_macos.sh` |

### Verification at release (HEAD `1a19bd5`)

- `pytest -q`: **1681 passed / 13 deselected** (slow-marker performance tests run separately).
- `mypy --strict loki`: 0 errors across 116 source files (package-only).
- `mypy --strict loki tests scripts`: 0 errors across 315 source files (full repo).
- `ruff check` + `ruff format --check loki tests scripts`: clean.
- `QT_QPA_PLATFORM=offscreen python scripts/smoke_gui.py`: clean.
- `QT_QPA_PLATFORM=offscreen python -m loki`: boots GUI cleanly (Briefcase launcher contract).
- `pytest -m slow --timeout=420`: 13 performance tests pass (R11.1, R11.3, R12.1-R12.3, R18.1, fleet R10.2, plus extraction-pipeline gates).

### Threat-context posture

- Default `STANDARD` (untrusted firmware-image input is the primary risk surface).
- `models`, `scripts`: `MINIMAL_EXPOSURE` (pure data / smoke harness).
- `feeds`: **`FULL`** — first subsystem with outbound network egress + signature/trust verification (NVD CVE bundle; package-embedded default trust anchor with `FeedsConfig.signing_key_path` rotation override).

### Release artifacts

All three native installers ship from the v1.0.0 tag-triggered CI run (`26894607203`) at HEAD `1a19bd5` and have been verified to launch on a target macOS install (2026-06-04). Workflow artifacts auto-expire **2026-09-01**; persist them to a GitHub Release before then if long-tail availability matters.

- **macOS DMG** — `Loki-macOS-dmg` (155 MB), built via Briefcase ad-hoc signed; uploaded as a workflow artifact. Notarization not yet wired (deferred — needs a paid Apple Developer ID). For repeated workflows where you re-sign downloaded CI artifacts with your own local Personal Team certificate from Xcode, see `scripts/codesign_local_macos.sh`.
- **Windows installer** — `Loki-Windows-installer` (77 MB), built via Briefcase ad-hoc signed; uploaded as a workflow artifact. Authenticode signing deferred — needs a paid code-signing certificate.
- **Linux AppImage** — `Loki-Linux-AppImage` (134 MB), built via Briefcase ad-hoc signed; uploaded as a workflow artifact. The build path required pinning `pyqt6<6.10` in both `[project].dependencies` and `[tool.briefcase].requires`. PyQt6 6.10 moved its Linux x86_64 wheel platform tag from `manylinux_2_28_x86_64` to `manylinux_2_34_x86_64`; Briefcase's AppImage builder runs in a `manylinux_2_28` container (AlmaLinux 8 / glibc 2.28) where the newer tag has no compatible wheel, so pip silently fell back to the sdist and the sip/qmake source build failed (`PyProjectOptionException: 'qmake'`) since qmake6 is not in the container. The pin resolves to PyQt6 6.9.1 (last release with a `manylinux_2_28` wheel). Re-evaluate when Briefcase bumps its AppImage base image past glibc 2.34, or if/when we switch the Linux backend to Flatpak / system (deb).

### Briefcase launcher contract

Briefcase's bundled launcher invokes the application as `python -m loki` (via `runpy._run_module_as_main`) on every platform. v1.0.0 ships `loki/__main__.py` to satisfy that contract; it lazy-imports `loki.gui.app.run()` and forwards the Qt event-loop exit code. The `[tool.briefcase.app.loki].startup_module = "loki.gui"` pyproject setting is honoured by some platform backends but not all, so the canonical `__main__` is the load-bearing surface — don't remove it. The contract is pinned by three tests in `tests/gui/test_main_module.py` so a future refactor cannot drop it silently.

### Known follow-on threads (post-v1)

- **OT-LK-005 (LOW)** — baseline schema migration tool. Not blocking until a second `Schema_Version` exists; until then the quarantine path is the right contract.
- **OT-LK-006 (LOW)** — `ExtractionManifest` schema migration. Symmetric with OT-LK-005; not blocking until the model layer changes shape.
- **Forward-tracked from OT-LK-004** (each can become its own OT-LK when prioritised): QThreadPool / QObject.moveToThread() migration for the three GUI workers; ExtractionWorker bool-flag → `threading.Event` uniformity (the only remaining holdout); preferences UI; export surface (CSV/JSON/PDF); `Action_Function` Protocol extraction so alternative shells can hook in; Briefcase release-path completions (icons, EULA text, .desktop polish); Help-menu content beyond the single-entry stub.
- **Distribution gating** — Apple Developer ID code-signing + `xcrun notarytool` notarization for the macOS DMG; Authenticode code-signing for the Windows installer. Both blocked on operator credentials, not agent capability.

[1.0.0]: https://github.com/sabercat204/loki/releases/tag/v1.0.0
