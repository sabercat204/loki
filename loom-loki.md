```markdown

# LOOM — Living Object-Oriented Manifest
## Version 1.0.0

> Initial fork of WEAVE / Loom v0.3.0 for Loki. This Loom is being initialized retroactively — the full requirements / design / tasks triples already live at `specs/{loki-data-models,extraction-pipeline,baseline-persistence,classification-pipeline,analysis-engine}/`, and the v0.2.0 implementation now ships across **five subsystems** plus a GUI scaffold. The harness records the existing Tier 1–2 spec discipline as a Tier 3 subsystem registry so future operator-driven changes can be tracked through the standard Shuttle Protocol.

---

## 1. Project Metadata

    project_name: "Loki"
    project_codename: "loki"
    description: "Firmware analysis platform. Pulls firmware images from disk, extracts their components (UEFI PI / Intel IFD / capsules / option ROMs / microcode), classifies each component along four taxonomic axes (type / vendor / security_posture / mutability), persists named baselines via GLEIPNIR, compares against those baselines, scores deviations, and writes structured analysis reports. v1 ships four subsystems; analysis engine, feeds, and fleet engine are pending."
    primary_language: "Python 3.11+"
    secondary_languages: []
    frameworks: [Pydantic v2 (data models), PyYAML (baseline persistence + config), PyQt6 (GUI scaffold), uefi_firmware (UEFI PI extraction), Hypothesis (property tests), pytest + pytest-qt (testing), mypy --strict, ruff]
    package_name: "loki"
    repo_root: "~/Sloptropy/loki/"
    spec_directory: "specs/"
    implementation_tool: "Manual + Cursor / Claude Code"
    author: "LOKI contributors"
    created: "2026-04-XX"             # First commit on the loki repo predates this fork; exact date in the project's .git history
    loom_version: "1.0.0"
    threat_context_default: "STANDARD"   # Untrusted firmware-image input is the primary risk surface; no network egress, no destructive operations, no credential handling

> **License:** Proprietary (per `pyproject.toml`).
> **Distribution status:** Alpha (per `pyproject.toml` `Development Status :: 3 - Alpha`).
> **Verification at fork:** 897 pytest pass, 6 deselected; mypy --strict clean across 176 source files; ruff lint + format clean; offscreen GUI smoke (`QT_QPA_PLATFORM=offscreen scripts/smoke_gui.py`) clean. Per HANDOFF.md as of the v0.1.0 fork date.

---

## 2. Subsystem Registry

Each entry summarizes a code module that already ships as part of v0.1.0 (status IMPLEMENTED) or a candidate subsystem flagged in HANDOFF.md / README.md as not-yet-built (status PROPOSED). Future Shuttle Protocol cycles mutate these entries through the standard CAST → DRAFT → TENSION → HARDEN → FRAY → BIND flow.

### Registry Entries

    subsystem_name: "models"
    codename: "Pydantic Data Models"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/loki-data-models/"
    description: "Pure-data type layer. Eight Pydantic v2 modules (~1100 source lines): enums.py (14 StrEnum types), firmware.py (FirmwareImage with deterministic image_id via uuid5(file_hash), ExtractedComponent, ExtractionError, ExtractionManifest), classification.py (AxisClassification, SignatureInfo, OverrideRecord, ClassificationRecord with auto-computed composite_confidence + needs_review flag), baseline.py (BaselineRecord, BaselineRegistry with three lookup methods, DeviationRecord, BaselineComparison with auto-computed summary counts by DeltaType), analysis.py (DeviationScore, FindingEvidence, FindingRecord, ActionRecord), reports.py (ReportSummary, ImageAnalysisReport with auto-computed severity distribution, FleetAnalysisReport), config.py (seven config sub-models + LokiConfig with from_yaml classmethod). Strict validation on construction; lossless JSON / YAML round-trip."
    threat_context: "MINIMAL_EXPOSURE"
    public_interface:
      exports:
        - "FirmwareImage, ExtractedComponent, ExtractionError, ExtractionManifest"
        - "AxisClassification, SignatureInfo, OverrideRecord, ClassificationRecord"
        - "BaselineRecord, BaselineRegistry, DeviationRecord, BaselineComparison"
        - "DeviationScore, FindingEvidence, FindingRecord, ActionRecord"
        - "ReportSummary, ImageAnalysisReport, FleetAnalysisReport"
        - "LokiConfig + 7 sub-config Pydantic models; from_yaml classmethod"
        - "14 StrEnum types: ComponentType, Vendor, SecurityPosture, Mutability, Severity, PostureRating, OutputFormat, LogLevel, etc."
      consumes: []
      produces: [type definitions + LOKI_NAMESPACE UUID5 namespace constant; consumed across every other subsystem]
    dependencies: []
    dependents: [extraction, classification, baseline, gui, cli, scripts, every test module]

    ---

    subsystem_name: "extraction"
    codename: "Extraction Pipeline"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/extraction-pipeline/"
    description: "Turns a firmware binary on disk into a validated ExtractionManifest containing zero or more ExtractedComponent records and any ExtractionError instances captured during processing. v1 covers Intel Flash Descriptor (full-flash) images, UEFI PI firmware volumes, raw FFS blobs, UEFI capsules, PCI option ROMs, and Intel CPU microcode update blobs. Tiano + LZMA-Custom decompression and inner-component emission supported. Coreboot CBFS, ARM Trusted Firmware, Apple iBoot, Android boot, and vendor-private capsule wrappers are explicitly deferred. Deterministic: same binary plus same config produces the same manifest minus timestamp fields. Component IDs are derived as uuid5(LOKI_NAMESPACE, f'{file_hash}:0x{offset:x}:{raw_hash}') so the same component carries the same ID across runs and across hosts. All 28 tasks per `specs/extraction-pipeline/tasks.md` ticked off."
    threat_context: "STANDARD"
    public_interface:
      exports: [extract_firmware, ExtractionResult, ExtractionConfig (re-exported from models), magic-byte format detection, inner-component carving]
      consumes: [firmware binary on disk; ExtractionConfig from models]
      produces: [ExtractionManifest (validated Pydantic), tools_available diagnostic dict, duration_seconds, per-component-type and per-error counts]
    dependencies: [models]
    dependents: [classification, gui (extraction worker), cli, scripts, tests]
    properties:
      - "Round-trip: same binary + same config → bit-equal manifest minus timestamps"
      - "Component-ID determinism: uuid5(LOKI_NAMESPACE, ...) is bit-equal across runs and hosts"
      - "Output-filename purity: filenames depend only on the deterministic component_id"
      - "No environmental side-channels: no env-var leaks into manifest output"
      - "Eleven Hypothesis-property tests pin the contract"

    ---

    subsystem_name: "baseline"
    codename: "GLEIPNIR Persistence"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/baseline-persistence/"
    description: "YAML-on-disk persistence layer for named baselines. One human-readable file per baseline. Atomic writes via temp-file-rename. mtime/size concurrency check on read-back. Typed exception hierarchy under loki.baseline.errors. Quarantine directory for malformed or schema-mismatched baselines. R2.8-R2.10 (background-thread loading) and R7.10-R7.11 (per-file progress + cancellation) honored at the GUI layer. CLI surface: `loki baseline list/show/import/export/delete`. All 22 tasks per `specs/baseline-persistence/tasks.md` ticked off."
    threat_context: "STANDARD"   # Untrusted YAML input from disk; PyYAML safe_load enforced; quarantine for malformed input.
    public_interface:
      exports: [BaselineStore, BaselineEnvelope, BaselineNotFoundError, BaselineSchemaError, BaselineConcurrencyError, save / load / list / delete operations, quarantine helpers]
      consumes: [BaselineRecord / BaselineRegistry from models; YAML files on disk]
      produces: [persisted YAML files; quarantined files in <root>/quarantine/; in-memory BaselineRecord instances on load]
    dependencies: [models]
    dependents: [gui (baseline load worker), cli, scripts, tests, analysis-engine (planned)]
    properties:
      - "Round-trip: BaselineRecord → YAML → BaselineRecord is structurally equal"
      - "Atomicity: write is observable as either complete or absent; no partial files"
      - "Concurrency safety: mtime + size check rejects stale reads after concurrent writes"
      - "Quarantine isolation: malformed input never overwrites a valid stored baseline"

    ---

    subsystem_name: "classification"
    codename: "Four-Axis Classifier"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/classification-pipeline/"
    description: "Turns ExtractedComponent records into validated ClassificationRecord instances along four taxonomic axes: type, vendor, security_posture, mutability. Library API at `from loki.classification import classify_components`. R5.6 dual-record contract: missing-bytes components emit both a ClassificationRecord and a corresponding error for the same component_id. Property 33–42 coverage at full Hypothesis depth. Public API surface includes ProgressEvent, ProgressCallback, CancellationToken for long-running runs. R6 v1 contract: `cve_matches` list always empty (CVE feed integration deferred to feeds subsystem). All 25 tasks per `specs/classification-pipeline/tasks.md` ticked off. Performance: R11.1 (4096 components × 1024 rules under 30s, actual ~3s) and R11.3 (4096 components × 256 MiB total under 60s, actual ~3s) both pass."
    threat_context: "STANDARD"
    public_interface:
      exports: [classify_components, ClassificationResult, ProgressEvent, ProgressCallback, CancellationToken; signature loaders; rule registry]
      consumes: [ExtractedComponent records; signature definitions; rule modules under loki/classification/rules/]
      produces: [ClassificationRecord per component; classification errors for components missing required bytes]
    dependencies: [models, extraction]
    dependents: [analysis-engine (planned), gui (classification view, planned), cli, tests]
    properties:
      - "Property 33–42: ten formal correctness properties from `specs/classification-pipeline/design.md`"
      - "R5.6 dual-record: missing-bytes input emits both record and error for same component_id"
      - "Determinism: same inputs + same rule registry → same ClassificationRecord set"
      - "Performance: 4096-component runs complete within published budgets"

    ---

    subsystem_name: "gui"
    codename: "Loki Desktop"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/gui-views/"
    design_path: "specs/gui-views/design.md"
    tasks_path: "specs/gui-views/tasks.md"
    description: "PyQt6 desktop surface formalized retroactively in specs/gui-views/ (OT-LK-004 RESOLVED 2026-06-02). Single QMainWindow + horizontal QSplitter (260 px navigation pane left, growable QTabWidget workspace right). Six read-only views (FirmwareImage, Extraction, Baseline, Analysis, ImageAnalysisReport, Fleet) render Pydantic models from the headless library APIs; the seventh view (ClassificationView, dead code) was removed in OT-LK-004 wave A. Three QThread-subclass workers (Extraction / BaselineLoad / Analysis) bridge synchronous library callbacks to Qt signals and accept cooperative cancellation (threading.Event for BaselineLoad and Analysis post-wave-A; bool flag for Extraction with a forward-tracked migration). 26 EARS-style requirements + 9 properties P77-P85. Smoke harness at scripts/smoke_gui.py (offscreen mode via QT_QPA_PLATFORM=offscreen)."
    threat_context: "STANDARD"   # PyQt6 surface running against operator-supplied firmware files; thread-safety via Qt signals; no network egress.
    public_interface:
      exports: [LokiApp / MainWindow / Workspace / BaselineLoadWorker / ExtractionWorker / AnalysisWorker (consumed only via main entry point)]
      consumes: [models, baseline, extraction, classification, analysis (read-only consumer); demo data under loki/gui/demo/]
      produces: [interactive desktop application; persisted window/splitter geometry via QSettings('LOKI', 'Desktop')]
    dependencies: [models, extraction, baseline, classification, analysis]
    dependents: [cli (`loki gui` subcommand), scripts/smoke_gui.py]

    ---

    subsystem_name: "cli"
    codename: "loki CLI"
    spec_status: "AD_HOC"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/cli/ (placeholder; no requirements/design/tasks files yet)"
    description: "Top-level CLI dispatcher at loki.cli:main, registered as the `loki` console script in pyproject.toml. v1 subcommands: `loki gui` (launch desktop), `loki extract --progress` (run extraction pipeline against a firmware file with progress reporting), `loki baseline list/show/import/export/delete` (baseline management). Classification CLI subcommand intentionally deferred to a future spec (HANDOFF.md candidate move #2)."
    threat_context: "STANDARD"
    public_interface:
      exports: [main entry point; subcommand dispatch]
      consumes: [user CLI args; loki.* subsystems]
      produces: [stdout/stderr text; persisted baseline files; ExtractionManifest output to stdout/disk]
    dependencies: [models, extraction, baseline, gui]
    dependents: []

    ---

    subsystem_name: "scripts"
    codename: "Smoke Harness"
    spec_status: "AD_HOC"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "(none — HANDOFF.md verification gate)"
    description: "scripts/smoke_gui.py — offscreen GUI smoke test that launches the LokiApp under QT_QPA_PLATFORM=offscreen, exercises the main window initialisation path, and exits cleanly. One of the four verification gates in the HANDOFF.md release contract."
    threat_context: "MINIMAL_EXPOSURE"
    public_interface:
      exports: []
      consumes: [gui]
      produces: [exit code 0 or non-zero (gates CI)]
    dependencies: [gui, models]
    dependents: []

    ---

    subsystem_name: "analysis-engine"
    codename: "Analysis Engine"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/analysis-engine/{requirements.md (BIND'd 2026-05-28; 1194 lines, 20 EARS), design.md (BIND'd 2026-05-28; 1211 lines, 11 sections, P43-P52), tasks.md (BIND'd 2026-05-28; 28/28 tasks ticked), requirements-tension-pass.md (audit trail)}"
    description: "IMPLEMENTED + APPROVED subsystem at v1.0.0. Library API at `from loki.analysis import analyze_image` produces FindingRecord and DeviationScore instances by comparing ClassificationRecord sets against BaselineRegistry entries. Twelve modules under loki/analysis/ (api, pipeline, version, matching, pairing, findings, scoring, posture, report, errors, timing, __init__). Six finding categories per v1: classification_mismatch, signature_regression, unexpected_component, missing_required_component, classification_gap, analysis_cancelled (Cancellation_Marker). PostureRating six-rule cascade per R17.5 post-HARDEN with G3-A catch-all + G4-B CRITICAL escalation. Determinism: same Target_Records + same Matched_Baseline + same AnalysisConfig + same ANALYSIS_VERSION produce bit-equal report modulo ImageAnalysisReport.timestamp + cancelled-run evidence.raw_indicators. Cooperative cancellation is a return-path, not a throw-path. AnalysisError exception hierarchy at loki/analysis/errors.py with four subclasses (AnalysisConfigError, BaselineNotFoundError, AnalysisInputError, AnalysisReportConstructionError). All ten Properties P43-P52 covered by Hypothesis tests; Properties 50+51 also pinned by static AST audits. R18.1 performance budget validated at 0.10s wall time for 1024+1024 components (~50x under the 5s budget). All 28 tasks per `specs/analysis-engine/tasks.md` ticked off."
    threat_context: "STANDARD"
    public_interface:
      exports: [analyze_image, AnalysisProgressEvent, AnalysisProgressCallback, AnalysisCancellationToken, ANALYSIS_VERSION, AnalysisError, AnalysisConfigError, BaselineNotFoundError, AnalysisInputError, AnalysisReportConstructionError]
      consumes: [ClassificationRecord sets from classification, BaselineRegistry entries from baseline (read-only), FirmwareImage + AnalysisConfig from caller]
      produces: [ImageAnalysisReport with embedded BaselineComparison, FindingRecord per emission category, DeviationScore on classification_mismatch findings]
    dependencies: [models, classification, baseline]
    dependents: [(planned) cli (loki analyze subcommand), gui (analysis view), feeds (read-only of implant rules)]
    properties:
      - "Property 43: Emitted ImageAnalysisReport is Pydantic-validated on return"
      - "Property 44: Baseline matching is deterministic per Match_Strategy"
      - "Property 45: Component_Pairing is a bijection-with-defects keyed by component_id"
      - "Property 46: Per-axis Axis_Score and Composite_Score are deterministic in [0.0, 1.0] / [0.0, 10.0]"
      - "Property 47: Two runs produce equal reports modulo timestamp (and modulo cancellation_at_index)"
      - "Property 48: ImageAnalysisReport round-trips through JSON losslessly"
      - "Property 49: PostureRating is a closed function of the finding list (HARDENED never emitted)"
      - "Property 50: Forbidden_Leakage_Field_Set is never logged (static AST audit + dynamic caplog audit)"
      - "Property 51: No environmental side channels (AST audit pins import discipline)"
      - "Property 52: Cancellation_Marker contract holds (sentinel UUID, last entry, deterministic finding_id)"
      - "R18.1 performance: 1024+1024 components under 5s wall time (actual ~0.10s)"

    ---

    subsystem_name: "classify-cli"
    codename: "Classification CLI"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/classification-cli/{requirements.md (HARDEN'd 2026-05-28; 891 lines, 13 EARS), requirements-tension-pass.md (audit + HARDEN status footer), design.md (BIND'd 2026-05-28; 980 lines, 12 main sections, P53-P58), tasks.md (BIND'd 2026-05-28; 25/25 tasks ticked across 7 waves)}"
    description: "IMPLEMENTED + APPROVED subsystem at v1.0.0. Adds a `loki classify` subcommand to the existing top-level `loki` console script that reads a previously-saved ExtractionManifest JSON document (file path or stdin via `-`), runs the classification library against a caller-supplied rules directory, and emits a single ClassificationResult JSON object on stdout plus a one-line counts summary on stderr. All 25 tasks across 7 waves landed: pytest baseline rose from 1211 to 1317 (+106 new tests including 1 slow-marker R11.1 wrapper-only timing test); mypy --strict source-file count rose from 217 to 240 (+1 source helper at loki/classify_helpers.py + 22 test modules). The seven design defaults D1-D7 are baked in (D1: helpers in classify_helpers.py rather than inline in cli.py; D2: _CancelFlag is a tiny @dataclass; D3: --debug sets propagate=False for the run; D4: TTY guard fires first when manifest is `-`; D5: exit code 4 covers both ClassificationPipelineError catchall and unexpected Exception; D6: helpers are module-private with single-leading-underscore names; D7: _load_manifest returns int on failure rather than raising). The R5.6 dual-record contract from classification-pipeline is preserved verbatim. Cooperative cancellation is mapped to SIGINT → Cancel_Flag → exit 130 via the library's existing return-path (not throw-path) cancellation contract. Properties P53-P58 pin the contract: P53 stdin-or-file equivalence, P54 exit-code totality on `{0, 2, 3, 4, 5, 6, 130}`, P55 Cancel_Flag-driven cancellation marker shape (deterministic in-process test) plus a separate example-based subprocess test for SIGINT end-to-end, P56 `--summary-only` produces zero stdout bytes, P57 stderr summary line emission discipline (exactly one on success/cancellation/per-component-error; zero on whole-run failure), P58 no-leakage on stderr (paired static AST audit + dynamic stderr-capture audit; component_id whitelisted on Progress_Line only). Closes OT-LK-003. Three judgment calls during implementation: model_validate_json over model_validate (Pydantic strict-mode JSON-aware path); fixture case-fix in tests/classify_cli/conftest.py (uppercase enum labels for real-library compatibility); subprocess SIGINT test uses sys.executable + -c form (no loki/__main__.py exists)."
    threat_context: "STANDARD"   # Untrusted manifest input via stdin or filesystem; no network egress, no credential handling, no destructive operations.
    public_interface:
      exports: []   # CLI is a script entry point. Helper functions in `loki/classify_helpers.py` are module-internal (single-leading-underscore pattern); not re-exported from `loki/__init__.py`.
      consumes: [ExtractionManifest from models (input ingestion), ClassificationConfig from models (constructed), classify_components + ProgressEvent + ClassificationResult + ClassificationError from classification (read-only), ClassificationConfigError + ClassificationRuleError + ClassificationPipelineError from classification (caught + mapped to exit codes)]
      produces: [stdout JSON (single indented `{records, errors}` object) on success or cancellation, stderr counts summary line on every run that produces a ClassificationResult, optional stderr Progress_Line stream under `--progress`, optional stderr DEBUG records under `--debug`, exit codes from the closed set {0, 2, 3, 4, 5, 6, 130}]
    dependencies: [models, classification]
    dependents: [cli (extension only — registers the new subcommand on the existing loki dispatcher; no new module is consumed-by)]
    properties:
      - "Property 53: Stdin-or-file equivalence (Hypothesis test, max_examples=25)"
      - "Property 54: Exit-code totality on {0, 2, 3, 4, 5, 6, 130} (parameterized test over typed-error hierarchy + input-validation modes)"
      - "Property 55: Cancel_Flag-driven cancellation contract (deterministic in-process test) + separate example-based subprocess test for SIGINT end-to-end"
      - "Property 56: `--summary-only` produces zero stdout bytes (Hypothesis, max_examples=50)"
      - "Property 57: Stderr_Summary_Line emission discipline (four-case parameterized: success / partial-cancellation / per-component-error / whole-run failure)"
      - "Property 58: No-leakage on stderr (paired static AST audit + dynamic stderr-capture audit; component_id whitelisted on Progress_Line only)"

    ---

    subsystem_name: "feeds"
    codename: "External Feeds"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/feeds/{requirements.md (HARDEN'd 2026-05-29; 1732 lines, 15 EARS, P59-P68), requirements-tension-pass.md (audit trail; G1-G7 + M1-M4 resolved), design.md (BIND'd 2026-05-29; 1029 lines, D1-D8), tasks.md (BIND'd 2026-05-29; 28 tasks, 8 waves)}"
    description: "PROPOSED subsystem with APPROVED spec triple (requirements + design + tasks all BIND'd). CVE feed integration (NVD-style) plus implant-rule signatures. Library API at `from loki.feeds import FeedRegistry` + `loki feeds refresh` CLI subcommand. Will populate ClassificationRecord.cve_matches (currently always [] per R6 in v1) by mapping (component, classification) pairs against NVD-derived CVE cache. Eight banked CAST decisions plus eight design defaults (D1 hash-pin trust anchor; D2 NVD JSON 2.0; D3 semver-heuristic version matching; D4 frozen dataclasses for result types; D5 10k-row INSERT batch; D6 no progress callback on refresh; D7 same-host redirect policy; D8 P59-P68). TENSION pass resolved all seven forward threads: G1-B dual-scheme wording deferred to design; G2 hand-rolled CPE parser; G3-C tiny built-in implant set; G4-A seven-code exit taxonomy {0,2,3,4,5,6,130}; G5 trust_anchor_path field name; G6 P59-P68 (ten properties); G7 six-audit FULL-context surface. Architecture: 12 modules under loki/feeds/ (registry, cache, refresh, trust, cpe, implants, models, errors, version, timing, cli, __init__) + builtin_implants/ directory with three starter rules. Six FULL-context audits (static+dynamic log, static+dynamic request, TLS verification, redirect policy). Implementation footprint estimate: ~800 source lines under loki/feeds/ + ~1800 test lines under tests/feeds/; one model-layer migration (trust_anchor_path: str | None = None); ten properties P59-P68. Pytest baseline expected to rise from 1317 to ~1500-1550."
    threat_context: "FULL"   # D8-B banked: outbound network egress to NVD + trust-anchor verification (signature or hash-pin). First FULL subsystem in the project; sets project-wide precedent.
    public_interface:
      exports: [(planned) FeedRegistry, FEEDS_VERSION, RefreshResult, RefreshStatus, CVELookupResult, ImplantRuleLookupResult, FeedsRefreshError, FeedsSignatureError, FeedsNetworkError, FeedsCacheError, FeedsConfigError]
      consumes: [(planned) NVD JSON feed snapshots over HTTPS; implant-rule signature files (built-in plus operator extension); FeedsConfig from models]
      produces: [(planned) cached SQLite feed database at <cache_path>/feeds.db with WAL mode; lookup results consumed by analysis-engine and any future analysis-cli]
    dependencies: [(planned) models]
    dependents: [(planned) classification (cve_matches population), analysis-engine]

    ---

    subsystem_name: "consumer-wiring"
    codename: "CVE Consumer Integration"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/consumer-wiring/{requirements.md (HARDEN'd 2026-05-29; 6 requirements, P69-P71), requirements-tension-pass.md (G1-G4 + M1-M3), design.md (BIND'd 2026-05-29; D1-D7), tasks.md (BIND'd 2026-05-29; 10/10 tasks, 4 waves)}"
    description: "IMPLEMENTED + APPROVED subsystem. Bridges the Feeds subsystem's cve_lookup API into classification (populates ClassificationRecord.cve_matches) and analysis (surfaces FindingEvidence.matched_cve + DeviationScore.cve_introduced). Opt-in via feeds: FeedRegistry | None kwarg on classify_components. The analysis engine reads cve_matches from the model field only (no loki.feeds import). CLI integration: loki classify --feeds-config. Properties P69-P71: CVE population determinism, CVE introduction detection correctness, backward compatibility. Configurable cve_score_bump (default 0.5, range [0.0, 5.0]) on AnalysisConfig."
    threat_context: "STANDARD"
    public_interface:
      exports: []
      consumes: [FeedRegistry from feeds, classify_components API surface, emit_classification_mismatch from analysis]
      produces: [populated cve_matches on ClassificationRecord, matched_cve + cve_introduced on analysis findings]
    dependencies: [models, classification, analysis-engine, feeds]
    dependents: []
    properties:
      - "Property 69: CVE population determinism (same registry + same components = same cve_matches)"
      - "Property 70: CVE introduction detection correctness (target novel CVEs = cve_introduced=True)"
      - "Property 71: Backward compatibility (feeds=None = identical to v1 behavior)"

    ---

    subsystem_name: "fleet-analysis"
    codename: "Fleet Analyzer"
    spec_status: "APPROVED"
    lifecycle_stage: "IMPLEMENTED"
    spec_path: "specs/fleet-analysis/{requirements.md (11 requirements, P72-P76), design.md (D1-D6), tasks.md (18/18 tasks ticked, 5 waves)}"
    description: "IMPLEMENTED + APPROVED subsystem at v1.0.0. Library API at `from loki.fleet import analyze_fleet` aggregates pre-produced ImageAnalysisReport instances across an operator-defined fleet into a FleetAnalysisReport. Eight modules under loki/fleet/ (api, aggregation, membership, models, errors, version, cli, __init__). Two membership modes: config-driven YAML and directory-scan. Five aggregation passes: posture distribution, common findings (normalized-title grouping), CVE rollup, outlier detection (median-based, skip <3), worst-image ranking (top-3 by risk_score). CLI: `loki fleet analyze --config|--dir`. Properties P72-P76 covered by Hypothesis tests. Performance: 100 images x 1000 findings in ~2s (budget: 10s). All 18 tasks per `specs/fleet-analysis/tasks.md` ticked off."
    threat_context: "STANDARD"
    public_interface:
      exports: [analyze_fleet, FLEET_VERSION, FleetError, FleetConfigError, FleetInputError, load_from_config, load_from_directory]
      consumes: [ImageAnalysisReport instances (pre-produced); fleet membership config (YAML or directory)]
      produces: [FleetAnalysisReport (validated Pydantic model)]
    dependencies: [models]
    dependents: [cli (loki fleet subcommand), gui (fleet view, planned)]
    properties:
      - "Property 72: Determinism (same inputs = same output modulo timestamp)"
      - "Property 73: Posture distribution totality (sum == image_count)"
      - "Property 74: Outlier subset (every outlier UUID in input set)"
      - "Property 75: Common finding threshold (fleet_count >= 2)"
      - "Property 76: Risk-score ordering stability (stable across runs)"

### Lifecycle Transition Rules

The standard WEAVE rules apply. Special note for this retroactively-initialized harness: the v0.1.0 fork records the four shipped subsystems as `IMPLEMENTED` with `spec_status: APPROVED` (because the specs/{loki-data-models,extraction-pipeline,baseline-persistence,classification-pipeline}/ triples are all complete with every task ticked off), the gui / cli / scripts as `IMPLEMENTED` with `spec_status: AD_HOC` (no formal spec; HANDOFF.md and code are the source of truth), and the three pending subsystems as `PROPOSED`. The natural progression for the pending three is:

- **analysis-engine:** has a stub `requirements.md`. Next move per HANDOFF.md: drive the requirements through DRAFT → TENSION → HARDEN → BIND in a dedicated session, then design + tasks in subsequent sessions.
- **feeds:** not yet specced. Will be CAST when CVE-population work begins (after analysis-engine ships, since analysis-engine consumes feed signatures).
- **fleet-analysis:** depends on analysis-engine; CAST after analysis-engine reaches IMPLEMENTED.

---

## 3. Dependency Graph

    edges:
      - source: "extraction"
        target: "models"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "baseline"
        target: "models"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "classification"
        target: "models"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "classification"
        target: "extraction"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
        notes: "Read-only consumer of ExtractedComponent shape; classification does not invoke extraction at runtime, only types from extraction's manifest."
      - source: "gui"
        target: "models"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "gui"
        target: "extraction"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "gui"
        target: "baseline"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "gui"
        target: "classification"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "cli"
        target: "models"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "cli"
        target: "extraction"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "cli"
        target: "baseline"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "cli"
        target: "gui"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
        notes: "`loki gui` subcommand entry point only; no other consumption."
      - source: "scripts"
        target: "gui"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "scripts"
        target: "models"
        established_by: "initial-v0.1.0"
        last_verified: "2026-05-28"
      - source: "analysis-engine"
        target: "models"
        established_by: "v0.4.0 (Wave 8 BIND)"
        last_verified: "2026-05-28"
      - source: "analysis-engine"
        target: "classification"
        established_by: "v0.4.0 (Wave 8 BIND)"
        last_verified: "2026-05-28"
        notes: "Read-only consumer of ClassificationRecord shape; analysis-engine does not invoke classification at runtime, only types from classification's record output."
      - source: "analysis-engine"
        target: "baseline"
        established_by: "v0.4.0 (Wave 8 BIND)"
        last_verified: "2026-05-28"
        notes: "Read-only consumer of BaselineRegistry / BaselineRecord; analysis-engine does not invoke baseline at runtime, only types and the registry's three lookup methods."
      - source: "classify-cli"
        target: "models"
        established_by: "v0.6.0 (Wave 6 implementation BIND)"
        last_verified: "2026-05-28"
        notes: "Read-only consumer of ExtractionManifest (input ingestion via Pydantic strict validation) and ClassificationConfig (constructed at runtime; passed to the library). Edge materialized at v0.6.0 — `loki/classify_helpers.py` consumes ExtractionManifest via `model_validate_json(text, strict=True)`; `loki/cli.py` constructs ClassificationConfig at runtime from the parsed args."
      - source: "classify-cli"
        target: "classification"
        established_by: "v0.6.0 (Wave 6 implementation BIND)"
        last_verified: "2026-05-28"
        notes: "Public-API consumer of classify_components plus ProgressEvent + ClassificationResult + ClassificationError + ClassificationPipelineError hierarchy. Edge materialized at v0.6.0 — the `_handle_classify` handler in `loki/cli.py` performs a lazy import of the public API and catches the typed-error hierarchy mapped to exit codes 4/5/6."
      - source: "cli"
        target: "classify-cli"
        established_by: "v0.6.0 (Wave 6 implementation BIND)"
        last_verified: "2026-05-28"
        notes: "Extension only — the existing `loki` console script's argparse dispatcher registers the `classify` subcommand from classify-cli via `_add_classify_subcommand(sub)` in `build_parser()`. Mirrors the existing cli → gui edge pattern. Edge materialized at v0.6.0."

      - source: "feeds"
        target: "models"
        established_by: "v0.9.0 (feeds implementation BIND)"
        last_verified: "2026-05-29"
      - source: "cli"
        target: "feeds"
        established_by: "v0.9.0 (feeds CLI surface)"
        last_verified: "2026-05-29"
        notes: "loki feeds refresh/status subcommands."
      - source: "consumer-wiring"
        target: "models"
        established_by: "v0.9.0 (consumer-wiring implementation BIND)"
        last_verified: "2026-05-29"
      - source: "consumer-wiring"
        target: "classification"
        established_by: "v0.9.0 (consumer-wiring implementation BIND)"
        last_verified: "2026-05-29"
        notes: "Extends classify_components with feeds/source_image kwargs."
      - source: "consumer-wiring"
        target: "analysis-engine"
        established_by: "v0.9.0 (consumer-wiring implementation BIND)"
        last_verified: "2026-05-29"
        notes: "Updates emit_classification_mismatch to surface cve_introduced/matched_cve."
      - source: "consumer-wiring"
        target: "feeds"
        established_by: "v0.9.0 (consumer-wiring implementation BIND)"
        last_verified: "2026-05-29"
        notes: "Classification pipeline calls FeedRegistry.cve_lookup at runtime."

      - source: "fleet-analysis"
        target: "models"
        established_by: "v1.0.0 (fleet-analysis implementation BIND)"
        last_verified: "2026-05-29"
        notes: "Read-only consumer of ImageAnalysisReport, FleetAnalysisReport, FindingRecord, ActionRecord, PostureRating, SeverityLevel, FirmwareImage, LOKI_NAMESPACE."
      - source: "cli"
        target: "fleet-analysis"
        established_by: "v1.0.0 (fleet CLI surface)"
        last_verified: "2026-05-29"
        notes: "loki fleet analyze subcommand."

The graph is a strict DAG. `models` is the leaf (no dependencies). `extraction` and `baseline` depend only on `models`. `classification` depends on `models` + `extraction` (types only, not runtime). `analysis-engine` depends on `models` + `classification` + `baseline` (types only, not runtime). `classify-cli` depends on `models` + `classification`. `feeds` depends on `models`. `consumer-wiring` depends on `models` + `classification` + `analysis-engine` + `feeds` (the cross-cutting integration surface). `fleet-analysis` depends on `models` only (reads pre-produced ImageAnalysisReport instances; no runtime import of analysis-engine or feeds). `gui` consumes the full set. `cli` orchestrates `extraction`, `baseline`, `gui`, `classify-cli`, `feeds`, and `fleet-analysis`. `scripts` is a CI gate over `gui`.

---

## 4. Evolution Log

    - date: "2026-06-02"
      version: "1.0.2"
      action: "OT-LK-004 RESOLVED — gui spec triple BIND-complete; subsystem registry flipped AD_HOC → APPROVED. Cleanup waves A+C landed pre-spec; QThread→QThreadPool migration deferred to a future OT-LK."
      author: "LOKI contributors"
      subsystems_affected: [gui (AD_HOC → APPROVED)]
      notes: |
        Single-conversation arc closing OT-LK-004 (GUI views
        formalization). Eight commits across this round:

        Pre-flight cleanup (so the spec describes the cleanest
        possible state of the GUI, not the AD_HOC v1.0.0 state):

        - 98c2110 — wave A: AnalysisWorker gets a threading.Event
          cancellation token + typed-exception error contract
          mirroring BaselineLoadWorker; MainWindow.closeEvent now
          cancels and joins the analysis worker too. ClassificationView
          (loki/gui/views/classification_view.py, 83 lines) deleted —
          dead code never opened from MainWindow; its rendering
          surface is now covered by AnalysisView. Verification
          preserved: 1678 pytest pass, mypy --strict 0 errors / 313
          source files (was 314), ruff + format clean, smoke clean.
        - e138baf — wave C: AnalysisView fills in every public
          field on ImageAnalysisReport (recommended_actions table,
          baseline_comparison sub-section with summary + deviation
          tables, full per-finding evidence: classification_record
          axis breakdown, deviation_score per-axis, matched_rule /
          CVE / signature, raw_indicators, finding_id). FleetView
          renders FleetAnalysisReport.recommended_actions. Both
          changes are additive and read-only; no model changes;
          test count preserved.

        Spec triple (this round, three waves of agent work):

        - DRAFT panel: 3 isolated agents wrote DRAFT requirements
          from different angles (model-fidelity-first,
          threat-context-first, operator-experience-first). Judge
          agent picked Draft 1 (model-fidelity) as winner on every
          primary criterion (CAST faithfulness; EARS format match
          with specs/analysis-engine/requirements.md; full
          coverage of survey-identified formalization risks; richest
          P77-P85 property allocation; file:line citation density;
          appropriate length at ~26 requirements). Grafted ~10
          concrete details from runners-up (subsystem-boundary
          import audit; QApplication identity quad; worker emit-
          exclusivity invariant; SHA-256 chunk-size; closeEvent
          ordering specifics; concrete extraction / analysis config
          defaults).
        - TENSION panel: 5 isolated lenses (correctness-vs-impl;
          threat-context-completeness; cross-subsystem-contract-
          adherence; EARS-format-compliance; operator-honest-
          framing). Each found gaps the others didn't. Cross-lens
          consensus surfaced three high-value items (BaselineRegistry
          term mismatch; closeEvent / cancellation defensive
          programming; stale R10 cross-reference) that each got
          applied to multiple requirements.
        - HARDEN: tension-pass document at
          specs/gui-views/requirements-tension-pass.md (292 lines)
          consolidates all five lenses; HARDEN footer records
          audit-items-applied count plus three new forward-tracked
          items added to Requirement 24 (single-window-only
          ratification; worker BaselineStore re-load; help-menu
          single-entry closure) and three new CI gates added to
          Requirement 26 (loki.cli import audit; processEvents
          audit; network-egress import-time audit).
        - DESIGN BIND: specs/gui-views/design.md (695 lines) covers
          subsystem positioning, architecture diagram, view ↔ model
          binding table, worker contracts, action surface +
          enablement matrix, persistence / closeEvent lifecycle,
          threading model with D2 forward-tracked migration
          rationale, test surface, P77-P85 properties with
          Validates-Requirements mapping, three open questions Q1-Q3,
          and five revertable design defaults.
        - TASKS BIND: specs/gui-views/tasks.md (685 lines) groups
          ~17 tasks into five waves: (1) acceptance verification
          run-and-confirm against the running GUI per requirement;
          (2) test coverage gap fills (the survey-identified
          AnalysisWorker test gap; new tab-key uniqueness +
          QSettings round-trip + analysis cancel idempotence
          properties P77-P79); (3) forward-tracked refactor
          candidates (D2 QThreadPool, ExtractionWorker bool→Event
          migration, D11 preferences UI, D12 export, Action_Function
          Protocol extraction, Briefcase docs/icons/release path
          completions) — each becomes its own OT-LK after spec
          ships; (4) doc refresh (README At-a-Glance row, CHANGELOG
          GUI section); (5) final acceptance gate.

        Operator-banked CAST decisions (D1-D15) recorded in the
        spec triple so future contributors don't relitigate. Three
        consequential ones to highlight:

        - D2 threading model: ratifies QThread-subclass-per-task
          for v1; QObject.moveToThread() / QThreadPool migration is
          forward-tracked in Requirement 24 and tasks.md Wave 3.
        - D3 cancellation primitive: threading.Event uniformly,
          except ExtractionWorker still uses a bool flag (forward-
          tracked nit; AnalysisWorker conformed in wave A).
        - D11 / D12: configuration UI and export surface explicitly
          deferred — v1 GUI is default-pipeline-only. CLI is the
          operator-config surface for v1.

        Subsystem registry: gui spec_status AD_HOC → APPROVED;
        spec_path / design_path / tasks_path now point at the real
        spec files; description rewritten to reflect the formalized
        surface and waves A+C. Dependencies list extended with
        analysis (was implicit before; now explicit).

        OT-LK-004 status: OPEN — formalization round needed →
        RESOLVED. The 11 risks the survey flagged for the spec-triple
        writer are all addressed in the requirements doc (Action_
        Function MainWindow protocol in R13; Tab_Key namespacing in
        R9; UI-level concurrency in R15; QSettings org/domain locking
        in R18; AnalysisWorker test gap in R21+R26+Wave 2 task).

        Forward-tracked threads remain open: OT-LK-005 (baseline
        schema migration tool) unchanged; OT-LK-006 (ExtractionManifest
        schema migration) unchanged. New forward threads from the
        gui spec triple — to be opened as separate OT-LK entries when
        prioritised: QThreadPool migration; ExtractionWorker Event
        migration; preferences dialog; export surface; Action_Function
        Protocol extraction; Briefcase release-path completions;
        Linux AppImage qmake build gap (already tracked under v1.0.0
        release notes).

        Changed files in this round (this commit only — waves A
        and C committed separately):

        - specs/gui-views/requirements.md (new, 1725 lines, 26
          requirements + properties P77-P85).
        - specs/gui-views/requirements-tension-pass.md (new, 292
          lines, 5-lens TENSION audit + HARDEN footer).
        - specs/gui-views/design.md (new, 695 lines).
        - specs/gui-views/tasks.md (new, 685 lines, ~17 tasks
          across 5 waves).
        - loom-loki.md (this file): gui registry entry flipped to
          APPROVED + IMPLEMENTED with real spec / design / tasks
          paths; this evolution-log entry appended; OT-LK-004 status
          updated below.
        - STATE.md (gitignored; not committed): refreshed.

        No source code changes in this round (waves A + C handle
        those separately; spec triple is documentation-only).

      verification:
        - "pytest -q: 1678 passed, 13 deselected (preserved across the round)"
        - "mypy --strict loki tests scripts: 0 errors / 313 source files"
        - "ruff check + ruff format --check loki tests scripts: clean"
        - "QT_QPA_PLATFORM=offscreen scripts/smoke_gui.py: clean"
        - "spec format: 27 #### Acceptance Criteria headings; 0 bare-bold AC blocks; 9 P-NN property allocations P77-P85"

    - date: "2026-06-02"
      version: "1.0.1"
      action: "v1.0.0 release prep: STATE.md refresh + .venv rebuild + AD_HOC-discovery audit; OT-LK-004 GUI views and native packaging found IMPLEMENTED + AD_HOC."
      author: "LOKI contributors"
      subsystems_affected: []
      notes: |
        Documentation-only round preparing the v1.0.0 release tag
        against the platform that landed at v1.0.0 in the prior
        evolution-log entry (2026-05-29). No source code changes;
        no spec changes; no test changes.

        Survey findings (worth recording so future sessions have
        the corrected picture):

        1. .venv rebuild. The prior .venv carried a stale
           interpreter shebang (`/Users/daborond/Projects/loki/`)
           against the actual repo path
           (`/Users/daborond/Sloptropy/loki/`). This was the
           workaround referenced in OT-LK-001 notes
           ("workaround is `.venv/bin/python -m <tool>`"). Rebuilt
           with `python3.12 -m venv .venv` + `pip install -e
           '.[dev]'`; direct `.venv/bin/{pytest,mypy,ruff}`
           invocations now work.

        2. OT-LK-004 (GUI views) is largely DONE as AD_HOC. The
           harness §5 status said "OPEN — depends on
           classification-cli or analysis-engine" and "v1 runs
           headless". Reality at HEAD (commit 1bae4f7): the
           `loki/gui/` package contains 1879 lines including a
           950-line `main_window.py`, a `navigation.py`, a public
           `loki.gui.app.run()` entry point, and seven views:
           `analysis_view.py`, `baseline_view.py`,
           `classification_view.py`, `extraction_view.py`,
           `firmware_image_view.py`, `fleet_view.py`,
           `report_view.py`. The QThread workers
           (`analysis_worker.py`, `baseline_load_worker.py`,
           `extraction_worker.py`) wire the views to the headless
           library APIs. The CLI exposes `loki gui` (subcommand
           in `loki/cli.py:_handle_gui`). Smoke harness
           (`scripts/smoke_gui.py`) clean under
           `QT_QPA_PLATFORM=offscreen`. The subsystem registry
           already records `gui` as IMPLEMENTED + AD_HOC; what's
           stale is OT-LK-004's wording. OT-LK-004 status amended
           below: the OPEN portion is FORMALIZATION (write the
           spec triple against the existing implementation so it
           transitions from AD_HOC → APPROVED) plus any
           gap-features that audit surfaces, NOT greenfield
           implementation.

        3. Native packaging is largely DONE as AD_HOC. Briefcase
           is configured in `pyproject.toml [tool.briefcase]`
           (bundle `dev.loki`; macOS / windows / linux app
           targets; startup_module `loki.gui`). `scripts/
           build_app.sh` shells Briefcase with optional `--sign`
           flag. A 162-MB DMG ships at `dist/Loki-0.1.0.dmg`
           dated 2026-05-29. What's missing: `[project].version`
           and `[tool.briefcase].version` are still `0.1.0`
           rather than `1.0.0`; Apple developer-certificate
           codesigning + `xcrun notarytool` notarization not
           wired into a CI pipeline; release-tag-triggered
           packaging not yet automated.

        4. README claims overstate AD_HOC reality. The "At a
           Glance" Packaging row reads "macOS .app + DMG,
           Windows, Linux AppImage" which is true for the
           macOS DMG that exists but has not yet been verified
           on Windows / Linux runners. The "Subsystems" table
           includes a `loki gui` row which is accurate. Overall
           the README is closer to truth than the harness was;
           STATE.md was the staler artifact (now refreshed
           2026-06-02).

        Operator decision (2026-06-02): pursue v1 in three
        sequenced phases — (a) library v1 release artifacts
        (this round + tag), (b) OT-LK-004 GUI formalization
        spec triple, (c) packaging completion (codesign +
        notarize + CI). Each is its own focused conversation
        per the project's "spec drafting is its own
        conversation" rule.

        OT-LK-004 status amended below from "OPEN — depends on
        classification-cli or analysis-engine" to "OPEN —
        formalization round needed (GUI is IMPLEMENTED + AD_HOC
        at HEAD)".

        Changed files in this round:

        - STATE.md (gitignored; not committed): refreshed to
          current pytest count, mypy file count, subsystem
          summary, and operator's banked v1 sequence.
        - loom-loki.md (this file): this evolution-log entry
          appended; OT-LK-004 status amended.

        No source code, spec, or test changes. Verification at
        HEAD (commit 1bae4f7) preserved per the gates
        recorded below.

      verification:
        - "pytest -q: 1678 passed, 13 deselected (28.4s)"
        - "mypy --strict loki: 0 issues across 116 source files"
        - "mypy --strict loki tests scripts: 0 issues across 314 source files"
        - "ruff check + ruff format --check loki tests scripts: clean"
        - "QT_QPA_PLATFORM=offscreen scripts/smoke_gui.py: clean"
        - "pytest -m slow --co: 13 performance tests collected"

    - date: "2026-05-29"
      version: "1.0.0"
      action: "Fleet analysis engine IMPLEMENTED (18/18 tasks); ninth IMPLEMENTED + APPROVED subsystem; harness promoted to v1.0.0"
      author: "LOKI contributors"
      subsystems_affected: [fleet-analysis (PROPOSED -> IMPLEMENTED + APPROVED)]
      notes: |
        Single-session implementation of the fleet analysis engine
        across all five waves (18 tasks). The subsystem was already
        at Wave 1 (scaffold + exceptions) from a prior session;
        this session completed Waves 2-5.

        Implementation:
        - Wave 2: config-driven + directory-scan membership loading
        - Wave 3: five aggregation functions (posture distribution,
          common findings with UUID normalization, CVE rollup,
          outlier detection with median-based threshold, worst-image
          ranking with risk_score formula) + FleetRiskScore internal
          model
        - Wave 4: analyze_fleet public API + loki fleet analyze CLI
        - Wave 5: Hypothesis properties P72-P76, performance test
          (2.09s vs 10s budget), E2E smoke test, determinism test,
          documentation refresh

        Harness promoted to v1.0.0: all nine planned subsystems
        now ship at IMPLEMENTED + APPROVED. The platform is
        feature-complete for v1.

      verification:
        - "pytest -q: 1648 passed, 13 deselected"
        - "mypy --strict: 0 issues across 302 source files"
        - "ruff check + ruff format --check: clean (302 files)"
        - "pytest -m slow: 13 performance tests (12 pass; 1 pre-existing baseline-perf)"
        - "Public API: from loki.fleet import analyze_fleet, FLEET_VERSION works"
        - "CLI: loki fleet analyze --help exits 0"

    - date: "2026-05-29"
      version: "0.9.0"
      action: "Feeds subsystem IMPLEMENTED (28/28 tasks) + consumer-wiring subsystem IMPLEMENTED (10/10 tasks); two new IMPLEMENTED + APPROVED subsystems in one session"
      author: "LOKI contributors"
      subsystems_affected: [feeds (PROPOSED -> IMPLEMENTED), consumer-wiring (new; IMPLEMENTED + APPROVED)]
      notes: |
        Single-session arc implementing the feeds subsystem (Waves 1-8,
        all 28 tasks) and the consumer-wiring integration spec (Waves
        1-4, all 10 tasks).

        Feeds subsystem (OT-LK-002 closed):
        - Library API: FeedRegistry with cve_lookup, implant_rule_lookup, refresh
        - CLI: loki feeds refresh/status with {0,2,3,4,5,6,130} exit codes
        - Six FULL-context security audits (static+dynamic log/request/TLS/redirect)
        - Properties P59-P68 (10 Hypothesis properties)
        - Performance: R12.1 (50ms/200k CVEs), R12.2 (5ms/1024 rules), R12.3 (60s/100MiB)
        - SQLite WAL cache with atomic refresh and 10k-row INSERT batches
        - Trust-anchor resolution (hash-pin D1) with operator override
        - Same-host redirect policy (D7), TLS CERT_REQUIRED

        Consumer-wiring subsystem:
        - classify_components gains feeds/source_image kwargs
        - _populate_cve_matches helper with graceful degradation
        - emit_classification_mismatch surfaces matched_cve (lex-first) + cve_introduced
        - cve_score_bump (configurable, default 0.5) applied before PostureRating cascade
        - loki classify --feeds-config flag
        - Properties P69-P71
        - TENSION pass surfaced G1-G4 + M1-M3; all resolved at HARDEN

        Verification:
        - pytest: 1583 passed, 12 deselected (was 1317 pre-session)
        - mypy --strict: 0 issues across 283 source files
        - ruff check + format: clean
        - 12 slow-marker performance tests pass

      verification:
        - "pytest -q: 1583 passed, 12 deselected"
        - "mypy --strict: 0 issues across 283 source files"
        - "ruff check + ruff format --check: clean"
        - "pytest -m slow: 11 of 12 pass (1 pre-existing baseline-perf failure)"

    - date: "2026-05-29"
      version: "0.8.0"
      action: "OT-LK-002 spec triple complete: feeds subsystem requirements HARDEN'd + design BIND'd + tasks BIND'd in a single session; spec_status DRAFT -> APPROVED. Implementation phase opens."
      author: "LOKI contributors"
      subsystems_affected: [feeds (spec_status DRAFT -> APPROVED; spec triple complete)]
      notes: |
        Single-session arc completing the feeds spec triple. The
        TENSION pass (already written in a prior round) was resolved
        with all eight recommendations accepted, then HARDEN
        amendments applied to requirements.md, followed by design.md
        BIND and tasks.md BIND in the same session.

        HARDEN amendments to requirements.md (1712 -> 1732 lines):

        - G1-B: dual-scheme trust wording stays; deferred to design.
        - G2: R6.9 added — hand-rolled CPE parser at loki/feeds/cpe.py.
        - G3-C: R7.10 added — tiny built-in set; no fixed cadence.
        - G4-A: R11.7 rewritten — seven-code closed set {0,2,3,4,5,6,130}.
        - G5: R4.4 extended — empty-string "" treated as None.
        - G6: R15.8-15.10 added — P66 inline-refresh trigger, P67
          cache atomicity, P68 tiered failure branching.
        - G7: R13.6 rewritten — six audits (TLS + redirect added).
        - M1: R14.5 cleaned up ("or its equivalent" removed).
        - M4: R13.1 reformatted as numbered bullets.
        - Forward threads section rewritten as "resolved" summary.

        design.md (1029 lines, 8 deferred decisions D1-D8):

        - Module layout: 12 modules under loki/feeds/ + builtin_implants/.
        - Public API: FeedRegistry class with from_config, refresh,
          cve_lookup, implant_rule_lookup.
        - Result types: frozen dataclasses (D4).
        - Trust anchor: hash-pin scheme (D1); stdlib hashlib only.
        - Cache: SQLite WAL; CacheDB class with atomic refresh.
        - CPE parser: hand-rolled minimal (HARDEN G2).
        - Implant rules: YAML-based; three built-in starters.
        - CLI: loki feeds refresh with seven exit codes.
        - Six audits: log (static+dynamic), request (static+dynamic),
          TLS verification, redirect policy.
        - Ten properties P59-P68.

        tasks.md (410 lines, 28 tasks, 8 waves):

        - Wave 1 (1-4): scaffold, models, exceptions, config migration.
        - Wave 2 (5-8): CPE parser, implant loader/matcher, trust resolver.
        - Wave 3 (9-10): CacheDB (SQLite WAL), timing.
        - Wave 4 (11-12): refresh logic, FeedRegistry (library API).
        - Wave 5 (13-16): CLI surface, convenience helpers.
        - Wave 6 (17-23): six FULL-context audits (parallelizable).
        - Wave 7 (24-26): Properties P59-P68, performance, smoke.
        - Wave 8 (27-28): documentation, final gate.

        Implementation cadence target: ~8 sessions, one wave per
        session. Mirrors analysis-engine's eight-wave plan.

        Open thread state changes:

        - OT-LK-002: status moved from "requirements DRAFT shipped"
          to "spec triple complete; implementation phase opens."

        Verification: doc-only round. Test baseline carried forward
        unchanged at 1317 pytest pass / 9 deselected; mypy --strict
        clean across 240 source files; ruff clean.

      verification:
        - "Doc-only round; pytest re-run confirmed 1317 pass / 9 deselected"
        - "spec format diagnostics on requirements.md, design.md, tasks.md: clean"
      changed_files:
        - "specs/feeds/requirements.md (HARDEN amendments; 1712 -> 1732 lines)"
        - "specs/feeds/design.md (new; 1029 lines, D1-D8)"
        - "specs/feeds/tasks.md (new; 410 lines, 28 tasks, 8 waves)"
        - "loom-loki.md (this file; v0.7.0 -> v0.8.0; feeds entry updated; evolution-log entry added)"

    - date: "2026-05-29"
      version: "0.7.0"
      action: "OT-LK-002 requirements DRAFT shipped: feeds subsystem requirements.md drafted against the eight banked CAST decisions; spec_status PROPOSED -> DRAFT. Doc-only update; no source code changed."
      author: "LOKI contributors"
      subsystems_affected: [feeds (PROPOSED entry; spec_status flipped PROPOSED -> DRAFT; spec_path populated; threat_context flipped STANDARD -> FULL per banked D8-B)]
      notes: |
        Single-round arc continuing the OT-LK-002 spec triple
        drafting against the eight banked CAST decisions from the
        v0.6.1 round. The DRAFT lands as 1712 lines of
        requirements.md with 15 EARS requirements covering the
        full feeds subsystem surface plus the FULL-threat-context
        no-leakage discipline (the project's first FULL subsystem).

        DRAFT contents at a glance:

        - 15 EARS requirements covering: library API surface (R1);
          NVD as the only feed source in v1 (R2); cache layout +
          indexing + cache-age inline refresh (R3); trust-anchor
          resolution + signed-feed validation (R4); tiered
          refresh-failure semantics (R5); CPE-2.3 lookup shape +
          result determinism (R6); hybrid implant-rule surface
          (R7); FULL threat-context discipline on network requests
          (R8); cooperative cancellation on the refresh path (R9);
          determinism + round-trip on lookup paths (R10); `loki
          feeds refresh` CLI surface (R11); performance bounds on
          refresh + lookup paths (R12); no-leakage discipline on
          log records + CLI lines + request paths (R13); versioning
          + Cache_Metadata schema (R14); property-based test
          contracts (R15).

        - Properties P59 through P65 (seven properties): P59
          lookup determinism; P60 implant-lookup determinism; P61
          HTTPS-request leakage; P62 Cancel_Flag-driven
          cancellation contract (deterministic in-process test
          plus separate example-based subprocess test for SIGINT
          end-to-end, mirroring classify-cli's P55 split); P63
          stderr summary line emission discipline; P64 no-leakage
          on stdout and stderr; P65 CVE-result sort stability.
          Property numbering picks up at P66 for the next
          subsystem.

        - Forward threads section at the tail enumerates the
          seven items deferred to TENSION pass: NVD
          signing-vs-hash-pinning verification (D4-D's
          implementation shape; NVD-API-key support flagged here
          as part of the same thread); CPE parser
          dependency-vs-handroll (`python-cpe` PyPI dependency vs.
          minimal hand-rolled parser); bundled-implant-rule
          maintenance cadence; exit-code taxonomy for D5-D's
          tiered failure modes (mirroring classify-cli's
          {0, 2, 3, 4, 5, 6, 130} pattern); FeedsConfig model
          migration (signing_key_path: str | None = None); P59-P65
          property-numbering allocation confirmation;
          FULL-context audit work (paired AST + dynamic-capture
          audits on log records and HTTPS requests).

        Two precedents reinforced this round:

        - The Forward-threads section pattern from
          analysis-engine and classification-cli is reused
          here at the requirements DRAFT level (rather than
          deferred to TENSION pass exclusively). Forward threads
          surface during the DRAFT writing whenever a
          requirement-level decision implies a downstream
          implementation choice that the TENSION pass owns.

        - The Acceptance-Criteria heading discipline (`####
          Acceptance Criteria` on its own line) is preserved
          throughout; spec format diagnostics on the new
          requirements.md are clean.

        Subsystem registry impact:

        - feeds entry's spec_status flipped PROPOSED -> DRAFT.
        - feeds entry's threat_context flipped STANDARD -> FULL
          per banked D8-B; the project's first FULL subsystem.
          Audit-trigger flag is now active for any feeds work
          going forward.
        - feeds entry's description rewritten to reference the
          eight banked CAST decisions verbatim plus the seven
          forward threads. Implementation-footprint estimate
          recorded (~600 source lines + ~1500 test lines).
        - spec_path populated with the new file location.
        - dependency-graph edges NOT yet materialized (no source
          code touched). The (planned) edges feeds -> models and
          feeds -> classification (dependents-side cve_matches
          population) are the same shape implied by the v0.6.1
          CAST round; they materialize on Wave-N implementation
          BIND, not on this DRAFT.

        Open thread state changes:

        - OT-LK-002: status moved from "CAST round complete; eight
          design dimensions banked; spec triple drafting deferred"
          to "requirements DRAFT shipped against the eight banked
          CAST decisions; TENSION pass next; spec triple BIND
          remaining."
        - OT-LK-002 priority unchanged at MEDIUM.

        Verification: doc-only round across the new
        requirements.md and the harness updates. No pytest, mypy,
        or ruff re-runs needed (no source code touched). spec format
        Format diagnostics on requirements.md: clean. Test baseline
        carried forward unchanged at 1317 pytest pass / 9
        deselected; mypy --strict clean across 240 source files;
        ruff check + ruff format --check clean.

      verification:
        - "Doc-only round; no pytest, mypy, or ruff re-runs needed (no source code touched)"
        - "spec format diagnostics on requirements.md: clean (verified post-write)"
        - "Diagnostics on loom-loki.md: clean (verified post-edit)"
      changed_files:
        - "loki/specs/feeds/requirements.md (new; 1712 lines, 15 EARS, P59-P65, Forward-threads section)"
        - "loom-loki.md (this file; v0.6.1 -> v0.7.0; feeds subsystem entry updated; OT-LK-002 entry updated; new evolution-log entry added)"

    - date: "2026-05-28"
      version: "0.6.1"
      action: "OT-LK-002 CAST round complete: eight design dimensions banked for the future feeds subsystem spec triple. Doc-only update; no source code changed."
      author: "LOKI contributors"
      subsystems_affected: [feeds (PROPOSED entry; CAST decisions banked for future spec triple)]
      notes: |
        Single-round arc against the project's "spec drafting is its
        own conversation" rule. Per the operator's explicit choice
        of B-disciplined over B-fast, this conversation runs ONLY
        the CAST round; the requirements DRAFT and onward live in
        future sessions.

        The CAST conversation walked eight design dimensions
        (D1, D1a, D2-D8) one at a time, with the operator banking
        each in sequence. The operator opened the round by
        explicitly resolving the prior session's open cadence
        question (daily refresh + on-demand override); the agent
        then identified seven additional open dimensions that the
        feeds spec triple needs answered before requirements DRAFT
        can land cleanly.

        Banked decisions (full text in §5 OT-LK-002 entry):

        - D1   Refresh-trigger surface  : daily-default + on-demand
        - D1a  How daily fires          : D1a-C cadence-aware (no scheduler)
        - D2   Cache layout             : D2-C SQLite + WAL mode
        - D3   Feed sources in v1       : D3-A NVD only
        - D4   Signed-feed validation   : D4-D hybrid trust anchor
        - D5   Refresh-failure semantics: D5-D tiered (sig→fail; net→warn)
        - D6   Match shape              : D6-A CPE matching
        - D7   Implant-rule surface     : D7-C hybrid (builtin + extension)
        - D8   Threat context           : D8-B FULL (precedent-setting)

        Seven forward threads surfaced for TENSION-pass resolution
        once requirements DRAFT lands (full text in §5):

        1. NVD signing-vs-hash-pinning verification.
        2. CPE parser dependency-vs-handroll.
        3. Bundled-implant-rule maintenance cadence.
        4. Exit-code taxonomy for D5-D's tiered failure modes.
        5. `FeedsConfig` model migration (one new optional field).
        6. Property numbering allocates P59 for feeds.
        7. FULL-context audit work (network-request leakage audits).

        Two precedents set this round:

        - D8-B is the first FULL-threat-context subsystem in the
          project. The audit-trigger flag becomes meaningful from
          this point forward; future subsystems with network
          egress or trust-anchor verification inherit FULL by
          default unless explicitly argued otherwise.
        - The D4-D + D7-C "package-default + operator-extension"
          hybrid pattern is reused twice in this CAST: once for
          the trust anchor, once for the implant-rule surface.
          This is consistent with classify-cli's revertable-
          defaults discipline (D1-D7 in the classify-cli design)
          and likely sets the project's preferred pattern for
          "ship a working out-of-box default but allow operator
          override."

      verification:
        - "Doc-only round; no pytest, mypy, or ruff re-runs needed (no source code touched)"
        - "Diagnostics on loom-loki.md: clean (verified post-edit)"
      changed_files:
        - "loom-loki.md (this file; v0.6.0 -> v0.6.1; OT-LK-002 entry rewritten with banked CAST; new evolution-log entry added)"

    - date: "2026-05-28"
      version: "0.6.0"
      action: "OT-LK-003 classification-cli implementation BIND'd: Waves 1-7 of specs/classification-cli/tasks.md ticked off; spec triple transitioned from DRAFT/BIND state to APPROVED + IMPLEMENTED."
      what_changed:
        - "All 25 tasks across 7 waves implemented and verified"
        - "loki/classify_helpers.py created (private-helper module per D1 + D6)"
        - "loki/cli.py extended with _add_classify_subcommand and _handle_classify"
        - "tests/classify_cli/ test tree: 22 test modules + 1 helper module + 1 conftest"
        - "Pytest count: 1211 -> 1317 (+106 new tests including 1 slow-marker)"
        - "Properties P53-P58 pinned: stdin/file equivalence, exit-code totality, cancellation contract, --summary-only zero stdout, summary-line emission discipline, no-leakage paired audits"
        - "Seven D-defaults baked in: D1 (helpers in classify_helpers.py), D2 (_CancelFlag dataclass), D3 (--debug propagate=False), D4 (TTY guard fires first), D5 (exit 4 catches both pipeline catchall + unexpected Exception), D6 (helpers module-private), D7 (_load_manifest int-on-failure)"
        - "Three judgment calls during implementation surfaced and accepted: model_validate_json over model_validate (Pydantic strict-mode JSON-aware path); fixture case-fix in tests/classify_cli/conftest.py (uppercase enum labels for real-library compatibility); subprocess SIGINT test uses sys.executable + -c form (no loki/__main__.py exists)"
      verification:
        - "pytest -q: 1317 passed, 9 deselected"
        - "pytest -m slow: includes the new R11.1 wrapper-only timing test (cli_overhead under 200ms)"
        - "mypy --strict: 0 issues across 240 source files"
        - "ruff check + ruff format --check: clean"
      notes:
        - "Wave dispatch via orchestrator pattern: each wave dispatched as a single subagent invocation; the orchestrator preserved context and verified gates between waves"
        - "Three operator-approved deviations from spec drafting in the prior session compounded; this implementation session honored the wave-by-wave discipline (one wave = one focused round)"
        - "OT-LK-003 closed; OT-LK-006 (ExtractionManifest schema migration forward thread) remains open for a future spec"

    - date: "2026-05-28"
      version: "0.5.0"
      action: "OT-LK-003 classification-cli spec triple advanced through CAST → DRAFT → TENSION → HARDEN → design BIND in a single session"
      author: "LOKI contributors"
      subsystems_affected: [classify-cli (new PROPOSED entry), classification (consumed read-only), models (read-only consumer of ExtractionManifest, ClassificationConfig)]
      notes: |
        Spec triple work landed across one extended session against
        the project's "spec drafting is its own conversation" rule.
        Operator deviation explicitly approved and recorded in
        `specs/classification-cli/requirements-tension-pass.md`
        HARDEN footer.

        Round-by-round:

        1. CAST conversation — D1-D12 design dimensions presented
           with three-to-four options each. Operator banked
           recommendations: D1-A (manifest-only positional with
           UNIX composition), D2-B (file-or-stdin via `-`),
           D3-A (single indented JSON object on stdout),
           D4-A+C (counts + needs_review tally on stderr summary
           line), D5-A (`--progress` per-event lines on stderr),
           D6-A (SIGINT handler flips Cancel_Flag, exit 130 via
           cooperative cancellation), D7-A (mandatory
           `--rules-path`), D8-B (default taxonomy_version
           `"1.0.0"`), D9-B (no `confidence_threshold` flag in
           v1; pin to 0.6 internally), D11 (closed exit-code set
           {0, 2, 3, 4, 5, 6, 130}), D12-A (spec dir name
           `classification-cli`). Plus two new flags introduced
           by operator request: `--debug` (scoped to
           loki.classification logger) and `--summary-only`
           (suppresses stdout JSON; stderr summary line
           preserved). Property numbering picks up at P53.
           OT-LK-002 banked decision recorded out-of-band:
           signed feeds with key pinning for the future feeds
           subsystem.

        2. DRAFT — requirements.md drafted via subagent. 13 EARS
           requirements, 891 lines, diagnostics-clean.
           Properties P53-P58 designated with explicit P59
           handoff for the next subsystem. The R5.6 dual-record
           contract from classification-pipeline preserved
           verbatim.

        3. TENSION pass — sibling artifact at
           `specs/classification-cli/requirements-tension-pass.md`.
           Walked the DRAFT against five upstream artifacts
           (the live classification library, model layer,
           upstream classification spec, existing CLI handlers,
           D-decision matrix). Surfaced 8 substantive gaps
           (G1-G8) plus 3 wording items (M1-M3).

           Most consequential gaps:
           - G2-B: drop `<R>` rules-loaded count from the
             stderr summary line. The library exposes
             len(self._rules.rules) only on the internal
             ClassificationPipeline._rules attribute, which is
             private per upstream R12.4. Surfacing 0 as the
             original spec proposed leaves an operationally
             meaningless metric; defer until the public API
             carries the count.
           - G5-A: the `--debug` flag should set
             `propagate = False` for the duration of the run,
             not just attach a handler. Otherwise Python
             logging propagation makes "no handler attached"
             non-equivalent to "DEBUG records won't surface."

           All 11 audit items applied to requirements.md.
           Diagnostics remain clean.

        4. HARDEN — requirements.md tagged HARDEN with the
           sibling artifact recording the audit-and-resolution
           trail. Two new tracking items recorded inline in the
           Introduction's design-phase notes:
           - OT-LK-006 forward thread: ExtractionManifest
             schema migration analogous to OT-LK-005 for
             baseline schema.
           - Future revision opportunity: extend the stderr
             summary line with a rules_loaded count once the
             public ClassificationResult carries it.

        5. Design BIND — design.md drafted same session. 980
           lines covering: subsystem positioning, 14 goals + 9
           non-goals, four interface families, full
           `_handle_classify` shape with code-shaped helpers
           (`_load_manifest`, `_install_sigint_handler`,
           `_install_debug_logger`, `_build_progress_callback`,
           `_serialize_result`, `_format_summary_line`), exit-
           code resolution table, sequence walkthrough of a
           cancellation-at-5 run, no-leakage discipline (paired
           static AST audit + dynamic stderr-capture audit),
           wrapper-only timing measurement plan, 15-file test
           layout, six properties P53-P58 with **Validates:
           Requirements X.Y** references, three-layer error
           handling, testing strategy, seven design defaults
           D1-D7 (module split into classify_helpers.py, tiny
           _CancelFlag dataclass, propagate=False on --debug,
           TTY guard fires first when manifest is `-`, exit
           code 4 covers both ClassificationPipelineError
           catchall and unexpected exceptions, helper module
           private with single-underscore names, integer-on-
           failure pattern in _load_manifest), three open
           questions Q1-Q3 deferred to task-breakdown.
           Diagnostics: 2 non-blocking property warnings
           matching the pattern accepted on
           `specs/analysis-engine/design.md`.

        6. Subsystem registry — new entry `classify-cli` added
           to §2 with status PROPOSED + spec_status DRAFT
           (BIND'd). Threat context STANDARD (untrusted
           manifest input via stdin; no network egress, no
           credential handling, no destructive operations).
           Dependencies: models (read-only consumer of
           ExtractionManifest + ClassificationConfig) and
           classification (consumes the public free function
           classify_components plus ProgressEvent +
           ClassificationResult + ClassificationError +
           ClassificationPipelineError hierarchy). Dependent on
           by: cli (the existing top-level `loki` console
           script that registers the new subcommand).

        7. Open threads — OT-LK-003 status flipped from OPEN
           to "spec triple BIND'd; tasks BIND remaining" with
           the same priority. New OT-LK-006 added for
           ExtractionManifest schema migration. Existing
           threads OT-LK-002, OT-LK-004, OT-LK-005 unchanged.

        Verification: doc-only round across requirements,
        design, and the TENSION-pass artifact. No code added
        or modified. Existing 1211-pytest baseline preserved.
        mypy --strict, ruff check, ruff format --check, and
        offscreen GUI smoke remain green per the prior
        checkpoint; this round did not retest because no
        source code changed.

        Changed files in this round:

        - `specs/classification-cli/`
        - `specs/classification-cli/requirements.md` (new — DRAFT, then HARDEN edits applied in same session)
        - `specs/classification-cli/requirements-tension-pass.md` (new — TENSION pass artifact + HARDEN status footer)
        - `specs/classification-cli/design.md` (new — BIND'd same session)
        - `loom-loki.md` (this file; v0.4.0 → v0.5.0; new subsystem entry; new evolution log entry; OT-LK-003 status; new OT-LK-006)

        Next round: tasks BIND for classification-cli in a
        fresh session. Per the project's working pattern, that
        is its own conversation. Estimate: 25-30 EARS-numbered
        tasks across 4-6 implementation waves.

    - date: "2026-05-28"
      version: "0.4.0"
      action: "OT-LK-001 closed with the analysis-engine v1.0.0 ship; harness records the eleven-round arc that took analysis-engine from stub-requirements DRAFT to v1.0.0 IMPLEMENTED + APPROVED"
      author: "LOKI contributors"
      subsystems_affected: [all]
      notes: |
        Harness initialized as part of the workspace-wide cleanup on
        2026-05-28. Loki has been shipping at v0.1.0 since the
        classification pipeline closed out (Wave 8); per HANDOFF.md
        the project is at 897 pytest pass / 6 deselected, mypy
        --strict clean across 176 source files, ruff lint + format
        clean, slow performance tests pass locally, and the
        offscreen GUI smoke is clean.

        The fork captures the existing reality:

        - 8 subsystems registered. Four are IMPLEMENTED with
          APPROVED specs (models, extraction, baseline,
          classification — the specs/ triples are complete
          with every task ticked off). Three are IMPLEMENTED with
          AD_HOC specs (gui, cli, scripts — HANDOFF.md and code
          are the source of truth; no specs/ triples).
          Three are PROPOSED with no implementation yet
          (analysis-engine has a stub requirements.md;
          feeds and fleet-analysis are not yet specced).
        - Threat context default STANDARD. The data layer
          (models) is MINIMAL_EXPOSURE — pure types. The smoke
          harness (scripts) is MINIMAL_EXPOSURE. Everything else
          is STANDARD: untrusted firmware-image input is the
          primary risk surface. No subsystem is FULL — no network
          egress (until feeds lands), no destructive operations,
          no credential handling.
        - Dependency graph is a strict DAG with 14 edges
          materialized (7 IMPLEMENTED-to-IMPLEMENTED edges, 7
          PROPOSED edges documented but not materialized in
          §3). models is the leaf; cli and scripts are roots.

        Open threads inherited from HANDOFF.md candidate moves:

        - OT-LK-001: analysis-engine spec drafting. The natural
          next major piece of work. Requirements stub exists at
          specs/analysis-engine/requirements.md.
          HANDOFF.md is explicit that spec drafting is its own
          conversation, not merged with implementation in a
          single session. The persisted contracts
          (FindingRecord, DeviationScore, ImageAnalysisReport,
          FleetAnalysisReport) are already in
          loki/models/{analysis,reports}.py.
        - OT-LK-002: CVE feed integration (the feeds
          subsystem). No spec yet. Will populate
          ClassificationRecord.cve_matches (currently always []
          per R6). Depends on a downstream conversation about
          NVD-feed signature trust and refresh cadence.
        - OT-LK-003: classification CLI subcommand.
          v1 ships only the classification library API; a future
          spec defines `loki classify run/show/...`.
        - OT-LK-004: GUI classification view. v1 runs headless;
          a future spec defines the desktop classification
          surface.
        - OT-LK-005: schema migration tool. v1 supports exactly
          one Schema_Version and quarantines any other; the
          future baseline-schema-migration spec defines an
          explicit migration path between schema versions.

        No source code edits this session. No tests added or
        modified. The harness initialization is documentation-
        only; its purpose is to bring Loki onto the same
        WEAVE Tier 3 footing as game/, razorrooster/, dorkstar/,
        and regchecker/ so future operator-driven changes can
        be tracked through the standard Shuttle Protocol.

        Verification: existing test suite (897 pytest pass / 6
        deselected; mypy --strict 176 files; ruff clean; slow
        perf gates green; offscreen GUI smoke clean) per the
        project's existing CI contract documented in HANDOFF.md.
        Not re-run this session because no code changed.

        Changed files in this round:

        - loki/loom-loki.md (this file, new).

    - date: "2026-05-28"
      version: "0.1.1"
      action: "OT-LK-001 TENSION pass landed for analysis-engine requirements.md DRAFT"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        TENSION pass on the analysis-engine requirements.md DRAFT
        completed and recorded as a sibling artifact at
        `specs/analysis-engine/requirements-tension-pass.md`.

        The DRAFT requirements doc is structurally complete: 1163
        lines, 20 EARS-style requirements with `#### Acceptance
        Criteria` blocks, no TODO / OPEN-QUESTION markers,
        diagnostics-clean per the spec format checker. The
        TENSION pass walked the doc end-to-end against the model
        layer (`loki/models/{firmware,classification,baseline,
        analysis,reports,config,enums}.py`) and the four shipped
        subsystems' patterns to verify internal consistency.

        TENSION findings:

        - 4 substantive gaps requiring HARDEN-phase resolution:
          - G1: BaselineComparison.comparison_timestamp is left
            unspecified by R17.4. Recommended fix: tie to
            ImageAnalysisReport.timestamp.
          - G2: R15.1 determinism modulo timestamp doesn't
            address the second timestamp introduced by G1's
            BaselineComparison construction. Resolved by adopting
            G1's recommendation.
          - G3: R17.5 PostureRating mapping has a fall-through
            gap for runs that emit only unexpected_component,
            signature_regression: MEDIUM, or classification_gap
            findings. Recommended fix: restructure as a four-
            clause "otherwise"-cascade with DEGRADED as the
            "any finding emitted" catch-all.
          - G4: R17.5 does not escalate classification_mismatch
            CRITICAL (Composite_Score >= 8.0) to PostureRating.
            COMPROMISED. Operator decision: option A (preserve
            tampering-vs-drift distinction) or option B (treat
            critical drift as compromise).
        - 3 wording / aesthetic items:
          - M1: target_component_id naming in R15.7 is
            misleading for missing_required_component findings.
          - M2: "highest-priority" in R17.5 is implicit-via-
            R9.10. Could be made explicit.
          - M3: R15 determinism doesn't explicitly cover the
            cancellation-marker case where two runs cancel at
            different indices. Resolved by light amendment to
            R15.1.

        What the TENSION pass did NOT find: no internal
        contradictions between any pair of acceptance criteria;
        no missing model-layer dependencies (every type, enum
        value, and BaselineRegistry method the spec assumes
        exists in the model layer); no drift from the upstream
        subsystems' patterns; no Forbidden_Leakage_Field_Set
        drift; no CVE-feed entanglement; no fleet entanglement;
        no persistence entanglement.

        Recommended HARDEN amendment is documented in the
        TENSION note. Once the operator answers G3 phrasing
        and G4 escalation policy, the four-bullet edit takes
        the doc to BIND-ready, after which design.md drafting
        opens in a subsequent session per HANDOFF.md's
        spec-drafting-is-its-own-conversation rule.

        No source code edits this session. No tests added or
        modified. Documentation-only round.

        Verification: existing test suite unchanged at 897
        pytest pass / 6 deselected; mypy --strict, ruff lint
        + format, and offscreen GUI smoke unchanged. Not
        re-run this session because no code changed; the
        round is a spec review only.

        Changed files in this round:

        - loki/specs/analysis-engine/requirements-tension-pass.md (new).
        - loki/loom-loki.md (this file, version 0.1.0 -> 0.1.1; OT-LK-001 status updated; analysis-engine subsystem entry's spec_path and description refreshed).

    - date: "2026-05-28"
      version: "0.2.0"
      action: "OT-LK-001 BIND — analysis-engine requirements.md HARDEN amendment landed; spec_status DRAFT -> APPROVED"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.2.0 minor bump triggered by analysis-engine
        requirements BIND, per the §10 versioning rule "Most
        likely v0.2.0 trigger: analysis-engine BIND."

        Operator chose G3-A (insert a sixth-rule DEGRADED catch-
        all in R17.5 between current rules 3 and 4) and G4-B
        (escalate `classification_mismatch: CRITICAL` to
        `PostureRating.COMPROMISED`) per the TENSION pass review
        note at `specs/analysis-engine/requirements-tension-
        pass.md`. M1 (rename target_component_id) and M2 (explicit
        max-Composite_Score wording) skipped as cosmetic; the
        existing wording is unambiguous-via-R9.10 and reads
        cleanly as-is.

        HARDEN amendment to requirements.md (1163 -> 1194 lines)
        consisted of three edits:

        1. R15.1 (M3 fix): added a WHERE clause for cancelled
           runs that strips the Cancellation_Marker's
           `evidence.raw_indicators` from the determinism
           equality. All other Cancellation_Marker fields
           (`finding_id`, `category`, `severity`) still match
           across two cancellation runs at different indices.
        2. R17.4 (G1 + G2 fix): specified that
           `BaselineComparison.comparison_timestamp` equals
           `ImageAnalysisReport.timestamp`. The two timestamp
           fields move in lockstep, so the determinism property
           in R15.1 still strips a single timestamp value with
           no need to amend R15.1 for G2.
        3. R17.5 (G3-A + G4-B fix): restructured the
           `PostureRating` mapping. The COMPROMISED clause now
           also fires when any `classification_mismatch`
           Composite_Score is >= 8.0 (severity CRITICAL). A new
           sixth rule (DEGRADED catch-all) covers runs whose only
           findings are `unexpected_component`,
           `signature_regression: MEDIUM`, or
           `classification_gap`. The PostureRating field is now
           defined for every input combination.

        Subsystem state changes:

        - analysis-engine: spec_status DRAFT -> APPROVED. The
          requirements.md file is BIND'd and locked; design.md
          and tasks.md remain pending. lifecycle_stage stays
          PROPOSED until implementation lands.

        Open thread state changes:

        - OT-LK-001: status moved from "TENSION pass complete;
          HARDEN gated on operator decisions" to "requirements
          BIND'd; design.md is the next session." Next-session
          checklist of design-phase decisions (engine shape,
          AnalysisProgressEvent dataclass, AnalysisError
          hierarchy, AnalysisConfig extensions, FindingEvidence
          extension, P43-P52 properties, no-leakage audit) is
          recorded in OT-LK-001's notes field for the incoming
          session.

        No source code edits this session. No tests added or
        modified. Documentation-only round, second of the same
        day.

        Verification: existing test suite unchanged at 897
        pytest pass / 6 deselected; mypy --strict, ruff lint
        + format, and offscreen GUI smoke unchanged. Not re-run
        this session because no code changed; the round is a
        spec amendment only.

        Changed files in this round:

        - loki/specs/analysis-engine/requirements.md (1163 -> 1194 lines; three HARDEN edits to R15.1, R17.4, R17.5).
        - loki/specs/analysis-engine/requirements-tension-pass.md (HARDEN-amendment record appended).
        - loki/loom-loki.md (this file, version 0.1.1 -> 0.2.0; analysis-engine spec_status DRAFT -> APPROVED; OT-LK-001 status updated to BIND'd; v0.2.0 evolution-log entry added).
        - loki/STATE.md (harness version + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.0"
      action: "OT-LK-001 design.md DRAFT BIND'd; analysis-engine completes the requirements + design pair (tasks.md still pending)"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.0 minor bump triggered by analysis-engine
        design.md DRAFT BIND. Per §10's "Minor bump (0.Y.0): new
        subsystem registered, FRAY landed, or significant cross-
        subsystem change" — design.md BIND for analysis-engine
        qualifies. The subsystem now has APPROVED requirements +
        design; tasks.md is the remaining pre-implementation
        artefact.

        Operator chose all seven design defaults at the CAST
        gate that opened this session (D1: free function not
        class, mirroring classification's classify_components;
        D2: errors.py module mirroring baseline / classification;
        D3: FindingEvidence.deviation_score direct model-layer
        extension per R9.1; D4: AnalysisConfig.match_strategy /
        confidence_gap_threshold / baseline_id direct model-layer
        extensions per R14; D5: MatchStrategy as StrEnum in
        loki/models/enums.py; D6: AnalysisProgressEvent strips
        component_id for tighter no-leakage discipline than
        classification's ProgressEvent; D7: Properties P43-P52,
        ten properties picking up from classification's
        P33-P42).

        design.md (1211 lines, 11 top-level sections):

        - § Overview, Goals + non-goals, Constraints carried
          forward — sets the determinism / no-leakage / no-side-
          channels disciplines mirroring extraction / baseline /
          classification.
        - § Components and Interfaces (top-level summary) +
          § Architecture (detailed: module layout under
          loki/analysis/; public API shape including the
          AnalysisProgressEvent dataclass that strips
          component_id; internal AnalysisPipeline; full
          exception hierarchy at loki/analysis/errors.py with
          four AnalysisError subclasses; Cancellation_Marker
          construction).
        - § Data Models — three model-layer extensions
          (MatchStrategy enum in enums.py; AnalysisConfig fields
          in config.py; FindingEvidence.deviation_score in
          analysis.py), all backwards-compatible.
        - § Sequence walkthrough — eleven design points covering
          single-timestamp anchor, cancellation-before-progress
          ordering, single-dict pairing, classification_mismatch
          + signature_regression non-mutual-exclusion,
          classification_gap on unpaired Target_Records,
          priority_rank second-pass, sorted missing_required
          findings, PostureRating derivation, BaselineComparison
          empty-deviations contract, calling-thread-only
          callbacks, and R14 validation timing.
        - § Per-category finding emitters — derive_finding_id
          helper; emitters for classification_mismatch,
          signature_regression, unexpected_component,
          missing_required_component, classification_gap; the
          scoring helpers (axis_score, composite_score,
          base_severity_from_composite, security_direction,
          signature_delta, mutability_change).
        - § PostureRating derivation — six-rule cascade
          implementing G3-A + G4-B HARDEN amendments. The cascade
          implementation walks findings once, collecting flags,
          then returns the matching rating; the has_any_finding
          catch-all handles runs whose only findings are
          unexpected_component, signature_regression: MEDIUM,
          classification_gap, or analysis_cancelled.
        - § Determinism, § Error handling, § Performance and
          resource use — five disciplines pinning the
          determinism property; whole-run vs cooperative-
          cancellation error split; performance budgets.
        - § No-leakage audits — static AST audit + dynamic
          caplog audit, mirroring the four shipped subsystems.
        - § Progress callback and the leakage rule — explains
          the D6 default (strip component_id from
          AnalysisProgressEvent) with a clear upgrade path.
        - § Correctness Properties — Properties P43-P52, ten
          formal invariants validated by Hypothesis-based
          property tests at tests/analysis/test_properties.py.
          Five properties (P44, P45, P46, P49, P52) use multi-
          paragraph or bullet-list structure between header and
          Validates line; the format checker emits five non-
          blocking warnings; D8 in deferred-decisions documents
          the explicit choice to keep the structural clarity.
        - § Testing Strategy — tests/analysis/ layout (~16
          test files); estimated 80-120 new tests; existing
          test infrastructure carries forward unchanged.
        - § Deferred decisions and open questions — D1-D8
          explicit defaults plus six locked-in v1 contracts that
          future revisions can revisit (SignatureDelta.CHANGED
          reservation; flat severity for unexpected_component
          and missing_required_component; recommended_actions
          empty; default_severity_threshold read-not-consumed;
          M1 + M2 cosmetic deferrals).
        - § Out-of-scope explicit list — confirms the intro
          non-goals are honored throughout.

        Diagnostics: 0 errors, 5 warnings (all on multi-
        paragraph Property descriptions; explicitly accepted
        per D8).

        Subsystem state changes:

        - analysis-engine: spec_path updated to reflect the new
          design.md artefact. spec_status remains APPROVED
          (requirements + design BIND'd; tasks.md pending).
          lifecycle_stage stays PROPOSED until implementation
          lands.

        Open thread state changes:

        - OT-LK-001: status moved from "requirements BIND'd;
          design.md is the next session" to "design BIND'd;
          tasks.md is the next session." Notes field carries
          forward the seven D-defaults plus the new D8, plus
          a tasks.md sizing recommendation (~25-35 tasks across
          6-8 waves following the classification-pipeline
          pattern).

        No source code edits this session. No tests added or
        modified. Documentation-only round, third of the same
        day after v0.1.1 (TENSION) and v0.2.0 (HARDEN/BIND of
        requirements).

        Verification: existing test suite unchanged at 897
        pytest pass / 6 deselected; mypy --strict, ruff lint
        + format, and offscreen GUI smoke unchanged. Not re-run
        this session because no code changed; the round is a
        spec drafting only.

        Changed files in this round:

        - loki/specs/analysis-engine/design.md (new; 1211 lines, 11 top-level sections, Properties P43-P52, D1-D8 deferred decisions).
        - loki/loom-loki.md (this file, version 0.2.0 -> 0.3.0; analysis-engine subsystem spec_path + description refreshed; OT-LK-001 status moved to "tasks.md is the next session"; v0.3.0 evolution-log entry added).
        - loki/STATE.md (harness version + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.1"
      action: "OT-LK-001 tasks.md DRAFT BIND'd; analysis-engine spec triple now complete (requirements + design + tasks)"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.1 patch bump triggered by analysis-engine
        tasks.md DRAFT BIND. Per §10's "Patch bump (0.1.Z):
        documentation correction, cross-reference repair, or
        single-subsystem metadata update" — tasks.md doesn't
        register a new subsystem and isn't a FRAY landing, so
        patch is the right level. The minor bump for the
        subsystem will land at v0.4.0 when implementation BIND
        moves analysis-engine from PROPOSED to IMPLEMENTED.

        tasks.md (568 lines, 28 tasks across 8 waves) follows
        the classification-pipeline structural template
        (numbered task list, requirement + design references
        per task, wave manifest JSON at the tail, suggested
        cadence narrative, notes section). The eight waves:

        1. **Wave 1 (skeleton):** task 1 — empty package
           scaffold under loki/analysis/ + tests/analysis/.
           Verifies clean import.
        2. **Wave 2 (foundations):** tasks 2-7 — version
           constant, MatchStrategy StrEnum (D5), AnalysisConfig
           extension with three new fields (D4),
           FindingEvidence.deviation_score extension (D3),
           AnalysisError exception hierarchy at
           loki/analysis/errors.py (D2), Stopwatch timing
           helper. Pure data-shape work.
        3. **Wave 3 (matching + pairing + finding_id):** tasks
           8-10 — Match_Strategy resolution per R2 with all
           three strategies, Component_Pairing logic per R3
           with duplicate-id detection, derive_finding_id
           helper + Cancellation_Marker constructor.
        4. **Wave 4 (scoring + posture):** tasks 11-12 — six
           pure scoring helpers (axis_score,
           composite_score, base_severity_from_composite,
           security_direction, signature_delta,
           mutability_change) per R9 + R10.7 + R11 + R12 + R13;
           PostureRating six-rule cascade per R17.5
           (post-HARDEN G3-A + G4-B amendments).
        5. **Wave 5 (per-category emitters):** tasks 13-17 —
           one task per finding category
           (classification_mismatch, signature_regression,
           unexpected_component, missing_required_component,
           classification_gap). Each emitter is a pure
           function returning a FindingRecord with
           deterministic finding_id.
        6. **Wave 6 (pipeline + public API):** tasks 18-20 —
           report assembly with assign_priority_ranks
           in-place mutator + derive_report_id +
           assemble_report wrapping Pydantic; AnalysisPipeline
           internal class orchestrating the full sequence
           walkthrough; analyze_image public free-function
           entry point (D1). Subsystem becomes importable
           end-to-end.
        7. **Wave 7 (cross-cutting tests):** tasks 21-26 —
           static side-channels AST audit, static no-leakage
           AST audit, dynamic caplog no-leakage audit,
           Hypothesis P43-P52 property test suite,
           performance smoke (slow marker, R18.1 budget),
           end-to-end smoke covering extract -> classify ->
           analyze chain.
        8. **Wave 8 (docs + final gate):** tasks 27-28 — README
           + STATE + HANDOFF + harness refresh; final four-gate
           verification. The harness bump to v0.4.0 + the
           PROPOSED -> IMPLEMENTED state transition land here.

        Implementation cadence target: ~6 sessions, one wave
        per session. Mirrors classification's six-day plan
        because analysis has comparable scope (10 vs 10
        properties, similar pipeline shape, same upstream /
        downstream coupling).

        Subsystem state changes:

        - analysis-engine: spec_path updated to reflect the
          new tasks.md artefact. spec_status remains APPROVED
          (requirements + design + tasks all BIND'd).
          lifecycle_stage stays PROPOSED until implementation
          lands per wave 8.

        Open thread state changes:

        - OT-LK-001: status moved from "design BIND'd;
          tasks.md is the next session" to "spec triple
          complete; implementation phase opens." Notes field
          carries forward the six-session implementation
          cadence breakdown.

        No source code edits this session. No tests added or
        modified. Documentation-only round, fourth of the same
        day after v0.1.1 (TENSION), v0.2.0 (requirements
        BIND), and v0.3.0 (design BIND).

        Verification: existing test suite unchanged at 897
        pytest pass / 6 deselected; mypy --strict, ruff lint
        + format, and offscreen GUI smoke unchanged. Not re-run
        this session because no code changed; the round is a
        spec drafting only.

        Changed files in this round:

        - loki/specs/analysis-engine/tasks.md (new; 568 lines, 28 tasks across 8 waves, JSON wave manifest + cadence + notes).
        - loki/loom-loki.md (this file, version 0.3.0 -> 0.3.1; analysis-engine subsystem spec_path + description refreshed; OT-LK-001 status moved to "spec triple complete; implementation phase opens"; v0.3.1 evolution-log entry added).
        - loki/STATE.md (harness version + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.2"
      action: "OT-LK-001 implementation Wave 1 + Wave 2 landed (tasks 1-7 of 28); first code-touching round of the analysis-engine implementation phase"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine, models]
      notes: |
        Same-day v0.3.2 patch bump — first implementation round of
        OT-LK-001. Per §10's "Patch bump (0.1.Z): documentation
        correction, cross-reference repair, or single-subsystem
        metadata update" — implementation rounds before BIND
        complete are patch-level. The minor bump for the subsystem
        will land at v0.4.0 when wave 8's final-gate task closes
        and the subsystem moves PROPOSED -> IMPLEMENTED.

        Wave 1 (skeleton):

        - Task 1: scaffolded loki/analysis/ + tests/analysis/
          packages. 12 source modules under loki/analysis/ + 2
          test-package modules under tests/analysis/, all empty
          docstring + __all__ shells. Subsystem imports cleanly
          via `import loki.analysis`.

        Wave 2 (foundations):

        - Task 2: loki/analysis/version.py defines
          ANALYSIS_VERSION = "1.0.0" (semver per R1.5; consumed by
          R15.8's report_id derivation). Re-exported from
          loki.analysis. Test file: test_version.py (4 tests).
        - Task 3: MatchStrategy StrEnum added to
          loki/models/enums.py with three values (EXPLICIT, AUTO,
          EXPLICIT_OR_AUTO) per R2.1 + D5. Re-exported from
          loki.models. Test file: test_match_strategy_enum.py
          (7 tests).
        - Task 4: AnalysisConfig extended with three new fields
          per R14 + D4: match_strategy (default AUTO),
          confidence_gap_threshold (default 0.6 matching the
          model's needs_review threshold; range [0.0, 1.0]),
          baseline_id (default None). Existing severity_weights
          sum-to-1.0 validator preserved. Test file:
          test_analysis_config_extension.py (15 tests covering
          defaults, bounds, Pydantic round-trip via
          model_validate_json, dict round-trip via
          model_validate(strict=False), and YAML round-trip via
          LokiConfig.from_yaml).
        - Task 5: FindingEvidence extended with optional
          deviation_score: DeviationScore | None = None per R9.1
          + D3. Backwards-compatible: existing call sites keep
          their argument shape. Test file:
          test_finding_evidence_extension.py (8 tests covering
          default, populated round-trip, JSON serialization
          shape).
        - Task 6: AnalysisError exception hierarchy at
          loki/analysis/errors.py per R16 + D2. Four subclasses:
          AnalysisConfigError, BaselineNotFoundError,
          AnalysisInputError, AnalysisReportConstructionError.
          BaselineNotFoundError enforces exactly-one-of
          baseline_id-vs-vendor_model_version invariant.
          AnalysisInputError validates side ∈ {target, baseline}
          and accepts any Iterable of duplicates. All five classes
          re-exported from loki.analysis. Test file:
          test_errors.py (16 tests).
        - Task 7: Stopwatch context manager at
          loki/analysis/timing.py mirroring
          loki/classification/timing.py exactly. The single
          permitted clock-using module inside loki.analysis;
          Property 51's AST audit (Wave 7, task 21) will pin
          this. Test file: test_timing.py (8 tests).

        Verification gates after Wave 1 + 2:

        - pytest: 956 passed, 6 deselected (was 897; +59 new
          tests across 6 new test files).
        - mypy --strict: clean across 196 source files (was 176;
          +20 = 14 source modules + 6 new test files).
        - ruff check: clean.
        - ruff format --check: clean.
        - offscreen GUI smoke: clean.

        Three Pydantic-strict-mode test failures surfaced during
        the first run and were fixed in-flight: model_validate
        on dict from model_dump(mode="json") needs strict=False
        to coerce string-encoded enums + UUIDs (matches
        LokiConfig.from_yaml's existing pattern; documented in
        the project's existing baseline-persistence design).
        JSON round-trip via model_validate_json() decodes
        natively under strict mode; that path is the primary
        round-trip discipline. Both paths are now covered in
        tests.

        Workspace observation worth recording: the .venv/bin/*
        entry-point scripts have stale shebangs pointing at
        /Users/daborond/Projects/loki/.venv/bin/python3.12 (a
        path that no longer exists from a prior workspace move).
        Workaround used this session: invoke .venv/bin/python -m
        <tool> instead of .venv/bin/<tool>. Operator may want
        to rebuild the venv at some point but it is not blocking
        implementation. The python binary itself works correctly;
        only the wrapper-script shebangs are stale.

        Subsystem state changes:

        - analysis-engine: spec_status remains APPROVED;
          lifecycle_stage stays PROPOSED until wave 8.
          Implementation progress: 7 of 28 tasks complete (25%);
          waves 1 + 2 of 8 complete.
        - models: extended in-place by tasks 3, 4, 5. All
          extensions are backwards-compatible. Model layer's
          spec_status remains APPROVED.

        Open thread state changes:

        - OT-LK-001: status moved from "spec triple complete;
          implementation phase opens" to "Waves 1+2 landed; Wave 3
          next." Notes field carries forward the wave-by-wave
          remaining cadence.

        Changed files in this round:

        - loki/loki/analysis/{__init__,api,pipeline,version,matching,pairing,findings,scoring,posture,report,errors,timing}.py (12 new modules; api/pipeline/matching/pairing/findings/scoring/posture/report still empty docstring shells with __all__: list[str] = []).
        - loki/loki/models/enums.py (MatchStrategy added; __all__ updated).
        - loki/loki/models/__init__.py (MatchStrategy re-exported).
        - loki/loki/models/config.py (AnalysisConfig extended with three fields + uuid + MatchStrategy imports).
        - loki/loki/models/analysis.py (FindingEvidence extended with deviation_score field).
        - loki/tests/analysis/{__init__,conftest,test_version,test_match_strategy_enum,test_analysis_config_extension,test_finding_evidence_extension,test_errors,test_timing}.py (8 new test files).
        - loki/specs/analysis-engine/tasks.md (tasks 1-7 ticked off).
        - loki/loom-loki.md (this file, version 0.3.1 -> 0.3.2; OT-LK-001 status updated; v0.3.2 evolution-log entry added).
        - loki/STATE.md (harness version + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.3"
      action: "OT-LK-001 implementation Wave 3 landed (tasks 8-10 of 28); matching + pairing + finding_id helper now live"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.3 patch bump — Wave 3 of OT-LK-001's eight-
        wave implementation plan. 10 of 28 tasks now complete (36%).
        Subsystem stays PROPOSED until wave 8's final gate moves
        it to IMPLEMENTED.

        Wave 3 (matching + pairing + finding_id helper):

        - Task 8 (matching): loki/analysis/matching.py implements
          two pure functions — validate_analysis_config (R14.1
          keyset check) and resolve_matched_baseline (R2 three-
          strategy resolution: EXPLICIT, AUTO, EXPLICIT_OR_AUTO).
          The module also exports REQUIRED_SEVERITY_WEIGHT_KEYS as
          a frozenset for downstream introspection. The model
          layer's existing validators (sum-to-1.0, range,
          StrEnum, UUID-or-None) are not re-checked; only the
          engine-specific four-key set rule is enforced. Test
          file: test_matching.py (19 tests covering all three
          strategies including the EXPLICIT_OR_AUTO no-silent-
          fallback contract from R2.5, the read-only-registry
          contract from R2.8, and the None-vendor edge case
          surfaced as a small spec gap; see notes below).
        - Task 9 (pairing): loki/analysis/pairing.py implements
          four pure functions — check_pairing_preconditions (R3.6
          + R3.7 duplicate-id detection on either side),
          build_baseline_index (R18.2 single-dict pairing key),
          pair_records (yields (target, baseline-or-None) tuples
          in target input order per R3.4), unpaired_baselines
          (returns ascending-component_id-sorted unpaired records
          per R3.4). Test file: test_pairing.py (20 tests
          including a 1024+1024 linear-time smoke).
        - Task 10 (finding_id + Cancellation_Marker):
          loki/analysis/findings.py implements derive_finding_id
          (R15.7 deterministic uuid5 over
          (baseline_id, finding_category, target_component_id)),
          ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID module
          constant (R7.2; uuid5 over "analysis-cancelled"), and
          make_cancellation_marker (R7.1-R7.7 Cancellation_Marker
          construction). Test files: test_finding_id.py (10
          tests) + test_cancellation_marker.py (15 tests). The
          remaining per-category emitters in this module
          (classification_mismatch, signature_regression,
          unexpected_component, missing_required_component,
          classification_gap) land in Wave 5.

        Verification gates after Wave 3:

        - pytest: 1015 passed, 6 deselected (was 956; +59 new
          tests across 4 new test files).
        - mypy --strict: clean across 200 source files (was 196;
          +4 new test files; matching.py, pairing.py, findings.py
          all populated).
        - ruff check: clean.
        - ruff format --check: clean.
        - offscreen GUI smoke: clean.

        Three minor in-flight fixes during the round:

        1. Three Pydantic-strict-mode round-trip patterns kept
           consistent with Wave 2's earlier fix.
        2. Two ruff issues (I001 import-order, N811 lowercase-
           alias-of-constant) — auto-fixed where possible; the
           N811 was resolved by switching the test from
           ``import ... as a; import ... as b`` to importlib-
           based double-import (more robust at testing module
           identity anyway).
        3. One mypy strictness issue: FirmwareImage.{vendor,
           model,firmware_version} are Optional[str] but
           BaselineRegistry.get_by_vendor_model_version takes
           plain str. Fixed in matching._resolve_auto: when any
           of the three target_image fields is None, the engine
           raises BaselineNotFoundError carrying the literal
           "<unset>" string for the missing fields, rather than
           passing None through. This is a small spec gap (R2.3
           implicitly assumes non-None values); a future spec
           amendment could explicitly cover the None case if
           the operator wants different semantics.

        Subsystem state changes:

        - analysis-engine: spec_status remains APPROVED;
          lifecycle_stage stays PROPOSED until wave 8.
          Implementation progress: 10 of 28 tasks complete (36%);
          waves 1 + 2 + 3 of 8 complete.

        Open thread state changes:

        - OT-LK-001: status moved from "Waves 1+2 landed; Wave 3
          next" to "Waves 1+2+3 landed; Wave 4 next." Notes field
          updated with the matching None-vendor handling
          observation.

        Changed files in this round:

        - loki/loki/analysis/matching.py (populated; was empty docstring shell).
        - loki/loki/analysis/pairing.py (populated; was empty docstring shell).
        - loki/loki/analysis/findings.py (partially populated — derive_finding_id helper, sentinel constant, make_cancellation_marker constructor; per-category emitters still pending Wave 5).
        - loki/tests/analysis/{test_matching,test_pairing,test_finding_id,test_cancellation_marker}.py (4 new test files, 64 tests total).
        - loki/specs/analysis-engine/tasks.md (tasks 8-10 ticked off).
        - loki/loom-loki.md (this file, version 0.3.2 -> 0.3.3; OT-LK-001 status updated; v0.3.3 evolution-log entry added).
        - loki/STATE.md (harness version + verification gates + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.4"
      action: "OT-LK-001 implementation Wave 4 landed (tasks 11-12 of 28); scoring helpers + PostureRating cascade now live"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.4 patch bump — Wave 4 of OT-LK-001's eight-
        wave implementation plan. 12 of 28 tasks now complete (43%).
        Subsystem stays PROPOSED until wave 8's final gate.

        Wave 4 (scoring + posture):

        - Task 11 (scoring): loki/analysis/scoring.py implements
          six pure helpers — axis_score (R9.3 pair-of-axes
          comparison), composite_score (R9.4 weighted sum scaled
          to [0.0, 10.0]), base_severity_from_composite (R10.7
          closed mapping with five thresholds), security_direction
          (R11), signature_delta (R12 with v1's CHANGED
          reservation), mutability_change (R13). Each helper is
          deterministic and side-effect free. Test file:
          test_scoring.py (~30 tests including five Hypothesis
          property tests covering axis-score-in-unit-interval,
          composite-score-in-bounded-range, severity-returns-
          valid-level for all valid inputs).
        - Task 12 (posture): loki/analysis/posture.py implements
          derive_posture_rating per the post-HARDEN R17.5 six-
          rule cascade with G3-A catch-all (any finding emitted
          but no score-based rule fires -> DEGRADED) and G4-B
          escalation (classification_mismatch with composite_score
          >= 8.0 -> COMPROMISED). Walks the finding list once,
          collects four flags + a running max, returns the
          matching rating. Defensive: classification_mismatch
          findings without a populated DeviationScore (e.g. a
          hand-built test fixture) are treated as composite=0.0
          and fall through to the catch-all rule. Test file:
          test_posture.py (~25 tests including a Property-49
          Hypothesis test that randomly mixes finding categories,
          severities, and composite scores and asserts the result
          is always one of the four v1 PostureRating values
          (HARDENED never returned)).

        Verification gates after Wave 4:

        - pytest: 1080 passed, 6 deselected (was 1015; +65 new
          tests across 2 new test files).
        - mypy --strict: clean across 202 source files (was 200;
          +2 new test files; scoring.py + posture.py both
          populated).
        - ruff check: clean.
        - ruff format --check: clean.
        - offscreen GUI smoke: clean.

        Two minor in-flight fixes during the round:

        1. ruff I001 import-order violation in test_posture.py
           — auto-fixed via ``ruff check --fix``.
        2. mypy strict typing issue: the test fixture
           ``_finding`` originally constructed FindingEvidence
           via ``**dict[str, object]`` unpacking, which mypy
           strict rejects on Pydantic strict-typed constructors.
           Restructured to construct FindingEvidence directly
           with all fields named; identical behaviour, mypy-clean.

        Subsystem state changes:

        - analysis-engine: spec_status remains APPROVED;
          lifecycle_stage stays PROPOSED until wave 8.
          Implementation progress: 12 of 28 tasks complete (43%);
          waves 1 + 2 + 3 + 4 of 8 complete. The non-pipeline
          business logic (matching, pairing, scoring, posture,
          finding_id derivation, Cancellation_Marker
          construction) is now feature-complete. Wave 5 lands
          the five per-category emitters, after which the
          pipeline class in Wave 6 wires everything together.

        Open thread state changes:

        - OT-LK-001: status moved from "Waves 1+2+3 landed;
          Wave 4 next" to "Waves 1+2+3+4 landed; Wave 5 next."

        Changed files in this round:

        - loki/loki/analysis/scoring.py (populated; was empty docstring shell).
        - loki/loki/analysis/posture.py (populated; was empty docstring shell).
        - loki/tests/analysis/{test_scoring,test_posture}.py (2 new test files, ~55 tests total).
        - loki/specs/analysis-engine/tasks.md (tasks 11-12 ticked off).
        - loki/loom-loki.md (this file, version 0.3.3 -> 0.3.4; OT-LK-001 status updated; v0.3.4 evolution-log entry added).
        - loki/STATE.md (harness version + verification gates + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.5"
      action: "OT-LK-001 implementation Wave 5 landed (tasks 13-17 of 28); five per-category finding emitters now live"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.5 patch bump — Wave 5 of OT-LK-001's eight-
        wave implementation plan. 17 of 28 tasks now complete (61%).
        Subsystem stays PROPOSED until wave 8's final gate.

        Wave 5 (per-category emitters): all five emitters land in
        loki/analysis/findings.py (alongside the Wave 3 helpers
        derive_finding_id + ANALYSIS_CANCELLED_SENTINEL_COMPONENT_ID
        + make_cancellation_marker):

        - Task 13 (classification_mismatch): the largest emitter.
          Computes four Axis_Scores via axis_score, derives
          Composite_Score via composite_score, picks base_severity
          from Composite_Score per R10.7, computes the three
          DeviationScore axis fields (security_direction,
          signature_delta, mutability_change) via the matching
          scoring helpers, sets component_criticality from the
          baseline's composite_confidence per R9.7, sets
          cve_introduced=False per R9.9, constructs a DeviationScore
          with priority_rank=1 placeholder (pipeline overwrites in
          Wave 6's second pass per R9.10), and embeds the score on
          evidence.deviation_score. The title and description
          strings list the disagreeing axes; both fields are in
          the Forbidden_Leakage_Field_Set per R20.5 and never
          logged. Test file: test_findings_classification_mismatch.py
          (18 tests including all four severity boundary
          cases at 2.0 / 4.0 / 6.0 / 8.0 / 10.0 — note that
          two tests fall at exactly 6.0 and 8.0 per the inclusive-
          at-top-of-tier mapping in R10.7).
        - Task 14 (signature_regression): determines direction
          (HIGH for baseline-signed/target-unsigned per R5.6,
          MEDIUM for the reverse), sets matched_signature to
          "BASELINE_SIGNED" or "TARGET_SIGNED" per R5.5. Defensive
          ValueError when pre-conditions are violated (signature_info
          None on either side, or .present fields don't differ).
          No DeviationScore embedded per R9.11. Test file:
          test_findings_signature_regression.py (12 tests).
        - Task 15 (unexpected_component): flat MEDIUM severity per
          R6.5, evidence carries the unpaired Target_Record. No
          DeviationScore. Test file:
          test_findings_unexpected_component.py (8 tests).
        - Task 16 (missing_required_component): flat HIGH severity
          per R8.5, component_id field carries the BASELINE
          record's component_id per R8.3 (since no target record
          exists with this id), evidence carries the unpaired
          baseline record. The finding_id derivation uses
          baseline.component_id as its target_component_id arg per
          R15.7's note that the third tuple element is sourced from
          the relevant side per finding category. Test file:
          test_findings_missing_required.py (9 tests).
        - Task 17 (classification_gap): flat LOW severity per R10.6
          (gaps are diagnostic, not threats). Independent of
          pairing per R10.2 — the emitter's signature takes only
          the target record, no baseline. Test file:
          test_findings_classification_gap.py (9 tests).

        Verification gates after Wave 5:

        - pytest: 1131 passed, 6 deselected (was 1080; +51 new
          tests across 6 new test files including a shared
          tests/analysis/_helpers.py module).
        - mypy --strict: clean across 208 source files (was 202;
          +6 new test files; findings.py grew substantially).
        - ruff check: clean.
        - ruff format --check: clean.
        - offscreen GUI smoke: clean.

        Three minor in-flight fixes during the round:

        1. ruff I001 import-order violations in two of the new
           test files — auto-fixed via ``ruff check --fix``.
        2. mypy strict typing seam: the scoring helpers
           security_direction and mutability_change took
           SecurityPostureLabel and MutabilityLabel respectively,
           but AxisClassification.label is typed as plain str at
           the model layer (rules may produce any label string;
           StrEnum values are the canonical set but not the only
           permitted). Loosened both helpers to take str
           parameters; comparisons against the StrEnum members
           still work via StrEnum equality (e.g.
           SecurityPostureLabel.SECURE == "SECURE"). Tests from
           Wave 4 continue to pass because StrEnum members ARE
           strings.
        3. Floating-point precision: 10 * (0.4+0.2+0.3+0.1) =
           10.0 + ~2e-15, which the model layer's strict
           DeviationScore.composite_score validator rejects.
           Clamped composite to [0.0, 10.0] in
           emit_classification_mismatch before constructing the
           DeviationScore. The model contract stays strict; the
           producer side handles FP slop.

        Subsystem state changes:

        - analysis-engine: spec_status remains APPROVED;
          lifecycle_stage stays PROPOSED until wave 8.
          Implementation progress: 17 of 28 tasks complete (61%);
          waves 1+2+3+4+5 of 8 complete. The complete per-pair
          finding-emission surface is feature-complete. Wave 6
          adds report assembly and the pipeline orchestrator
          that wires everything together; analyze_image becomes
          callable end-to-end at that point.

        Open thread state changes:

        - OT-LK-001: status moved from "Waves 1+2+3+4 landed;
          Wave 5 next" to "Waves 1-5 landed; Wave 6 next."

        Changed files in this round:

        - loki/loki/analysis/findings.py (extended with five emitters and helper utilities; was Wave 3 partial scaffold).
        - loki/loki/analysis/scoring.py (security_direction + mutability_change helpers loosened from StrEnum-typed to str-typed parameters per the model layer's AxisClassification.label: str typing).
        - loki/tests/analysis/_helpers.py (new shared fixture builder module; underscore-prefixed so pytest does not collect).
        - loki/tests/analysis/{test_findings_classification_mismatch,test_findings_signature_regression,test_findings_unexpected_component,test_findings_missing_required,test_findings_classification_gap}.py (5 new test files, 56 tests total).
        - loki/specs/analysis-engine/tasks.md (tasks 13-17 ticked off).
        - loki/loom-loki.md (this file, version 0.3.4 -> 0.3.5; OT-LK-001 status updated; v0.3.5 evolution-log entry added).
        - loki/STATE.md (harness version + verification gates + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.6"
      action: "OT-LK-001 implementation Wave 6 landed (tasks 18-20 of 28); analysis-engine now callable end-to-end via analyze_image"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.6 patch bump — Wave 6 of OT-LK-001's eight-
        wave implementation plan. **20 of 28 tasks now complete (71%).**
        The integration wave: matching + pairing + scoring + posture
        + emitters + report assembly + pipeline + public API are all
        wired together. ``from loki.analysis import analyze_image``
        is a callable, fully-validated end-to-end entry point.
        Subsystem stays PROPOSED until wave 8's final gate.

        Wave 6 (integration):

        - Task 18 (report assembly): loki/analysis/report.py
          implements three pure functions —
          assign_priority_ranks (R9.10 in-place mutation of
          classification_mismatch findings' embedded
          DeviationScore.priority_rank, sorted by descending
          composite_score with ascending component_id tie-break);
          derive_report_id (R15.8 deterministic uuid5 over
          (target_image_id, baseline_id, analysis_version));
          assemble_report (R17 ImageAnalysisReport construction
          including BaselineComparison whose comparison_timestamp
          equals run_started_at per R17.4 post-HARDEN; wraps
          Pydantic ValidationError as
          AnalysisReportConstructionError per R16.5). Test file:
          test_report.py (~16 tests).
        - Task 19 (AnalysisPipeline): loki/analysis/pipeline.py
          implements the AnalysisPipeline orchestrator. Constructor
          validates config (R14), resolves Matched_Baseline (R2),
          and checks pairing pre-conditions (R3.6/R3.7). The single
          run() method orchestrates the full sequence walkthrough
          from design.md §"Sequence walkthrough": single-timestamp
          anchor at run start, R20.1 INFO log, baseline_index
          construction, target-loop with cancellation-before-
          progress-before-finding-emission ordering, per-pair
          finding emission (classification_mismatch +
          signature_regression non-mutual-exclusion per R4.8),
          classification_gap independent of pairing (R10.2),
          missing_required_component pass after target loop
          (skipped on cancellation per R7.1), Cancellation_Marker
          as last entry on cancelled runs, priority_rank second
          pass (R9.10), posture_rating derivation, report
          assembly, R20.2 INFO log with per-category counts. Test
          file: test_pipeline.py (~22 tests including
          fail-fast-on-invalid-input, empty-target-records,
          per-pair finding emission per category, combined
          findings, Cancellation_Marker contract, progress
          callback contract, two-runs-equal-modulo-timestamp,
          R20.1 + R20.2 log content).
        - Task 20 (analyze_image public entry): loki/analysis/api.py
          implements the AnalysisProgressEvent dataclass (D6
          default — strips component_id), three type aliases
          (AnalysisProgressCallback, AnalysisCancellationToken),
          and the analyze_image free function. The function
          constructs an AnalysisPipeline, adapts the public
          progress-event-shaped callback to the pipeline's
          (index, total) shape, and returns pipeline.run()'s
          result. Test file: test_api.py (~10 tests including
          public-surface smoke, the AnalysisProgressEvent
          frozen-dataclass contract, the
          loki.analysis-does-not-pull-in-loki.gui audit per R1.9,
          the calling-thread progress contract per R19.3).

        Verification gates after Wave 6:

        - pytest: 1175 passed, 6 deselected (was 1131; +44 new
          tests across 3 new test files).
        - mypy --strict: clean across 211 source files (was 208;
          +3 new test files; report.py, pipeline.py, api.py all
          populated).
        - ruff check: clean.
        - ruff format --check: clean.
        - offscreen GUI smoke: clean.

        Three minor in-flight fixes during the round:

        1. ruff I001 import-order + F401 unused-import — both
           auto-fixed via ``ruff check --fix``.
        2. mypy strict typing seam: the test helper _config()
           originally used **dict[str, object] unpacking, which
           strict mode rejects on Pydantic strict-typed
           constructors. Restructured to a kwargs-only signature
           with named parameters; same call shape, mypy-clean.
        3. mypy: two ``list:`` and ``dict:`` annotations missing
           type args (pyproject's strict config flags these);
           added explicit ``list[FindingRecord]`` and
           ``dict[str, object]`` annotations. The latter required
           an isinstance(...) guard before .pop() because the
           value type is then ``object``.

        Subsystem state changes:

        - analysis-engine: spec_status remains APPROVED;
          lifecycle_stage stays PROPOSED until wave 8.
          Implementation progress: 20 of 28 tasks complete (71%);
          waves 1-6 of 8 complete. **The complete library API
          is feature-complete** — analyze_image, the typed
          exception hierarchy, the public progress + cancellation
          surface, and the determinism contract are all
          callable. Wave 7 adds the cross-cutting tests
          (AST audits, Hypothesis property suite P43-P52,
          performance smoke, end-to-end smoke); Wave 8 ratifies
          the implementation through README/STATE/HANDOFF
          refresh and the final-gate run.

        Open thread state changes:

        - OT-LK-001: status moved from "Waves 1-5 landed; Wave 6
          next" to "Waves 1-6 landed; Wave 7 next."

        Changed files in this round:

        - loki/loki/analysis/report.py (populated; was empty docstring shell).
        - loki/loki/analysis/pipeline.py (populated; was empty docstring shell).
        - loki/loki/analysis/api.py (populated; was empty docstring shell).
        - loki/loki/analysis/__init__.py (re-exports analyze_image, AnalysisProgressEvent, and the two type aliases).
        - loki/tests/analysis/{test_report,test_pipeline,test_api}.py (3 new test files, ~48 tests total).
        - loki/specs/analysis-engine/tasks.md (tasks 18-20 ticked off).
        - loki/loom-loki.md (this file, version 0.3.5 -> 0.3.6; OT-LK-001 status updated; v0.3.6 evolution-log entry added).
        - loki/STATE.md (harness version + verification gates + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.3.7"
      action: "OT-LK-001 implementation Wave 7 landed (tasks 21-26 of 28); cross-cutting tests pin Properties P43-P52 + R18.1 performance budget"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.3.7 patch bump — Wave 7 of OT-LK-001's eight-
        wave implementation plan. **26 of 28 tasks now complete (93%).**
        Subsystem stays PROPOSED until wave 8's final gate. The
        implementation surface is feature-complete; Wave 7
        delivers the cross-cutting tests that pin the
        determinism, no-leakage, and no-side-channels invariants
        the design committed to.

        Wave 7 (cross-cutting tests):

        - Task 21 (static side-channels AST audit):
          tests/analysis/test_no_side_channels.py walks every
          .py under loki/analysis/ and pins (a) the forbidden
          import set ({random, secrets, socket, urllib*,
          requests, httpx}); (b) ``time.*`` clock calls only
          allowed in loki/analysis/timing.py; (c) ``datetime.now()``
          calls only allowed in loki/analysis/pipeline.py;
          (d) no os.environ access anywhere. Two affirmative
          checks confirm the allow-listed modules actually use
          the gated APIs, so allow-list entries don't go dead.
          Implements Property 51.
        - Task 22 (static no-leakage AST audit):
          tests/analysis/test_no_log_leakage.py walks every
          logger.{info,warning,error,debug,critical,exception,log}
          call and rejects any reference to the
          Forbidden_Leakage_Field_Set: classification's
          (component_id, signature_info.signer,
          source_image_hash, axis evidence) plus analysis-engine's
          additions (FindingEvidence.matched_rule / matched_cve /
          matched_signature / raw_indicators, FindingRecord.title /
          description). Implements Property 50 (static side).
        - Task 23 (dynamic caplog audit):
          tests/analysis/test_log_no_leakage.py captures every
          log record across the full lifecycle (paired
          disagreement, signature regression, unexpected
          component, missing required component, classification
          gap, cancellation), and asserts no record's formatted
          message contains any forbidden substring. Includes a
          dedicated test that the cancellation index N is in
          evidence.raw_indicators only and never in any log
          record per R7.4. Affirmative tests on R20.1 + R20.2
          log shape; idle-state test confirms no record is
          emitted while no analysis is in progress. Implements
          Property 50 (dynamic side).
        - Task 24 (Hypothesis property suite P43-P52):
          tests/analysis/test_properties.py implements the ten
          formal correctness properties from design.md
          §"Correctness Properties". P43 (report Pydantic
          validation), P44 (deterministic baseline matching),
          P45 (pairing bijection-with-defects), P46 (axis_score
          + composite_score determinism in unit interval / [0,
          10] respectively), P47 (two-runs-equal-modulo-
          timestamp), P48 (lossless JSON round-trip), P49
          (PostureRating closed function), P52 (Cancellation_Marker
          contract). Properties P50 + P51 are exercised by the
          AST audits (tasks 21+22) and caplog audit (task 23).
          Hypothesis settings: max_examples=50 for in-memory
          properties, max_examples=25 for full-pipeline
          properties; both with HealthCheck.too_slow +
          function_scoped_fixture suppressed.
        - Task 25 (R18.1 performance smoke):
          tests/analysis/test_performance.py marks two slow
          tests, both excluded from the default ``pytest -q``
          run via the project's existing ``-m 'not slow'``
          addopts. Both validate the 1024+1024 component budget
          under 5 seconds; the second test exercises the
          mismatch-everywhere path (1024 classification_mismatch
          findings, full priority_rank second pass). On the
          operator's reference machine: 0.10s total for both
          tests — under the 5s budget by approximately 50x.
        - Task 26 (end-to-end smoke):
          tests/test_analysis_smoke.py builds a controlled fleet
          that triggers all six finding categories in one
          analyze_image call (classification_mismatch,
          signature_regression, unexpected_component,
          missing_required_component, classification_gap, plus a
          cancellation smoke for analysis_cancelled). Verifies
          report shape, posture rating, JSON round-trip, and the
          public API surface. Mirrors
          tests/test_classification_smoke.py.

        Verification gates after Wave 7:

        - pytest: 1211 passed, 8 deselected (was 1175; +36 new
          tests across 6 new test files; 2 deselected slow-marker
          tests added).
        - pytest -m slow: 2 perf tests pass in 0.10s (well under
          the R18.1 budget).
        - mypy --strict: clean across 217 source files (was 211;
          +6 new test files).
        - ruff check: clean.
        - ruff format --check: clean.
        - offscreen GUI smoke: clean.

        Two minor in-flight fixes during the round:

        1. ruff F401 unused imports + I001 import-order — both
           auto-fixed via ``ruff check --fix``.
        2. ruff RUF002 ambiguous-multiplication-sign in two
           docstrings — replaced ``×`` with ``x`` per
           loki/HANDOFF.md's standing convention. Markdown is
           not affected by RUF002; it fires on Python comments
           and docstrings only.
        3. mypy strict bare-list type-arg — added
           ``list[ClassificationRecord]`` annotation in the
           caplog test's _forbidden_substrings helper.

        Subsystem state changes:

        - analysis-engine: spec_status remains APPROVED;
          lifecycle_stage stays PROPOSED until wave 8's final
          gate. Implementation progress: 26 of 28 tasks complete
          (93%); waves 1-7 of 8 complete. The cross-cutting test
          surface is now feature-complete. Wave 8 ratifies the
          implementation through doc refresh and the final-gate
          run; the lifecycle_stage transition PROPOSED ->
          IMPLEMENTED lands there and triggers the harness
          minor-bump to v0.4.0.

        Open thread state changes:

        - OT-LK-001: status moved from "Waves 1-6 landed; Wave 7
          next" to "Waves 1-7 landed; Wave 8 next — final gate."

        Changed files in this round:

        - loki/tests/analysis/test_no_side_channels.py (new; 233 lines, AST audit pinning Property 51).
        - loki/tests/analysis/test_no_log_leakage.py (new; ~190 lines, static AST audit pinning Property 50 static side).
        - loki/tests/analysis/test_log_no_leakage.py (new; ~360 lines, dynamic caplog audit covering all six finding categories).
        - loki/tests/analysis/test_properties.py (new; ~470 lines, Hypothesis property suite for P43-P52).
        - loki/tests/analysis/test_performance.py (new; ~140 lines, slow-marker R18.1 budget validation).
        - loki/tests/test_analysis_smoke.py (new; ~190 lines, end-to-end smoke triggering all six finding categories).
        - loki/specs/analysis-engine/tasks.md (tasks 21-26 ticked off).
        - loki/loom-loki.md (this file, version 0.3.6 -> 0.3.7; OT-LK-001 status updated; v0.3.7 evolution-log entry added).
        - loki/STATE.md (harness version + verification gates + OT-LK-001 status updated).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

    - date: "2026-05-28"
      version: "0.4.0"
      action: "OT-LK-001 CLOSED — Wave 8 final-gate ratification; analysis-engine v1.0.0 ships at IMPLEMENTED + APPROVED"
      author: "LOKI contributors"
      subsystems_affected: [analysis-engine]
      notes: |
        Same-day v0.4.0 minor bump per §10's "Most likely v0.2.0
        trigger: analysis-engine BIND" — the implementation BIND
        has now landed, so the next minor bump rolls forward
        from v0.3.x to v0.4.0. **OT-LK-001 closes.** All 28 tasks
        across 8 waves complete. Subsystem state transitions:

        - analysis-engine: spec_status APPROVED (unchanged) +
          lifecycle_stage PROPOSED -> IMPLEMENTED. Subsystem now
          ships at v1.0.0 alongside the four pre-existing shipping
          subsystems (models, extraction, baseline, classification).
        - Dependency graph §3 materializes the three previously-
          (planned) edges: analysis-engine -> models,
          analysis-engine -> classification, analysis-engine ->
          baseline. Edge count rises from 14 to 17 materialized.

        Wave 8 (final gate):

        - Task 27 (docs refresh):
          - loki/README.md: Status table updated (4 -> 5
            shipping subsystems); new ## Analysis engine section
            (~150 lines) with public API example, six-finding-
            category breakdown, six-rule PostureRating cascade,
            cooperative-cancellation pattern, determinism +
            no-leakage discipline pointers, P43-P52 reference,
            R18.1 perf summary, out-of-scope list. Repository
            layout updated with loki/analysis/ subtree (12
            modules) and tests/analysis/ subtree (~21 test files).
            ## Verification at the current checkpoint section
            updated: 1211 tests / 217 source files / 8 slow-marker
            tests / R18.1 budget. ## Next moves section
            re-prioritized: analysis engine moves out of the list
            (now shipping); CVE feed integration (OT-LK-002) is
            the new top priority.
          - loki/STATE.md: harness version + verification gates +
            OT-LK-001 status updated; subsystem registry now lists
            5 IMPLEMENTED + APPROVED subsystems instead of 4.
          - Sloptropy/STATE_AND_NEXT_STEPS.md: workspace-level
            loki entry refreshed.
          - loki/loom-loki.md (this file): version 0.3.7 -> 0.4.0;
            §1 metadata description updated to reference five
            spec triples (analysis-engine joins the list); §2
            analysis-engine subsystem entry refreshed (lifecycle
            IMPLEMENTED + full description + populated public_interface
            + ten Property entries P43-P52 + R18.1 perf entry); §3
            dependency graph materializes the three new edges with
            "established_by: v0.4.0 (Wave 8 BIND)"; OT-LK-001
            status moved to CLOSED with a closing summary; v0.4.0
            evolution-log entry added.
          - loki/HANDOFF.md not refreshed in this round; that's a
            separate bookkeeping pass.
        - Task 28 (final verification gate):
          - pytest -q: 1211 passed, 8 deselected.
          - pytest -m slow: 8 passed (2 baseline + 2 classification
            + 2 extraction + 2 analysis); 1211 deselected.
            Analysis R18.1 budget: 0.10s actual vs 5.0s budget.
          - mypy --strict loki tests scripts: clean across 217
            source files.
          - ruff check: clean.
          - ruff format --check: clean (217 files).
          - QT_QPA_PLATFORM=offscreen scripts/smoke_gui.py: clean.
          - Public API smoke:
            ``from loki.analysis import analyze_image,
            AnalysisProgressEvent, ANALYSIS_VERSION`` works;
            ANALYSIS_VERSION = "1.0.0".

        Subsystem state changes:

        - analysis-engine: lifecycle_stage PROPOSED -> IMPLEMENTED.
          spec_status remains APPROVED. Subsystem ships at v1.0.0.
          All 28 tasks per specs/analysis-engine/tasks.md
          ticked off.

        Open thread state changes:

        - OT-LK-001: CLOSED. The thread's notes preserve the full
          implementation history (Waves 1-8) for future reference.
          Next analysis-related OTs that may open in subsequent
          rounds: GUI analysis view (OT-LK-004 already covers a
          related GUI surface), CLI analysis subcommand (would be
          OT-LK-006 if/when opened), analyze_fleet (deferred —
          needs feeds first per the design's deferred-decisions).

        Total round count: this is round eleven of the day. Order:
        TENSION pass (v0.1.1) -> requirements HARDEN (v0.2.0) ->
        design BIND (v0.3.0) -> tasks BIND (v0.3.1) -> Wave 1+2
        impl (v0.3.2) -> Wave 3 (v0.3.3) -> Wave 4 (v0.3.4) ->
        Wave 5 (v0.3.5) -> Wave 6 (v0.3.6) -> Wave 7 (v0.3.7) ->
        Wave 8 BIND (v0.4.0). Each round was checkpoint-clean
        before advancing to the next.

        Final analysis-engine surface area:

        - 12 source modules under loki/analysis/ totalling
          approximately 1300 lines of source (excluding test code
          and docstrings).
        - 22 test files under tests/analysis/ totalling
          approximately 2900 lines of test code.
        - 1 end-to-end smoke at tests/test_analysis_smoke.py
          (~200 lines).
        - Test count delta this implementation phase: +314 default
          tests + 2 slow-marker performance tests.
        - Source file count delta: +14 source modules + 22 test
          modules = +36 total. (176 -> 217.)

        Workspace observation continues: .venv/bin/* shebangs are
        stale (point at /Users/daborond/Projects/loki/.venv/bin/
        python3.12 from a prior workspace move); workaround is
        ``.venv/bin/python -m <tool>`` instead of
        ``.venv/bin/<tool>``. Operator may want to rebuild the
        venv at some point; not blocking.

        Changed files in this round:

        - loki/README.md (Status table; new ## Analysis engine section ~150 lines; Repository layout updated with analysis/ subtrees; ## Verification at the current checkpoint refreshed; ## Next moves re-prioritized).
        - loki/specs/analysis-engine/tasks.md (tasks 27-28 ticked off; full task list now 28/28 complete).
        - loki/loom-loki.md (this file, version 0.3.7 -> 0.4.0; §1 metadata; §2 analysis-engine subsystem entry refreshed at IMPLEMENTED; §3 dependency graph materialized 3 new edges; OT-LK-001 status CLOSED; v0.4.0 evolution-log entry added).
        - loki/STATE.md (harness version + verification gates + OT-LK-001 status updated; subsystem count now 5 IMPLEMENTED+APPROVED).
        - Sloptropy/STATE_AND_NEXT_STEPS.md (workspace-level loki entry refreshed).

---

## 5. Open Threads

    - id: "OT-LK-001"
      title: "analysis-engine implementation (CLOSED — all 28 tasks complete; subsystem IMPLEMENTED at v1.0.0)"
      status: "CLOSED — 2026-05-28; analysis-engine v1.0.0 ships at IMPLEMENTED + APPROVED"
      priority: "CLOSED"
      notes: "Spec triple BIND'd 2026-05-28. All eight implementation waves landed same day (Wave 1 skeleton, Wave 2 foundations, Wave 3 matching + pairing + finding_id helper + Cancellation_Marker, Wave 4 six scoring helpers + PostureRating six-rule cascade, Wave 5 five per-category emitters, Wave 6 report assembly + AnalysisPipeline + analyze_image, Wave 7 cross-cutting tests covering Properties P43-P52 + R18.1 perf + e2e smoke, Wave 8 docs refresh + lifecycle transition + final gate). Final checkpoint: 1211 pytest pass / 8 deselected; mypy --strict clean across 217 source files; ruff lint + format clean; offscreen GUI smoke clean; R18.1 perf budget 0.10s actual vs 5s budget. The complete library API (`from loki.analysis import analyze_image`) is feature-complete and fully tested. The closed task list is preserved at `specs/analysis-engine/tasks.md` (28/28 ticked). subsystem state: lifecycle_stage IMPLEMENTED, spec_status APPROVED. Next OT for the analysis surface: GUI analysis view (paired with OT-LK-004's GUI classification view), CLI analysis subcommand (OT-LK-006 if/when opened), or analyze_fleet (deferred — needs feeds first). Workspace observation continues: .venv/bin/* shebangs are stale; workaround is .venv/bin/python -m <tool>; this should be rebuilt at some point but is not blocking."

    - id: "OT-LK-002"
      title: "CVE feed integration (CLOSED — feeds + consumer-wiring + fleet all shipped)"
      status: "CLOSED — 2026-05-29; feeds v1.0.0, consumer-wiring v1.0.0, fleet-analysis v1.0.0 all ship at IMPLEMENTED + APPROVED"
      priority: "CLOSED"
      notes: |
        HANDOFF.md candidate move #1. Will populate
        ClassificationRecord.cve_matches (currently always [] in v1
        per upstream classification R6) by mapping
        (component, classification) pairs against an NVD-style feed.

        CAST round resolved 2026-05-28. Eight design dimensions
        banked, listed below. Two of those (D1, D8) carry forward
        precedent for the future spec triple; six (D1a, D2-D7) shape
        v1's implementation footprint. The model layer's
        `FeedsConfig` already exists in `loki/models/config.py` with
        fields `nvd_url`, `update_interval`, `cache_path`,
        `implant_rules_path`; D4-D adds one optional field
        `signing_key_path: str | None = None` (small migration).

        Banked CAST decisions:

        - D1   Refresh-trigger surface  : daily-default + on-demand
                                          via `loki feeds refresh`
                                          subcommand. Both surfaces
                                          ship in v1.
        - D1a  How daily fires          : D1a-C cadence-aware on-
                                          demand. No scheduler, no
                                          daemon, no OS integration.
                                          Cache-age check at the top
                                          of the lookup path fires
                                          an inline refresh if older
                                          than the configured
                                          `FeedsConfig.update_interval`.
                                          `--no-refresh` flag for
                                          read-only consumers; manual
                                          `loki feeds refresh` for
                                          warm-up.
        - D2   Cache layout             : D2-C SQLite at
                                          `<cache_path>/feeds.db`
                                          with WAL mode. Stdlib only
                                          (no new dependency).
                                          Indexed `(vendor, product,
                                          version)` lookup matching
                                          the D6-A CPE shape.
        - D3   Feed sources in v1       : D3-A NVD only. Vendor
                                          advisories deferred to a
                                          future spec that will
                                          introduce both a second
                                          source and the feed-source
                                          abstraction together.
        - D4   Signed-feed validation   : D4-D hybrid trust anchor.
                                          Package-embedded default
                                          public key (the common
                                          case works out of the
                                          box) plus optional
                                          `FeedsConfig.signing_key_path`
                                          override (rotation escape
                                          hatch + high-trust
                                          operators bring their own
                                          key).
        - D5   Refresh-failure semantics: D5-D tiered. Signature/hash
                                          validation failure is hard
                                          fail (security event;
                                          someone might be feeding
                                          bad data). Network/server
                                          failure is warn-and-
                                          continue with stale-cache
                                          fallback (operational
                                          hiccup; previous snapshot
                                          is still trustworthy).
                                          Partial download is hard
                                          fail (data integrity
                                          event; better to leave the
                                          previous DB intact).
        - D6   Match shape              : D6-A CPE matching against
                                          NVD's native vocabulary.
                                          Classification axes
                                          (`vendor: INTEL`,
                                          firmware_version) map
                                          mechanically to
                                          CPE-2.3's
                                          `(vendor, product, version)`
                                          triple. Consumes
                                          `ClassificationRecord.cve_matches`
                                          field verbatim — no model
                                          migration on the consumer
                                          side.
        - D7   Implant-rule surface     : D7-C hybrid implant rules.
                                          Built-in starter set
                                          shipped in
                                          `loki/feeds/builtin_implants/`
                                          (conservative IOCs from
                                          public threat reports —
                                          BlackLotus, MosaicRegressor,
                                          LoJax, etc.; stable file
                                          hashes and well-defined
                                          GUID matches only). Operator-
                                          extension via
                                          `FeedsConfig.implant_rules_path`.
                                          Schema mirrors the existing
                                          classification-rules
                                          pattern at
                                          `loki/classification/rules/`.
                                          No network feed for
                                          implants in v1.
        - D8   Threat context           : D8-B FULL. First subsystem
                                          with outbound network
                                          egress + signature/trust
                                          verification. Sets the
                                          precedent that FULL means
                                          "we make external network
                                          calls and validate trust
                                          anchors." Audit-trigger
                                          flag now active in the
                                          harness for any feeds work
                                          going forward.

        Forward threads surfaced during CAST (resolve at TENSION pass
        of the future requirements DRAFT, NOT here):

        1. NVD signing-vs-hash-pinning verification. D4-D banks "key
           pinning"; whether NVD signs the feed bundle vs. publishes
           SHA-256 integrity hashes only requires checking against
           current NVD documentation. Banked decision still holds
           (key pinning is what we want); implementation may end up
           pinning a hash root instead of a public key, which is
           structurally similar.
        2. CPE parser dependency-vs-handroll. `python-cpe` on PyPI
           is lightly maintained; license + Python 3.12 compatibility
           need verification. Hand-rolling a minimal CPE-2.3 parser
           is feasible (~30 fields, stable spec since 2011).
        3. Bundled-implant-rule maintenance cadence. Shipping the
           starter set creates a release-cadence dependency: new
           public implant disclosures means new loki releases.
           Mitigation: keep the bundled set conservative.
        4. Exit-code taxonomy. D5-D's tiered semantics imply distinct
           exit codes for SignatureValidationError, NetworkError,
           PartialDownloadError, CacheCorruption. Closed-set
           decision belongs at design phase, mirroring classify-cli's
           `{0, 2, 3, 4, 5, 6, 130}` pattern.
        5. `FeedsConfig` model migration. D4-D adds
           `signing_key_path: str | None = None`. Counts in the
           implementation footprint as a small but real model-layer
           change.
        6. Property-numbering allocation. Per project-wide
           convention, feeds picks up at P59. The next subsystem
           after feeds picks up at the post-feeds count.
        7. FULL-context audit work. D8-B's threat-context lift means
           the feeds spec needs explicit no-leakage audits on
           network requests (no env vars, system identifiers, or
           firmware content in HTTPS bodies or headers). Probably
           an AST audit + a request-capture dynamic audit,
           paralleling the classify-cli stderr audits.

        Per the project's "spec drafting is its own conversation"
        rule, the requirements DRAFT lands in a future session
        AGAINST this banked CAST. Estimated arc: requirements
        DRAFT → TENSION → HARDEN (1 session); design BIND (1
        session); tasks BIND (1 session); 6-8 implementation
        waves (6-8 sessions). Total ~10-12 focused sessions.

    - id: "OT-LK-003"
      title: "Classification CLI subcommand (CLOSED — implementation v1.0.0 ships at IMPLEMENTED + APPROVED)"
      status: "CLOSED — 2026-05-28; classify-cli v1.0.0 ships at IMPLEMENTED + APPROVED"
      priority: "CLOSED"
      notes: "HANDOFF.md candidate move #2. Requirements DRAFT → TENSION → HARDEN landed 2026-05-28; design BIND landed same session against project's `spec drafting is its own conversation` rule (operator-approved deviation, recorded in `specs/classification-cli/requirements-tension-pass.md` HARDEN footer). Spec triple at `specs/classification-cli/{requirements.md, design.md, requirements-tension-pass.md, tasks.md}`. The 12 banked design decisions D1-D12 from CAST conversation plus two operator-added flags (`--debug`, `--summary-only`) are documented in requirements.md; the seven design defaults D1-D7 plus three open questions Q1-Q3 are documented in design.md (D-defaults all baked in at implementation; Q1-Q3 pinned by implementation choices). Properties P53-P58 with explicit P59 handoff to the next subsystem. Subsystem registered as `classify-cli` in §2; lifecycle_stage IMPLEMENTED, spec_status APPROVED. v1.0.0 shipped: ~310 source lines added (loki/classify_helpers.py + loki/cli.py classify additions); ~104 new tests across 22 test modules under tests/classify_cli/; final pytest count 1317; final mypy --strict file count 240. R11.1 wrapper-only timing budget validated at <200ms. Closed via the Wave 6 implementation BIND that materialized the three classify-cli dependency-graph edges (classify-cli → models, classify-cli → classification, cli → classify-cli)."

    - id: "OT-LK-004"
      title: "GUI views (classification + analysis + fleet) — formalization"
      status: "RESOLVED — 2026-06-02; gui spec triple BIND-complete at specs/gui-views/; subsystem registry flipped AD_HOC → APPROVED in loom v1.0.2"
      priority: "CLOSED"
      notes: |
        Closed in a single conversation arc on 2026-06-02. Three
        commits land the implementation cleanup before the spec
        triple drafts (98c2110 wave A, e138baf wave C); a fourth
        commit lands the spec triple itself.

        Cleanup waves (pre-spec, so the spec describes the cleanest
        possible state of the GUI rather than the v1.0.0 AD_HOC
        snapshot):

        - Wave A (98c2110): AnalysisWorker gets a threading.Event
          cancellation token + typed-exception error contract
          mirroring BaselineLoadWorker; closeEvent now cancels and
          joins the analysis worker too. ClassificationView (83
          lines) deleted — dead code never opened from MainWindow;
          its rendering surface is covered by AnalysisView.
        - Wave B (QThreadPool migration) DEFERRED to a future OT-LK
          per operator decision in CAST. The v1 spec ratifies the
          existing QThread-subclass pattern with a forward-tracked
          migration recorded in Requirement 24.
        - Wave C (e138baf): AnalysisView fills in every public
          field on ImageAnalysisReport (recommended_actions table,
          baseline_comparison sub-section, full per-finding evidence
          including classification_record axis breakdown,
          deviation_score per-axis, matched_rule / CVE / signature,
          raw_indicators, finding_id). FleetView renders
          FleetAnalysisReport.recommended_actions.

        Spec triple (parallel-agent workflow; same conversation):

        - DRAFT panel: 3 isolated agents wrote DRAFT requirements
          from different angles (model-fidelity / threat-context /
          operator-experience). Judge picked Draft 1 on every
          primary criterion (CAST faithfulness; EARS format; risk
          coverage; property-allocation richness; file:line citation
          density; appropriate length). Grafted ~10 concrete details
          from runners-up.
        - TENSION panel: 5 isolated lenses (correctness-vs-impl;
          threat-context-completeness; cross-subsystem-contract-
          adherence; EARS-format-compliance; operator-honest-
          framing). Cross-lens consensus surfaced three high-value
          items (BaselineRegistry term mismatch; closeEvent /
          cancellation defensive programming; stale R10 cross-
          reference) that each got applied to multiple requirements.
        - HARDEN: tension-pass document (292 lines) consolidates
          all five lenses; HARDEN footer records audit-items applied
          plus three new forward-tracked items in Requirement 24
          (single-window-only ratification; worker BaselineStore
          re-load; help-menu single-entry closure) and three new CI
          gates in Requirement 26 (loki.cli import audit;
          processEvents audit; network-egress import-time audit).
        - DESIGN BIND: 695 lines covering subsystem positioning,
          architecture diagram, view ↔ model binding table, worker
          contracts, action surface + enablement matrix, persistence
          / closeEvent lifecycle, threading model with D2 forward-
          tracked migration rationale, test surface, properties P77-
          P85 with Validates-Requirements mapping, three open
          questions Q1-Q3, and five revertable design defaults.
        - TASKS BIND: ~17 tasks across 5 waves: (1) acceptance
          verification per requirement; (2) test coverage gap fills;
          (3) forward-tracked refactor candidates (each becomes its
          own OT-LK after spec ships); (4) doc refresh; (5) final
          acceptance gate.

        Subsystem registry: gui spec_status AD_HOC → APPROVED;
        spec_path / design_path / tasks_path now point at the real
        spec files at specs/gui-views/.

        Spec artifacts:

        - specs/gui-views/requirements.md (1725 lines, 26
          requirements + 9 properties P77-P85)
        - specs/gui-views/requirements-tension-pass.md (292 lines,
          5-lens TENSION audit + HARDEN footer)
        - specs/gui-views/design.md (695 lines)
        - specs/gui-views/tasks.md (685 lines, ~17 tasks across
          5 waves)

        Forward threads opened by this round (each will become its
        own OT-LK entry when prioritised; not opened proactively to
        avoid backlog clutter): QThreadPool migration; ExtractionWorker
        bool→Event migration; preferences dialog; export surface;
        Action_Function Protocol extraction; Briefcase release-path
        completions; Linux AppImage qmake build gap (already tracked
        in v1.0.0 release notes).

    - id: "OT-LK-005"
      title: "Baseline schema migration tool"
      status: "OPEN — process improvement"
      priority: "LOW"
      notes: "HANDOFF.md candidate move #4. v1 supports exactly one Schema_Version per BaselineRegistry; the baseline subsystem quarantines any other. A future `baseline-schema-migration` spec defines an explicit migration path between schema versions. Not blocking until the second Schema_Version exists; until then the quarantine path is the right contract."

    - id: "OT-LK-006"
      title: "ExtractionManifest schema migration"
      status: "OPEN — surfaced 2026-05-28 during classification-cli TENSION pass"
      priority: "LOW"
      notes: "Surfaced during OT-LK-003 TENSION pass. The `ExtractionManifest` envelope has no `schema_version` field today, unlike the baseline-persistence envelope (R4 of baseline-persistence). Cross-version manifest compatibility is therefore implicit; if the model layer evolves (e.g. adds a required field on `ExtractedComponent` or `ExtractionManifest` itself), saved manifest JSON files on disk become unparseable by Pydantic strict-mode validation. Out of scope for the classification-cli spec; tracked here as a future thread analogous to OT-LK-005 for baseline schema migration. Not blocking until the model layer changes shape; until then the implicit-versioning contract holds. A future `extraction-manifest-schema-migration` spec defines a Schema_Version envelope and a migration command. Cross-cutting: extraction subsystem owns the envelope; classification-cli (and any future analysis-cli, fleet-analysis surface) consumes it; the model layer ratifies the new envelope shape."

---

## 6. Selvage Rules

The standard WEAVE Selvage Rules (S-001 through S-014) apply unchanged. See `~/Sloptropy/game/loom-game.md` Appendix B for the canonical reference. Loki-specific notes:

- **S-007 (missing error paths)** is heavily exercised here because the project's Tier 1–2 spec triples all explicitly enumerate failure modes (R5.6 dual-record contract in classification, the typed exception hierarchy in baseline, the per-component ExtractionError in extraction). Any new analyzer or feed integration must produce a structured error per the existing pattern, not silently skip.
- **S-009 (circular dependencies)** is enforced by the strict DAG in §3. `models` must remain the leaf; any FRAY that would back-edge from models to a downstream subsystem must be rejected at HARDEN.
- **S-013 (threat context mismatch)** matters most when adding the feeds subsystem (OT-LK-002), because it introduces network egress for the first time. The default STANDARD posture will need explicit re-evaluation; if signature-pinning is chosen, the credential-handling exception lifts that subsystem partially toward FULL.

---

## 7. The Warp — Finalized Interfaces

The Warp captures the eight registered subsystems' approved public interfaces. The full type signatures live in the specs/{loki-data-models,extraction-pipeline,baseline-persistence,classification-pipeline}/ triples plus the source under loki/. The Loom Warp here reflects the contracts at v0.1.0:

### models

```python
# Selected exports from loki.models — full set in loki/models/__init__.py
from loki.models import (
    # firmware
    FirmwareImage, ExtractedComponent, ExtractionError, ExtractionManifest,
    # classification
    AxisClassification, SignatureInfo, OverrideRecord, ClassificationRecord,
    # baseline
    BaselineRecord, BaselineRegistry, DeviationRecord, BaselineComparison,
    # analysis
    DeviationScore, FindingEvidence, FindingRecord, ActionRecord,
    # reports
    ReportSummary, ImageAnalysisReport, FleetAnalysisReport,
    # config
    LokiConfig,
    # enums
    ComponentType, Vendor, SecurityPosture, Mutability, Severity, PostureRating,
    OutputFormat, LogLevel, DeltaType,  # plus 5 more StrEnums
    # constants
    LOKI_NAMESPACE,
)

# Strict validation on construction; lossless JSON / YAML round-trip;
# auto-computed fields on ClassificationRecord (composite_confidence,
# needs_review), BaselineComparison (summary counts by DeltaType),
# ImageAnalysisReport (severity distribution), FirmwareImage (image_id
# = uuid5(LOKI_NAMESPACE, file_hash)), and ExtractedComponent
# (component_id = uuid5(LOKI_NAMESPACE, f"{file_hash}:0x{offset:x}:{raw_hash}")).
```

### extraction

```python
from loki.extraction import extract_firmware
from loki.models import ExtractionConfig

config = ExtractionConfig(
    default_output_dir="/tmp/loki-out",
    max_component_size=50_000_000,
    timeout_per_component=60,
)
result = extract_firmware(Path("/firmware/image.rom"), config)
# result.manifest is a validated ExtractionManifest;
# result.tools_available is dict[str, bool];
# result.duration_seconds is a float.
```

Property invariants per `specs/extraction-pipeline/design.md §Properties`:

1. Round-trip: same binary + same config → bit-equal manifest minus timestamps.
2. Component-ID determinism: `uuid5(LOKI_NAMESPACE, ...)` is bit-equal across runs and hosts.
3. Output-filename purity: filenames depend only on the deterministic component_id.
4. No environmental side-channels: no env-var leaks into manifest output.
5. Eleven Hypothesis-property tests pin the contract.

### baseline (GLEIPNIR)

```python
from loki.baseline import BaselineStore
from loki.models import BaselineRecord, BaselineRegistry

store = BaselineStore(root_dir=Path("./baselines"))
store.save(name="gold-laptop-bios-v1", record=record)         # atomic write
record = store.load(name="gold-laptop-bios-v1")               # mtime/size concurrency check
store.list()                                                   # → list[str]
store.delete(name="gold-laptop-bios-v1")
# Quarantine for malformed input is automatic; access via store.quarantine.list()
```

Property invariants:

1. Round-trip: BaselineRecord → YAML → BaselineRecord is structurally equal.
2. Atomicity: write is observable as either complete or absent; no partial files.
3. Concurrency safety: mtime + size check rejects stale reads after concurrent writes.
4. Quarantine isolation: malformed input never overwrites a valid stored baseline.

### classification

```python
from loki.classification import (
    classify_components, ClassificationResult,
    ProgressEvent, ProgressCallback, CancellationToken,
)

result = classify_components(
    components=manifest.components,        # from extraction
    progress=callback,                     # optional ProgressCallback
    cancel=CancellationToken(),            # optional CancellationToken
)
# result.records is list[ClassificationRecord];
# result.errors is list[ClassificationError];
# R5.6 dual-record contract: missing-bytes components emit BOTH a record AND an error
# for the same component_id.
```

Property invariants per `specs/classification-pipeline/design.md §Properties` (P33–P42, ten properties):

- Determinism: same inputs + same rule registry → same ClassificationRecord set.
- R5.6 dual-record contract.
- Performance: 4096 components × 1024 rules under 30s (R11.1 — actual ~3s); 4096 components × 256 MiB total under 60s (R11.3 — actual ~3s).
- Hypothesis property tests at full depth pin the contract.

### gui

```python
from loki.gui.app import LokiApp

app = LokiApp(args)
app.exec()                                  # standard Qt event loop
# Threaded workers: BaselineLoadWorker (per-file progress + cancellation per R2.8-R2.10
# + R7.10-R7.11), ExtractionWorker (background extraction with progress).
```

The smoke harness at `scripts/smoke_gui.py` is the gate; run with `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/smoke_gui.py` in CI.

### cli

```sh
# Console-script entry point: loki = loki.cli:main (per pyproject.toml [project.scripts])
loki gui                                   # launch desktop
loki extract <firmware.rom> [--progress]   # run extraction pipeline
loki baseline list
loki baseline show <name>
loki baseline import <yaml-path>
loki baseline export <name> [--output <yaml-path>]
loki baseline delete <name>
```

### Implementation surface map

```
loki/loki/
├── __init__.py
├── cli.py              → cli
├── models/             → models
│   ├── enums.py
│   ├── firmware.py
│   ├── classification.py
│   ├── baseline.py
│   ├── analysis.py
│   ├── reports.py
│   └── config.py
├── extraction/         → extraction
│   ├── api.py          (entry point)
│   ├── config.py
│   ├── detection.py
│   ├── ids.py
│   ├── inner_carve.py
│   ├── manifest.py
│   ├── streaming.py
│   ├── timing.py
│   ├── errors.py
│   ├── extractors/     (per-format extractor implementations)
│   └── tools/          (UEFI / decompression helpers)
├── baseline/           → baseline (GLEIPNIR)
│   ├── store.py
│   ├── envelope.py
│   ├── schema.py
│   ├── concurrency.py
│   ├── quarantine.py
│   ├── naming.py
│   └── errors.py
├── classification/     → classification
│   ├── api.py          (entry point)
│   ├── classifier.py
│   ├── pipeline.py
│   ├── signatures.py
│   ├── timing.py
│   ├── version.py
│   ├── errors.py
│   └── rules/          (rule modules)
└── gui/                → gui
    ├── app.py
    ├── main_window.py
    ├── workspace.py
    ├── navigation.py
    ├── extraction_worker.py
    ├── baseline_load_worker.py
    ├── actions/
    ├── views/
    └── demo/

loki/scripts/smoke_gui.py     → scripts (smoke harness)
loki/tests/                   → covers all subsystems (897 pytest tests, 6 deselected)
```

---

## 8. Conventions

    coordinate_system: "(N/A — Loki is a non-spatial system)"
    deterministic_id_namespace: "uuid5(LOKI_NAMESPACE, ...) — see loki.models.LOKI_NAMESPACE constant"
    component_id_formula: "uuid5(LOKI_NAMESPACE, f'{file_hash}:0x{offset:x}:{raw_hash}')"
    image_id_formula: "uuid5(LOKI_NAMESPACE, file_hash)"
    persistence_format: "YAML on disk for baselines (one file per baseline); JSON via Pydantic for ephemeral manifests"
    schema_versioning: "Schema_Version field on BaselineRecord; quarantine for non-matching versions; explicit migration tool deferred to OT-LK-005"
    cli_entry_point: "loki = loki.cli:main (per pyproject.toml [project.scripts])"
    framebuffer_or_window_or_layout: "(GUI-specific; PyQt6 main window with workspace + navigation + actions panes)"
    api_keys_storage: "(N/A — Loki has no API keys in v1; feeds subsystem will introduce signature-key handling at CAST)"
    license: "Proprietary"
    test_marker_for_slow_tests: "@pytest.mark.slow (excluded by default per pyproject.toml [tool.pytest.ini_options])"
    distribution_status: "Alpha (per pyproject.toml Development Status :: 3 - Alpha)"
    verification_gates: "pytest -q (897 pass / 6 deselected) + mypy --strict (176 files clean) + ruff check (clean) + ruff format --check (clean) + offscreen GUI smoke (scripts/smoke_gui.py exit 0) — all four are required before any release tag"

---

## 9. Session Management

The standard WEAVE session-management guidance applies. Loki-specific notes:

- **Reset cadence:** the harness covers eight registered subsystems with a strict DAG and four shipped Tier 1–2 spec triples. A single Shuttle session can address an end-to-end cross-subsystem change for the IMPLEMENTED set without exhausting context. The PROPOSED subsystems (analysis-engine especially) likely need multi-session decomposition: HANDOFF.md is explicit that spec drafting is its own conversation, not merged with implementation. The classification spec was drafted across multiple turns of a recent conversation and the implementation followed across a half-dozen wave-sized sessions; the same cadence is the path of least surprise for analysis-engine.
- **Implementation tool note:** the project has historically used manual implementation with Cursor / Claude Code rather than a Tier 3 spec-driven tool. This Loom does not change that; future Shuttle cycles output specs that operators implement by hand against the existing `specs/` triples.
- **Spec-versioning relationship:** `specs/loki-data-models/`, `specs/extraction-pipeline/`, `specs/baseline-persistence/`, and `specs/classification-pipeline/` are the authoritative pre-Loom artefacts. They are not displaced by this harness; the harness's §2 / §7 reflects them. The pending `specs/analysis-engine/requirements.md` stub is the seed for the next major Shuttle cycle.

---

## 10. Versioning This File

When updating the Loom, increment the version in Project Metadata (§1) and add an Evolution Log entry (§4). The standard rules apply:

- **Major bump (X.0.0):** breaking change to the Loom itself (section restructure, format change). Currently at 0.1.0; no major bumps anticipated for v1.
- **Minor bump (0.Y.0):** new subsystem registered, FRAY landed, or significant cross-subsystem change. Most likely v0.2.0 trigger: analysis-engine BIND.
- **Patch bump (0.1.Z):** documentation correction, cross-reference repair, or single-subsystem metadata update.

---

WEAVE v0.3.0 — Workflow Engineering via Adaptive Validated Elaboration

"The specification is the product. Code is a derived artifact."
```
