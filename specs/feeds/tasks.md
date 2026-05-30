
# Implementation Plan

## Overview

This is the executable task list for the **feeds** spec. Tasks are ordered so that each one builds on previous tasks and leaves the repo in a verifiable state (every checkpoint passes `pytest`, `mypy --strict`, `ruff check`, and `ruff format --check`).

Each task lists the exact files it touches, the test surface it adds, and the design / requirement references it implements. Sub-bullets under each task are checklist items the implementer ticks off as they go; they are not separate tasks.

Honest scope reminder: this plan covers the feeds subsystem only. Per the requirements introduction, vendor advisory feeds, a scheduler/daemon, an implant-rule network feed, auto-population of `ClassificationRecord.cve_matches`, modification of the analysis engine's finding surfaces, streaming NVD download, GUI integration, cache schema migration, and fleet CVE rollup are explicitly out of scope. v1 ships the library API at `from loki.feeds import FeedRegistry` plus the `loki feeds refresh` CLI subcommand.

The eight design decisions locked in at the design BIND gate (D1: hash-pin trust anchor default; D2: NVD JSON 2.0 format; D3: semver-heuristic version-range matching; D4: frozen dataclasses for result types; D5: 10,000-row INSERT batch size; D6: no progress callback on refresh; D7: same-host-only redirect policy; D8: Properties P59-P68) are baked into this task list.

## Pre-flight checklist

Before starting, confirm the repo is healthy:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy --strict loki tests scripts
.venv/bin/python -m ruff check
.venv/bin/python -m ruff format --check
```

All four must be green. The current checkpoint per `loki/HANDOFF.md` is **1317 passed, 9 deselected** with mypy clean across **217 source files**. The feeds work assumes the model layer, extraction pipeline, baseline-persistence, classification-pipeline, and analysis-engine subsystems are all intact and at their v1 contracts.

The feeds subsystem's threat context is FULL per D8-B. This is the project's first surface with outbound network egress and trust-anchor verification. The six-audit FULL-context discipline is pinned by tasks 25-30.

## Tasks

- [x] 1. Scaffold the `loki/feeds/` package skeleton

  - Create `loki/feeds/__init__.py`, `registry.py`, `cache.py`, `refresh.py`, `trust.py`, `cpe.py`, `implants.py`, `models.py`, `errors.py`, `version.py`, `timing.py`, `cli.py` as empty modules with docstrings + `__all__: list[str] = []`.
  - Create `loki/feeds/_trust_anchor.pem` as a placeholder (empty file; replaced with real content in task 8).
  - Create `loki/feeds/builtin_implants/__init__.py` (empty package marker).
  - Create `tests/feeds/__init__.py` and an empty `tests/feeds/conftest.py` so pytest can collect from the new tree.
  - Verify the empty subsystem imports cleanly: `.venv/bin/python -c "import loki.feeds"`.
  - Run the four verification gates and confirm test count is unchanged (1317 / 9 deselected). Source file count rises to 232+ (14 new modules + 2 test-tree modules).
  - _Requirements: none — pure scaffolding_
  - _Design: Architecture — Module layout_

- [x] 2. Implement `FEEDS_VERSION` and the result models

  - In `loki/feeds/version.py` define `FEEDS_VERSION: str = "1.0.0"`.
  - In `loki/feeds/models.py` implement all result dataclasses per the design: `RefreshStatus` (StrEnum), `RefreshResult`, `CVEMatch`, `CVELookupResult`, `CVELookupQuery`, `ImplantRuleMatch`, `ImplantRuleLookupResult`, `ImplantRuleLookupQuery`, and the `CancellationToken` type alias.
  - All result types are `@dataclass(frozen=True)`.
  - Re-export everything from `loki/feeds/__init__.py`.
  - Add `tests/feeds/test_models.py` covering: every dataclass is constructible, frozen (assignment raises), `RefreshStatus` enum values match `{"SUCCESS", "WARN_STALE", "CANCELLED", "FAILED"}`, `FEEDS_VERSION` matches `^\d+\.\d+\.\d+$`.
  - _Requirements: 1.8, 6.5, 7.9, 10.5, 11.4_
  - _Design: Architecture — Result models; D4 frozen dataclasses_

- [x] 3. Implement the typed exception hierarchy

  - In `loki/feeds/errors.py` define: `FeedsError(Exception)` root, `FeedsConfigError(FeedsError)`, `FeedsSignatureError(FeedsError)`, `FeedsNetworkError(FeedsError)`, `FeedsCacheError(FeedsError)` with `partial_download: bool` attribute, `FeedsRefreshError(FeedsError)`.
  - Each exception carries a non-empty `message: str` attribute.
  - `FeedsCacheError.__init__` takes `message: str` and `partial_download: bool = False`.
  - Re-export from `loki/feeds/__init__.py`.
  - Add `tests/feeds/test_errors.py` covering: every exception is constructible, all are subclasses of `FeedsError`, `FeedsCacheError.partial_download` attribute is accessible, `str()` includes the message.
  - _Requirements: 5.1-5.6, 11.7_
  - _Design: Architecture — Exception hierarchy; Error handling_

- [x] 4. Extend `FeedsConfig` with `trust_anchor_path` (HARDEN G5)

  - In `loki/models/config.py` add `trust_anchor_path: str | None = None` to `FeedsConfig`.
  - Update `tests/test_config.py` (or wherever `FeedsConfig` is tested) to:
    - Construct a `FeedsConfig` with `trust_anchor_path` omitted → defaults to `None`.
    - Construct with `trust_anchor_path="some/path"` → accepted.
    - YAML round-trip via `LokiConfig.from_yaml` with the new field present and absent.
  - _Requirements: 4.1-4.4 (HARDEN G5)_
  - _Design: Data Models — `FeedsConfig` extension_

- [x] 5. Implement the CPE parser and formatter (HARDEN G2)

  - In `loki/feeds/cpe.py` implement: `CPETriple` frozen dataclass, `parse_cpe(cpe_string: str) -> CPETriple`, `format_cpe(triple: CPETriple, part: str = "o") -> str`.
  - Parser handles the `cpe:2.3:<part>:<vendor>:<product>:<version>:*:*:*:*:*:*:*` form.
  - Handle CPE-2.3 escaping: `\\:` for literal colons in field values, `*` for ANY, `-` for NA.
  - Round-trip equivalence: `parse_cpe(format_cpe(parse_cpe(s))) == parse_cpe(s)` for all valid CPE strings.
  - Add `tests/feeds/test_cpe.py` covering:
    - Valid CPE strings from NVD (e.g. `cpe:2.3:o:intel:firmware:1.2.3:*:*:*:*:*:*:*`) parse correctly.
    - Format produces valid CPE-2.3 string.
    - Round-trip equivalence holds for a Hypothesis-generated corpus.
    - Malformed strings raise `ValueError`.
    - Escaped colons in vendor/product/version fields.
  - _Requirements: 6.2, 6.9_
  - _Design: Architecture — CPE parser; D3 version-range matching_

- [x] 6. Implement the implant-rule loader

  - In `loki/feeds/implants.py` implement: `ImplantRule` frozen dataclass, `ImplantRuleSet` frozen dataclass, `load_implant_rules(builtin_dir, operator_dir) -> ImplantRuleSet`.
  - Rule YAML schema: `rule_id`, `threat_family`, `ioc.content_hash`, `ioc.firmware_guid`.
  - Rule-id prefix: `"implant:"`.
  - Merge logic: operator rules shadow built-in rules on `rule_id` collision with INFO log.
  - Create the three built-in rule files: `loki/feeds/builtin_implants/blacklotus.yaml`, `mosaicregressor.yaml`, `lojax.yaml` with representative IOC hashes from public threat reports.
  - Add `tests/feeds/test_implant_loader.py` covering:
    - Built-in rules load without operator dir.
    - Operator extension merges correctly.
    - Rule-id collision shadowing (operator wins; INFO logged).
    - Invalid YAML raises `FeedsConfigError`.
    - Empty `ioc` raises `FeedsConfigError`.
    - All loaded rules have `"implant:"` prefix.
  - _Requirements: 7.1-7.5, 7.10_
  - _Design: Architecture — Implant-rule loader_

- [x] 7. Implement the implant-rule lookup

  - In `loki/feeds/implants.py` add: `match_implant_rules(query: ImplantRuleLookupQuery, rule_set: ImplantRuleSet) -> ImplantRuleLookupResult`.
  - Match on exact `content_hash` and/or exact `firmware_guid` (R7.6).
  - Results sorted lexicographically ascending by `rule_id` (R7.7).
  - Result entries carry `rule_id`, `ioc_field` (which field fired), `threat_family`; NOT the matched value itself (R7.9 / R13).
  - Add `tests/feeds/test_implant_lookup.py` covering:
    - Hash match fires.
    - GUID match fires.
    - Both match on same rule → single entry.
    - No match → empty result.
    - Sort order across multiple matches.
    - Determinism: two calls produce byte-equal results.
  - _Requirements: 7.6-7.9, 10.2_
  - _Design: Architecture — Implant-rule loader; Property 60_

- [x] 8. Implement the trust-anchor resolver

  - In `loki/feeds/trust.py` implement: `TrustAnchor` class, `resolve_trust_anchor(trust_anchor_path: str | None) -> TrustAnchor`.
  - Package-embedded default: `loki/feeds/_trust_anchor.pem` — for v1 this contains a SHA-256 hash-pin (D1 hash-pin default). Replace the placeholder with a representative hash value.
  - `verify_bundle(bundle_bytes, verification_artifact)`: compute `hashlib.sha256(bundle_bytes).hexdigest()` and compare against the stored hash. Raise `FeedsSignatureError` on mismatch.
  - `identity`: SHA-256 fingerprint of the trust-anchor material itself.
  - Resolution: `None` or `""` → package-embedded; non-empty string → load file.
  - Raise `FeedsConfigError` on missing/unreadable/unparseable trust-anchor file (no downgrade-by-typo).
  - Add `tests/feeds/test_trust.py` covering:
    - Default resolution (None) loads package-embedded.
    - Empty-string resolution loads package-embedded (HARDEN G5).
    - Operator override loads from file.
    - Missing override file raises `FeedsConfigError`.
    - `verify_bundle` succeeds on matching hash.
    - `verify_bundle` raises `FeedsSignatureError` on hash mismatch.
    - Trust-anchor `identity` is a fixed-length hex string.
  - _Requirements: 4.1-4.9_
  - _Design: Architecture — Trust-anchor resolver; D1 hash-pin_

- [x] 9. Implement the CacheDB layer

  - In `loki/feeds/cache.py` implement: `CacheDB` class with `__init__(db_path)`, `ensure_schema()`, `get_metadata()`, `refresh_atomic(cve_rows, metadata, cancel)`, `query_cves(vendor, product, version)`, `check_writer_version(current_major)`.
  - WAL mode via `PRAGMA journal_mode=WAL` on open (R3.2).
  - Schema per the design: `cve_records` table with composite PK and `idx_cve_lookup` index, `cache_metadata` single-row table.
  - `COLLATE NOCASE` on `vendor` and `product` columns (R6.2).
  - Atomic refresh: `BEGIN IMMEDIATE` → `DELETE FROM cve_records` → batch `executemany` INSERT (10,000 rows, cancellation check between batches) → `UPDATE cache_metadata` → `COMMIT`. On cancel or failure → `ROLLBACK`.
  - `check_writer_version`: compare major version; raise `FeedsCacheError` on mismatch (R14.3).
  - Add `tests/feeds/test_cache.py` covering:
    - Schema creation on fresh DB.
    - WAL mode is active.
    - Metadata get/set round-trip.
    - Atomic refresh commits all rows.
    - Cancellation mid-refresh rolls back (prior data intact).
    - Write failure rolls back (prior data intact).
    - Version mismatch raises `FeedsCacheError`.
    - `query_cves` case-insensitive on vendor/product.
    - `query_cves` exact-match on version.
    - Results sorted by `cve_id` ascending.
    - Multiple registries against same DB don't corrupt (R1.6).
  - _Requirements: 3.1-3.3, 3.10, 6.2, 6.4, 12.5, 14.2-14.3_
  - _Design: Architecture — Cache layer; D5 batch size_

- [x] 10. Implement the timing helper

  - In `loki/feeds/timing.py` implement a `Stopwatch` context manager (mirrors `loki/analysis/timing.py`). This is the single permitted clock-using module inside `loki.feeds`.
  - Add `tests/feeds/test_timing.py` covering: monotonic time recording; `duration_ms >= 0` after exit.
  - _Requirements: 12 (performance measurement)_
  - _Design: Determinism discipline_

- [x] 11. Implement the refresh logic

  - In `loki/feeds/refresh.py` implement: `perform_refresh(config: FeedsConfig, cache_db: CacheDB, trust_anchor: TrustAnchor, *, force: bool, cancel: CancellationToken | None) -> RefreshResult`.
  - Orchestration per the design's Refresh Logic section:
    1. Cancellation check "pre-connection" (R9.1a).
    2. Fetch NVD bundle via `urllib.request.urlopen` with: fixed User-Agent (R2.6), no custom headers (R2.7), TLS `CERT_REQUIRED` + `check_hostname=True` (R8.7), same-host redirect policy (R8.6 / D7).
    3. Chunked read with cancellation check "download-chunk" (R9.1b).
    4. Validate Content-Length vs bytes received (R5.3).
    5. Fetch sibling verification artifact.
    6. `trust_anchor.verify_bundle(bundle_bytes, artifact)` (R4.5).
    7. Cancellation check "pre-write" (R9.1c).
    8. Parse NVD JSON 2.0 bundle → CVE rows (D2).
    9. `cache_db.refresh_atomic(cve_rows, metadata, cancel)` with "per-cve-insert" cancellation (R9.1d).
    10. On cancellation at any point → Cancellation_Marker + `RefreshResult(status=CANCELLED)`.
  - Custom redirect handler that rejects cross-origin redirects (D7).
  - No retry on failure (R5.7).
  - Add `tests/feeds/test_refresh.py` covering:
    - Success path with monkey-patched `urlopen` returning synthetic bundle.
    - Signature failure raises `FeedsSignatureError`.
    - Partial download raises `FeedsCacheError(partial_download=True)`.
    - Network failure raises `FeedsNetworkError`.
    - Cancellation at each of the four cooperative points returns CANCELLED with marker.
    - Cross-origin redirect raises `FeedsNetworkError`.
    - User-Agent header is exactly `"loki-feeds/<FEEDS_VERSION>"`.
    - No unexpected headers in captured requests.
    - TLS context has `CERT_REQUIRED` and `check_hostname=True`.
  - _Requirements: 1.3, 2.1, 2.6, 2.7, 3.4, 4.5, 5.1-5.7, 8.1-8.7, 9.1-9.6_
  - _Design: Architecture — Refresh logic; Sequence walkthrough — Explicit refresh_

- [x] 12. Implement `FeedRegistry` (the library entry point)

  - In `loki/feeds/registry.py` implement `FeedRegistry` with `from_config(feeds_config)`, `refresh(*, force, cancel)`, `cve_lookup(query, *, allow_refresh)`, `implant_rule_lookup(query)`.
  - Construction sequence per the design: validate URL, resolve trust anchor, open CacheDB, check writer version, load implant rules.
  - `cve_lookup` inline-refresh logic: check cache age → stale? → inline refresh (with WARN-AND-CONTINUE for network failure, HARD FAIL for signature/partial).
  - `allow_refresh=False` skips cache-age check entirely (R3.5).
  - `implant_rule_lookup` does not touch CacheDB or network (R7).
  - Re-export `FeedRegistry` from `loki/feeds/__init__.py`.
  - Add `tests/feeds/test_registry.py` covering:
    - Construction from valid config succeeds.
    - Invalid `nvd_url` raises `FeedsConfigError`.
    - `http://` URL raises `FeedsConfigError` (R2.5).
    - Empty URL raises `FeedsConfigError` (R2.4).
    - `cve_lookup` with `allow_refresh=False` against stale cache → no fetch, result returned.
    - `cve_lookup` with `allow_refresh=True` against stale cache → fetch triggered.
    - `cve_lookup` with fresh cache → no fetch triggered.
    - Inline refresh network failure → `stale_warning=True` result.
    - Inline refresh signature failure → `FeedsSignatureError` propagated.
    - `implant_rule_lookup` returns matches from loaded rules.
    - Multiple registries against same cache_path don't corrupt.
  - _Requirements: 1.1-1.10, 2.4-2.5, 3.4-3.8_
  - _Design: Architecture — Public API surface; Sequence walkthrough_

- [x] 13. Implement the `loki feeds refresh` CLI surface

  - In `loki/feeds/cli.py` implement `register_feeds_subcommand(subparsers)` and `run_feeds_refresh(args) -> int`.
  - Register on the top-level dispatcher in `loki/cli.py`.
  - Flags: `--config`, `--force`, `--summary-only` (R11.2).
  - SIGINT handler: flip `threading.Event` as CancellationToken, restore previous handler after (R9.4).
  - Double-Ctrl-C does NOT short-circuit (R9.5).
  - Stdout: indented JSON `Stdout_Refresh_Status` with keys `status`, `cves_imported`, `bytes_fetched`, `duration_seconds`, `last_refresh_at`, `feeds_version`, `diagnostics` (R11.4). Suppressed by `--summary-only`.
  - Stderr: `Stderr_Summary_Line` on SUCCESS and CANCELLED; NOT on HARD FAIL (R11.6, P63).
  - Exit codes: `{0, 2, 3, 4, 5, 6, 130}` per HARDEN G4-A (R11.7).
  - `--help` works without config (R11.1).
  - Add `tests/feeds/test_cli.py` covering (subprocess-based):
    - `loki feeds refresh --help` exits 0.
    - Missing config exits 2.
    - Success path: stdout JSON parsed, stderr summary line present, exit 0.
    - `--summary-only`: no stdout, stderr summary present, exit 0.
    - `--force` flag accepted.
    - Cancellation (simulated SIGINT via os.kill in subprocess): exit 130.
    - Network failure (monkey-patched): exit 6.
    - Signature failure: exit 3.
    - Partial-download failure: exit 4.
    - Cache write failure: exit 5.
  - _Requirements: 9.4-9.7, 11.1-11.9_
  - _Design: Architecture — CLI surface_

- [x] 14. Implement the `loki feeds status` CLI subcommand (informational)

  - In `loki/feeds/cli.py` add a `status` subcommand: `loki feeds status [--config]`.
  - Displays: last refresh timestamp, CVE count, cache size on disk, feeds version, cache schema version.
  - No network egress. Read-only against the CacheDB.
  - Exit 0 on success; exit 2 on missing/invalid config.
  - Add `tests/feeds/test_cli.py` test case for the status subcommand.
  - _Requirements: none explicit — quality-of-life; mirrors `loki baseline list`_
  - _Design: not explicitly in requirements; small informational surface_

- [x] 15. Wire the `CVELookupQuery` derivation from `ClassificationRecord`

  - In `loki/feeds/registry.py` add a helper: `derive_cve_query(record: ClassificationRecord, image: FirmwareImage) -> CVELookupQuery`.
  - `vendor` = lowercased `record.vendor_axis.label` (R6 Glossary: CPE_Triple).
  - `product` = derived from `record.type_axis.label` + `image.model` (per Glossary rules).
  - `version` = `image.firmware_version` (per Glossary).
  - This is a convenience helper, not a required API — callers can construct `CVELookupQuery` directly.
  - Add `tests/feeds/test_query_derivation.py` covering: various axis labels produce the expected triples; missing `firmware_version` raises `FeedsConfigError`.
  - _Requirements: 6.1 (Glossary: CPE_Triple derivation)_
  - _Design: Architecture — Public API surface_

- [x] 16. Add the `ImplantRuleLookupQuery` derivation from `ExtractedComponent`

  - In `loki/feeds/registry.py` add a helper: `derive_implant_query(component: ExtractedComponent) -> ImplantRuleLookupQuery`.
  - `content_hash` = `component.raw_hash`.
  - `firmware_guid` = `component.guid` (may be None).
  - Add `tests/feeds/test_query_derivation.py` test case for the implant query derivation.
  - _Requirements: 7 (Glossary: Implant_Rule_Lookup_Query)_
  - _Design: Architecture — Public API surface_

- [x] 17. Add the static side-channels AST audit

  - Create `tests/feeds/test_no_side_channels.py`: AST-walk every Python file in `loki/feeds/` and assert that `os.environ`, `os.getenv`, `random`, `secrets`, `socket.gethostname`, `getpass.getuser` imports and attribute accesses appear ONLY in `timing.py` (for `time.monotonic`) and `refresh.py` / `trust.py` (for `urllib`, `ssl`, `hashlib` — the designated network modules).
  - Mirror `tests/analysis/test_no_side_channels.py` pattern.
  - _Requirements: 10.4, 13_
  - _Design: Determinism; Property 51 analog_

- [x] 18. Add the static no-leakage AST audit on log records

  - Create `tests/feeds/test_no_log_leakage.py`: AST-walk every Python file in `loki/feeds/` and assert no logger call references any field in the Forbidden_Leakage_Field_Set (R13.1 enumeration).
  - Mirror `tests/analysis/test_no_log_leakage.py` pattern.
  - _Requirements: 13.2, 13.6(a)_
  - _Design: No-leakage audits — audit 1_

- [x] 19. Add the dynamic no-leakage caplog audit on log records

  - Create `tests/feeds/test_log_no_leakage.py`: capture every log record emitted during curated refresh and lookup operations; assert no record's formatted message contains any Forbidden_Leakage_Field_Set value.
  - Curated operations: successful refresh, failed refresh (network), cve_lookup hit, cve_lookup miss, implant_rule_lookup hit, cancellation.
  - Mirror `tests/analysis/test_log_no_leakage.py` pattern.
  - _Requirements: 13.2, 13.6(b)_
  - _Design: No-leakage audits — audit 2_

- [x] 20. Add the static AST audit on HTTPS requests

  - Create `tests/feeds/test_no_request_leakage_ast.py`: AST-walk `loki/feeds/` and assert no `urllib.request.Request` or `http.client` call site reads from forbidden source patterns (`os.environ`, `os.getenv`, `os.uname`, `socket.gethostname`, `getpass.getuser`, `FeedsConfig` attributes other than `nvd_url`).
  - _Requirements: 8.3, 13.6(c)_
  - _Design: No-leakage audits — audit 3_

- [x] 21. Add the dynamic request-capture audit

  - Create `tests/feeds/test_no_request_leakage_dynamic.py`: monkey-patch `urllib.request.urlopen` to capture request objects, run a refresh against a synthetic local fixture, assert captured URLs/headers contain only permitted values (the configured `nvd_url`, `User-Agent: loki-feeds/<VERSION>`, standard Accept headers).
  - _Requirements: 8.4, 13.6(d)_
  - _Design: No-leakage audits — audit 4_

- [x] 22. Add the TLS verification audit

  - Create `tests/feeds/test_tls_verification.py`: construct the Feeds subsystem's SSL context and assert `verify_mode == ssl.CERT_REQUIRED` and `check_hostname == True`.
  - _Requirements: 8.7, 13.6(e)_
  - _Design: No-leakage audits — audit 5_

- [x] 23. Add the redirect-host-match policy audit

  - Create `tests/feeds/test_redirect_policy.py`: simulate a cross-origin redirect (e.g. `nvd.nist.gov` → `evil.example`) and assert `FeedsNetworkError` is raised. Simulate a same-host redirect and assert it is followed.
  - _Requirements: 8.6, 13.6(f)_
  - _Design: No-leakage audits — audit 6; D7 same-host redirect_

- [x] 24. Add the Hypothesis property-based test suite (P59-P68)

  - Create `tests/feeds/test_properties.py` with ten properties per the design's Correctness Properties section:
    - **P59** lookup determinism (cve_lookup): `max_examples=50`.
    - **P60** lookup determinism (implant_rule_lookup): `max_examples=50`.
    - **P61** HTTPS-request leakage: `max_examples=25`.
    - **P62** Cancel_Flag-driven cancellation contract: deterministic, four parameterized cases.
    - **P63** Stderr_Summary_Line emission discipline: `max_examples=25`.
    - **P64** no-leakage on stderr and stdout: `max_examples=25`.
    - **P65** CVE-result sort stability: `max_examples=50`.
    - **P66** inline-refresh trigger: `max_examples=25`.
    - **P67** cache atomicity under failure: deterministic, three parameterized cases.
    - **P68** tiered inline-refresh failure branching: deterministic, three parameterized cases.
  - All suppress `HealthCheck.too_slow` and `HealthCheck.function_scoped_fixture`.
  - _Requirements: 15.1-15.11_
  - _Design: Correctness Properties P59-P68_

- [x] 25. Add the performance tests (slow marker)

  - Create `tests/feeds/test_performance.py` with slow-marker tests:
    - **R12.1** `cve_lookup` against 200,000 synthetic CVE records in ≤ 50 ms.
    - **R12.2** `implant_rule_lookup` against 1,024 synthetic rules in ≤ 5 ms.
    - **R12.3** `refresh()` against 100 MiB synthetic bundle in ≤ 60 s (network excluded; local fixture).
  - All marked `@pytest.mark.slow` to exclude from default `pytest -q` run.
  - _Requirements: 12.1-12.3_
  - _Design: Performance and resource use_

- [x] 26. Add an end-to-end smoke test

  - Create `tests/feeds/test_smoke.py` (or extend `tests/test_feeds_smoke.py` at the top level):
    - Construct a `FeedRegistry` with a synthetic pre-populated CacheDB.
    - Run `cve_lookup` → get results.
    - Run `implant_rule_lookup` → get results.
    - Assert result shapes and determinism.
    - Wire results into a `ClassificationRecord.cve_matches` field and confirm the model accepts it.
  - _Requirements: end-to-end contract verification_
  - _Design: Testing Strategy_

- [x] 27. Update README, STATE, HANDOFF, and loom-loki

  - Update `README.md` with a dedicated `## Feeds subsystem` section describing: public entry point, six finding categories the analysis engine now gets CVE data for, the CLI subcommand, the six-audit FULL-context discipline.
  - Update `STATE.md` to reflect the feeds spec progressing to IMPLEMENTED.
  - Update `HANDOFF.md` with the new subsystem status.
  - Update `loom-loki.md` to v0.5.0: add the feeds subsystem to the subsystem registry, update the dependency graph, record the lifecycle transition.
  - _Requirements: none — documentation only_
  - _Design: not explicit — project discipline_

- [x] 28. Final verification gate

  - Run the full verification suite:
    ```bash
    .venv/bin/python -m pytest -q
    .venv/bin/python -m mypy --strict loki tests scripts
    .venv/bin/python -m ruff check
    .venv/bin/python -m ruff format --check
    .venv/bin/python -m pytest -m slow
    ```
  - Confirm: all tests pass (new baseline count), mypy clean, ruff clean, slow tests pass.
  - Confirm: `from loki.feeds import FeedRegistry, FEEDS_VERSION` works.
  - Confirm: `loki feeds refresh --help` works.
  - Confirm: the six FULL-context audits all pass in the default suite.
  - Record the final test count and source-file count in this task.
  - _Requirements: all — final gate_
  - _Design: all — final verification_

## Wave plan

- **Wave 1 (tasks 1-4).** Scaffolding, result models, exception hierarchy, model-layer migration. Pure structure — no logic, no network, no SQLite. Leaves the subsystem importable end-to-end.
- **Wave 2 (tasks 5-8).** The four internal modules: CPE parser, implant-rule loader + matcher, trust-anchor resolver. Self-contained units with good test isolation.
- **Wave 3 (tasks 9-10).** CacheDB layer + timing helper. The SQLite contract (WAL, atomicity, indexing, batch INSERT) is pinned here.
- **Wave 4 (tasks 11-12).** Refresh logic + FeedRegistry. The subsystem becomes callable end-to-end as a library API. Network discipline and inline-refresh wiring land here.
- **Wave 5 (tasks 13-16).** CLI surface + convenience helpers. The `loki feeds refresh` subcommand becomes usable. Exit-code taxonomy pinned.
- **Wave 6 (tasks 17-23).** The six FULL-context audits (AST + dynamic, log + request + TLS + redirect). Tasks are independent and can be done in parallel.
- **Wave 7 (tasks 24-26).** Property-based tests, performance tests, end-to-end smoke. Pins the correctness and performance contracts.
- **Wave 8 (tasks 27-28).** Documentation refresh and final verification gate.

The cadence mirrors the analysis-engine's eight-wave plan. Implementations land at most one wave per session per the project's standing discipline.

## Notes

- **Stick to the design's Module layout exactly.** If a new responsibility doesn't fit any of the listed modules, raise it as an open question rather than inventing a new module — that's a sign the design needs an update first.
- **The FULL-context audits (tasks 17-23) are the hardest novelty in this subsystem.** The Feeds subsystem is the first to need request-leakage audits. Mirror the analysis-engine's log-leakage audit pattern; extend it with the request-capture and TLS audits.
- **The `slow` marker is already registered in `pyproject.toml`.** The performance budgets in R12 are slow and noisy in CI by design.
- **The trust-anchor scheme (D1 hash-pin) is the implementation default.** If NVD documentation reveals a different scheme at implementation time, `trust.py` adapts; the public API does not change.
- **No new dependencies.** stdlib only: `sqlite3`, `urllib.request`, `ssl`, `hashlib`, `json`, `yaml` (already a project dependency for rule loading). No `cryptography`, no `python-cpe`, no `requests`.
- **The Forbidden_Leakage_Field_Set is larger for this subsystem than for analysis.** It includes `trust_anchor_path`, trust-anchor file contents, extracted-component fields, classification-record fields, baseline-record fields, and environment variables. The dynamic audits must cover the network-egress surface as well as the log surface.
- **v1 ships the library API + CLI surface.** GUI integration, fleet rollup, auto-population of `cve_matches`, and vendor-advisory feeds are all out of scope and have their own (future) specs.
- **Property numbering picks up at P59 by project-wide convention.** The next subsystem picks up at P69.
- **Cross-subsystem property referencing is fine.** Properties P59-P68 may reference earlier properties (e.g. analysis P43-P52 establish `ImageAnalysisReport` invariants that consume feeds output); the feeds property tests do not need to re-validate those invariants.
