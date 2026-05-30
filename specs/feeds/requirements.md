
# Requirements Document

## Introduction

The Feeds subsystem is the LOKI module that turns external CVE
feed snapshots and a curated set of implant-rule signatures into
two lookup surfaces consumed by the classification pipeline and
the analysis engine. It closes OT-LK-002 from `loom-loki.md` § 5
Open Threads: v1 of the classification pipeline currently leaves
`ClassificationRecord.cve_matches` always empty (R6 of
classification-pipeline) and v1 of the analysis engine leaves
`FindingEvidence.matched_cve` always `None` and
`DeviationScore.cve_introduced` always `False` (R9.9 of
analysis-engine). The Feeds subsystem fills those upstream gaps
without requiring a re-spec of either consumer; both consumers
read the populated `cve_matches` field verbatim, and the analysis
engine surfaces the values via the existing `matched_cve` and
`cve_introduced` channels once they carry data.

This subsystem is the project's first surface with outbound
network egress and the project's first surface that performs
trust-anchor verification on external content. Its threat
context is therefore FULL (per OT-LK-002 D8-B), elevated from
the STANDARD baseline that the four shipped subsystems run
under. The leakage discipline that classification and analysis
already enforce on logs and progress events is extended in this
spec to cover outbound HTTPS requests: no environment variable,
no system identifier, and no firmware content SHALL appear in
any HTTPS body, header, or URL the Feeds subsystem emits.

This spec covers feeds only:

- The shape of the public lookup entry points (CVE matching by
  CPE triple; implant-rule matching by file hash + GUID).
- The CVE feed source contract: NVD-style JSON snapshots only in
  v1 (per D3-A).
- The on-disk cache layout: SQLite at `<cache_path>/feeds.db`
  with WAL mode, stdlib-only, indexed `(vendor, product,
  version)` lookup (per D2-C).
- The refresh-trigger surface: a `loki feeds refresh` CLI
  subcommand for explicit refreshes, plus inline cache-age-driven
  refreshes triggered at the top of the lookup path when the
  cache is older than `FeedsConfig.update_interval` (per D1 +
  D1a-C). No scheduler, no daemon, no OS integration.
- The trust-anchor model: a package-embedded default verification
  key plus an optional `FeedsConfig.trust_anchor_path` override
  (per D4-D).
- The tiered refresh-failure semantics: signature/hash validation
  failure is hard fail, network/server failure is warn-and-
  continue with stale-cache fallback, partial download is hard
  fail (per D5-D).
- The CPE-2.3 match shape: the engine consumes
  `ClassificationRecord` axis labels and the firmware version
  string, derives a `(vendor, product, version)` triple, and
  matches that triple against the cached NVD CPE corpus (per
  D6-A). Includes both a CPE parser and a CPE pretty printer
  with a round-trip equivalence requirement, mirroring the
  project's "parsers are tricky" discipline.
- The implant-rule surface: a built-in starter set shipped under
  `loki/feeds/builtin_implants/` plus an optional
  operator-supplied directory at `FeedsConfig.implant_rules_path`
  (per D7-C). No network feed for implants in v1.
- Determinism, cooperative cancellation (return-path, mirroring
  analysis-engine R7 and classify-cli's Cancel_Flag), and the
  no-leakage audit extended to outbound HTTPS requests.
- The exit-code-shaped typed exception hierarchy, with a closed
  set of exception classes; the actual closed exit-code set
  belongs to the future `loki feeds` CLI subcommand spec and is
  recorded as a forward thread.
- Performance bounds on lookup latency and on the impact of an
  inline refresh on the lookup path.

It does not cover:

- Vendor-advisory feeds (Cisco PSIRT, Microsoft MSRC, Red Hat
  Security Data API, etc.). v1 ships NVD only per D3-A; a future
  spec introduces both a second feed source and the feed-source
  abstraction together. Out of scope.
- A scheduler, a daemon, or any OS-level periodic-refresh
  integration (cron, launchd, systemd timers, Windows Task
  Scheduler). v1 fires inline on the lookup path under D1a-C and
  via explicit `loki feeds refresh` invocations only. Out of
  scope.
- An implant-rule network feed. v1 ships the curated starter set
  in-package and accepts operator-supplied additions on disk;
  pulling implant rules from an external feed is reserved for a
  future spec. Out of scope.
- A CVE-to-finding rendering surface. The Feeds subsystem
  populates `ClassificationRecord.cve_matches`; the analysis
  engine then surfaces those values via its existing
  `FindingEvidence.matched_cve` and
  `DeviationScore.cve_introduced` channels. v1 of the Feeds
  subsystem does NOT itself emit `FindingRecord` instances. Out
  of scope.
- Persistence of the per-call lookup result beyond the in-memory
  return value. The CVE corpus is persisted (the cache); the
  per-classification lookup output is not. Out of scope.
- A fleet-wide CVE rollup. Cross-image CVE aggregation is
  fleet-analysis territory and depends on the (deferred) fleet
  engine. Out of scope.
- A GUI integration surface. Wiring the lookup output onto the
  desktop is OT-LK-004 / a future GUI spec. Out of scope.
- Schema migration of the SQLite cache file across feeds
  versions. v1 supports exactly one cache schema version; if
  the model evolves, the future migration spec defines the
  migration path, mirroring OT-LK-005 for baseline schema and
  OT-LK-006 for ExtractionManifest schema. Out of scope.
- Any modification of the existing `loki/models/config.py`
  `FeedsConfig` model. D4-D banks one new optional field
  `trust_anchor_path: str | None = None` on `FeedsConfig`; that
  one-line model migration is implementation work and is out of
  scope for this requirements DRAFT. Tracked as a forward
  thread.

The shape and quality bar mirror `classification-cli/requirements.md`
(13 EARS requirements, the closest size analog at HARDEN time)
and `analysis-engine/requirements.md` (the larger-spec Glossary
+ Properties idiom). Determinism, the typed exception hierarchy,
the no-leakage audit, and the cooperative-cancellation
return-path pattern all carry forward from the upstream
subsystems. The parser + pretty-printer + round-trip discipline
mirrors the "parsers are tricky" guidance the project applies
whenever an external grammar shows up; the CPE-2.3 grammar is
the external grammar in this spec.

Carry-forward platform constraints: Python 3.12 baseline;
Pydantic v2 strict; `mypy --strict` clean; `ruff check` and
`ruff format` clean. Property numbering in this spec starts at
P59; previous specs end at P58 (classification-cli). Threat
context is FULL: this is the first subsystem in the project to
make outbound network calls and to validate trust anchors on
external content, and the audit-trigger flag in the harness is
active for any feeds work going forward.

Design-phase implementation notes (not requirements; tracked
here so the design conversation has the right starting context):

- D4-D banks a hybrid trust anchor: a package-embedded default
  public key (the common case) plus an optional
  `FeedsConfig.trust_anchor_path` override (rotation and
  high-trust operators). Whether NVD signs the feed bundle
  (giving us a PGP/X.509 verification surface) or merely
  publishes SHA-256 integrity hashes alongside the JSON
  download (giving us a hash-pinning surface) needs to be
  verified against current NVD documentation at TENSION pass;
  either implementation satisfies the banked decision since
  both are forms of pinning a known-good anchor against a
  fetched artifact. Tracked as a forward thread.
- The CPE parser MAY consume the lightly-maintained `python-cpe`
  package on PyPI or MAY be hand-rolled against the CPE-2.3
  spec (~30 fields, stable since 2011). The dependency-vs-
  handroll choice belongs to the design phase; license and
  Python 3.12 compatibility verification of `python-cpe` is
  the gating concern. Tracked as a forward thread.
- The closed set of exit codes for the future `loki feeds` CLI
  surface (paralleling classify-cli's `{0, 2, 3, 4, 5, 6, 130}`
  set) is a design-phase decision. The Feeds subsystem itself
  surfaces typed exceptions per Requirement 13; mapping those
  exceptions to a CLI exit-code taxonomy is the future CLI
  spec's job. Tracked as a forward thread.
- The bundled implant-rule starter set creates a release-cadence
  dependency: new public implant disclosures (BlackLotus-class
  events) eventually translate to LOKI releases. Mitigation
  banked at CAST: keep the bundled set conservative; ship only
  signatures with stable file hashes and well-defined GUID
  matches drawn from public threat reports. The maintenance
  cadence itself belongs to the operator-policy conversation
  rather than this spec; tracked as a forward thread.

## Glossary

- **Feeds**: The subsystem specified by this document. The Python
  package at `loki/feeds/` plus its on-disk SQLite cache file at
  `<FeedsConfig.cache_path>/feeds.db` and the bundled implant-rule
  directory at `loki/feeds/builtin_implants/`.
- **CVE_Lookup**: The public entry point of Feeds that takes a
  `(vendor, product, version)` triple (the CPE_Triple) and a
  `FeedsConfig` and returns a list of CVE identifier strings drawn
  from the cached NVD corpus. The list is the value the caller
  assigns to `ClassificationRecord.cve_matches`.
- **Implant_Lookup**: The public entry point of Feeds that takes a
  bundle of component-derived indicators (file hash, optional UEFI
  GUID) and returns a list of implant-rule identifier strings drawn
  from the merged built-in starter set and operator-supplied
  rules.
- **Refresh_Trigger**: One of the two surfaces that initiates a
  feed refresh: the explicit `loki feeds refresh` CLI subcommand
  (manual warm-up) or the inline cache-age check at the top of
  the CVE_Lookup path (cadence-aware on-demand). v1 defines no
  other Refresh_Trigger.
- **Cache_Database**: The SQLite database file stored at
  `<FeedsConfig.cache_path>/feeds.db`, opened in WAL mode, holding
  the CVE corpus normalized into rows indexed on `(vendor,
  product, version)`. The schema is v1-only; cross-version
  migration is out of scope.
- **Cache_Age**: The wall-clock interval, in seconds, between the
  Cache_Database's last successful refresh timestamp and the
  current UTC time. The lookup path consults Cache_Age against
  `FeedsConfig.update_interval` to decide whether an inline
  refresh is required.
- **Stale_Cache_Fallback**: The behavior, defined by D5-D, where a
  CVE_Lookup that triggers an inline refresh and the refresh
  fails for a network/server reason continues against the
  pre-refresh Cache_Database content rather than failing the
  lookup. The pre-refresh content is "stale" from the perspective
  of the failed refresh but is structurally intact.
- **Trust_Anchor**: The public verification key used to
  authenticate a fetched feed snapshot. v1 defines two
  Trust_Anchor sources: the package-embedded default key shipped
  in `loki/feeds/_trust/` (used when
  `FeedsConfig.trust_anchor_path` is `None`) and the
  operator-supplied override key file pointed to by
  `FeedsConfig.trust_anchor_path` (used when the field is set).
  Whether the cryptographic primitive ends up being signature
  verification or hash-pinning is a TENSION-pass clarification;
  the term Trust_Anchor refers to whichever pinning artifact the
  design BIND ratifies.
- **Builtin_Implant_Rules**: The directory shipped inside the
  `loki` Python package at `loki/feeds/builtin_implants/`,
  containing one YAML file per implant rule in the curated
  starter set (BlackLotus, MosaicRegressor, LoJax, and
  successors). Schema mirrors the existing classification-rules
  pattern at `loki/classification/rules/`.
- **Operator_Implant_Rules**: The directory pointed to by
  `FeedsConfig.implant_rules_path`, holding optional
  operator-supplied implant rules in the same YAML schema as
  Builtin_Implant_Rules. The Feeds subsystem merges
  Operator_Implant_Rules onto Builtin_Implant_Rules at lookup
  time; collisions are resolved per Requirement 8.
- **CPE_Triple**: The three-string tuple `(vendor, product,
  version)` derived from a `ClassificationRecord` for the purpose
  of CVE matching. The `vendor` value is the lowercased string
  representation of `ClassificationRecord.vendor_axis.label`;
  `product` is derived from
  `ClassificationRecord.type_axis.label` plus the parent
  `FirmwareImage.model` value via the rules in Requirement 6;
  `version` is the parent `FirmwareImage.firmware_version`
  string.
- **CPE_String**: The full CPE-2.3 formatted-string identifier
  (`cpe:2.3:o:<vendor>:<product>:<version>:...:*`) parsed and
  emitted by the Feeds subsystem's CPE parser and pretty
  printer. The CPE_Triple is a projection of the CPE_String
  onto its three indexed fields; the round-trip equivalence in
  Requirement 6 establishes that
  `parse(print(parse(s))) == parse(s)` for every CPE_String the
  parser accepts.
- **NVD_Snapshot**: One JSON document downloaded from the URL
  named by `FeedsConfig.nvd_url`, plus the corresponding
  Trust_Anchor verification artifact (signature file or hash
  manifest). Each NVD_Snapshot fully replaces the Cache_Database
  content on a successful refresh; partial replacement is not
  permitted (D5-D's "partial download is hard fail" semantics).
- **Refresh_Failure**: One of three closed-set failure modes
  defined by D5-D:
  `SignatureValidationFailure` (Trust_Anchor verification
  rejected the fetched artifact; hard fail; security event),
  `NetworkFailure` (the HTTPS fetch did not complete due to a
  network or server condition; warn-and-continue with
  Stale_Cache_Fallback; operational hiccup), and
  `PartialDownloadFailure` (the fetch completed but produced an
  artifact whose declared content length did not match the
  downloaded byte count, or the artifact failed structural
  validation; hard fail; data integrity event). Each maps to a
  distinct typed exception per Requirement 13.
- **Cancellation_Marker**: A boolean flag the caller may pass to
  CVE_Lookup or to the explicit refresh entry point, polled
  cooperatively by the Feeds subsystem at the start of each
  inner loop iteration (per-row lookup batch, per-CPE match
  iteration, per-batch refresh chunk). Mirrors the
  return-path-not-throw-path pattern from analysis-engine R7
  and classify-cli's Cancel_Flag (Requirement 6 of
  classification-cli).
- **Forbidden_Leakage_Field_Set**: The set of values the Feeds
  subsystem SHALL NOT include in any outbound HTTPS request
  (URL path, URL query string, request header, or request
  body), in any log record, in any progress event, in any
  diagnostic counter, or in any persisted artifact. The set
  inherits the analysis-engine's
  `{component_id, signer, source_image_hash, evidence,
  matched_rule, matched_cve, matched_signature, raw_indicators,
  finding.title, finding.description}` and adds, for the
  network-egress surface specifically, the values of every
  process environment variable, the operator's hostname, the
  operator's user-account name, the operator's home-directory
  path, and the byte content of any firmware image or extracted
  component.
- **Out_Of_Scope_Operation**: Anything beyond providing CVE_Lookup
  and Implant_Lookup against an NVD-derived Cache_Database and a
  merged implant-rule corpus: vendor-advisory feeds, scheduler
  integration, implant-rule networking, finding emission, fleet
  rollup, GUI wiring, cache schema migration. Explicitly
  deferred.

# Requirements Document

## Introduction

The Feeds subsystem is the LOKI surface that turns
``ClassificationRecord.cve_matches`` from an always-empty list (the
v1 contract pinned by Requirement 6 of classification-pipeline) into
a populated, NVD-derived list of CPE-matched CVE identifiers. It also
introduces an implant-rule lookup surface that the analysis engine
consumes to produce ``unexpected_component`` and
``classification_mismatch`` findings with implant-tagged evidence.
This subsystem closes OT-LK-002 from ``loom-loki.md`` § 5 Open Threads
and is the first LOKI subsystem to operate at threat-context FULL:
v1 is also the first subsystem to perform outbound network egress
(NVD feed fetches over HTTPS) and to validate trust anchors
(signature or hash verification on fetched feed bundles).

The Feeds subsystem is a library API plus a thin CLI surface. It does
not run extraction, does not run classification, does not call the
analysis engine, and does not persist any record outside its own
SQLite cache. Its job is to (a) keep a local on-disk cache of NVD
CVE data fresh against a configured update interval, (b) answer
CPE-shaped lookup queries against that cache, (c) load a built-in
plus optional operator-extension implant-rule set, and (d) answer
implant-rule lookup queries against the loaded set.

This spec covers the feeds surface only:

- The library API at ``from loki.feeds import ...`` exposing
  ``FeedRegistry``, ``refresh_feed``, ``cve_lookup``, and
  ``implant_rule_lookup``.
- The on-disk cache contract: SQLite at
  ``<FeedsConfig.cache_path>/feeds.db`` with WAL mode, indexed for
  ``(vendor, product, version)`` lookups.
- The cadence-aware on-demand refresh model: there is no scheduler,
  no daemon, no OS integration; the cache-age check fires an inline
  refresh at the top of the lookup path when the cache is older than
  ``FeedsConfig.update_interval``, and a ``--no-refresh`` flag opts
  read-only consumers out of the inline trigger.
- The ``loki feeds refresh`` CLI subcommand for explicit warm-up.
- The signed-feed validation contract (D4-D hybrid trust anchor):
  package-embedded default public key plus an optional
  ``FeedsConfig.trust_anchor_path`` override.
- The tiered refresh-failure semantics (D5-D): signature/hash
  validation failure is HARD FAIL; network/server failure is
  WARN-AND-CONTINUE with stale-cache fallback; partial download is
  HARD FAIL.
- The CPE-2.3 match shape (D6-A): ``(vendor, product, version)``
  triples derived from ``ClassificationRecord`` axes drive lookups
  against NVD's native vocabulary; no consumer-side model migration.
- The hybrid implant-rule surface (D7-C): a built-in starter set
  shipped at ``loki/feeds/builtin_implants/`` plus an optional
  operator-extension directory at
  ``FeedsConfig.implant_rules_path``; rule schema mirrors
  ``loki/classification/rules/``; no network feed for implants in v1.
- The FULL threat-context discipline: no environment variables, no
  system identifiers, and no firmware content SHALL appear in any
  HTTPS request body, header, or URL the Feeds subsystem emits;
  enforced by a paired AST audit and request-capture dynamic audit
  mirroring the classify-cli stderr-audit pattern.
- The no-leakage discipline on log records and CLI output, mirroring
  classify-cli's stderr discipline and the analysis engine's
  ``Forbidden_Leakage_Field_Set`` audit.
- Cooperative cancellation on the refresh path, mirroring the
  return-path-not-throw-path pattern used by the analysis engine and
  classify-cli.
- Determinism: same cache contents plus same query inputs SHALL
  produce identical lookup output, modulo the per-record
  ``timestamp`` field permitted by the model layer.

It does not cover:

- Vendor advisory feeds (Dell, Lenovo, HP, AMI, Insyde, Phoenix,
  vendor PSIRTs, MITRE ATT&CK feeds). D3-A bans v1 from any
  source other than NVD; vendor advisories are deferred to a
  future spec that will introduce both a second source and the
  feed-source abstraction together. Out of scope.
- A network feed for implant rules. D7-C ships only a built-in
  starter set plus operator-extension; no implant-rule feed is
  fetched from the network in v1. Out of scope.
- A scheduler, daemon, or OS-level cron integration. D1a-C is
  cadence-aware on-demand only; the cache-age check at the
  lookup path is the only refresh surface besides the explicit
  ``loki feeds refresh`` CLI subcommand. Out of scope.
- Auto-population of ``ClassificationRecord.cve_matches`` from
  inside the classification library. The classification pipeline's
  Requirement 6 v1 contract leaves the field empty by design;
  populating it is the analysis engine's or a higher-level
  caller's job and SHALL NOT be performed inline by the
  classification library itself. The Feeds subsystem provides the
  lookup API; consumer wiring is out of scope here.
- Modifying the analysis engine's ``evidence.matched_cve`` or
  ``DeviationScore.cve_introduced`` surfaces. Once the Feeds
  subsystem ships, those surfaces start carrying real values
  through analysis-engine consumption of ``cve_lookup``; the
  consumer-side wiring is the analysis engine's concern, not
  this spec's. Out of scope.
- A streaming or chunked NVD feed download mode. The full feed
  bundle is downloaded to a temporary location, validated, and
  then committed to the cache atomically; v1 SHALL NOT require an
  incremental fetcher. Out of scope.
- A GUI surface. Refresh status, last-refresh timestamps, and
  cache statistics are exposed via the CLI subcommand and the
  library API only; OT-LK-004 GUI integration is its own future
  spec. Out of scope.
- Migration of ``FeedsConfig`` itself. D4-D adds one optional
  field ``trust_anchor_path: str | None = None`` to the existing
  ``FeedsConfig`` model in ``loki/models/config.py``; the model
  migration is implementation work for the Feeds subsystem's
  task plan, NOT a requirement of this spec. The migration
  appears in the design phase's task breakdown and is tracked as
  forward thread #5 in this document's "Forward threads" section.
- A "sync from another LOKI host" cache-replication mode. The
  cache is local to the running host; v1 does not coordinate
  caches across machines. Out of scope.
- CVE search by free-text product name or by CWE identifier.
  The lookup surface accepts CPE-shaped triples only; full-text
  search is out of scope.
- Vulnerability-severity-driven filtering at lookup time. The
  Feeds subsystem returns the full set of matched CVEs for a
  query; severity prioritization is the analysis engine's
  policy concern, not the Feeds subsystem's. Out of scope.

The shape and quality bar mirror ``classification-cli/requirements.md``
(the most recent precedent for a CLI surface integrated into a larger
subsystem) and ``analysis-engine/requirements.md`` (the closest
precedent for a pure-library subsystem with strict no-leakage and
determinism contracts). The threat-context lift to FULL is new for
this subsystem and sets a project-wide precedent for any future
subsystem that performs network egress or trust-anchor verification.

Carry-forward platform constraints: Python 3.12 baseline; Pydantic v2
strict; ``mypy --strict`` clean; ``ruff check`` and ``ruff format``
clean. Property numbering in this spec starts at P59; previous specs
end at P58 (classification-cli).

Banked CAST decisions (encoded as requirements below; not
relitigable in this spec):

- **D1**  Refresh-trigger surface: daily-default plus on-demand
  via ``loki feeds refresh``. Both surfaces ship in v1.
- **D1a** How daily fires: cadence-aware on-demand. NO scheduler,
  NO daemon, NO OS integration. Cache-age check at the top of
  the lookup path triggers an inline refresh when the cache is
  older than ``FeedsConfig.update_interval``. ``--no-refresh``
  flag for read-only consumers.
- **D2**  Cache layout: SQLite at
  ``<FeedsConfig.cache_path>/feeds.db`` with WAL mode. Stdlib
  ``sqlite3`` only; no new dependency. Indexed
  ``(vendor, product, version)`` lookup.
- **D3**  Feed sources in v1: NVD only.
- **D4**  Signed-feed validation: hybrid trust anchor.
  Package-embedded default public key plus optional
  ``FeedsConfig.trust_anchor_path`` override.
- **D5**  Refresh-failure semantics: tiered. Signature/hash
  validation failure is HARD FAIL. Network/server failure is
  WARN-AND-CONTINUE with stale-cache fallback. Partial download
  is HARD FAIL.
- **D6**  Match shape: CPE-2.3 ``(vendor, product, version)``
  triple matching against NVD's native vocabulary.
- **D7**  Implant-rule surface: hybrid. Built-in starter set
  shipped in ``loki/feeds/builtin_implants/`` plus
  ``FeedsConfig.implant_rules_path`` for operator extension. No
  network feed for implants in v1.
- **D8**  Threat context: FULL. First subsystem with outbound
  network egress and trust-anchor verification.

Design-phase implementation notes (not requirements; tracked here
so the design conversation has the right starting context):

- The cache-age check at the top of the lookup path (Requirement
  3.4) fires the inline refresh synchronously on the calling
  thread; v1 SHALL NOT spawn a background worker or asyncio task
  for the inline refresh, so a slow refresh blocks the lookup
  caller. This is consistent with the project's synchronous
  library-API discipline (Requirement 1.7 of
  classification-pipeline; Requirement 1.11 of classification-cli).
- The ``Forbidden_Leakage_Field_Set`` for this subsystem extends
  the upstream library's set with two new entries:
  ``FeedsConfig.trust_anchor_path`` (the operator-supplied trust
  anchor path) and any HTTPS-request body content. The full set
  is enumerated in Requirement 13.
- The ``FeedsConfig`` model migration (adding
  ``trust_anchor_path: str | None = None``) is implementation
  work and SHALL be performed during the Feeds subsystem's
  Wave 1 / Wave 2 implementation, NOT during this requirements
  round. The requirements treat the field as if it already
  exists; the design phase's task breakdown owns the migration.
- The set of forward threads listed at the END of this document
  is explicitly deferred to the TENSION pass; this DRAFT does
  NOT pre-resolve them.

## Glossary

- **Feeds**: The subsystem specified by this document. The library
  package at ``loki/feeds/`` plus the ``loki feeds`` CLI subcommand
  registered on the top-level ``loki`` argparse dispatcher at
  ``loki/loki/cli.py``.
- **FeedRegistry**: The library entry point. A singleton-style
  object obtained via ``FeedRegistry.from_config(feeds_config)``
  that owns the SQLite cache handle, the loaded implant rule set,
  and the resolved trust anchor; exposes ``refresh()``,
  ``cve_lookup(...)``, and ``implant_rule_lookup(...)`` methods.
- **Cache_Path**: The directory referred to by
  ``FeedsConfig.cache_path``. The Feeds subsystem creates the
  directory if it does not exist and places its SQLite database at
  ``<Cache_Path>/feeds.db``.
- **Cache_DB**: The SQLite database file at
  ``<Cache_Path>/feeds.db``, opened in WAL mode (Write-Ahead
  Logging journal mode), holding the normalized NVD CVE data and
  the cache-metadata table.
- **Cache_Metadata**: A single-row metadata table inside the
  Cache_DB recording the last successful refresh's UTC timestamp,
  the source feed bundle's content hash, the source feed bundle's
  signature or hash-pin material, the loaded NVD feed format
  version, and the Feeds subsystem version that wrote the row.
- **Update_Interval**: The integer-seconds value of
  ``FeedsConfig.update_interval``. The cache-age check compares
  ``now() - Cache_Metadata.last_refresh_at`` against this value
  to decide whether to trigger an inline refresh.
- **NVD_Feed_Source**: The HTTPS URL referred to by
  ``FeedsConfig.nvd_url``, plus any sibling URLs published
  alongside it (signature file or hash-pin file). The Feeds
  subsystem performs an HTTPS GET against the URL and validates
  the fetched bundle against the resolved Trust_Anchor.
- **Trust_Anchor**: The public-key or hash-pin material the Feeds
  subsystem uses to validate a fetched NVD bundle. Resolves via
  D4-D hybrid logic: when ``FeedsConfig.trust_anchor_path`` is
  ``None``, the package-embedded default at
  ``loki/feeds/_trust_anchor.pem`` (or equivalent stdlib-loadable
  format chosen at design phase) is used; when
  ``FeedsConfig.trust_anchor_path`` is non-``None``, the file at
  that path is loaded instead.
- **CVE_Lookup_Query**: The structured input to
  ``cve_lookup(...)``. Carries a non-empty
  ``(vendor, product, version)`` triple drawn from a
  ``ClassificationRecord``'s axes plus any optional CPE-2.3
  qualifiers (update, edition, language, sw_edition, target_sw,
  target_hw, other) that the design phase decides to expose.
- **CVE_Lookup_Result**: The structured output of
  ``cve_lookup(...)``. A list of CVE identifier strings (e.g.
  ``"CVE-2024-12345"``) plus, per CVE, a CPE match-shape
  diagnostic (which of the query's fields matched against the
  cache row), the CVE's published-date timestamp, and the CVE's
  CVSS-v3 base score and severity rating where available; the
  exact result-record shape is pinned by Requirement 5.
- **Builtin_Implant_Rules**: The directory shipped inside the
  ``loki`` package at ``loki/feeds/builtin_implants/``. Contains
  the conservative starter set of implant IOCs from public
  threat reports (BlackLotus, MosaicRegressor, LoJax, and
  similar; the exact rule-file inventory is pinned at design
  phase).
- **Operator_Implant_Rules**: The directory referred to by
  ``FeedsConfig.implant_rules_path``. Optional operator-extension
  rules loaded alongside Builtin_Implant_Rules; the loaded set
  is the union of the two with operator rules taking precedence
  on rule-id collision (per Requirement 7).
- **Implant_Rule_Lookup_Query**: The structured input to
  ``implant_rule_lookup(...)``. Carries an
  ``ExtractedComponent`` (or its derivable triple of
  ``content_hash``, ``firmware_guid``, and component-type tag)
  drawn from a manifest the analysis engine is processing.
- **Implant_Rule_Lookup_Result**: The structured output of
  ``implant_rule_lookup(...)``. A list of matched implant-rule
  identifiers plus, per match, the IOC field that fired
  (``content_hash`` or ``firmware_guid``) and the rule's threat
  family label (e.g. ``"BlackLotus"``); the exact result-record
  shape is pinned by Requirement 7.
- **Cancel_Flag**: A boolean flag that the Feeds subsystem flips
  to ``True`` on receipt of SIGINT during a ``loki feeds
  refresh`` invocation, and that the refresh path checks at
  well-defined cooperative points (between download chunks,
  between trust-anchor verification and DB commit, and between
  per-CVE INSERTs during the cache rebuild) per Requirement 9.
- **Cancellation_Marker**: The single sentinel record the
  refresh path writes when the Cancel_Flag is observed. Has a
  deterministic sentinel ``component_id`` of
  ``uuid.uuid5(LOKI_NAMESPACE, "feeds-refresh-cancelled")``,
  severity ``INFO``, and the cancellation-at-stage value lives
  in ``evidence.raw_indicators[0]`` ONLY (never logged); the
  marker is the LAST entry in the refresh result's diagnostics
  list, mirroring the analysis engine's R7 contract.
- **Refresh_Result**: The structured output of ``refresh()`` and
  of the ``loki feeds refresh`` CLI subcommand. Carries the
  refresh outcome status (``SUCCESS`` / ``WARN_STALE`` /
  ``CANCELLED`` / ``FAILED``), the bytes-fetched count, the
  CVEs-imported count, the duration, and any diagnostics.
- **Stdout_Refresh_Status**: The single indented JSON object the
  ``loki feeds refresh`` CLI writes to stdout on every run that
  produces a Refresh_Result. Mirrors the Refresh_Result shape;
  exact fields pinned by Requirement 11.
- **Stderr_Summary_Line**: The single-line diagnostic the
  ``loki feeds refresh`` CLI writes to stderr at the end of
  every run that produces a Refresh_Result, of the form
  ``feeds refresh: <STATUS>, <N> CVEs, <B> bytes,
  duration=<S>s``. Mirrors classify-cli's Stderr_Summary_Line
  pattern (Requirement 4 of classification-cli).
- **Forbidden_Leakage_Field_Set**: The set of values that SHALL
  NOT appear in any log record, any CLI stderr line, any
  CLI stdout line, or any HTTPS request body, header, or URL the
  Feeds subsystem emits. Enumerated in Requirement 13. Extends
  the upstream classify-cli set with two new members:
  ``FeedsConfig.trust_anchor_path`` (the operator's trust-anchor
  path) and any extracted-firmware byte content.
- **Out_Of_Scope_Operation**: Anything beyond fetching NVD,
  validating fetched bundles, persisting normalized CVE data
  to the local SQLite cache, loading the union of
  Builtin_Implant_Rules and Operator_Implant_Rules, and
  answering CPE-shaped or implant-IOC-shaped lookups. Vendor
  advisories, an implant-rule network feed, a scheduler or
  daemon, GUI integration, and cache replication across hosts
  are out of scope. Explicitly deferred.

## Requirements

### Requirement 1: Library API surface and library entry point

**User Story:** As a downstream consumer (the analysis engine, a
test, or a future ``loki analyze`` CLI), I want ``from loki.feeds
import FeedRegistry`` to give me a single object that owns the
cache, the implant rules, and the trust anchor, so that I do not
have to wire SQLite handles, key files, or rule loaders together
myself.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL expose a public package at
   ``loki.feeds`` whose ``__init__.py`` re-exports at least
   ``FeedRegistry``, ``FeedsRefreshError``,
   ``FeedsSignatureError``, ``FeedsNetworkError``,
   ``FeedsCacheError``, ``FeedsConfigError``, ``RefreshResult``,
   ``RefreshStatus``, ``CVELookupResult``,
   ``ImplantRuleLookupResult``, and ``FEEDS_VERSION``.
2. THE Feeds subsystem SHALL expose a class ``FeedRegistry``
   with a classmethod ``FeedRegistry.from_config(feeds_config:
   FeedsConfig) -> FeedRegistry`` that constructs the registry
   from a validated ``FeedsConfig`` instance and SHALL NOT
   accept positional or keyword overrides; configuration values
   come from the ``FeedsConfig`` model only.
3. THE ``FeedRegistry`` instance SHALL expose a method
   ``refresh(*, force: bool = False, cancel: CancellationToken |
   None = None) -> RefreshResult`` that performs an explicit
   refresh of the Cache_DB against the NVD_Feed_Source, returns
   a Refresh_Result describing the outcome, and honors the
   Cancel_Flag contract per Requirement 9.
4. THE ``FeedRegistry`` instance SHALL expose a method
   ``cve_lookup(query: CVELookupQuery, *, allow_refresh: bool =
   True) -> CVELookupResult`` that returns matching CVE records
   from the Cache_DB; ``allow_refresh=False`` opts the caller
   out of the inline cache-age refresh trigger per Requirement
   3.4.
5. THE ``FeedRegistry`` instance SHALL expose a method
   ``implant_rule_lookup(query: ImplantRuleLookupQuery) ->
   ImplantRuleLookupResult`` that returns matching implant-rule
   records from the loaded union of Builtin_Implant_Rules and
   Operator_Implant_Rules; this method SHALL NOT trigger any
   cache refresh and SHALL NOT consult the Cache_DB.
6. THE ``FeedRegistry`` instance SHALL be safe to construct
   multiple times in the same process; constructing two
   registries against the same Cache_Path SHALL NOT corrupt the
   Cache_DB (SQLite WAL mode plus the schema's per-table
   primary-key constraints are the contract here).
7. THE Feeds subsystem SHALL run synchronously on the calling
   thread and SHALL NOT spawn worker threads, asyncio tasks,
   or process pools in v1; both refresh and lookup paths block
   the caller until they complete or the Cancel_Flag is
   observed.
8. THE Feeds subsystem SHALL expose a module-level constant
   ``FEEDS_VERSION: str`` whose value is a Semantic-Versioning
   string (e.g. ``"1.0.0"``) bumped per Requirement 14; this
   constant SHALL appear in the Refresh_Result and in the
   Cache_Metadata's ``feeds_writer_version`` column.
9. THE Feeds subsystem SHALL NOT, in v1, expose any function
   that mutates ``ClassificationRecord.cve_matches`` directly;
   the field is populated by the consumer (the analysis engine
   or a higher-level caller) using the Feeds subsystem's
   lookup output. Auto-population from inside the Feeds
   subsystem is Out_Of_Scope_Operation.
10. THE Feeds subsystem SHALL NOT, in v1, accept any caller-
    supplied HTTP client, requests-style adapter, or transport
    object; the subsystem owns its own HTTPS client (the
    stdlib ``urllib.request`` + ``ssl`` modules are the design-
    phase default; v1 SHALL NOT introduce a new dependency to
    realize this).

### Requirement 2: NVD as the only feed source in v1

**User Story:** As a v1 user of LOKI, I want NVD to be the only
upstream feed source, so that my deployment has exactly one
upstream URL to think about, one trust anchor to manage, and one
update cadence to plan around.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL fetch CVE data only from the URL
   recorded in ``FeedsConfig.nvd_url`` and the sibling URLs
   that the NVD publishes alongside it (the signature file or
   hash-pin file; the exact sibling URL pattern is pinned at
   design phase against current NVD documentation).
2. THE Feeds subsystem SHALL NOT, in v1, fetch from any other
   feed source; vendor advisories (Dell, Lenovo, HP, AMI,
   Insyde, Phoenix, vendor PSIRTs), MITRE ATT&CK feeds, OSV,
   GitHub Security Advisories, and any other published
   vulnerability feed are Out_Of_Scope_Operation.
3. THE Feeds subsystem SHALL NOT, in v1, expose any abstraction
   for adding a second feed source at runtime; the ``loki feeds
   add-source`` style of CLI surface is deferred to a future
   spec that introduces multi-source support and the
   feed-source abstraction together.
4. WHEN ``FeedsConfig.nvd_url`` is empty, is not an ``https://``
   URL, or fails URL parsing, THE Feeds subsystem SHALL raise
   ``FeedsConfigError`` with a message naming
   ``feeds.nvd_url`` and the validation failure reason; the
   Feeds subsystem SHALL NOT proceed to network egress with an
   invalid URL.
5. THE Feeds subsystem SHALL reject any ``http://`` (plaintext)
   value of ``FeedsConfig.nvd_url`` with the same
   ``FeedsConfigError`` path as Requirement 2.4; HTTPS is
   mandatory, and downgrades to plaintext SHALL NOT be
   permitted by configuration in v1.
6. THE Feeds subsystem SHALL include the configured
   ``FEEDS_VERSION`` and a fixed ``User-Agent`` value of the
   form ``"loki-feeds/<FEEDS_VERSION>"`` on every outbound
   HTTPS request, and SHALL NOT vary the User-Agent across
   requests; the User-Agent is the only agent-identification
   the Feeds subsystem leaks to NVD by design.
7. THE Feeds subsystem SHALL NOT, in v1, send any request
   header beyond the User-Agent and the standard accept /
   accept-encoding headers required to fetch the bundle; in
   particular, the Feeds subsystem SHALL NOT send
   ``Authorization`` headers, NVD API keys, or operator-
   identifying tokens, even when a future NVD API tier might
   permit one. (NVD-API-key support is forward thread #1 and
   is deferred to TENSION.)

### Requirement 3: Cache layout, indexing, and cache-age inline refresh

**User Story:** As an operator running ``loki feeds`` workloads
on a development laptop, I want the cache to be a single SQLite
file under ``Cache_Path``, indexed for the CPE lookup shape, and
auto-refreshed when stale at the moment a lookup happens, so
that I do not run a daemon and I do not get surprised by stale
data.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL create the Cache_DB at the path
   ``<FeedsConfig.cache_path>/feeds.db`` and SHALL place no
   other files inside ``Cache_Path`` other than the
   SQLite-managed sidecar files (``feeds.db-wal``,
   ``feeds.db-shm``, and short-lived ``feeds.db-journal``
   files when SQLite chooses to roll back).
2. THE Feeds subsystem SHALL open the Cache_DB in WAL mode by
   issuing ``PRAGMA journal_mode=WAL`` immediately after
   opening the connection, and SHALL keep WAL mode across all
   refresh and lookup operations.
3. THE Feeds subsystem SHALL define the Cache_DB schema with at
   least the following tables: ``cve_records`` (one row per
   CVE-CPE-match combination, indexed on ``(vendor, product,
   version)`` per the D6-A match shape), ``implant_rules`` (one
   row per loaded implant rule, indexed on ``(content_hash,
   firmware_guid)``), and ``cache_metadata`` (single-row
   Cache_Metadata table); the exact column inventory is pinned
   at design phase, but the index on ``(vendor, product,
   version)`` is non-negotiable in v1.
4. WHEN ``cve_lookup`` is invoked and ``allow_refresh`` is
   ``True`` (the default) and ``now() -
   Cache_Metadata.last_refresh_at >= Update_Interval``, THE
   Feeds subsystem SHALL perform an inline refresh on the
   calling thread before answering the lookup query; the
   inline refresh SHALL respect the same trust-anchor and
   tiered-failure contract as an explicit ``refresh()`` call
   per Requirements 4 and 5.
5. WHEN ``cve_lookup`` is invoked and ``allow_refresh`` is
   ``False``, THE Feeds subsystem SHALL skip the cache-age
   check entirely and answer the lookup query against the
   current Cache_DB contents regardless of staleness; the
   caller has explicitly opted out of the inline trigger, and
   the Feeds subsystem SHALL NOT log a stale-cache warning on
   the lookup path under ``allow_refresh=False``.
6. WHEN ``cve_lookup`` is invoked, ``allow_refresh`` is ``True``,
   the cache is stale, and the inline refresh fails because of
   a network/server error (the WARN-AND-CONTINUE branch of
   D5-D), THE Feeds subsystem SHALL log a single WARNING-level
   log record naming the failure reason, SHALL NOT raise, and
   SHALL answer the lookup query against the stale Cache_DB
   contents; the lookup result SHALL carry a
   ``stale_warning: True`` flag distinguishable from the
   fresh-cache lookup result shape.
7. WHEN ``cve_lookup`` is invoked, ``allow_refresh`` is ``True``,
   the cache is stale, and the inline refresh fails because of
   a signature/hash validation failure or a partial-download
   failure (the HARD FAIL branches of D5-D), THE Feeds
   subsystem SHALL raise the corresponding
   ``FeedsSignatureError`` or ``FeedsCacheError`` per
   Requirement 5 and SHALL NOT answer the lookup query against
   the cached contents; HARD FAIL means the lookup path fails,
   not just the refresh.
8. WHEN ``cve_lookup`` is invoked and the Cache_DB does not
   exist (no prior refresh has ever populated the cache), THE
   Feeds subsystem SHALL behave as if the cache is stale and
   trigger an inline refresh per acceptance criterion 3.4;
   first-use bootstrap is the inline-refresh path, not a
   separate flow.
9. THE Feeds subsystem SHALL NOT, in v1, run a background
   thread, an asyncio task, an OS-level cron job, a
   ``launchd`` agent, a ``systemd`` timer, or any other
   scheduler-style refresh trigger; the cache-age check at
   the lookup path and the explicit ``loki feeds refresh``
   subcommand are the only refresh surfaces.
10. THE Feeds subsystem SHALL commit refresh results to the
    Cache_DB atomically: a refresh either fully replaces the
    ``cve_records`` table contents (and updates the
    Cache_Metadata row) or leaves both untouched. A partial
    refresh SHALL NOT be observable to a concurrent lookup;
    SQLite's transactional semantics under WAL mode are the
    contract here.

### Requirement 4: Trust-anchor resolution and signed-feed validation

**User Story:** As a security-minded LOKI operator, I want the
Feeds subsystem to validate every fetched NVD bundle against a
trust anchor before committing it to the cache, with a
package-embedded default for the common case and an explicit
override path for high-trust deployments and key rotation.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL resolve the Trust_Anchor at the
   start of every ``refresh()`` call and at the start of every
   inline refresh triggered from ``cve_lookup``; the resolved
   Trust_Anchor SHALL apply for the duration of that single
   refresh and SHALL NOT be cached across calls.
2. WHEN ``FeedsConfig.trust_anchor_path`` is ``None``, THE
   Feeds subsystem SHALL load the package-embedded default
   trust-anchor file shipped inside the ``loki`` package at
   ``loki/feeds/_trust_anchor.pem`` (or an equivalent file
   path pinned at design phase); the default file SHALL be
   present in every distributed wheel and source release, and
   the Feeds subsystem SHALL fail with ``FeedsConfigError`` if
   the file is missing from the installed package.
3. WHEN ``FeedsConfig.trust_anchor_path`` is non-``None``, THE
   Feeds subsystem SHALL load the file at that path as the
   Trust_Anchor and SHALL NOT consult the package-embedded
   default; the operator override fully replaces the default
   for that refresh.
4. WHEN ``FeedsConfig.trust_anchor_path`` is non-``None`` and
   the path does not exist, is not a regular file, is not
   readable by the current process, or fails parsing as a
   valid Trust_Anchor format (the design phase pins the
   accepted format set; X.509 PEM is the design-phase
   default), THE Feeds subsystem SHALL raise
   ``FeedsConfigError`` with a message naming
   ``feeds.trust_anchor_path`` and the validation failure
   reason; the Feeds subsystem SHALL NOT silently fall back
   to the package-embedded default in this case (no
   downgrade-by-typo). WHEN
   ``FeedsConfig.trust_anchor_path`` is the empty string
   ``""``, THE Feeds subsystem SHALL treat the value as
   equivalent to ``None`` (use the package-embedded
   default); this accommodates YAML serialization libraries
   that round-trip ``None`` to ``""``.
5. THE Feeds subsystem SHALL validate every fetched NVD bundle
   against the resolved Trust_Anchor before committing the
   bundle's CVE data to the Cache_DB; an unverified bundle
   SHALL NOT be parsed or imported under any code path.
6. WHEN signature or hash validation against the resolved
   Trust_Anchor fails, THE Feeds subsystem SHALL raise
   ``FeedsSignatureError`` per Requirement 5.2 (HARD FAIL)
   and SHALL NOT commit any data from the failed bundle to
   the Cache_DB.
7. THE Feeds subsystem SHALL record the bundle's content hash
   and the Trust_Anchor's identity (the public-key
   fingerprint or the hash-pin material; exact form pinned at
   design phase) in the Cache_Metadata row alongside the
   refresh timestamp, so that a future audit can verify which
   trust anchor admitted the currently-cached data.
8. THE Feeds subsystem SHALL NOT, in v1, support trust-anchor
   rotation mid-refresh; if the operator rotates their
   ``trust_anchor_path`` between two refresh calls, the second
   refresh validates against the new key and the Cache_Metadata
   row reflects the new key's identity, but no per-bundle
   key-rotation logic ships in v1.
9. THE Feeds subsystem SHALL NOT log the contents of the
   Trust_Anchor file, and SHALL NOT log
   ``FeedsConfig.trust_anchor_path``; the Trust_Anchor's
   identity (its fingerprint or hash-pin material) MAY appear
   in DEBUG-level diagnostics, but the file path and the file
   contents SHALL NOT.

### Requirement 5: Tiered refresh-failure semantics

**User Story:** As a CI script author, I want refresh failures
classified into "security event" (HARD FAIL) and "operational
hiccup" (WARN-AND-CONTINUE) categories with stable typed errors
and exit-code mappings, so that my script can branch correctly
without parsing log strings.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL classify every refresh failure
   into exactly one of three categories:
   - **HARD FAIL — signature/hash**:
     ``FeedsSignatureError`` raised when the fetched bundle
     fails Trust_Anchor validation. Treated as a security
     event because someone may be feeding bad data.
   - **HARD FAIL — partial download**: ``FeedsCacheError``
     raised when the fetched bundle is incomplete (the
     server returned fewer bytes than the advertised
     content length, the connection dropped mid-stream, or
     the post-fetch integrity check on the local
     intermediate file fails). Treated as a data-integrity
     event because committing partial data could shadow
     real CVEs.
   - **WARN-AND-CONTINUE — network/server**:
     ``FeedsNetworkError`` raised internally and CAUGHT on
     the inline-refresh path; the Cache_DB is left intact
     and the lookup result carries
     ``stale_warning: True``. On an explicit ``refresh()``
     call, ``FeedsNetworkError`` is propagated to the
     caller, NOT swallowed.
2. WHEN bundle signature or hash validation fails, THE Feeds
   subsystem SHALL raise ``FeedsSignatureError`` with a
   non-empty message naming the validation step that failed
   (e.g. ``"signature verification failed: invalid signature
   over bundle"`` or ``"hash pin mismatch: expected <pin>,
   got <observed>"``); the Feeds subsystem SHALL NOT commit
   any data from the bundle.
3. WHEN the bundle download terminates before the full
   content is retrieved (a partial-download failure), THE
   Feeds subsystem SHALL raise ``FeedsCacheError`` with a
   non-empty message naming ``"partial download"`` plus the
   bytes-received count and the bytes-expected count; the
   Feeds subsystem SHALL NOT commit any data from the
   partial bundle.
4. WHEN the fetch fails because of a network/server condition
   (DNS resolution failure, TCP connection failure, TLS
   handshake failure, HTTP non-2xx response, server-side
   timeout), THE Feeds subsystem SHALL emit
   ``FeedsNetworkError`` internally; on the inline-refresh
   path, the Feeds subsystem SHALL catch this error, log a
   single WARNING-level log record, leave the Cache_DB
   intact, and continue to answer the lookup query with
   ``stale_warning: True``; on the explicit ``refresh()``
   call path, the Feeds subsystem SHALL re-raise
   ``FeedsNetworkError`` to the caller and the
   ``loki feeds refresh`` CLI SHALL exit with a non-zero
   status per Requirement 11.
5. THE Feeds subsystem SHALL commit Cache_DB changes only
   after Trust_Anchor validation has succeeded and the
   bundle's content hash has been verified against the
   advertised value; HARD FAIL paths SHALL leave the
   Cache_DB unchanged.
6. THE Feeds subsystem SHALL classify a failure during
   Cache_DB write itself (SQLite ``OperationalError``,
   ``IntegrityError``, or disk-full) as ``FeedsCacheError``
   with a non-empty message naming the failing operation;
   SQLite's transactional semantics under WAL mode mean the
   pre-refresh Cache_DB contents SHALL remain intact across
   such failures, and the Feeds subsystem SHALL NOT attempt
   ad-hoc rollback logic on top of SQLite's own.
7. THE Feeds subsystem SHALL NOT, in v1, retry transient
   network/server failures inside the same call; a single
   ``FeedsNetworkError`` is emitted per failed fetch attempt,
   and retry policy is deferred to either the operator
   (re-run ``loki feeds refresh``) or to the next cache-age
   inline trigger.

### Requirement 6: CPE-2.3 lookup shape and result determinism

**User Story:** As the analysis engine consuming Feeds output,
I want ``cve_lookup`` to take a ``(vendor, product, version)``
triple drawn from a ``ClassificationRecord`` and return a
deterministic, sorted list of matched CVEs, so that downstream
findings are reproducible and the lookup contract is the same
across NVD feed snapshots that contain identical data.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL accept a ``CVELookupQuery`` whose
   minimum required fields are ``vendor: str``,
   ``product: str``, and ``version: str``; all three SHALL be
   non-empty after stripping leading and trailing whitespace,
   and the Feeds subsystem SHALL raise
   ``FeedsConfigError`` with a message naming the missing or
   empty field if any of the three is empty.
2. THE Feeds subsystem SHALL match the query's
   ``(vendor, product, version)`` triple against the Cache_DB's
   indexed CPE-2.3 ``(vendor, product, version)`` columns using
   case-insensitive ASCII comparison on ``vendor`` and
   ``product`` and exact-match comparison on ``version``; the
   exact match-shape policy (handling of CPE-2.3 wildcards
   ``*`` and ``-`` and the version-range operators
   ``versionStartIncluding``, ``versionEndExcluding``, etc.) is
   pinned at design phase against current NVD documentation,
   but acceptance criterion 6.4 (sort order) and 6.5
   (determinism) hold regardless of the chosen match policy.
3. THE Feeds subsystem SHALL NOT, in v1, normalize ``vendor`` or
   ``product`` values via a vendor-aliasing table; the lookup
   uses NVD's native CPE vocabulary verbatim, and any
   classification-axis-to-CPE-vendor mapping (e.g. mapping
   the LOKI ``Vendor.INTEL`` enum to NVD's ``intel``) is the
   caller's responsibility, NOT the Feeds subsystem's. (Vendor
   aliasing is forward thread #2 and is deferred to TENSION.)
4. THE Feeds subsystem SHALL return matched CVE identifiers in
   the CVE_Lookup_Result list sorted lexicographically
   ascending by CVE identifier string (the canonical
   ``CVE-YYYY-NNNNN`` form); two ``cve_lookup`` invocations
   on the same query and the same Cache_DB contents SHALL
   produce byte-equal CVE_Lookup_Result instances.
5. THE Feeds subsystem SHALL include in each
   CVE_Lookup_Result entry: the CVE identifier; the matched
   CPE-2.3 component fields the cache row carried; the CVE's
   published-date timestamp drawn from NVD; and, where NVD
   provides them, the CVE's CVSS-v3 base score (a float in
   ``[0.0, 10.0]``) and CVSS-v3 severity rating (one of
   ``"NONE"``, ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``);
   missing CVSS-v3 data SHALL surface as ``None`` rather than
   as a fabricated default.
6. THE Feeds subsystem SHALL NOT, in v1, populate the CVE-to-
   ``ClassificationRecord.cve_matches`` mapping itself; the
   consumer takes the CVE_Lookup_Result and writes the CVE
   identifier strings into ``cve_matches`` per its own
   policy. The ``cve_matches`` field's strict-mode list-of-
   strings constraint at the model layer (see
   ``loki/models/classification.py``) is honored by passing
   the lookup result through unchanged.
7. THE Feeds subsystem SHALL return an empty
   CVE_Lookup_Result list when no Cache_DB row matches the
   query; an empty result is a valid lookup outcome and
   SHALL NOT raise.
8. THE Feeds subsystem SHALL NOT include any field drawn from
   the Forbidden_Leakage_Field_Set in the CVE_Lookup_Result;
   the result carries CVE identifiers, CPE component fields,
   timestamps, and CVSS data only.
9. **CPE parser (HARDEN G2 — hand-roll):** THE Feeds
   subsystem SHALL implement a hand-rolled minimal CPE-2.3
   parser at ``loki/feeds/cpe.py`` using only the Python
   stdlib. v1 limits scope to the ``(vendor, product,
   version)`` triple plus the NVD-published version-range
   qualifiers (``versionStartIncluding``,
   ``versionEndExcluding``, ``versionStartExcluding``,
   ``versionEndIncluding``); additional CPE-2.3 qualifiers
   (update, edition, language, sw_edition, target_sw,
   target_hw, other) are accepted in ``CVELookupQuery`` but
   their match implementation is deferred to a future
   revision. The Feeds subsystem SHALL NOT depend on
   ``python-cpe`` or any third-party CPE library.

### Requirement 7: Hybrid implant-rule surface

**User Story:** As an operator with proprietary implant IOCs in
addition to the public threat-report set, I want the Feeds
subsystem to load the built-in starter rules and my extension
rules together, with my rules taking precedence on collision,
so that I can extend without forking the package.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL ship a built-in directory at
   ``loki/feeds/builtin_implants/`` containing the
   conservative starter set of implant-IOC rule files (the
   exact rule-file inventory is pinned at design phase, but
   the v1 starter set SHALL include rules covering at least
   the publicly-documented BlackLotus, MosaicRegressor, and
   LoJax implants and SHALL include only IOCs that have
   stable file hashes or well-defined firmware GUIDs).
2. WHEN ``FeedsConfig.implant_rules_path`` is non-``None``,
   THE Feeds subsystem SHALL load the rule files at that
   path AS WELL AS the built-in rule files, and SHALL form
   the loaded set as the union of the two; on rule-id
   collision, the operator-supplied rule takes precedence
   and the built-in rule is shadowed (a single INFO-level
   log record SHALL document the shadowing on first load).
3. WHEN ``FeedsConfig.implant_rules_path`` is ``None``, THE
   Feeds subsystem SHALL load only the built-in rule files;
   the absence of an operator extension is the v1 default
   and SHALL NOT produce a warning or error.
4. THE Feeds subsystem SHALL define the implant-rule file
   schema by mirroring the existing
   ``loki/classification/rules/`` rule-file shape (the exact
   shared fields are pinned at design phase against the
   current classification rule loader), and SHALL ensure that
   rule-id namespaces do not collide with classification
   rule-ids by applying a fixed prefix (the design phase
   pins the prefix; ``"implant:"`` is the design-phase
   default).
5. THE Feeds subsystem SHALL load implant rules at
   ``FeedRegistry.from_config(...)`` construction time and
   SHALL hold the loaded set in memory for the registry's
   lifetime; subsequent mutations to the rule files on disk
   SHALL NOT be observed by an in-flight registry, and the
   operator SHALL re-construct the registry to pick up new
   rules.
6. THE Feeds subsystem SHALL match an
   Implant_Rule_Lookup_Query against the loaded rule set on
   the union of (a) the query's ``content_hash`` field
   compared exactly against each rule's
   ``ioc.content_hash`` field, and (b) the query's
   ``firmware_guid`` field compared exactly against each
   rule's ``ioc.firmware_guid`` field; the exact match
   policy for additional IOC fields (e.g. partial-byte
   patterns) is deferred to a future spec.
7. THE Feeds subsystem SHALL return matched implant-rule
   identifiers in the Implant_Rule_Lookup_Result list sorted
   lexicographically ascending by rule identifier string;
   two ``implant_rule_lookup`` invocations on the same query
   and the same loaded rule set SHALL produce byte-equal
   Implant_Rule_Lookup_Result instances.
8. THE Feeds subsystem SHALL NOT, in v1, fetch implant rules
   from any network source; D7-C bans an implant-rule feed,
   and an operator who wants live updates SHALL place files
   in ``FeedsConfig.implant_rules_path`` and re-construct
   the registry.
9. THE Feeds subsystem SHALL include in each
   Implant_Rule_Lookup_Result entry: the rule identifier;
   the IOC field that fired (``"content_hash"`` or
   ``"firmware_guid"``); and the rule's threat family label
   (a non-empty string drawn from the rule file, e.g.
   ``"BlackLotus"``); the result entry SHALL NOT carry the
   matched value itself (the ``content_hash`` byte string
   SHALL NOT be echoed back to the caller in the result, to
   honor Requirement 13's no-leakage discipline).
10. **Maintenance cadence (HARDEN G3-C):** THE built-in
    starter set is reviewed at the project's discretion and
    is NOT maintained on a fixed cadence; operators with
    stricter implant-detection requirements SHALL place
    additional rule files in
    ``FeedsConfig.implant_rules_path``. The v1 built-in set
    ships with rules covering only the three implants
    explicitly named in acceptance criterion 7.1
    (BlackLotus, MosaicRegressor, LoJax) and does not
    commit to a disclosure-driven or quarterly release
    schedule.

### Requirement 8: FULL threat-context discipline on network requests

**User Story:** As a security reviewer auditing LOKI's first
network-egress subsystem, I want a hard contract that the Feeds
subsystem leaks no environment variables, no system identifiers,
and no firmware content in any HTTPS request body, header, or
URL, with both a static AST audit and a dynamic request-capture
audit pinning the contract.

#### Acceptance Criteria

1. THE Feeds subsystem's outbound HTTPS requests SHALL include
   only the following content: (a) the URL drawn from
   ``FeedsConfig.nvd_url`` (or its sibling URLs per
   Requirement 2.1), (b) the fixed User-Agent header per
   Requirement 2.6, (c) the standard accept and
   accept-encoding headers required to fetch the bundle; no
   request body content SHALL be sent on any request (NVD
   fetches are HTTP GETs with no body in v1).
2. THE Feeds subsystem SHALL NOT, on any outbound HTTPS
   request, include any environment variable's value, any
   ``os.uname()`` field (hostname, OS release, machine), any
   ``getpass.getuser()`` value, any
   ``socket.gethostname()`` value, any path drawn from
   ``Cache_Path`` or ``FeedsConfig.trust_anchor_path``, any
   ``ExtractedComponent`` field, any ``ClassificationRecord``
   field, any ``BaselineRecord`` field, or any byte content
   drawn from a firmware image being analyzed.
3. THE Feeds subsystem SHALL be covered by a static AST audit
   under ``tests/feeds/test_no_request_leakage_ast.py`` that
   parses every module under ``loki/feeds/`` and asserts that
   no ``urllib.request.Request``, ``http.client``-prefix, or
   ``ssl.create_default_context`` call site reads from any of
   the source patterns enumerated in acceptance criterion
   8.2 (``os.environ``, ``os.getenv``, ``os.uname``,
   ``socket.gethostname``, ``getpass.getuser``, attribute
   access on a ``FeedsConfig`` field other than
   ``nvd_url``, etc.); the audit SHALL fail loudly if any
   such read appears within the network-call dataflow.
4. THE Feeds subsystem SHALL be covered by a dynamic
   request-capture audit under
   ``tests/feeds/test_no_request_leakage_dynamic.py`` that
   monkey-patches the HTTPS transport layer (the design
   phase pins the patch point; the stdlib
   ``urllib.request.urlopen`` plus a captured
   ``http.client.HTTPSConnection`` shim is the design-phase
   default) to record every outbound request's URL and
   headers, runs a refresh against a synthetic local fixture,
   and asserts that the captured set of URLs and headers
   contains only the values permitted by acceptance
   criteria 8.1 and 8.2.
5. THE Feeds subsystem SHALL NOT, in v1, send telemetry,
   crash reports, anonymized usage data, or any out-of-band
   reporting beyond the NVD fetches themselves; the only
   outbound destinations SHALL be the configured
   ``FeedsConfig.nvd_url`` and its sibling URLs.
6. THE Feeds subsystem SHALL NOT, in v1, follow HTTP redirects
   from the NVD URL to a third-party host; if NVD itself
   returns a redirect, the Feeds subsystem SHALL follow the
   redirect ONLY when the redirect target's host matches the
   originally-configured ``FeedsConfig.nvd_url`` host
   (cross-origin redirects SHALL be rejected with
   ``FeedsNetworkError``); the design phase pins the host-
   match policy.
7. THE Feeds subsystem SHALL configure its TLS context to
   require a valid certificate chain against the system's
   default trust store and SHALL NOT, in v1, expose any
   configuration knob to disable certificate verification;
   ``FeedsConfig`` SHALL NOT grow a ``verify_tls`` boolean,
   and the operator SHALL NOT be able to opt out of
   certificate validation by configuration.

### Requirement 9: Cooperative cancellation on the refresh path

**User Story:** As a CLI user running ``loki feeds refresh``
against a slow NVD endpoint, I want pressing Ctrl-C to surface
a partial Refresh_Result on stdout (a ``CANCELLED`` status plus
the cancellation marker), exit 130, and leave the Cache_DB
intact, instead of leaving a corrupt half-imported cache or
dumping a Python traceback.

#### Acceptance Criteria

1. WHEN the Feeds subsystem is about to perform an HTTPS
   download or a Cache_DB write inside ``refresh()`` (whether
   called explicitly or from the inline-refresh path), THE
   Feeds subsystem SHALL accept a ``CancellationToken``
   callable that returns the current Cancel_Flag value, and
   SHALL poll the Cancel_Flag at the following well-defined
   cooperative points: (a) before opening the HTTPS
   connection; (b) between download chunks during the
   bundle fetch; (c) after Trust_Anchor validation succeeds
   and before the Cache_DB write transaction begins;
   (d) between per-CVE INSERTs during the cache rebuild.
2. WHEN the Cancel_Flag is observed at any of the cooperative
   points listed in acceptance criterion 9.1, THE Feeds
   subsystem SHALL stop further work, roll back the in-flight
   Cache_DB transaction (leaving the prior Cache_DB contents
   intact), construct a Cancellation_Marker per the Glossary
   contract, and return a Refresh_Result with status
   ``CANCELLED`` carrying the marker as the LAST entry in
   the ``diagnostics`` list.
3. THE Cancellation_Marker SHALL have a deterministic
   sentinel ``component_id`` of ``uuid.uuid5(LOKI_NAMESPACE,
   "feeds-refresh-cancelled")``, severity ``INFO``, and the
   cancellation-stage value (one of ``"pre-connection"``,
   ``"download-chunk"``, ``"pre-write"``, ``"per-cve-insert"``)
   in ``evidence.raw_indicators[0]`` ONLY; the cancellation
   stage SHALL NOT be emitted to any log record per
   Requirement 13.
4. THE Feeds subsystem's ``loki feeds refresh`` CLI SHALL
   install a process-level handler for ``signal.SIGINT`` that
   flips the Cancel_Flag from ``False`` to ``True`` and
   returns without raising; the previous SIGINT handler
   SHALL be preserved and SHALL be restored after the
   ``refresh()`` call returns or raises (mirroring
   classify-cli's Requirement 6 contract).
5. WHEN SIGINT arrives a second time after the Cancel_Flag
   has already been flipped, THE Feeds subsystem SHALL
   retain its installed handler and SHALL continue to run
   until ``refresh()`` returns; double-Ctrl-C SHALL NOT
   cause the Feeds subsystem to short-circuit out of the
   partial-result emission.
6. THE Feeds subsystem SHALL NOT, on receipt of SIGINT,
   raise ``KeyboardInterrupt`` out of the refresh call,
   kill the process forcibly, leave the Cache_DB in a
   half-written state, or skip the partial-result
   emission; cooperative cancellation is the only contracted
   shutdown path on the refresh surface.
7. THE Feeds subsystem's ``loki feeds refresh`` CLI SHALL
   exit with status ``130`` when the refresh path returns a
   Refresh_Result with status ``CANCELLED``, mirroring
   classify-cli's Requirement 6.3 contract.

### Requirement 10: Determinism and round-trip on lookup paths

**User Story:** As the property-based test suite, I want
``cve_lookup`` and ``implant_rule_lookup`` to produce identical
output for identical inputs and identical cache contents, so
that the analysis engine's findings are reproducible across
runs and across machines.

#### Acceptance Criteria

1. WHEN ``cve_lookup`` is invoked twice on the same
   CVELookupQuery, the same Cache_DB contents, the same
   loaded ``FEEDS_VERSION``, and ``allow_refresh=False``,
   THE Feeds subsystem SHALL produce two CVE_Lookup_Result
   instances that are byte-equal after stripping any
   per-result ``timestamp`` field (the lookup itself does
   not stamp a timestamp; timestamps in the result come
   from the cache's ``cve_records`` rows, which are
   determined by the upstream NVD bundle).
2. WHEN ``implant_rule_lookup`` is invoked twice on the same
   ImplantRuleLookupQuery and the same loaded rule set, THE
   Feeds subsystem SHALL produce two
   Implant_Rule_Lookup_Result instances that are byte-equal.
3. THE Feeds subsystem SHALL NOT, in v1, insert any
   environment-derived value into either lookup result; the
   process's hostname, the current working directory, and
   any environment variable SHALL NOT appear anywhere in
   the lookup output.
4. THE Feeds subsystem SHALL NOT consult the system clock,
   the random number generator, or any network resource on
   any lookup path that is not triggering an inline refresh;
   ``allow_refresh=False`` lookups are pure functions of the
   query plus the Cache_DB plus the loaded implant rule
   set.
5. FOR ALL valid CVELookupQuery inputs the Feeds subsystem
   accepts, the CVE_Lookup_Result SHALL be a
   Pydantic-validated structure (or a frozen dataclass; the
   exact result-type kind is pinned at design phase) and
   SHALL serialize via ``model_dump(mode="json")`` (or its
   dataclass equivalent) into a JSON-compatible dict.
6. THE Feeds subsystem SHALL NOT, in v1, produce a streaming
   lookup mode; both ``cve_lookup`` and
   ``implant_rule_lookup`` return a fully-materialized list,
   mirroring the classification library's
   non-streaming API per Requirement 1.7 of
   classification-pipeline.

### Requirement 11: ``loki feeds refresh`` CLI surface

**User Story:** As an operator warming the Feeds subsystem cache
before a workshop, I want a ``loki feeds refresh`` CLI
subcommand that performs an explicit refresh, prints a
structured Refresh_Result to stdout, prints a summary line to
stderr, and exits with a stable status code, so that I can
script the warm-up and branch on the exit code reliably.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL register a ``feeds`` subcommand
   on the top-level ``loki`` argparse dispatcher in
   ``loki/loki/cli.py``, with at least one second-level
   subcommand ``refresh``; ``loki feeds refresh --help``
   SHALL work without any additional environment
   configuration.
2. THE Feeds subsystem SHALL accept on ``loki feeds refresh``
   the following flags: ``--config <path>`` (optional;
   loads ``LokiConfig.from_yaml(path)`` and uses
   ``config.feeds`` as the ``FeedsConfig`` instance);
   ``--force`` (boolean; ignores the cache-age check and
   refreshes regardless of staleness); ``--summary-only``
   (boolean; suppresses the stdout JSON, mirroring
   classify-cli's Requirement 3.6).
3. WHEN ``--config`` is omitted, THE Feeds subsystem SHALL
   load configuration from the standard project location
   (the design phase pins the default; ``LokiConfig.from_yaml``
   against the project-default config file is the design-
   phase default); when no default config file is found,
   THE Feeds subsystem SHALL print a clear error to stderr
   and exit with status ``2`` without performing any
   network egress.
4. THE Feeds subsystem SHALL emit on stdout a single
   indented JSON object (the Stdout_Refresh_Status) with
   exactly the following top-level keys, in this order:
   ``status`` (one of ``"SUCCESS"``, ``"WARN_STALE"``,
   ``"CANCELLED"``, ``"FAILED"``); ``cves_imported`` (int);
   ``bytes_fetched`` (int); ``duration_seconds`` (float
   rounded to four decimal places); ``last_refresh_at``
   (ISO-8601 UTC string drawn from the Cache_Metadata row);
   ``feeds_version`` (the ``FEEDS_VERSION`` constant);
   ``diagnostics`` (a list, possibly empty, of strings
   describing non-fatal events, with the cancellation
   marker as the LAST entry on a CANCELLED run).
5. WHEN ``--summary-only`` is set, THE Feeds subsystem SHALL
   NOT write any byte to stdout, mirroring classify-cli's
   Requirement 3.6; the Stderr_Summary_Line and the exit
   code are unaffected by ``--summary-only``.
6. THE Feeds subsystem SHALL emit on stderr exactly one
   Stderr_Summary_Line at the end of every run that
   produces a Refresh_Result, of the form ``feeds refresh:
   <STATUS>, <N> CVEs, <B> bytes, duration=<S>s`` followed
   by a single newline; the line is unconditional on
   ``--summary-only`` and on the exit code.
7. THE ``loki feeds refresh`` CLI SHALL exit with one of the
   following closed-set exit codes (resolved at HARDEN per
   TENSION G4-A, mirroring classify-cli's seven-code
   cardinality):
   - ``0``: status ``SUCCESS`` (refresh completed and
     committed to the Cache_DB successfully).
   - ``2``: bad input (missing or unreadable config file;
     invalid CLI argument vector; ``FeedsConfigError``).
   - ``3``: ``FeedsSignatureError`` (HARD FAIL — the
     fetched bundle failed Trust_Anchor validation;
     security event).
   - ``4``: ``FeedsCacheError`` partial-download flavor
     (HARD FAIL — incomplete bundle; data integrity
     event).
   - ``5``: ``FeedsCacheError`` write-failure flavor
     (HARD FAIL — SQLite ``OperationalError``,
     ``IntegrityError``, or disk-full during cache
     commit).
   - ``6``: ``FeedsNetworkError`` (explicit-refresh path
     propagation — DNS failure, TCP failure, TLS
     failure, HTTP non-2xx, or server timeout).
   - ``130``: SIGINT received and cancellation honored
     (Refresh_Result status ``CANCELLED``).
8. THE ``loki feeds refresh`` CLI SHALL run synchronously on
   the calling thread and SHALL NOT spawn worker threads or
   asyncio tasks in v1; the underlying ``refresh()`` call
   already runs synchronously per Requirement 1.7.
9. THE ``loki feeds refresh`` CLI SHALL register a
   non-empty ``help`` string for every flag and a non-empty
   ``description`` for the subcommand, mirroring
   classify-cli's Requirement 12 self-documentation
   contract.

### Requirement 12: Performance bounds on refresh and lookup paths

**User Story:** As an operator running LOKI on a 2024-class
developer laptop, I want the Feeds subsystem's lookup and
refresh paths to meet bounded performance budgets so that
``loki feeds refresh`` does not take unreasonable wall time and
``cve_lookup`` does not become a bottleneck inside the analysis
engine.

#### Acceptance Criteria

1. WHEN ``cve_lookup`` is invoked against a Cache_DB
   populated with up to 200,000 CVE records (a v1 working-
   set assumption pinned at design phase), THE Feeds
   subsystem SHALL answer the lookup query in no more than
   50 milliseconds of wall-clock time on a 2024-class
   developer laptop with a local SSD, as measured by a
   slow-marker test that times the wrapper code (DB query
   + result construction); the bound assumes
   ``allow_refresh=False`` (no inline refresh is
   triggered).
2. WHEN ``implant_rule_lookup`` is invoked against a loaded
   rule set of up to 1,024 rules (a v1 working-set
   assumption pinned at design phase), THE Feeds subsystem
   SHALL answer the lookup query in no more than 5
   milliseconds of wall-clock time on the same hardware
   profile, as measured by a slow-marker test.
3. WHEN ``refresh()`` is invoked against an NVD bundle of
   up to 100 MiB (a v1 working-set assumption pinned at
   design phase), THE Feeds subsystem SHALL complete the
   refresh in no more than 60 seconds of wall-clock time on
   the same hardware profile, as measured by a slow-marker
   test that uses a synthetic local fixture for the bundle
   (network latency is excluded from the budget).
4. THE Feeds subsystem SHALL keep peak resident memory
   attributable to a refresh under a fixed working-set of
   256 MiB beyond the size of the in-memory bundle plus the
   loaded implant-rule set; v1 SHALL NOT require streaming
   parsers, but the Cache_DB INSERT path SHALL batch
   per-CVE writes such that the in-memory accumulator does
   not retain the full bundle's parsed structure across
   the entire commit.
5. THE Feeds subsystem SHALL NOT, in v1, hold the SQLite
   write lock during network I/O; the bundle SHALL be
   downloaded and validated entirely before the
   ``BEGIN IMMEDIATE`` write transaction is started, so a
   concurrent reader thread (a ``cve_lookup`` invocation
   in another part of the calling process) is not blocked
   on the network fetch.

### Requirement 13: No-leakage discipline on log records, CLI lines, and request paths

**User Story:** As a security reviewer auditing LOKI's first
FULL-threat-context subsystem, I want every byte the Feeds
subsystem writes — to log records, to CLI stdout, to CLI
stderr, and to outbound HTTPS requests — to obey a hard
no-leakage contract on the Forbidden_Leakage_Field_Set, with
a paired static AST audit and dynamic capture audit.

#### Acceptance Criteria

1. THE Feeds subsystem's Forbidden_Leakage_Field_Set SHALL
   include all of the following members, and the no-leakage
   discipline of acceptance criteria 13.2 through 13.6
   SHALL apply to every member:

   i.   ``FeedsConfig.trust_anchor_path`` value (the
        operator-supplied trust-anchor path string).
   ii.  The contents of the Trust_Anchor file itself (the
        PEM bytes or equivalent).
   iii. Any value drawn from ``ExtractedComponent`` fields
        (notably ``ExtractedComponent.content_hash``,
        ``ExtractedComponent.firmware_guid``, and any byte
        content).
   iv.  Any value carried in ``ClassificationRecord`` fields
        (notably ``ClassificationRecord.component_id``,
        ``SignatureInfo.signer``, and any
        ``AxisClassification.evidence`` string).
   v.   The ``BaselineRecord.source_image_hash`` value.
   vi.  The value of any environment variable read by the
        Feeds subsystem (the subsystem reads no environment
        variables in v1, but the discipline is
        forward-stated).
2. THE Feeds subsystem SHALL NOT, on any log record at any
   level (DEBUG, INFO, WARNING, ERROR), write any value
   from the Forbidden_Leakage_Field_Set; the cancellation-
   stage string from Requirement 9.3 is permitted on
   ``evidence.raw_indicators[0]`` of the Cancellation_Marker
   ONLY and SHALL NOT be logged.
3. THE Feeds subsystem SHALL NOT, on any CLI stdout line
   (the Stdout_Refresh_Status JSON), write any value from
   the Forbidden_Leakage_Field_Set; the
   Stdout_Refresh_Status carries CVE counts, byte counts,
   timestamps, status strings, and diagnostic strings only,
   and the diagnostic strings SHALL NOT carry any
   Forbidden_Leakage_Field_Set value.
4. THE Feeds subsystem SHALL NOT, on any CLI stderr line
   (the Stderr_Summary_Line, any typed-error message, or
   any ``--debug``-attached log handler output), write any
   value from the Forbidden_Leakage_Field_Set; the
   Stderr_Summary_Line carries integer counts and a
   duration only, and typed-error messages carry the
   exception's own ``message`` attribute and the offending
   path (where applicable) only.
5. THE Feeds subsystem SHALL NOT, on any outbound HTTPS
   request, include any value from the
   Forbidden_Leakage_Field_Set in the URL, the request
   body, or any header beyond the fixed User-Agent per
   Requirement 2.6; this is the FULL-threat-context core
   contract for this subsystem.
6. THE Feeds subsystem SHALL be covered by a six-audit test
   surface (HARDEN G7 — extended from four to six):
   (a) ``tests/feeds/test_no_log_leakage.py`` — static AST
   audit on log records; (b)
   ``tests/feeds/test_log_no_leakage.py`` — dynamic caplog
   audit on log records; (c)
   ``tests/feeds/test_no_request_leakage_ast.py`` — static
   AST audit on outbound HTTPS requests per Requirement 8.3;
   (d) ``tests/feeds/test_no_request_leakage_dynamic.py`` —
   dynamic request-capture audit on outbound HTTPS requests
   per Requirement 8.4; (e)
   ``tests/feeds/test_tls_verification.py`` — runtime
   SSLContext audit asserting ``verify_mode == CERT_REQUIRED``
   and ``check_hostname == True``, pinning Requirement 8.7;
   (f) ``tests/feeds/test_redirect_policy.py`` — dynamic
   redirect-host-match audit simulating a cross-origin
   redirect and asserting ``FeedsNetworkError`` is raised,
   pinning Requirement 8.6. All six audits run in the
   default ``pytest -q`` baseline (NOT gated behind the
   slow-marker) because none require real network access or
   a pre-populated Cache_DB. The six-audit surface SHALL
   fail loudly if any Forbidden_Leakage_Field_Set value
   reaches a log record, a CLI line, or an outbound request,
   or if the TLS or redirect contracts are violated.
7. THE Feeds subsystem MAY, in DEBUG-level diagnostics
   only, log the Trust_Anchor's *identity* (its public-key
   fingerprint or hash-pin material — a fixed-length
   ASCII string, not the full key bytes); the file path and
   the file contents SHALL NOT be logged at any level per
   Requirement 4.9.

### Requirement 14: Versioning and Cache_Metadata schema

**User Story:** As a future maintainer adding a second feed
source or extending the Cache_DB schema, I want
``FEEDS_VERSION`` to be a stable Semantic-Versioning string and
the Cache_Metadata row to record the writer version, so that I
can detect cross-version cache contents and plan migrations.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL define ``FEEDS_VERSION`` as a
   Semantic-Versioning string and SHALL bump it per the
   following rules: major bump on a breaking change to the
   ``FeedRegistry`` public API, the Cache_DB schema, or the
   trust-anchor format; minor bump on a backward-compatible
   feature addition; patch bump on a bug fix or
   documentation change with no API or schema effect.
2. THE Feeds subsystem SHALL write the current
   ``FEEDS_VERSION`` into the Cache_Metadata row's
   ``feeds_writer_version`` column on every successful
   refresh; the column SHALL be a non-empty Semantic-
   Versioning string.
3. WHEN the Feeds subsystem opens an existing Cache_DB whose
   ``feeds_writer_version`` column carries a value with a
   major version different from the current
   ``FEEDS_VERSION``, THE Feeds subsystem SHALL raise
   ``FeedsCacheError`` with a non-empty message naming the
   version mismatch and SHALL NOT proceed to read or write
   the Cache_DB; the operator SHALL re-run
   ``loki feeds refresh`` (which rebuilds the Cache_DB from
   scratch) or migrate the cache via a future migration
   tool.
4. THE Feeds subsystem SHALL NOT, in v1, ship a Cache_DB
   migration tool; cross-version migration is forward
   thread #5 (paired with the analogous
   ``ExtractionManifest`` schema migration, OT-LK-006) and
   is deferred to a future spec analogous to
   OT-LK-005's ``baseline-schema-migration``.
5. THE ``FEEDS_VERSION`` constant SHALL appear in the
   Stdout_Refresh_Status JSON per Requirement 11.4 and in
   the output of the project-wide top-level version flag on
   ``loki`` (the design phase pins the exact flag form,
   mirroring whatever surface classify-cli and
   ``loki extract`` use today).

### Requirement 15: Property-based test contracts

**User Story:** As the property-based test suite, I want the
Feeds subsystem's contracts pinned by Hypothesis-style
properties starting at P59, so that the next subsystem picks
up sequential numbering without overlap.

#### Acceptance Criteria

1. THE Feeds subsystem SHALL be covered by a property test
   designated **P59 (lookup determinism)** that, for
   randomly generated valid CVELookupQuery inputs against a
   fixed synthetic Cache_DB, asserts that two ``cve_lookup``
   invocations on the same query produce byte-equal
   CVE_Lookup_Result instances.
2. THE Feeds subsystem SHALL be covered by a property test
   designated **P60 (implant-lookup determinism)** that,
   for randomly generated valid ImplantRuleLookupQuery
   inputs against a fixed synthetic loaded rule set,
   asserts that two ``implant_rule_lookup`` invocations on
   the same query produce byte-equal
   Implant_Rule_Lookup_Result instances.
3. THE Feeds subsystem SHALL be covered by a property test
   designated **P61 (HTTPS-request leakage)** that, for
   randomly generated valid ``FeedsConfig`` instances with
   randomly generated ``trust_anchor_path`` values and a
   captured request transport, asserts that no
   ``trust_anchor_path`` value, no environment variable
   value, and no system identifier value appears in any
   captured request URL, header, or body.
4. THE Feeds subsystem SHALL be covered by a deterministic
   in-process test designated **P62 (Cancel_Flag-driven
   cancellation contract)** that, for the four cooperative
   cancellation points enumerated in Requirement 9.1,
   passes a synchronous CancellationToken returning
   ``True`` at the configured point and asserts: (a) the
   resulting Refresh_Result carries status ``CANCELLED``;
   (b) the Refresh_Result's ``diagnostics`` list ends with
   exactly one Cancellation_Marker whose ``component_id``
   is the deterministic sentinel from Requirement 9.3;
   (c) the pre-refresh Cache_DB contents remain intact
   after the cancellation; (d) the
   ``loki feeds refresh`` exit-code path resolves to
   ``130``. The end-to-end SIGINT behavior SHALL be
   covered by a separate example-based subprocess test,
   mirroring classify-cli's P55 split.
5. THE Feeds subsystem SHALL be covered by a property test
   designated **P63 (Stderr_Summary_Line emission
   discipline)** that asserts: (a) on every successful
   refresh (status ``SUCCESS``, exit ``0``), the
   Stderr_Summary_Line is emitted exactly once; (b) on
   every cancelled refresh (status ``CANCELLED``, exit
   ``130``), the Stderr_Summary_Line is emitted exactly
   once; (c) on every HARD-FAIL refresh (signature, partial
   download, or cache write; non-zero exit), the
   Stderr_Summary_Line is NOT emitted (only the typed-
   error message line appears).
6. THE Feeds subsystem SHALL be covered by a property test
   designated **P64 (no-leakage on stderr and stdout)**
   that, for randomly generated valid Refresh_Result
   shapes, asserts that no member of the
   Forbidden_Leakage_Field_Set appears in the
   Stdout_Refresh_Status JSON or in the
   Stderr_Summary_Line.
7. THE Feeds subsystem SHALL be covered by a property test
   designated **P65 (CVE-result sort stability)** that, for
   randomly generated valid CVELookupQuery inputs against a
   synthetic Cache_DB whose CVE rows are inserted in random
   order, asserts that the resulting CVE_Lookup_Result list
   is sorted lexicographically ascending by CVE identifier
   string, and that the sort is stable across runs.
8. THE Feeds subsystem SHALL be covered by a property test
   designated **P66 (inline-refresh trigger)** that:
   constructs a Cache_DB with a stale
   ``Cache_Metadata.last_refresh_at`` (older than
   ``FeedsConfig.update_interval``), monkey-patches the
   network transport to record fetch attempts, invokes
   ``cve_lookup(query, allow_refresh=True)``, and asserts
   that exactly one fetch attempt is observed; a second
   invocation against the now-fresh cache SHALL NOT trigger
   a second fetch.
9. THE Feeds subsystem SHALL be covered by a property test
   designated **P67 (cache atomicity under failure)** that:
   populates the Cache_DB with a known CVE set, simulates a
   Trust_Anchor validation failure after the bundle is
   fetched (triggering ``FeedsSignatureError``), and
   asserts that the prior Cache_DB contents remain byte-
   equal after the failed refresh; repeated for a simulated
   partial-download failure (triggering ``FeedsCacheError``)
   and a simulated Cache_DB write failure.
10. THE Feeds subsystem SHALL be covered by a property test
    designated **P68 (tiered inline-refresh failure
    branching)** that, parameterized over the three failure
    modes (network/server, signature/hash, partial
    download), triggers each failure on the inline-refresh
    path (``cve_lookup`` with ``allow_refresh=True`` against
    a stale cache) and asserts: (a) network/server failure
    results in a lookup result with ``stale_warning: True``
    and no raise; (b) signature/hash failure raises
    ``FeedsSignatureError`` and the lookup does NOT return
    a result; (c) partial-download failure raises
    ``FeedsCacheError`` and the lookup does NOT return a
    result.
11. THE property numbering for this spec SHALL start at P59
    and SHALL be sequential across the document; future
    specs pick up at P69.

## Forward threads — resolved

All seven forward threads from the DRAFT are resolved by the
TENSION pass (``requirements-tension-pass.md``) and the HARDEN
amendment applied 2026-05-29. Summary of resolutions:

1. **NVD signing-vs-hash-pinning verification — G1-B.**
   Deferred to design phase. The dual-scheme wording in R4 and
   R5.2 stays as-is; the design phase commits to one scheme
   (signature or hash-pin) based on current NVD documentation.
   NVD-API-key support remains banned by R2.7 in v1.
2. **CPE parser — G2 hand-roll.** Committed to a hand-rolled
   minimal CPE-2.3 parser at ``loki/feeds/cpe.py`` (stdlib
   only). v1 scope limited to ``(vendor, product, version)``
   plus version-range qualifiers. No ``python-cpe`` dependency.
   Acceptance criterion 6.9 pins this.
3. **Bundled-implant-rule maintenance cadence — G3-C.** The
   built-in starter set is reviewed at the project's
   discretion; no fixed cadence. Operators with stricter
   requirements use ``FeedsConfig.implant_rules_path``.
   Acceptance criterion 7.10 pins this.
4. **Exit-code taxonomy — G4-A.** Seven-code closed set:
   ``{0, 2, 3, 4, 5, 6, 130}``. Mirrors classify-cli's
   cardinality. Acceptance criterion 11.7 pins this.
5. **``FeedsConfig`` model migration — G5.** Field name:
   ``trust_anchor_path: str | None = None``. Empty-string
   ``""`` treated as equivalent to ``None``. Acceptance
   criterion 4.4 pins this. Implementation is task-plan
   work.
6. **Property-numbering allocation — G6 extended.** Properties
   extended from P59-P65 to P59-P68 (three additional:
   P66 inline-refresh trigger, P67 cache atomicity, P68
   tiered-failure-mode branching). Future specs pick up at
   P69.
7. **FULL-context audit work — G7 extended.** Audit surface
   extended from four to six tests: added
   ``test_tls_verification.py`` (R8.7) and
   ``test_redirect_policy.py`` (R8.6). All six run in the
   default ``pytest -q`` baseline, not gated behind
   slow-marker.

