
# Design Document — Feeds Subsystem

## Overview

The Feeds subsystem turns NVD-derived CVE snapshots and a curated implant-rule set into two lookup surfaces consumed by the analysis engine (and by future callers). It closes OT-LK-002 from `loom-loki.md` § 5 Open Threads. v1 of the classification pipeline leaves `ClassificationRecord.cve_matches` always empty (R6 of classification-pipeline); v1 of the analysis engine leaves `FindingEvidence.matched_cve` always `None` and `DeviationScore.cve_introduced` always `False` (R9.9 of analysis-engine). The Feeds subsystem fills those upstream gaps: it provides the lookup API; consumer wiring is out of scope.

The subsystem is the project's first surface with **outbound network egress** and the first surface that performs **trust-anchor verification** on external content. Its threat context is FULL (D8-B). It is **synchronous**, **single-threaded**, **deterministic** on the lookup paths (same Cache_DB + same query ⇒ byte-equal result), and **honest** about what it cannot do — it does not run extraction, does not run classification, does not call the analysis engine, does not persist any record outside its own SQLite cache, and does not render findings.

The shape mirrors the project's subsystem pattern: a small public surface at `loki.feeds`, a typed exception hierarchy at `loki/feeds/errors.py`, a `FeedRegistry` class as the library entry point, a `loki feeds refresh` CLI subcommand, AST + dynamic no-leakage audits (six in total for FULL threat context), and a designated set of correctness properties (P59-P68). Each non-trivial design choice cites the acceptance criteria it satisfies (e.g. `R3.4` = Requirement 3 acceptance criterion 4 from `.kiro/specs/feeds/requirements.md`).

## Goals and non-goals

### Goals

- Deliver a stable `FeedRegistry` class importable as `from loki.feeds import FeedRegistry` that owns the SQLite cache, the loaded implant rules, and the resolved trust anchor (R1.1-R1.10).
- Expose `cve_lookup` returning a deterministic, sorted `CVELookupResult` drawn from the CPE-indexed SQLite cache (R6.1-R6.8).
- Expose `implant_rule_lookup` returning a deterministic, sorted `ImplantRuleLookupResult` drawn from the merged in-memory rule set (R7.1-R7.9).
- Expose `refresh` performing an explicit NVD feed refresh with Trust_Anchor validation and atomic Cache_DB commit (R1.3, R3.10, R4, R5).
- Fire inline cache-age-driven refreshes at the top of the `cve_lookup` path when the cache is older than `FeedsConfig.update_interval` (R3.4-R3.8).
- Implement the D5-D tiered refresh-failure semantics: signature/hash → HARD FAIL; network/server → WARN-AND-CONTINUE with stale-cache fallback; partial download → HARD FAIL (R5.1-R5.7).
- Register `loki feeds refresh` CLI subcommand with the seven-code exit taxonomy `{0, 2, 3, 4, 5, 6, 130}` (R11.1-R11.9).
- Honor cooperative cancellation on the refresh path with four cooperative points, Cancellation_Marker, and exit 130 (R9.1-R9.7).
- Enforce the FULL threat-context discipline: no leakage on outbound HTTPS requests, log records, or CLI output (R8, R13).
- Meet performance bounds: `cve_lookup` < 50 ms against 200k CVEs; `implant_rule_lookup` < 5 ms against 1024 rules; `refresh` < 60 s against 100 MiB bundle (R12.1-R12.5).

### Non-goals (explicit)

- **Vendor advisory feeds.** v1 is NVD-only per D3-A (R2.1-R2.7).
- **Auto-population of `ClassificationRecord.cve_matches`.** Consumer wiring is out of scope (R1.9).
- **Modification of the analysis engine.** Once feeds ships, the analysis engine starts carrying real `matched_cve` / `cve_introduced` values through its own consumption logic; that wiring is the engine's concern.
- **A scheduler / daemon / OS integration.** Inline cache-age check + explicit `loki feeds refresh` are the only refresh surfaces (R3.9).
- **A network feed for implant rules.** v1 ships built-in + operator-extension on disk only (R7.8).
- **Streaming / chunked NVD download.** Full bundle downloaded, validated, then committed atomically (R3.10).
- **GUI integration.** OT-LK-004 is its own future spec.
- **Cache schema migration.** v1 supports one schema version; migration is a future spec.
- **CVE severity filtering at lookup time.** The Feeds subsystem returns the full match set; severity prioritization is the consumer's concern.
- **Vendor aliasing.** The lookup uses NVD's native CPE vocabulary verbatim (R6.3).

## Constraints carried forward

- Python 3.12 baseline. All new code must satisfy `mypy --strict`, `ruff check`, and `ruff format`.
- Pydantic v2 strict mode for result models (R10.5).
- `loki.feeds` must not import from `loki.gui` (mirroring R1.9 discipline from analysis-engine).
- Logging via the stdlib `logging` module under the logger name `loki.feeds` (mirror analysis-engine R19.4).
- No content leakage in logs, CLI output, or outbound HTTPS requests at any time (R8, R13). The Forbidden_Leakage_Field_Set is enumerated in R13.1.
- No new third-party dependencies. stdlib `sqlite3`, `urllib.request`, `ssl`, `hashlib`, `json`, `logging` are the implementation surface (R1.10).
- Determinism on lookup paths: the engine SHALL NOT consult the system clock, the random number generator, or any network resource on any lookup path that is not triggering an inline refresh (R10.4).
- Property numbering picks up at **P59** per the platform-wide convention (model layer 1-11, extraction 12-22, baseline-persistence 23-32, classification 33-42, analysis 43-52, classification-cli 53-58, feeds 59-68).

## Components and Interfaces

The four interface families are:

1. **Public surface** (`loki.feeds`): `FeedRegistry`, `RefreshResult`, `RefreshStatus`, `CVELookupResult`, `CVELookupQuery`, `ImplantRuleLookupResult`, `ImplantRuleLookupQuery`, `CancellationToken`, `FEEDS_VERSION`, and the five exception classes. All consumers import from `loki.feeds`.
2. **Cache layer** (`loki.feeds.cache`): `CacheDB` class. Owns the SQLite connection, WAL-mode pragma, schema creation, atomic refresh writes, and indexed lookups. Internal to the subsystem.
3. **Trust-anchor resolver** (`loki.feeds.trust`): `resolve_trust_anchor` function. Loads the package-embedded default or the operator-override file. Internal.
4. **CPE parser** (`loki.feeds.cpe`): `parse_cpe`, `format_cpe`, `CPETriple` dataclass. Hand-rolled minimal CPE-2.3 parser (R6.9 / HARDEN G2). Internal to the subsystem.
5. **Implant-rule loader** (`loki.feeds.implants`): `load_implant_rules` function. Merges built-in + operator-extension rule sets. Internal.
6. **Exception hierarchy** (`loki.feeds.errors`): `FeedsError` root + five subclasses (`FeedsConfigError`, `FeedsSignatureError`, `FeedsNetworkError`, `FeedsCacheError`, `FeedsRefreshError`). Module at `loki/feeds/errors.py`.
7. **CLI surface** (`loki/feeds/cli.py`): `loki feeds refresh` subcommand. Registered on the top-level dispatcher in `loki/cli.py`.

## Architecture

### Module layout

```
loki/feeds/
├── __init__.py            # re-exports the public surface
├── registry.py            # FeedRegistry class (the library entry point)
├── cache.py               # CacheDB: SQLite WAL-mode wrapper
├── refresh.py             # refresh logic: fetch, validate, commit
├── trust.py               # Trust_Anchor resolution (D4-D hybrid)
├── cpe.py                 # hand-rolled CPE-2.3 parser + formatter (HARDEN G2)
├── implants.py            # implant-rule loader + matcher
├── models.py              # result dataclasses (RefreshResult, CVELookupResult, etc.)
├── errors.py              # typed exception hierarchy
├── version.py             # FEEDS_VERSION constant
├── timing.py              # designated module for time.monotonic()
├── cli.py                 # loki feeds refresh CLI surface
├── _trust_anchor.pem      # package-embedded default trust anchor
└── builtin_implants/      # built-in implant-rule starter set
    ├── __init__.py
    ├── blacklotus.yaml
    ├── mosaicregressor.yaml
    └── lojax.yaml
```

`loki/feeds/__init__.py` re-exports exactly:

```python
from loki.feeds.errors import (
    FeedsCacheError,
    FeedsConfigError,
    FeedsError,
    FeedsNetworkError,
    FeedsRefreshError,
    FeedsSignatureError,
)
from loki.feeds.models import (
    CVELookupQuery,
    CVELookupResult,
    CVEMatch,
    CancellationToken,
    ImplantRuleLookupQuery,
    ImplantRuleLookupResult,
    ImplantRuleMatch,
    RefreshResult,
    RefreshStatus,
)
from loki.feeds.registry import FeedRegistry
from loki.feeds.version import FEEDS_VERSION
```

### Public API surface

#### `FeedRegistry` (R1.1-R1.10)

```python
# loki/feeds/registry.py
from __future__ import annotations

from loki.feeds.cache import CacheDB
from loki.feeds.errors import FeedsConfigError
from loki.feeds.implants import ImplantRuleSet, load_implant_rules
from loki.feeds.models import (
    CVELookupQuery,
    CVELookupResult,
    CancellationToken,
    ImplantRuleLookupQuery,
    ImplantRuleLookupResult,
    RefreshResult,
)
from loki.feeds.trust import resolve_trust_anchor
from loki.models.config import FeedsConfig


class FeedRegistry:
    """Library entry point for the Feeds subsystem.

    Owns the SQLite cache handle, the loaded implant rule set,
    and the resolved trust anchor.
    """

    @classmethod
    def from_config(cls, feeds_config: FeedsConfig) -> FeedRegistry:
        """Construct a FeedRegistry from a validated FeedsConfig.

        Raises FeedsConfigError on invalid configuration.
        """
        ...

    def refresh(
        self,
        *,
        force: bool = False,
        cancel: CancellationToken | None = None,
    ) -> RefreshResult:
        """Perform an explicit refresh of the Cache_DB.

        Args:
            force: Ignore cache-age check; refresh unconditionally.
            cancel: Cooperative cancellation token.

        Returns:
            RefreshResult describing the outcome.

        Raises:
            FeedsSignatureError: Trust_Anchor validation failed (HARD FAIL).
            FeedsCacheError: Partial download or cache write failure (HARD FAIL).
            FeedsNetworkError: Network/server failure on explicit refresh path.
        """
        ...

    def cve_lookup(
        self,
        query: CVELookupQuery,
        *,
        allow_refresh: bool = True,
    ) -> CVELookupResult:
        """Return matching CVE records from the Cache_DB.

        When allow_refresh=True and the cache is stale, an inline
        refresh fires on the calling thread before the query executes.
        Network/server failures on the inline-refresh path are caught
        (WARN-AND-CONTINUE); signature/partial-download failures
        propagate as HARD FAIL.

        Args:
            query: CPE-shaped lookup query.
            allow_refresh: Whether to trigger inline refresh on stale cache.

        Returns:
            CVELookupResult (possibly with stale_warning=True).

        Raises:
            FeedsSignatureError: Inline refresh signature failure (HARD FAIL).
            FeedsCacheError: Inline refresh partial-download or write failure.
            FeedsConfigError: Invalid query fields.
        """
        ...

    def implant_rule_lookup(
        self,
        query: ImplantRuleLookupQuery,
    ) -> ImplantRuleLookupResult:
        """Return matching implant-rule records from the loaded rule set.

        Does NOT trigger any cache refresh. Does NOT consult the Cache_DB.
        Pure function of the query and the loaded rule set.
        """
        ...
```

Construction sequence in `from_config`:

1. Validate `FeedsConfig.nvd_url` is non-empty `https://` URL (R2.4, R2.5).
2. Validate `FeedsConfig.cache_path` is non-empty; create directory if absent.
3. Resolve `FeedsConfig.trust_anchor_path`: `None` or `""` → package-embedded default; non-empty string → load and validate the file (R4.1-R4.4).
4. Open `CacheDB` at `<cache_path>/feeds.db` with WAL mode (R3.1-R3.2); check `feeds_writer_version` for major-version compatibility (R14.3).
5. Load implant rules: merge `builtin_implants/` + `FeedsConfig.implant_rules_path` (R7.1-R7.5).
6. Store resolved state on `self`; return instance.

#### Result models (R5, R6, R7, R10, R11)

```python
# loki/feeds/models.py
from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


CancellationToken = Callable[[], bool]


class RefreshStatus(StrEnum):
    SUCCESS = "SUCCESS"
    WARN_STALE = "WARN_STALE"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RefreshResult:
    status: RefreshStatus
    cves_imported: int
    bytes_fetched: int
    duration_seconds: float
    last_refresh_at: datetime | None
    feeds_version: str
    diagnostics: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CVEMatch:
    cve_id: str
    vendor: str
    product: str
    version: str
    published_date: datetime
    cvss_v3_score: float | None = None
    cvss_v3_severity: str | None = None


@dataclass(frozen=True)
class CVELookupResult:
    matches: list[CVEMatch] = field(default_factory=list)
    stale_warning: bool = False


@dataclass(frozen=True)
class CVELookupQuery:
    vendor: str
    product: str
    version: str


@dataclass(frozen=True)
class ImplantRuleMatch:
    rule_id: str
    ioc_field: str  # "content_hash" or "firmware_guid"
    threat_family: str


@dataclass(frozen=True)
class ImplantRuleLookupResult:
    matches: list[ImplantRuleMatch] = field(default_factory=list)


@dataclass(frozen=True)
class ImplantRuleLookupQuery:
    content_hash: str
    firmware_guid: str | None = None
```

Design notes on the result models:

- Frozen dataclasses (not Pydantic models) for the result types. The Feeds subsystem's results are lightweight read-only containers; they do not need Pydantic's strict-mode validation because their construction is controlled entirely within the subsystem. R10.5 permits either a Pydantic model or a frozen dataclass.
- `CVELookupResult.matches` is sorted lexicographically ascending by `cve_id` (R6.4). The sort is applied inside `CacheDB.query_cves` before return.
- `ImplantRuleLookupResult.matches` is sorted lexicographically ascending by `rule_id` (R7.7).
- `CVEMatch` carries the CPE fields that matched (for diagnostic purposes), the published-date, and CVSS-v3 data where available (R6.5). Missing CVSS-v3 surfaces as `None`.
- `CancellationToken` is a `Callable[[], bool]` alias, matching the analysis-engine's `AnalysisCancellationToken` pattern.

### Exception hierarchy (R5, R13)

```python
# loki/feeds/errors.py

class FeedsError(Exception):
    """Root exception for the Feeds subsystem."""


class FeedsConfigError(FeedsError):
    """Invalid configuration (exit code 2)."""


class FeedsSignatureError(FeedsError):
    """Trust-anchor validation failure (exit code 3). Security event."""


class FeedsCacheError(FeedsError):
    """Partial download or cache write failure (exit code 4 or 5)."""


class FeedsNetworkError(FeedsError):
    """Network/server failure (exit code 6 on explicit refresh)."""


class FeedsRefreshError(FeedsError):
    """General refresh failure not covered by the above."""
```

Exit-code mapping (R11.7, HARDEN G4-A):

| Exception | Exit code | Condition |
|-----------|-----------|-----------|
| None (success) | 0 | `RefreshResult.status == SUCCESS` |
| `FeedsConfigError` | 2 | Bad input, missing config, invalid URL |
| `FeedsSignatureError` | 3 | Trust_Anchor validation rejected bundle |
| `FeedsCacheError` (partial) | 4 | Incomplete bundle download |
| `FeedsCacheError` (write) | 5 | SQLite write failure during commit |
| `FeedsNetworkError` | 6 | Network/server failure on explicit refresh |
| SIGINT → `CANCELLED` | 130 | Cooperative cancellation honored |

To distinguish exit 4 from exit 5, `FeedsCacheError` carries a `partial_download: bool` attribute. The CLI checks this attribute to select the exit code.

### Cache layer (`loki/feeds/cache.py`)

```python
# loki/feeds/cache.py
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


class CacheDB:
    """SQLite WAL-mode wrapper for the Feeds cache."""

    def __init__(self, db_path: Path) -> None: ...

    def ensure_schema(self) -> None:
        """Create tables if they don't exist."""
        ...

    def get_metadata(self) -> CacheMetadata | None:
        """Return the single-row cache_metadata, or None if empty."""
        ...

    def refresh_atomic(
        self,
        cve_rows: list[dict],
        metadata: CacheMetadata,
        cancel: CancellationToken | None = None,
    ) -> None:
        """Atomically replace cve_records and update cache_metadata.

        Runs inside a single BEGIN IMMEDIATE transaction.
        Polls cancel between batch INSERTs.
        Raises FeedsCacheError on write failure.
        Rolls back on cancellation (Cache_DB unchanged).
        """
        ...

    def query_cves(self, vendor: str, product: str, version: str) -> list[CVEMatch]:
        """Query indexed (vendor, product, version) columns.

        Case-insensitive on vendor and product; exact on version.
        Returns results sorted lexicographically by cve_id.
        """
        ...

    def check_writer_version(self, current_major: int) -> None:
        """Raise FeedsCacheError if cache major version differs from current."""
        ...
```

Schema:

```sql
CREATE TABLE IF NOT EXISTS cve_records (
    cve_id         TEXT NOT NULL,
    vendor         TEXT NOT NULL COLLATE NOCASE,
    product        TEXT NOT NULL COLLATE NOCASE,
    version        TEXT NOT NULL,
    published_date TEXT NOT NULL,
    cvss_v3_score  REAL,
    cvss_v3_severity TEXT,
    PRIMARY KEY (cve_id, vendor, product, version)
);

CREATE INDEX IF NOT EXISTS idx_cve_lookup
    ON cve_records (vendor, product, version);

CREATE TABLE IF NOT EXISTS cache_metadata (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    last_refresh_at      TEXT NOT NULL,
    bundle_content_hash  TEXT NOT NULL,
    trust_anchor_identity TEXT NOT NULL,
    feed_format_version  TEXT NOT NULL,
    feeds_writer_version TEXT NOT NULL
);
```

Design notes:

- WAL mode issued via `PRAGMA journal_mode=WAL` immediately after connection open (R3.2).
- The `cve_records` table uses a composite primary key on `(cve_id, vendor, product, version)` because a single CVE can affect multiple CPE entries. The lookup index is on `(vendor, product, version)` — the query shape.
- `COLLATE NOCASE` on `vendor` and `product` columns satisfies R6.2's case-insensitive ASCII comparison requirement at the database level.
- `cache_metadata` has a `CHECK (id = 1)` constraint enforcing single-row semantics.
- Atomic refresh: `BEGIN IMMEDIATE` → `DELETE FROM cve_records` → batch INSERT → `UPDATE cache_metadata` → `COMMIT`. If cancelled or failed mid-way, `ROLLBACK` leaves prior data intact (R3.10).
- Batch INSERT uses `executemany` with configurable batch size (default 10,000 rows per `executemany` call) to avoid holding the full parsed bundle in a single Python list while allowing cancellation checks between batches (R9.1d, R12.4).

### Trust-anchor resolver (`loki/feeds/trust.py`)

```python
# loki/feeds/trust.py
from pathlib import Path
import hashlib


class TrustAnchor:
    """Resolved trust-anchor material."""

    def __init__(self, material: bytes, identity: str, source: str) -> None:
        self.material = material
        self.identity = identity  # fingerprint or hash-pin (ASCII)
        self.source = source      # "package-embedded" or "operator-override"

    def verify_bundle(self, bundle_bytes: bytes, verification_artifact: bytes) -> None:
        """Verify the bundle against this trust anchor.

        Raises FeedsSignatureError on failure.
        """
        ...


def resolve_trust_anchor(trust_anchor_path: str | None) -> TrustAnchor:
    """Resolve the trust anchor per D4-D hybrid logic.

    - None or "" → load package-embedded default at loki/feeds/_trust_anchor.pem
    - non-empty string → load file at that path

    Raises FeedsConfigError on missing/unreadable/unparseable file.
    """
    ...
```

Design notes:

- The dual-scheme wording from R4 is preserved (HARDEN G1-B). The implementation shape of `verify_bundle` depends on whether NVD publishes a signature or a hash-pin. The design supports both:
  - **Hash-pin scheme:** `material` is the expected SHA-256 hash. `verify_bundle` computes `hashlib.sha256(bundle_bytes).hexdigest()` and compares against the stored hash. No `cryptography` dependency.
  - **Signature scheme:** `material` is a PEM-encoded public key. `verify_bundle` uses `ssl` or the `cryptography` package for signature verification. If NVD publishes detached PGP/X.509 signatures, a dependency on `cryptography` is the design-phase fallback.
- v1 starts with the **hash-pin scheme** as the implementation default (smallest dependency footprint). If NVD documentation reveals a signature-based scheme at implementation time, the `TrustAnchor.verify_bundle` method adapts without changing the public API.
- `identity` is the SHA-256 fingerprint of the trust-anchor material itself (a fixed-length ASCII string safe for DEBUG-level logging per R4.9 / R13.7).

### CPE parser (`loki/feeds/cpe.py`) — HARDEN G2

```python
# loki/feeds/cpe.py
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CPETriple:
    vendor: str
    product: str
    version: str


def parse_cpe(cpe_string: str) -> CPETriple:
    """Parse a CPE-2.3 formatted-string into its (vendor, product, version) triple.

    Handles the wfn-fs-string form: cpe:2.3:<part>:<vendor>:<product>:<version>:...

    Raises ValueError on malformed input.
    """
    ...


def format_cpe(triple: CPETriple, part: str = "o") -> str:
    """Format a CPETriple back into a CPE-2.3 formatted-string.

    Round-trip equivalence: parse_cpe(format_cpe(parse_cpe(s))) == parse_cpe(s)
    """
    ...
```

Design notes:

- Hand-rolled per HARDEN G2. No `python-cpe` dependency.
- v1 scope: parse/format the `(vendor, product, version)` triple from NVD's CPE-2.3 formatted-string form (`cpe:2.3:o:vendor:product:version:*:*:*:*:*:*:*`). The remaining 8 CPE fields are accepted in the parsed string but not indexed or matched.
- The NVD JSON 2.0 feed provides CPEs as structured fields in `cpe_match` nodes; on the cache-population side the parser extracts the triple from each `criteria` string. On the lookup side the caller provides the triple directly via `CVELookupQuery`; the parser is not on the hot lookup path.
- Version-range qualifiers (`versionStartIncluding`, `versionEndExcluding`, etc.) are stored as separate columns in the `cve_records` table during refresh and consulted during lookup matching. The exact version-comparison logic uses a semver-aware string comparison when the version looks like semver, falling back to lexicographic comparison otherwise.

### Implant-rule loader (`loki/feeds/implants.py`)

```python
# loki/feeds/implants.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ImplantRule:
    rule_id: str          # prefixed: "implant:<slug>"
    threat_family: str    # e.g. "BlackLotus"
    content_hash: str | None
    firmware_guid: str | None


@dataclass(frozen=True)
class ImplantRuleSet:
    rules: tuple[ImplantRule, ...]


def load_implant_rules(
    builtin_dir: Path,
    operator_dir: Path | None,
) -> ImplantRuleSet:
    """Load and merge built-in + operator-extension implant rules.

    Operator rules shadow built-in rules on rule_id collision (R7.2).
    Logs a single INFO record per shadowed rule on first load.
    """
    ...
```

Implant-rule YAML schema (mirrors classification rule structure):

```yaml
# loki/feeds/builtin_implants/blacklotus.yaml
rule_id: "implant:blacklotus.bootmgfw"
threat_family: "BlackLotus"
ioc:
  content_hash: "a]4f8e...64-char-hex..."
  firmware_guid: null
```

Design notes:

- Rule-id namespace uses the `"implant:"` prefix per R7.4 to avoid collision with classification rule-ids.
- v1 ships three built-in rules: `blacklotus`, `mosaicregressor`, `lojax` (R7.1, HARDEN G3-C).
- The matching logic is exact-match on `content_hash` and/or `firmware_guid` per R7.6. No partial-byte patterns in v1.
- Rules are loaded once at `FeedRegistry.from_config()` time and held in memory for the registry's lifetime (R7.5).

### Refresh logic (`loki/feeds/refresh.py`)

The refresh path orchestrates:

1. Resolve Trust_Anchor (R4.1).
2. Check Cancel_Flag → cooperative point "pre-connection" (R9.1a).
3. Fetch NVD bundle from `FeedsConfig.nvd_url` via `urllib.request.urlopen` with:
   - `User-Agent: loki-feeds/<FEEDS_VERSION>` (R2.6).
   - No other custom headers (R2.7).
   - TLS context with `CERT_REQUIRED` + `check_hostname=True` (R8.7).
   - Redirect policy: follow only same-host redirects (R8.6).
4. Check Cancel_Flag between download chunks → cooperative point "download-chunk" (R9.1b).
5. Verify downloaded bundle size against Content-Length (partial-download detection) (R5.3).
6. Fetch the sibling verification artifact (signature file or hash manifest).
7. Validate bundle against Trust_Anchor (R4.5). On failure → `FeedsSignatureError` (R4.6, R5.2).
8. Check Cancel_Flag → cooperative point "pre-write" (R9.1c).
9. Parse NVD JSON bundle into CVE rows.
10. `CacheDB.refresh_atomic(cve_rows, metadata, cancel)` — atomic transaction with per-batch cancellation check (cooperative point "per-cve-insert", R9.1d).
11. On cancellation at any point → roll back, construct Cancellation_Marker, return `RefreshResult(status=CANCELLED)` (R9.2).

Network discipline:

- Only `FeedsConfig.nvd_url` and its sibling URLs are fetched (R2.1, R8.5).
- No environment variables, no system identifiers, no firmware content in any request (R8.1-R8.2).
- No request body on any request (GET only) (R8.1).
- Cross-origin redirects rejected with `FeedsNetworkError` (R8.6).
- No retry on transient failure (R5.7).

### CLI surface (`loki/feeds/cli.py`)

```python
# loki/feeds/cli.py
import argparse
import json
import signal
import sys

from loki.feeds.models import RefreshStatus


def register_feeds_subcommand(subparsers: argparse._SubParsersAction) -> None:
    """Register 'feeds' subcommand on the top-level loki dispatcher."""
    feeds_parser = subparsers.add_parser("feeds", help="Manage vulnerability feed cache")
    feeds_sub = feeds_parser.add_subparsers(dest="feeds_command")

    refresh_parser = feeds_sub.add_parser("refresh", help="Refresh the NVD feed cache")
    refresh_parser.add_argument("--config", type=str, default=None, help="Path to loki config YAML")
    refresh_parser.add_argument("--force", action="store_true", help="Ignore cache-age check")
    refresh_parser.add_argument("--summary-only", action="store_true", help="Suppress stdout JSON")


def run_feeds_refresh(args: argparse.Namespace) -> int:
    """Execute loki feeds refresh and return the exit code."""
    ...
```

Design notes:

- SIGINT handler installs at the start of `run_feeds_refresh`, flips a `threading.Event` (used as the `CancellationToken`), and restores the previous handler after `refresh()` returns (R9.4).
- Double-Ctrl-C does NOT short-circuit (R9.5); the installed handler persists.
- Stdout: single indented JSON `Stdout_Refresh_Status` object (R11.4), suppressed by `--summary-only` (R11.5).
- Stderr: single `Stderr_Summary_Line` (R11.6): `"feeds refresh: <STATUS>, <N> CVEs, <B> bytes, duration=<S>s\n"`.
- Stderr summary emitted on SUCCESS and CANCELLED; NOT emitted on HARD FAIL (R15.5 / P63).

## Data Models

This subsystem extends one model-layer file. The extension is backwards-compatible.

#### `FeedsConfig` extension (R4, HARDEN G5 — direct add to `loki/models/config.py`)

```python
# loki/models/config.py — FeedsConfig amended

class FeedsConfig(BaseModel):
    """Configuration for vulnerability feed ingestion."""

    model_config = ConfigDict(strict=True, frozen=False)

    nvd_url: str
    update_interval: int = Field(gt=0)
    cache_path: str
    implant_rules_path: str

    # NEW (R4, HARDEN G5):
    trust_anchor_path: str | None = None
```

Single new field: `trust_anchor_path: str | None = None`. Defaults to `None` (use the package-embedded trust anchor). Empty string `""` treated as equivalent to `None` per HARDEN G5. Backwards-compatible: existing YAML configs that omit the field get the default.

No new StrEnum is required. `RefreshStatus` lives in `loki/feeds/models.py` as a subsystem-local enum (not in the model layer) because it is not persisted or serialized to YAML configs.

## Sequence walkthrough

### Successful `cve_lookup` (cache fresh)

```
registry.cve_lookup(query, allow_refresh=True)
│
├─ Validate query fields (vendor, product, version non-empty after strip) → R6.1
│  └─ raise FeedsConfigError on empty field
│
├─ allow_refresh=True: check cache age
│  ├─ metadata = cache_db.get_metadata()
│  ├─ if metadata is None → cache empty → trigger inline refresh (R3.8)
│  ├─ if now() - metadata.last_refresh_at < update_interval → cache fresh → skip
│  └─ else → cache stale → trigger inline refresh (R3.4)
│
├─ (cache is fresh — no refresh triggered)
│
├─ results = cache_db.query_cves(query.vendor, query.product, query.version)
│  └─ SELECT ... WHERE vendor = ? AND product = ? AND version = ?
│     (COLLATE NOCASE on vendor/product; exact on version)
│
├─ sort results by cve_id ascending (R6.4)
│
└─ return CVELookupResult(matches=results, stale_warning=False)
```

### Successful `cve_lookup` (cache stale, inline refresh succeeds)

```
registry.cve_lookup(query, allow_refresh=True)
│
├─ Validate query fields
├─ Check cache age → stale → trigger inline refresh
│  ├─ [entire refresh logic from §Refresh logic above]
│  └─ refresh completes successfully → cache now fresh
│
├─ results = cache_db.query_cves(...)
└─ return CVELookupResult(matches=results, stale_warning=False)
```

### `cve_lookup` with inline refresh WARN-AND-CONTINUE

```
registry.cve_lookup(query, allow_refresh=True)
│
├─ Validate query fields
├─ Check cache age → stale → trigger inline refresh
│  ├─ refresh raises FeedsNetworkError internally
│  ├─ CATCH FeedsNetworkError
│  ├─ log WARNING: "feeds: inline refresh failed: <reason>" (R3.6)
│  └─ cache remains at pre-refresh state
│
├─ results = cache_db.query_cves(...)  (stale but structurally intact)
└─ return CVELookupResult(matches=results, stale_warning=True)
```

### `cve_lookup` with inline refresh HARD FAIL

```
registry.cve_lookup(query, allow_refresh=True)
│
├─ Validate query fields
├─ Check cache age → stale → trigger inline refresh
│  ├─ refresh raises FeedsSignatureError or FeedsCacheError(partial_download=True)
│  └─ PROPAGATE to caller (R3.7) — no lookup result returned
```

### Explicit `refresh()` with cancellation

```
registry.refresh(force=True, cancel=token)
│
├─ resolve Trust_Anchor
├─ cancel() check → "pre-connection" (R9.1a) — False → continue
├─ fetch NVD bundle (chunked read)
│  ├─ cancel() check between chunks → "download-chunk" (R9.1b) — True at chunk 5
│  └─ stop reading
│
├─ (no validation, no commit — cancelled before reaching that stage)
├─ ROLLBACK any partial state
├─ Construct Cancellation_Marker:
│  ├─ component_id = uuid5(LOKI_NAMESPACE, "feeds-refresh-cancelled")
│  ├─ severity = INFO
│  └─ evidence.raw_indicators[0] = "download-chunk" (never logged)
│
└─ return RefreshResult(
       status=CANCELLED,
       cves_imported=0,
       bytes_fetched=<partial>,
       duration_seconds=<elapsed>,
       last_refresh_at=<prior>,
       feeds_version=FEEDS_VERSION,
       diagnostics=[..., "cancelled at: download-chunk"],
   )
```

## Determinism

The Feeds subsystem's determinism contract (R10) applies to the **lookup paths only**, not to refresh paths (which perform network I/O and timestamp stamping).

- `cve_lookup(query, allow_refresh=False)` is a pure function of `(query, Cache_DB contents)`. No system clock, no RNG, no network (R10.4).
- `implant_rule_lookup(query)` is a pure function of `(query, loaded_rule_set)`. No system clock, no RNG, no network, no Cache_DB access (R10.2).
- Results are sorted deterministically (by `cve_id` or `rule_id` ascending).
- No environment-derived value appears in any lookup result (R10.3).

## Error handling

### Whole-run errors (raised; no partial result)

- `FeedsConfigError`: invalid `nvd_url`, empty query field, missing trust-anchor file, major-version mismatch on Cache_DB. Raised before any network or DB operation.
- `FeedsSignatureError`: bundle failed Trust_Anchor validation. Raised after fetch, before DB write. HARD FAIL.
- `FeedsCacheError`: partial download (bytes received < Content-Length) or SQLite write failure during commit. HARD FAIL.
- `FeedsNetworkError`: DNS/TCP/TLS/HTTP failure. On explicit `refresh()`, propagated to caller. On inline refresh inside `cve_lookup`, caught and swallowed with WARNING log + stale-cache fallback.

### Cooperative cancellation (NOT raised; partial result returned)

Per R9, cancellation returns a `RefreshResult(status=CANCELLED)` with Cancellation_Marker — it does NOT raise. The Cache_DB is left unchanged (transaction rolled back). On the CLI, this maps to exit 130.

### Per-record error swallowing — explicitly NOT permitted

The Feeds subsystem does not swallow per-CVE parse errors during refresh. If the NVD bundle contains a malformed CVE record that cannot be normalized into the `cve_records` schema, the entire refresh fails with `FeedsCacheError` (bundle structural validation failure). This is consistent with the "partial download is HARD FAIL" discipline: partial data is never committed.

## Performance and resource use

Per R12:

- **Lookup latency (R12.1):** `cve_lookup` against 200,000 CVE records in ≤ 50 ms. The `idx_cve_lookup` index on `(vendor, product, version)` with `COLLATE NOCASE` makes this a B-tree point lookup. SQLite typically answers in < 1 ms for point lookups; the 50 ms budget allows for result construction overhead.

- **Implant lookup latency (R12.2):** `implant_rule_lookup` against 1,024 rules in ≤ 5 ms. Linear scan over the in-memory rule set (1024 rules × 2 field comparisons ≈ 2048 string comparisons). Sub-millisecond in practice.

- **Refresh throughput (R12.3):** `refresh()` against 100 MiB bundle in ≤ 60 s (network latency excluded). Dominated by JSON parsing + SQLite INSERT. `executemany` with batch size 10,000 rows amortizes SQLite overhead.

- **Memory (R12.4):** Peak resident memory ≤ 256 MiB beyond the bundle + rule set. The bundle is loaded fully into memory (up to 100 MiB working assumption), parsed incrementally into batches, and each batch is committed before parsing the next. The in-memory accumulator does not retain the full parsed structure across the entire commit.

- **No write lock during network I/O (R12.5):** The bundle is downloaded and validated entirely before `BEGIN IMMEDIATE`. A concurrent `cve_lookup` (from another thread in the same process) reads the prior data during the fetch, then sees the new data after the commit.

- **Synchronous, single-threaded (R1.7):** No threading, no asyncio, no process pools. Mirrors the project discipline.

## No-leakage audits

Six complementary audits enforce R8 and R13 (HARDEN G7):

### 1. Static AST audit on log records (`tests/feeds/test_no_log_leakage.py`)

AST-walks every Python file in `loki/feeds/` and asserts no `logging.Logger.{debug,info,warning,error,exception}` call references any field in the Forbidden_Leakage_Field_Set. Mirrors `tests/analysis/test_no_log_leakage.py`.

### 2. Dynamic caplog audit on log records (`tests/feeds/test_log_no_leakage.py`)

Captures every log record emitted during curated refresh and lookup operations and asserts no record's formatted message contains any Forbidden_Leakage_Field_Set value. Mirrors `tests/analysis/test_log_no_leakage.py`.

### 3. Static AST audit on HTTPS requests (`tests/feeds/test_no_request_leakage_ast.py`)

AST-walks `loki/feeds/` and asserts that no `urllib.request.Request` construction, no `http.client` call site, and no `ssl.create_default_context` call site reads from any source pattern in R8.2 (`os.environ`, `os.getenv`, `os.uname`, `socket.gethostname`, `getpass.getuser`, attribute access on `FeedsConfig` beyond `nvd_url`).

### 4. Dynamic request-capture audit (`tests/feeds/test_no_request_leakage_dynamic.py`)

Monkey-patches `urllib.request.urlopen` to record every outbound request's URL and headers, runs a refresh against a synthetic local fixture, and asserts that captured URLs/headers contain only values permitted by R8.1-R8.2.

### 5. Runtime TLS verification audit (`tests/feeds/test_tls_verification.py`)

Constructs the Feeds subsystem's `ssl.SSLContext` and asserts `verify_mode == ssl.CERT_REQUIRED` and `check_hostname == True`. Pins R8.7.

### 6. Redirect-host-match policy audit (`tests/feeds/test_redirect_policy.py`)

Simulates a cross-origin redirect (NVD URL redirects to `evil.example`) and asserts `FeedsNetworkError` is raised. Pins R8.6.

All six audits run in the default `pytest -q` baseline (NOT gated behind slow-marker). None require real network access.

### What the audits permit

- `User-Agent: loki-feeds/<FEEDS_VERSION>` header (R2.6).
- Standard `Accept` and `Accept-Encoding` headers.
- The `FeedsConfig.nvd_url` value in the request URL.
- DEBUG-level logging of the Trust_Anchor's identity fingerprint (R4.9 / R13.7).

## Progress and cancellation

The Feeds subsystem does NOT expose a progress callback on the refresh path in v1. Refresh is a CLI-driven operation (or an inline operation transparent to the `cve_lookup` caller). Progress is communicated via:

- The Stderr_Summary_Line emitted after completion (R11.6).
- The `diagnostics` list in `RefreshResult` (R11.4).
- The exit code on the CLI surface (R11.7).

Cancellation is cooperative via `CancellationToken`:

- The `loki feeds refresh` CLI installs a SIGINT handler that flips the token.
- The refresh path polls at four cooperative points (R9.1a-d).
- On cancellation, a `Cancellation_Marker` is constructed with:
  - `component_id = uuid5(LOKI_NAMESPACE, "feeds-refresh-cancelled")`
  - `severity = INFO`
  - `evidence.raw_indicators[0]` = the cancellation stage (never logged)
- The marker is the LAST entry in `RefreshResult.diagnostics`.
- Exit code 130 on the CLI (R9.7).

## Correctness Properties

The Feeds subsystem adds **Properties 59 through 68**, picking up from classification-cli's P53-P58.

These ten properties are validated by Hypothesis-based property tests at `tests/feeds/test_properties.py`. Per the project convention: in-memory lookup properties use `max_examples=50`; full-pipeline (refresh + lookup) properties use `max_examples=25`; both set `suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture]`.

### Property 59: Lookup determinism (cve_lookup)

For every valid `CVELookupQuery` against a fixed synthetic Cache_DB (with `allow_refresh=False`), two `cve_lookup` invocations produce byte-equal `CVELookupResult` instances.

**Validates: Requirements 10.1, 6.4**

### Property 60: Lookup determinism (implant_rule_lookup)

For every valid `ImplantRuleLookupQuery` against a fixed synthetic loaded rule set, two `implant_rule_lookup` invocations produce byte-equal `ImplantRuleLookupResult` instances.

**Validates: Requirements 10.2, 7.7**

### Property 61: HTTPS-request leakage

For randomly generated valid `FeedsConfig` instances with randomly generated `trust_anchor_path` values and a captured request transport, no `trust_anchor_path` value, no environment variable value, and no system identifier value appears in any captured request URL, header, or body.

**Validates: Requirements 8.1-8.2, 13.5**

### Property 62: Cancel_Flag-driven cancellation contract

For the four cooperative cancellation points, passing a `CancellationToken` returning `True` at the configured point asserts: (a) `RefreshResult.status == CANCELLED`; (b) `RefreshResult.diagnostics` ends with the Cancellation_Marker whose sentinel component_id is `uuid5(LOKI_NAMESPACE, "feeds-refresh-cancelled")`; (c) pre-refresh Cache_DB contents remain intact; (d) the CLI exit-code path resolves to 130.

**Validates: Requirements 9.1-9.7**

### Property 63: Stderr_Summary_Line emission discipline

(a) On SUCCESS: emitted exactly once. (b) On CANCELLED: emitted exactly once. (c) On HARD FAIL: NOT emitted (only the typed-error message line appears).

**Validates: Requirements 11.6, 15.5**

### Property 64: No-leakage on stderr and stdout

For randomly generated valid `RefreshResult` shapes, no member of the Forbidden_Leakage_Field_Set appears in the Stdout_Refresh_Status JSON or in the Stderr_Summary_Line.

**Validates: Requirements 13.3-13.4**

### Property 65: CVE-result sort stability

For randomly generated valid `CVELookupQuery` inputs against a synthetic Cache_DB whose CVE rows are inserted in random order, the resulting `CVELookupResult.matches` list is sorted lexicographically ascending by `cve_id`, and the sort is stable across runs.

**Validates: Requirements 6.4, 10.1**

### Property 66: Inline-refresh trigger

Constructs a Cache_DB with a stale `last_refresh_at`, monkey-patches the network transport to record fetch attempts, invokes `cve_lookup(query, allow_refresh=True)`, and asserts exactly one fetch attempt is observed. A second invocation against the now-fresh cache triggers zero fetch attempts.

**Validates: Requirements 3.4, 3.5**

### Property 67: Cache atomicity under failure

Populates the Cache_DB with a known CVE set, simulates a Trust_Anchor validation failure after the bundle is fetched, and asserts prior Cache_DB contents remain byte-equal. Repeated for partial-download failure and Cache_DB write failure.

**Validates: Requirements 3.10, 5.5**

### Property 68: Tiered inline-refresh failure branching

Parameterized over three failure modes (network/server, signature/hash, partial download). Triggers each on the inline-refresh path (`cve_lookup` with `allow_refresh=True` against a stale cache). Asserts: (a) network/server → result with `stale_warning=True`, no raise; (b) signature/hash → `FeedsSignatureError` raised, no result; (c) partial download → `FeedsCacheError` raised, no result.

**Validates: Requirements 3.6, 3.7, 5.1-5.4**

## Testing Strategy

The test suite for the Feeds subsystem lives at `tests/feeds/` and is structured as:

```
tests/feeds/
├── _helpers.py                        # shared fixture builders
├── conftest.py                        # Hypothesis strategies, synthetic fixtures
├── test_registry.py                   # FeedRegistry construction + method tests
├── test_cache.py                      # CacheDB unit tests (schema, CRUD, atomicity)
├── test_refresh.py                    # refresh logic (success, failure modes, cancellation)
├── test_cve_lookup.py                 # cve_lookup unit tests
├── test_implant_lookup.py             # implant_rule_lookup unit tests
├── test_cpe.py                        # CPE parser + formatter + round-trip
├── test_trust.py                      # Trust_Anchor resolution + verification
├── test_implant_loader.py             # implant-rule loading + merge + shadowing
├── test_cli.py                        # CLI integration (subprocess-based)
├── test_properties.py                 # Hypothesis P59-P68
├── test_performance.py                # slow-marker performance tests (R12)
├── test_no_log_leakage.py             # static AST audit (audit 1)
├── test_log_no_leakage.py             # dynamic caplog audit (audit 2)
├── test_no_request_leakage_ast.py     # static AST audit on requests (audit 3)
├── test_no_request_leakage_dynamic.py # dynamic request-capture audit (audit 4)
├── test_tls_verification.py           # TLS context audit (audit 5)
└── test_redirect_policy.py            # redirect-host-match audit (audit 6)
```

Key testing patterns:

- **Synthetic Cache_DB fixtures.** Tests that exercise lookup and refresh paths construct in-memory SQLite databases pre-populated with known CVE rows. No real NVD data is fetched during testing.
- **Monkey-patched network transport.** Tests that exercise the refresh path patch `urllib.request.urlopen` to return synthetic bundles or simulate failures without real network access.
- **Subprocess CLI tests.** `test_cli.py` runs `loki feeds refresh` as a subprocess, captures stdout/stderr/exit-code, and asserts the Stdout_Refresh_Status and Stderr_Summary_Line contracts.
- **Performance tests behind slow-marker.** `test_performance.py` validates R12.1-R12.3 budgets with large synthetic fixtures. Excluded from default `pytest -q` run.

## Deferred decisions and open questions

Tracked here so future sessions don't re-derive answers.

### D1 — Trust-anchor implementation: hash-pin default

v1 implements the hash-pin scheme (SHA-256 hash comparison) as the Trust_Anchor verification mechanism. This is the smallest-dependency-footprint choice: requires only `hashlib` (stdlib). The dual-scheme wording in R4 and R5.2 permits a future revision to switch to signature verification (requiring the `cryptography` package) without changing the public API shape.

**Why this could change:** If NVD documentation (checked at implementation time) reveals that NVD publishes detached PGP/X.509 signatures rather than plain hash manifests, the implementation switches to signature verification. The `TrustAnchor.verify_bundle` method adapts; the public API (`FeedRegistry.refresh`, `FeedRegistry.cve_lookup`) does not change. The Cache_Metadata's `trust_anchor_identity` column records which scheme was used, enabling future mixed-scheme environments.

### D2 — NVD JSON 2.0 feed format

v1 consumes the NVD CVE JSON 2.0 format (the current feed format as of 2024-2025). The refresh logic parses the JSON bundle using the stdlib `json` module and extracts CVE records from the `vulnerabilities` array, each carrying `cve.id`, `cve.published`, `cve.metrics.cvssMetricV31[0].cvssData.baseScore`, and the `configurations.nodes[].cpeMatch[].criteria` CPE strings.

**Why this could change:** NVD may deprecate JSON 2.0 in favor of a future format. The `Cache_Metadata.feed_format_version` column records which format the cached data was derived from; a future revision can extend the parser without changing the cache schema.

### D3 — Version-range matching strategy

v1 stores NVD's version-range qualifiers (`versionStartIncluding`, `versionEndExcluding`, etc.) as additional columns in the `cve_records` table. The lookup query's `version` field is matched against both exact-version rows (`version = query.version`) and range rows (where `query.version` falls within the declared range). Range comparison uses semantic-version-aware comparison when the version string matches the `MAJOR.MINOR.PATCH` pattern, and falls back to lexicographic comparison otherwise.

**Why this could change:** Semantic version comparison is a heuristic for firmware versions, which often use non-standard versioning schemes. A future revision may introduce a configurable version-comparison strategy on `FeedsConfig`. v1's heuristic is the practical default for NVD data.

### D4 — Result types as frozen dataclasses (not Pydantic models)

`CVELookupResult`, `ImplantRuleLookupResult`, `RefreshResult`, and their nested types are frozen dataclasses rather than Pydantic v2 models. This is a deliberate departure from the model layer's Pydantic discipline. Rationale: these types are constructed entirely within the Feeds subsystem from validated data (either SQLite query results or parsed YAML rule files); they do not need Pydantic's strict-mode validation at construction time because the data has already been validated upstream (at cache-population time or rule-load time). Frozen dataclasses are lighter-weight and sufficient for the read-only-container use case.

**Why this could change:** If a consumer (e.g. a future `loki analyze` CLI that serializes lookup results to JSON for reporting) needs `model_dump_json()` on the result types, they can be migrated to Pydantic models. The public API shape does not change.

### D5 — Batch size for SQLite INSERT during refresh

Default batch size: 10,000 rows per `executemany` call. Between batches, the cancellation token is polled (R9.1d). The batch size balances SQLite throughput (larger batches = fewer round-trips to the database engine) against cancellation responsiveness (smaller batches = more frequent cancellation checks).

**Why this could change:** If the 60-second performance budget (R12.3) proves tight on large bundles, the batch size can be tuned without changing the public API or the correctness contract.

### D6 — No progress callback on refresh path

v1 does not expose a progress callback on the refresh path (unlike the analysis engine, which exposes `AnalysisProgressEvent`). The refresh path's progress is communicated via the `Stderr_Summary_Line` and the `RefreshResult.diagnostics` list. Rationale: refresh is a CLI-driven bulk operation, not a per-component iterative process; a progress bar is useful (and the CLI could add one later) but is not load-bearing for correctness.

**Why this could change:** If a future GUI revision wires the refresh onto a background thread and needs per-chunk progress, the `refresh` method can grow an optional `progress` callback at that time. The cancellation token is already in place; adding progress is a smaller extension than adding cancellation.

### D7 — Redirect policy: same-host only

v1 follows HTTP redirects only when the redirect target's host matches the originally-configured `FeedsConfig.nvd_url` host (R8.6). Cross-origin redirects are rejected with `FeedsNetworkError`. This is implemented via a custom `urllib.request` redirect handler that compares `urlparse(redirect_url).netloc` against `urlparse(nvd_url).netloc`.

**Why this could change:** If NVD introduces a CDN with a different hostname (e.g. `cdn.nvd.nist.gov` vs. `nvd.nist.gov`), the redirect policy could be extended to an allowlist of trusted hosts. v1's strict same-host policy is the security-conservative default.

### D8 — Property numbering: P59-P68

Ten properties, picking up from classification-cli's P53-P58. Matches the project's sequential discipline. The next subsystem to ship a spec triple picks up at P69.

## Out-of-scope explicit list

Confirming the introduction's non-goals are honored throughout the design:

- **Vendor advisory feeds:** NVD-only per D3-A. No second feed source.
- **Auto-population of `cve_matches`:** Consumer wiring is out of scope.
- **Scheduler / daemon:** Inline cache-age check + explicit CLI only.
- **Implant-rule network feed:** Built-in + operator-extension on disk only.
- **Streaming NVD download:** Full bundle, then validate, then commit.
- **GUI integration:** Future spec (OT-LK-004).
- **Cache schema migration:** Future spec.
- **Severity filtering at lookup time:** Consumer's concern.
- **Vendor aliasing:** NVD vocabulary verbatim.
- **Fleet CVE rollup:** Fleet-analysis territory.

---

*End of design.md. tasks.md is the next session per HANDOFF.md's spec-drafting-is-its-own-conversation rule; the implementation phase is the session after that.*
