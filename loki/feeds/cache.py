"""Cache layer — SQLite WAL-mode wrapper for the Feeds cache."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loki.feeds.errors import FeedsCacheError
from loki.feeds.models import CancellationToken, CVEMatch

__all__ = ["CacheDB", "CacheMetadata"]

logger = logging.getLogger("loki.feeds")

_BATCH_SIZE = 10_000

_SCHEMA_SQL = """\
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
"""

_INSERT_SQL = """\
INSERT OR REPLACE INTO cve_records
    (cve_id, vendor, product, version, published_date, cvss_v3_score, cvss_v3_severity)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

_UPSERT_METADATA_SQL = """\
INSERT INTO cache_metadata
    (id, last_refresh_at, bundle_content_hash, trust_anchor_identity,
     feed_format_version, feeds_writer_version)
VALUES (1, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    last_refresh_at = excluded.last_refresh_at,
    bundle_content_hash = excluded.bundle_content_hash,
    trust_anchor_identity = excluded.trust_anchor_identity,
    feed_format_version = excluded.feed_format_version,
    feeds_writer_version = excluded.feeds_writer_version
"""

_QUERY_SQL = """\
SELECT cve_id, vendor, product, version, published_date,
       cvss_v3_score, cvss_v3_severity
FROM cve_records
WHERE vendor = ? AND product = ? AND version = ?
ORDER BY cve_id ASC
"""


@dataclass(frozen=True)
class CacheMetadata:
    """Single-row cache metadata."""

    last_refresh_at: datetime
    bundle_content_hash: str
    trust_anchor_identity: str
    feed_format_version: str
    feeds_writer_version: str


class CacheDB:
    """SQLite WAL-mode wrapper for the Feeds cache."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self.ensure_schema()

    def ensure_schema(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)

    def get_metadata(self) -> CacheMetadata | None:
        row = self._conn.execute(
            "SELECT last_refresh_at, bundle_content_hash, trust_anchor_identity, "
            "feed_format_version, feeds_writer_version FROM cache_metadata WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        return CacheMetadata(
            last_refresh_at=datetime.fromisoformat(row[0]),
            bundle_content_hash=row[1],
            trust_anchor_identity=row[2],
            feed_format_version=row[3],
            feeds_writer_version=row[4],
        )

    def refresh_atomic(
        self,
        cve_rows: list[dict[str, object]],
        metadata: CacheMetadata,
        cancel: CancellationToken | None = None,
    ) -> None:
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute("DELETE FROM cve_records")

            for i in range(0, len(cve_rows), _BATCH_SIZE):
                if cancel is not None and cancel():
                    self._conn.execute("ROLLBACK")
                    return
                batch = cve_rows[i : i + _BATCH_SIZE]
                self._conn.executemany(
                    _INSERT_SQL,
                    [
                        (
                            r["cve_id"],
                            r["vendor"],
                            r["product"],
                            r["version"],
                            r["published_date"],
                            r.get("cvss_v3_score"),
                            r.get("cvss_v3_severity"),
                        )
                        for r in batch
                    ],
                )

            self._conn.execute(
                _UPSERT_METADATA_SQL,
                (
                    metadata.last_refresh_at.isoformat(),
                    metadata.bundle_content_hash,
                    metadata.trust_anchor_identity,
                    metadata.feed_format_version,
                    metadata.feeds_writer_version,
                ),
            )
            self._conn.execute("COMMIT")
        except (sqlite3.Error, OSError) as exc:
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise FeedsCacheError(f"Cache write failure: {exc}", partial_download=False) from exc

    def query_cves(self, vendor: str, product: str, version: str) -> list[CVEMatch]:
        cursor = self._conn.execute(_QUERY_SQL, (vendor, product, version))
        results: list[CVEMatch] = []
        for row in cursor:
            results.append(
                CVEMatch(
                    cve_id=row[0],
                    vendor=row[1],
                    product=row[2],
                    version=row[3],
                    published_date=datetime.fromisoformat(row[4]),
                    cvss_v3_score=row[5],
                    cvss_v3_severity=row[6],
                )
            )
        return results

    def check_writer_version(self, current_major: int) -> None:
        meta = self.get_metadata()
        if meta is None:
            return
        try:
            stored_major = int(meta.feeds_writer_version.split(".")[0])
        except (ValueError, IndexError) as exc:
            raise FeedsCacheError(
                f"Unparseable feeds_writer_version in cache: {meta.feeds_writer_version!r}",
                partial_download=False,
            ) from exc
        if stored_major != current_major:
            raise FeedsCacheError(
                f"Cache major version mismatch: cache has {stored_major}, "
                f"current is {current_major}",
                partial_download=False,
            )

    def close(self) -> None:
        self._conn.close()
