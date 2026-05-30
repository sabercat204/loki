"""Tests for loki.feeds.cache — CacheDB SQLite WAL-mode wrapper."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.feeds.cache import CacheDB, CacheMetadata
from loki.feeds.errors import FeedsCacheError


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "feeds.db"


@pytest.fixture()
def cache_db(db_path: Path) -> CacheDB:
    return CacheDB(db_path)


def _make_metadata(*, writer_version: str = "1.0.0") -> CacheMetadata:
    return CacheMetadata(
        last_refresh_at=datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC),
        bundle_content_hash="abc123",
        trust_anchor_identity="def456",
        feed_format_version="2.0",
        feeds_writer_version=writer_version,
    )


def _make_rows(n: int = 3) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for i in range(n):
        rows.append(
            {
                "cve_id": f"CVE-2025-{i:04d}",
                "vendor": "intel",
                "product": "firmware",
                "version": "1.2.3",
                "published_date": "2025-01-10T00:00:00+00:00",
                "cvss_v3_score": 7.5,
                "cvss_v3_severity": "HIGH",
            }
        )
    return rows


class TestSchemaCreation:
    def test_fresh_db_creates_tables(self, cache_db: CacheDB) -> None:
        meta = cache_db.get_metadata()
        assert meta is None

    def test_wal_mode_active(self, cache_db: CacheDB) -> None:
        row = cache_db._conn.execute("PRAGMA journal_mode").fetchone()
        assert row is not None
        assert row[0].lower() == "wal"


class TestMetadata:
    def test_get_set_roundtrip(self, cache_db: CacheDB) -> None:
        metadata = _make_metadata()
        cache_db.refresh_atomic([], metadata)
        got = cache_db.get_metadata()
        assert got is not None
        assert got.bundle_content_hash == "abc123"
        assert got.trust_anchor_identity == "def456"
        assert got.feed_format_version == "2.0"
        assert got.feeds_writer_version == "1.0.0"
        assert got.last_refresh_at == datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)


class TestAtomicRefresh:
    def test_commits_all_rows(self, cache_db: CacheDB) -> None:
        rows = _make_rows(5)
        cache_db.refresh_atomic(rows, _make_metadata())
        results = cache_db.query_cves("intel", "firmware", "1.2.3")
        assert len(results) == 5

    def test_cancellation_rolls_back(self, cache_db: CacheDB) -> None:
        rows = _make_rows(3)
        cache_db.refresh_atomic(rows, _make_metadata())
        assert len(cache_db.query_cves("intel", "firmware", "1.2.3")) == 3

        big_rows = _make_rows(20_001)
        for i, r in enumerate(big_rows):
            r["cve_id"] = f"CVE-2026-{i:05d}"

        call_count = 0

        def cancel_on_second() -> bool:
            nonlocal call_count
            call_count += 1
            return call_count >= 2

        cache_db.refresh_atomic(big_rows, _make_metadata(), cancel=cancel_on_second)
        results = cache_db.query_cves("intel", "firmware", "1.2.3")
        assert len(results) == 3

    def test_write_failure_rolls_back(self, cache_db: CacheDB) -> None:
        rows = _make_rows(3)
        cache_db.refresh_atomic(rows, _make_metadata())

        bad_rows: list[dict[str, object]] = [
            {
                "cve_id": None,  # NOT NULL violation
                "vendor": "x",
                "product": "y",
                "version": "1.0",
                "published_date": "2025-01-01T00:00:00+00:00",
                "cvss_v3_score": None,
                "cvss_v3_severity": None,
            }
        ]
        with pytest.raises(FeedsCacheError):
            cache_db.refresh_atomic(bad_rows, _make_metadata())

        results = cache_db.query_cves("intel", "firmware", "1.2.3")
        assert len(results) == 3


class TestVersionCheck:
    def test_matching_version_passes(self, cache_db: CacheDB) -> None:
        cache_db.refresh_atomic([], _make_metadata(writer_version="1.2.3"))
        cache_db.check_writer_version(1)

    def test_mismatched_version_raises(self, cache_db: CacheDB) -> None:
        cache_db.refresh_atomic([], _make_metadata(writer_version="2.0.0"))
        with pytest.raises(FeedsCacheError, match="mismatch"):
            cache_db.check_writer_version(1)

    def test_empty_cache_passes(self, cache_db: CacheDB) -> None:
        cache_db.check_writer_version(1)


class TestQueryCves:
    def test_case_insensitive_vendor_product(self, cache_db: CacheDB) -> None:
        rows = _make_rows(2)
        rows[0]["vendor"] = "Intel"
        rows[0]["product"] = "Firmware"
        rows[1]["vendor"] = "intel"
        rows[1]["product"] = "firmware"
        rows[1]["cve_id"] = "CVE-2025-9999"
        cache_db.refresh_atomic(rows, _make_metadata())

        results = cache_db.query_cves("INTEL", "FIRMWARE", "1.2.3")
        assert len(results) == 2

    def test_exact_match_on_version(self, cache_db: CacheDB) -> None:
        rows = _make_rows(1)
        cache_db.refresh_atomic(rows, _make_metadata())
        assert len(cache_db.query_cves("intel", "firmware", "1.2.3")) == 1
        assert len(cache_db.query_cves("intel", "firmware", "9.9.9")) == 0

    def test_results_sorted_by_cve_id(self, cache_db: CacheDB) -> None:
        rows = _make_rows(5)
        cache_db.refresh_atomic(rows, _make_metadata())
        results = cache_db.query_cves("intel", "firmware", "1.2.3")
        cve_ids = [r.cve_id for r in results]
        assert cve_ids == sorted(cve_ids)

    def test_multiple_registries_same_db(self, db_path: Path) -> None:
        db1 = CacheDB(db_path)
        db2 = CacheDB(db_path)
        rows = _make_rows(3)
        db1.refresh_atomic(rows, _make_metadata())
        results = db2.query_cves("intel", "firmware", "1.2.3")
        assert len(results) == 3
        db1.close()
        db2.close()
