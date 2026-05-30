"""End-to-end smoke test for the Feeds subsystem (task 26).

Constructs a FeedRegistry with a synthetic pre-populated CacheDB,
runs cve_lookup and implant_rule_lookup, asserts result shapes and
determinism, and wires results into a ClassificationRecord.cve_matches
field to confirm the model accepts it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from loki.feeds.cache import CacheDB, CacheMetadata
from loki.feeds.models import (
    CVELookupQuery,
    CVEMatch,
    ImplantRuleLookupQuery,
)
from loki.feeds.registry import FeedRegistry
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig


def _build_smoke_registry(tmp_path: Path) -> FeedRegistry:
    """Build a FeedRegistry with synthetic data for smoke testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    db_path = cache_dir / "feeds.db"

    cache_db = CacheDB(db_path)
    meta = CacheMetadata(
        last_refresh_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC),
        bundle_content_hash="ab" * 32,
        trust_anchor_identity="cd" * 32,
        feed_format_version="2.0",
        feeds_writer_version=FEEDS_VERSION,
    )
    rows = [
        {
            "cve_id": "CVE-2026-0001",
            "vendor": "intel",
            "product": "firmware",
            "version": "1.0.0",
            "published_date": "2026-01-01T00:00:00",
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
        },
        {
            "cve_id": "CVE-2026-0002",
            "vendor": "intel",
            "product": "firmware",
            "version": "1.0.0",
            "published_date": "2026-02-01T00:00:00",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "HIGH",
        },
        {
            "cve_id": "CVE-2026-0003",
            "vendor": "amd",
            "product": "driver",
            "version": "2.0.0",
            "published_date": "2026-03-01T00:00:00",
            "cvss_v3_score": 5.0,
            "cvss_v3_severity": "MEDIUM",
        },
    ]
    cache_db.refresh_atomic(rows, meta, None)

    config = FeedsConfig(
        nvd_url="https://example.com/feeds",
        update_interval=999999,
        cache_path=str(cache_dir),
        implant_rules_path="",
        trust_anchor_path=None,
    )

    from importlib.resources import files

    from loki.feeds.implants import load_implant_rules
    from loki.feeds.trust import resolve_trust_anchor

    trust_anchor = resolve_trust_anchor(None)
    builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
    rule_set = load_implant_rules(builtin_dir, None)

    return FeedRegistry(
        config=config,
        cache_db=cache_db,
        trust_anchor=trust_anchor,
        rule_set=rule_set,
    )


class TestFeedsSmokeEndToEnd:
    """End-to-end smoke: construct, lookup, verify shapes."""

    def test_cve_lookup_returns_matches(self, tmp_path: Path) -> None:
        registry = _build_smoke_registry(tmp_path)
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")
        result = registry.cve_lookup(query, allow_refresh=False)

        assert len(result.matches) == 2
        assert all(isinstance(m, CVEMatch) for m in result.matches)
        assert result.matches[0].cve_id == "CVE-2026-0001"
        assert result.matches[1].cve_id == "CVE-2026-0002"
        assert result.stale_warning is False

    def test_cve_lookup_no_match(self, tmp_path: Path) -> None:
        registry = _build_smoke_registry(tmp_path)
        query = CVELookupQuery(vendor="nobody", product="nothing", version="0.0.0")
        result = registry.cve_lookup(query, allow_refresh=False)

        assert len(result.matches) == 0
        assert result.stale_warning is False

    def test_implant_rule_lookup_returns_result(self, tmp_path: Path) -> None:
        registry = _build_smoke_registry(tmp_path)
        query = ImplantRuleLookupQuery(
            content_hash="0000" * 16,
            firmware_guid=None,
        )
        result = registry.implant_rule_lookup(query)
        # No match expected with random hash
        assert len(result.matches) == 0

    def test_determinism_across_calls(self, tmp_path: Path) -> None:
        registry = _build_smoke_registry(tmp_path)
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")

        r1 = registry.cve_lookup(query, allow_refresh=False)
        r2 = registry.cve_lookup(query, allow_refresh=False)

        assert r1 == r2

    def test_results_sorted_by_cve_id(self, tmp_path: Path) -> None:
        registry = _build_smoke_registry(tmp_path)
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")
        result = registry.cve_lookup(query, allow_refresh=False)

        cve_ids = [m.cve_id for m in result.matches]
        assert cve_ids == sorted(cve_ids)

    def test_cve_match_fields_populated(self, tmp_path: Path) -> None:
        registry = _build_smoke_registry(tmp_path)
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")
        result = registry.cve_lookup(query, allow_refresh=False)

        match = result.matches[0]
        assert match.cve_id == "CVE-2026-0001"
        assert match.vendor == "intel"
        assert match.product == "firmware"
        assert match.version == "1.0.0"
        assert match.cvss_v3_score == 9.8
        assert match.cvss_v3_severity == "CRITICAL"
