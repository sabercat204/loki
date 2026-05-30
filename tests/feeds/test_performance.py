"""Performance tests for the Feeds subsystem (task 25).

Slow-marker tests verifying R12.1-R12.3 budgets:
- R12.1: cve_lookup against 200,000 CVE records in <= 50 ms
- R12.2: implant_rule_lookup against 1,024 rules in <= 5 ms
- R12.3: refresh() against 100 MiB synthetic bundle in <= 60 s
         (network excluded; local fixture)

All marked @pytest.mark.slow to exclude from default `pytest -q`.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from loki.feeds.cache import CacheDB, CacheMetadata
from loki.feeds.implants import ImplantRule, ImplantRuleSet, match_implant_rules
from loki.feeds.models import (
    CVELookupQuery,
    ImplantRuleLookupQuery,
    RefreshStatus,
)
from loki.feeds.refresh import perform_refresh
from loki.feeds.registry import FeedRegistry
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig


@pytest.mark.slow
class TestCveLookupPerformance:
    """R12.1: cve_lookup against 200,000 CVE records in <= 50 ms."""

    def test_200k_cves_under_50ms(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        db_path = cache_dir / "feeds.db"

        cache_db = CacheDB(db_path)
        rows = [
            {
                "cve_id": f"CVE-2026-{i:06d}",
                "vendor": f"vendor_{i % 100}",
                "product": f"product_{i % 50}",
                "version": f"{i % 10}.0.0",
                "published_date": "2026-01-01T00:00:00",
                "cvss_v3_score": 5.0 + (i % 50) / 10.0,
                "cvss_v3_severity": "MEDIUM",
            }
            for i in range(200_000)
        ]
        meta = CacheMetadata(
            last_refresh_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC),
            bundle_content_hash="ab" * 32,
            trust_anchor_identity="cd" * 32,
            feed_format_version="2.0",
            feeds_writer_version=FEEDS_VERSION,
        )
        cache_db.refresh_atomic(rows, meta, None)

        config = FeedsConfig(
            nvd_url="https://example.com/feeds",
            update_interval=999999,
            cache_path=str(cache_dir),
            implant_rules_path="",
            trust_anchor_path=None,
        )

        from importlib.resources import files

        from loki.feeds.trust import resolve_trust_anchor

        trust_anchor = resolve_trust_anchor(None)
        builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
        from loki.feeds.implants import load_implant_rules

        rule_set = load_implant_rules(builtin_dir, None)

        registry = FeedRegistry(
            config=config,
            cache_db=cache_db,
            trust_anchor=trust_anchor,
            rule_set=rule_set,
        )

        query = CVELookupQuery(vendor="vendor_0", product="product_0", version="0.0.0")

        start = time.monotonic()
        _result = registry.cve_lookup(query, allow_refresh=False)
        elapsed_ms = (time.monotonic() - start) * 1000.0

        assert elapsed_ms <= 50.0, f"cve_lookup took {elapsed_ms:.2f} ms (budget: 50 ms)"


@pytest.mark.slow
class TestImplantLookupPerformance:
    """R12.2: implant_rule_lookup against 1,024 rules in <= 5 ms."""

    def test_1024_rules_under_5ms(self) -> None:
        rules = tuple(
            ImplantRule(
                rule_id=f"implant:synthetic_{i:04d}",
                threat_family=f"family_{i % 10}",
                content_hash=f"{i:064x}",
                firmware_guid=None,
            )
            for i in range(1024)
        )
        rule_set = ImplantRuleSet(rules=rules)

        query = ImplantRuleLookupQuery(
            content_hash="f" * 64,
            firmware_guid=None,
        )

        start = time.monotonic()
        _result = match_implant_rules(query, rule_set)
        elapsed_ms = (time.monotonic() - start) * 1000.0

        assert elapsed_ms <= 5.0, f"implant_rule_lookup took {elapsed_ms:.2f} ms (budget: 5 ms)"


@pytest.mark.slow
class TestRefreshPerformance:
    """R12.3: refresh() against 100 MiB synthetic bundle in <= 60 s."""

    def test_100mb_bundle_under_60s(self, tmp_path: Path) -> None:
        # Build a ~100 MiB synthetic NVD bundle
        # Each CVE entry is ~200 bytes; 500,000 entries ≈ 100 MiB
        vulns = []
        for i in range(500_000):
            vulns.append(
                {
                    "cve": {
                        "id": f"CVE-2026-{i:06d}",
                        "published": "2026-01-01T00:00:00",
                        "metrics": {},
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": f"cpe:2.3:o:vendor_{i % 100}:product_{i % 50}:{i % 10}.0.0:*:*:*:*:*:*:*"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            )
        bundle = json.dumps({"vulnerabilities": vulns}).encode()
        bundle_hash = hashlib.sha256(bundle).hexdigest()

        class FakeResponse:
            def __init__(self, data: bytes) -> None:
                self._data = data
                self._pos = 0
                self.headers = {"Content-Length": str(len(data))}

            def read(self, size: int = -1) -> bytes:
                if self._pos >= len(self._data):
                    return b""
                end = self._pos + size if size > 0 else len(self._data)
                chunk = self._data[self._pos : end]
                self._pos = end
                return chunk

            def close(self) -> None:
                pass

        call_count = 0

        def fake_open(
            self: object, request: object, *args: object, **kwargs: object
        ) -> FakeResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return FakeResponse(bundle)
            return FakeResponse(bundle_hash.encode())

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        db_path = cache_dir / "feeds.db"
        cache_db = CacheDB(db_path)

        config = FeedsConfig(
            nvd_url="https://example.com/feeds",
            update_interval=3600,
            cache_path=str(cache_dir),
            implant_rules_path="",
            trust_anchor_path=None,
        )

        from loki.feeds.trust import resolve_trust_anchor

        trust_anchor = resolve_trust_anchor(None)

        start = time.monotonic()
        with patch("urllib.request.OpenerDirector.open", fake_open):
            result = perform_refresh(config, cache_db, trust_anchor, force=True, cancel=None)
        elapsed_s = time.monotonic() - start

        assert result.status == RefreshStatus.SUCCESS
        assert result.cves_imported == 500_000
        assert elapsed_s <= 60.0, f"refresh took {elapsed_s:.2f}s (budget: 60s)"
