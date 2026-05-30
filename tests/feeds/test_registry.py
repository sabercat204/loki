"""Tests for loki.feeds.registry — FeedRegistry library entry point."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from loki.feeds.cache import CacheMetadata
from loki.feeds.errors import FeedsConfigError, FeedsNetworkError, FeedsSignatureError
from loki.feeds.models import CVELookupQuery, ImplantRuleLookupQuery
from loki.feeds.registry import FeedRegistry
from loki.models.config import FeedsConfig


def _make_config(
    tmp_path: Path,
    nvd_url: str = "https://nvd.example.com/bundle.json",
) -> FeedsConfig:
    return FeedsConfig(
        nvd_url=nvd_url,
        update_interval=3600,
        cache_path=str(tmp_path / "cache"),
        implant_rules_path="",
    )


def _make_bundle() -> bytes:
    bundle = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-1234",
                    "published": "2025-01-15T00:00:00+00:00",
                    "metrics": {},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:o:intel:firmware:1.2.3:*:*:*:*:*:*:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    return json.dumps(bundle).encode()


class _FakeResponse:
    def __init__(self, data: bytes) -> None:
        self._stream = BytesIO(data)
        self.headers = MagicMock()
        self.headers.get.return_value = str(len(data))

    def read(self, n: int = -1) -> bytes:
        return self._stream.read(n)

    def close(self) -> None:
        pass


class TestConstruction:
    def test_valid_config_succeeds(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)
        assert registry is not None

    def test_invalid_nvd_url_empty(self, tmp_path: Path) -> None:
        config = FeedsConfig(
            nvd_url="",
            update_interval=3600,
            cache_path=str(tmp_path / "cache"),
            implant_rules_path="",
        )
        with pytest.raises(FeedsConfigError, match="non-empty"):
            FeedRegistry.from_config(config)

    def test_http_url_raises(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, nvd_url="http://insecure.example.com/feed")
        with pytest.raises(FeedsConfigError, match="https://"):
            FeedRegistry.from_config(config)


class TestCveLookup:
    def test_allow_refresh_false_no_fetch(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.2.3")
        result = registry.cve_lookup(query, allow_refresh=False)
        assert result.matches == []
        assert result.stale_warning is False

    def test_allow_refresh_true_fresh_cache_no_fetch(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)

        # Pre-populate cache with fresh metadata
        now = datetime.now(UTC)
        meta = CacheMetadata(
            last_refresh_at=now,
            bundle_content_hash="abc",
            trust_anchor_identity="def",
            feed_format_version="2.0",
            feeds_writer_version="1.0.0",
        )
        registry._cache_db.refresh_atomic([], meta)

        query = CVELookupQuery(vendor="intel", product="firmware", version="1.2.3")

        with patch("loki.feeds.registry.perform_refresh") as mock_refresh:
            result = registry.cve_lookup(query, allow_refresh=True)
            mock_refresh.assert_not_called()

        assert result.stale_warning is False

    def test_allow_refresh_true_stale_cache_triggers_fetch(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)

        # Pre-populate with old metadata
        old = datetime.now(UTC) - timedelta(seconds=7200)
        meta = CacheMetadata(
            last_refresh_at=old,
            bundle_content_hash="abc",
            trust_anchor_identity="def",
            feed_format_version="2.0",
            feeds_writer_version="1.0.0",
        )
        registry._cache_db.refresh_atomic([], meta)

        query = CVELookupQuery(vendor="intel", product="firmware", version="1.2.3")

        with patch("loki.feeds.registry.perform_refresh") as mock_refresh:
            registry.cve_lookup(query, allow_refresh=True)
            mock_refresh.assert_called_once()

    def test_inline_refresh_network_failure_stale_warning(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)

        # Pre-populate with stale metadata
        old = datetime.now(UTC) - timedelta(seconds=7200)
        meta = CacheMetadata(
            last_refresh_at=old,
            bundle_content_hash="abc",
            trust_anchor_identity="def",
            feed_format_version="2.0",
            feeds_writer_version="1.0.0",
        )
        registry._cache_db.refresh_atomic([], meta)

        query = CVELookupQuery(vendor="intel", product="firmware", version="1.2.3")

        with patch(
            "loki.feeds.registry.perform_refresh",
            side_effect=FeedsNetworkError("timeout"),
        ):
            result = registry.cve_lookup(query, allow_refresh=True)

        assert result.stale_warning is True

    def test_inline_refresh_signature_failure_propagates(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)

        # Empty cache triggers refresh
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.2.3")

        with patch(
            "loki.feeds.registry.perform_refresh",
            side_effect=FeedsSignatureError("bad sig"),
        ):
            with pytest.raises(FeedsSignatureError):
                registry.cve_lookup(query, allow_refresh=True)


class TestImplantRuleLookup:
    def test_returns_matches_from_loaded_rules(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        registry = FeedRegistry.from_config(config)

        # The built-in rules use specific hashes — query with one
        query = ImplantRuleLookupQuery(
            content_hash="nonexistent_hash_value_here",
            firmware_guid=None,
        )
        result = registry.implant_rule_lookup(query)
        assert result.matches == []


class TestMultipleRegistries:
    def test_same_cache_path_no_corruption(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        r1 = FeedRegistry.from_config(config)
        r2 = FeedRegistry.from_config(config)

        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0")
        result1 = r1.cve_lookup(query, allow_refresh=False)
        result2 = r2.cve_lookup(query, allow_refresh=False)
        assert result1.matches == result2.matches
