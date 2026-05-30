"""Tests for loki.feeds.refresh — fetch, validate, and commit logic."""

from __future__ import annotations

import hashlib
import json
import ssl
import urllib.request
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from loki.feeds.cache import CacheDB
from loki.feeds.errors import FeedsCacheError, FeedsNetworkError, FeedsSignatureError
from loki.feeds.models import RefreshStatus
from loki.feeds.refresh import (
    _USER_AGENT,
    _build_ssl_context,
    _SameHostRedirectHandler,
    perform_refresh,
)
from loki.feeds.trust import TrustAnchor
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig


def _make_config(nvd_url: str = "https://nvd.example.com/bundle.json") -> FeedsConfig:
    return FeedsConfig(
        nvd_url=nvd_url,
        update_interval=3600,
        cache_path="/tmp/test-feeds",
        implant_rules_path="",
    )


def _make_bundle() -> bytes:
    """Create a minimal valid NVD JSON 2.0 bundle."""
    bundle = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-0001",
                    "published": "2025-01-01T00:00:00+00:00",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
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


def _make_artifact(bundle_bytes: bytes) -> bytes:
    """SHA-256 hash artifact for a given bundle."""
    return hashlib.sha256(bundle_bytes).hexdigest().encode()


class _FakeResponse:
    """Fake urllib response object."""

    def __init__(self, data: bytes, content_length: int | None = None) -> None:
        self._stream = BytesIO(data)
        self.headers = MagicMock()
        if content_length is not None:
            self.headers.get.return_value = str(content_length)
        else:
            self.headers.get.return_value = str(len(data))

    def read(self, n: int = -1) -> bytes:
        return self._stream.read(n)

    def close(self) -> None:
        pass


@pytest.fixture()
def cache_db(tmp_path: Path) -> CacheDB:
    return CacheDB(tmp_path / "feeds.db")


@pytest.fixture()
def trust_anchor() -> TrustAnchor:
    material = b"test-anchor"
    identity = hashlib.sha256(material).hexdigest()
    return TrustAnchor(material=material, identity=identity, source="test")


class TestSuccessPath:
    def test_success_with_mocked_urlopen(
        self, cache_db: CacheDB, trust_anchor: TrustAnchor
    ) -> None:
        bundle = _make_bundle()
        artifact = _make_artifact(bundle)
        config = _make_config()

        call_count = 0

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _FakeResponse(bundle)
            return _FakeResponse(artifact)

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            result = perform_refresh(config, cache_db, trust_anchor)

        assert result.status == RefreshStatus.SUCCESS
        assert result.cves_imported == 1
        assert result.bytes_fetched == len(bundle)
        assert result.feeds_version == FEEDS_VERSION

    def test_user_agent_header(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        bundle = _make_bundle()
        artifact = _make_artifact(bundle)
        config = _make_config()

        captured_requests: list[urllib.request.Request] = []

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            captured_requests.append(req)
            if len(captured_requests) == 1:
                return _FakeResponse(bundle)
            return _FakeResponse(artifact)

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            perform_refresh(config, cache_db, trust_anchor)

        assert len(captured_requests) >= 1
        first_req = captured_requests[0]
        assert first_req.get_header("User-agent") == _USER_AGENT

    def test_no_unexpected_headers(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        bundle = _make_bundle()
        artifact = _make_artifact(bundle)
        config = _make_config()

        captured_requests: list[urllib.request.Request] = []

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            captured_requests.append(req)
            if len(captured_requests) == 1:
                return _FakeResponse(bundle)
            return _FakeResponse(artifact)

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            perform_refresh(config, cache_db, trust_anchor)

        first_req = captured_requests[0]
        headers = dict(first_req.headers)
        assert set(headers.keys()) == {"User-agent"}


class TestSignatureFailure:
    def test_raises_on_hash_mismatch(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        bundle = _make_bundle()
        bad_artifact = b"0000000000000000000000000000000000000000000000000000000000000000"
        config = _make_config()

        call_count = 0

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _FakeResponse(bundle)
            return _FakeResponse(bad_artifact)

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            with pytest.raises(FeedsSignatureError, match="mismatch"):
                perform_refresh(config, cache_db, trust_anchor)


class TestPartialDownload:
    def test_raises_on_short_read(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        bundle = _make_bundle()
        config = _make_config()

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse(bundle[:10], content_length=len(bundle))

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            with pytest.raises(FeedsCacheError) as exc_info:
                perform_refresh(config, cache_db, trust_anchor)
            assert exc_info.value.partial_download is True


class TestNetworkFailure:
    def test_raises_on_connection_error(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        config = _make_config()

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            raise urllib.error.URLError("Connection refused")

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            with pytest.raises(FeedsNetworkError, match="Network failure"):
                perform_refresh(config, cache_db, trust_anchor)


class TestCancellation:
    def test_cancel_pre_connection(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        config = _make_config()
        result = perform_refresh(config, cache_db, trust_anchor, cancel=lambda: True)
        assert result.status == RefreshStatus.CANCELLED
        assert "cancelled at: pre-connection" in result.diagnostics

    def test_cancel_during_download(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        config = _make_config()
        call_count = 0

        def cancel_on_second() -> bool:
            nonlocal call_count
            call_count += 1
            return call_count >= 2

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse(b"x" * 200_000)

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            result = perform_refresh(config, cache_db, trust_anchor, cancel=cancel_on_second)

        assert result.status == RefreshStatus.CANCELLED
        assert any("download-chunk" in d for d in result.diagnostics)

    def test_cancel_pre_write(self, cache_db: CacheDB, trust_anchor: TrustAnchor) -> None:
        bundle = _make_bundle()
        artifact = _make_artifact(bundle)
        config = _make_config()

        call_count = 0

        def cancel_at_pre_write() -> bool:
            nonlocal call_count
            call_count += 1
            # First call: pre-connection check (False)
            # Calls during download chunks (False)
            # After download and verify, pre-write check (True)
            return call_count >= 4

        req_count = 0

        def fake_open(req: Any, **kwargs: Any) -> _FakeResponse:
            nonlocal req_count
            req_count += 1
            if req_count == 1:
                return _FakeResponse(bundle)
            return _FakeResponse(artifact)

        with patch("loki.feeds.refresh.urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open = fake_open
            result = perform_refresh(config, cache_db, trust_anchor, cancel=cancel_at_pre_write)

        assert result.status == RefreshStatus.CANCELLED
        assert any("pre-write" in d for d in result.diagnostics)


class TestCrossOriginRedirect:
    def test_rejects_cross_origin(self) -> None:
        handler = _SameHostRedirectHandler("nvd.example.com")
        req = urllib.request.Request("https://nvd.example.com/bundle.json")
        with pytest.raises(FeedsNetworkError, match="Cross-origin"):
            handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/redirect")


class TestTLSContext:
    def test_ssl_context_settings(self) -> None:
        ctx = _build_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
