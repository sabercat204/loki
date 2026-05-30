"""Dynamic request-capture audit for ``loki.feeds`` (task 21).

Monkey-patches ``urllib.request.urlopen`` (via the opener used by
refresh logic) to capture request objects, runs a refresh against
a synthetic local fixture, and asserts captured URLs/headers contain
only permitted values.

Permitted:
- URL: the configured ``nvd_url`` and its ``.sha256`` sibling
- Header: ``User-Agent: loki-feeds/<VERSION>``

Implements R8.4, R13.6(d).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from loki.feeds.cache import CacheDB
from loki.feeds.models import RefreshStatus
from loki.feeds.refresh import perform_refresh
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig

_PERMITTED_USER_AGENT = f"loki-feeds/{FEEDS_VERSION}"


def _build_synthetic_bundle() -> bytes:
    """Build a minimal NVD JSON 2.0 bundle."""
    import json

    bundle = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "published": "2026-01-01T00:00:00",
                    "metrics": {},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:o:intel:firmware:1.0.0:*:*:*:*:*:*:*"}
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


class TestRequestCapture:
    """Captured requests contain only permitted URLs and headers."""

    def test_refresh_sends_only_permitted_headers(self, tmp_path: Path) -> None:
        import hashlib

        bundle_bytes = _build_synthetic_bundle()
        bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()

        captured_requests: list[object] = []

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
            captured_requests.append(request)
            call_count += 1
            if call_count == 1:
                return FakeResponse(bundle_bytes)
            # Second call is the .sha256 artifact — return the correct hash
            return FakeResponse(bundle_hash.encode())

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        db_path = cache_dir / "feeds.db"
        cache_db = CacheDB(db_path)

        config = FeedsConfig(
            nvd_url="https://nvd.example.com/cves/2.0",
            update_interval=3600,
            cache_path=str(cache_dir),
            implant_rules_path="",
            trust_anchor_path=None,
        )

        from loki.feeds.trust import resolve_trust_anchor

        trust_anchor = resolve_trust_anchor(None)

        with patch("urllib.request.OpenerDirector.open", fake_open):
            result = perform_refresh(config, cache_db, trust_anchor, force=True, cancel=None)

        assert result.status == RefreshStatus.SUCCESS

        # Verify captured requests
        assert len(captured_requests) >= 2
        for req in captured_requests:
            url = getattr(req, "full_url", None) or str(req)
            assert "nvd.example.com" in url
            ua = req.get_header("User-agent") if hasattr(req, "get_header") else None
            if ua is not None:
                assert ua == _PERMITTED_USER_AGENT

    def test_no_unexpected_headers(self, tmp_path: Path) -> None:
        """Requests carry only User-Agent, no custom/forbidden headers."""
        import hashlib

        bundle_bytes = _build_synthetic_bundle()
        bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()

        captured_requests: list[object] = []

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
            captured_requests.append(request)
            call_count += 1
            if call_count == 1:
                return FakeResponse(bundle_bytes)
            return FakeResponse(bundle_hash.encode())

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        db_path = cache_dir / "feeds.db"
        cache_db = CacheDB(db_path)

        config = FeedsConfig(
            nvd_url="https://nvd.example.com/cves/2.0",
            update_interval=3600,
            cache_path=str(cache_dir),
            implant_rules_path="",
            trust_anchor_path=None,
        )

        from loki.feeds.trust import resolve_trust_anchor

        trust_anchor = resolve_trust_anchor(None)

        with patch("urllib.request.OpenerDirector.open", fake_open):
            perform_refresh(config, cache_db, trust_anchor, force=True, cancel=None)

        allowed_header_keys = {"User-agent", "Host"}
        for req in captured_requests:
            if hasattr(req, "header_items"):
                for key, _value in req.header_items():
                    assert key in allowed_header_keys, f"Unexpected header: {key}"
