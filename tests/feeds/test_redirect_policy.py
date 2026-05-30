"""Redirect host-match policy audit for ``loki.feeds`` (task 23).

Simulates cross-origin and same-host redirects, asserting:
- Cross-origin redirect raises ``FeedsNetworkError``
- Same-host redirect is followed

Implements R8.6, R13.6(f); D7 same-host redirect policy.
"""

from __future__ import annotations

import urllib.request

import pytest

from loki.feeds.errors import FeedsNetworkError
from loki.feeds.refresh import _SameHostRedirectHandler


class TestSameHostRedirectHandler:
    """The custom redirect handler rejects cross-origin redirects."""

    def test_same_host_redirect_allowed(self) -> None:
        """Redirect within the same host is followed."""
        handler = _SameHostRedirectHandler("nvd.nist.gov")
        original_req = urllib.request.Request("https://nvd.nist.gov/path1")
        new_url = "https://nvd.nist.gov/path2"

        result = handler.redirect_request(original_req, None, 301, "Moved", {}, new_url)
        assert result is not None
        assert "nvd.nist.gov" in result.full_url

    def test_cross_origin_redirect_rejected(self) -> None:
        """Redirect to a different host raises FeedsNetworkError."""
        handler = _SameHostRedirectHandler("nvd.nist.gov")
        original_req = urllib.request.Request("https://nvd.nist.gov/path1")
        new_url = "https://evil.example.com/payload"

        with pytest.raises(FeedsNetworkError, match="Cross-origin redirect"):
            handler.redirect_request(original_req, None, 301, "Moved", {}, new_url)

    def test_cross_origin_redirect_includes_hosts_in_message(self) -> None:
        """Error message names both original and redirect hosts."""
        handler = _SameHostRedirectHandler("nvd.nist.gov")
        original_req = urllib.request.Request("https://nvd.nist.gov/start")
        new_url = "https://attacker.io/steal"

        with pytest.raises(FeedsNetworkError) as exc_info:
            handler.redirect_request(original_req, None, 302, "Found", {}, new_url)
        assert "nvd.nist.gov" in exc_info.value.message
        assert "attacker.io" in exc_info.value.message

    def test_subdomain_considered_different_host(self) -> None:
        """sub.nvd.nist.gov != nvd.nist.gov — rejected."""
        handler = _SameHostRedirectHandler("nvd.nist.gov")
        original_req = urllib.request.Request("https://nvd.nist.gov/data")
        new_url = "https://sub.nvd.nist.gov/data"

        with pytest.raises(FeedsNetworkError, match="Cross-origin redirect"):
            handler.redirect_request(original_req, None, 301, "Moved", {}, new_url)
