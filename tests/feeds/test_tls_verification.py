"""TLS verification audit for ``loki.feeds`` (task 22).

Constructs the Feeds subsystem's SSL context and asserts:
- ``verify_mode == ssl.CERT_REQUIRED``
- ``check_hostname == True``

Implements R8.7, R13.6(e).
"""

from __future__ import annotations

import ssl

from loki.feeds.refresh import _build_ssl_context


class TestTLSVerification:
    """The SSL context enforces certificate verification."""

    def test_verify_mode_is_cert_required(self) -> None:
        ctx = _build_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_check_hostname_is_true(self) -> None:
        ctx = _build_ssl_context()
        assert ctx.check_hostname is True

    def test_protocol_is_modern(self) -> None:
        """Context uses TLS 1.2+ (no SSLv2/SSLv3)."""
        ctx = _build_ssl_context()
        assert (
            ctx.protocol == ssl.PROTOCOL_TLS_CLIENT or ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
        )
