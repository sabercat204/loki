"""Tests for loki.feeds.trust — trust-anchor resolution and verification."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from loki.feeds.errors import FeedsConfigError, FeedsSignatureError
from loki.feeds.trust import TrustAnchor, resolve_trust_anchor


class TestResolveDefault:
    """Default resolution (None or empty string) loads package-embedded."""

    def test_none_loads_embedded(self) -> None:
        anchor = resolve_trust_anchor(None)
        assert anchor.source == "package-embedded"
        assert len(anchor.material) > 0

    def test_empty_string_loads_embedded(self) -> None:
        anchor = resolve_trust_anchor("")
        assert anchor.source == "package-embedded"
        assert len(anchor.material) > 0

    def test_none_and_empty_produce_same_result(self) -> None:
        a1 = resolve_trust_anchor(None)
        a2 = resolve_trust_anchor("")
        assert a1.identity == a2.identity
        assert a1.material == a2.material


class TestResolveOperatorOverride:
    """Operator override from a file path."""

    def test_operator_override_from_file(self, tmp_path: Path) -> None:
        anchor_file = tmp_path / "custom_anchor.pem"
        anchor_file.write_text(
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc123\n"
        )
        anchor = resolve_trust_anchor(str(anchor_file))
        assert anchor.source == "operator-override"
        assert b"abc123" in anchor.material

    def test_operator_override_identity(self, tmp_path: Path) -> None:
        content = b"test-anchor-material\n"
        anchor_file = tmp_path / "anchor.pem"
        anchor_file.write_bytes(content)
        anchor = resolve_trust_anchor(str(anchor_file))
        expected_identity = hashlib.sha256(content).hexdigest()
        assert anchor.identity == expected_identity


class TestResolveErrors:
    """Error conditions for resolve_trust_anchor."""

    def test_missing_file_raises_config_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.pem"
        with pytest.raises(FeedsConfigError, match="does not exist"):
            resolve_trust_anchor(str(missing))

    @pytest.mark.skipif(
        os.name == "nt", reason="chmod-based permission tests unreliable on Windows"
    )
    def test_unreadable_file_raises_config_error(self, tmp_path: Path) -> None:
        unreadable = tmp_path / "noperm.pem"
        unreadable.write_text("content")
        unreadable.chmod(0o000)
        try:
            with pytest.raises(FeedsConfigError, match="Failed to read"):
                resolve_trust_anchor(str(unreadable))
        finally:
            unreadable.chmod(stat.S_IRUSR | stat.S_IWUSR)


class TestVerifyBundle:
    """Test TrustAnchor.verify_bundle()."""

    def test_verify_success(self) -> None:
        bundle = b"hello world"
        expected_hash = hashlib.sha256(bundle).hexdigest()
        verification_artifact = expected_hash.encode("utf-8")

        anchor = TrustAnchor(
            material=b"some-material",
            identity="abcd1234" * 8,
            source="package-embedded",
        )
        # Should not raise.
        anchor.verify_bundle(bundle, verification_artifact)

    def test_verify_success_with_whitespace(self) -> None:
        bundle = b"test data"
        expected_hash = hashlib.sha256(bundle).hexdigest()
        # Add trailing newline/whitespace.
        verification_artifact = f"  {expected_hash}  \n".encode()

        anchor = TrustAnchor(
            material=b"material",
            identity="x" * 64,
            source="operator-override",
        )
        anchor.verify_bundle(bundle, verification_artifact)

    def test_verify_mismatch_raises_signature_error(self) -> None:
        bundle = b"legitimate bundle"
        wrong_hash = "0" * 64
        verification_artifact = wrong_hash.encode("utf-8")

        anchor = TrustAnchor(
            material=b"material",
            identity="y" * 64,
            source="package-embedded",
        )
        with pytest.raises(FeedsSignatureError, match="mismatch"):
            anchor.verify_bundle(bundle, verification_artifact)

    def test_verify_case_insensitive(self) -> None:
        bundle = b"case test"
        expected_hash = hashlib.sha256(bundle).hexdigest().upper()
        verification_artifact = expected_hash.encode("utf-8")

        anchor = TrustAnchor(
            material=b"m",
            identity="z" * 64,
            source="package-embedded",
        )
        # Should not raise (case insensitive comparison).
        anchor.verify_bundle(bundle, verification_artifact)


class TestIdentityAttribute:
    """Identity should be a 64-char hex string."""

    def test_identity_is_64_hex(self) -> None:
        anchor = resolve_trust_anchor(None)
        assert len(anchor.identity) == 64
        # Should be valid hex.
        int(anchor.identity, 16)

    def test_identity_matches_material_sha256(self, tmp_path: Path) -> None:
        content = b"identity-test-content"
        f = tmp_path / "id_test.pem"
        f.write_bytes(content)
        anchor = resolve_trust_anchor(str(f))
        assert anchor.identity == hashlib.sha256(content).hexdigest()


class TestSourceAttribute:
    """Source attribute correctness."""

    def test_embedded_source(self) -> None:
        anchor = resolve_trust_anchor(None)
        assert anchor.source == "package-embedded"

    def test_override_source(self, tmp_path: Path) -> None:
        f = tmp_path / "src.pem"
        f.write_text("data")
        anchor = resolve_trust_anchor(str(f))
        assert anchor.source == "operator-override"
