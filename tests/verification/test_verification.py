"""Tests for the signature verification subsystem."""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from loki.verification import (
    VERIFICATION_VERSION,
    SignatureVerificationResult,
    TrustStore,
    VerificationError,
    VerificationParseError,
    VerificationTrustError,
    verify_signature,
)


def _generate_self_signed_cert(
    cn: str = "Test Root CA",
    days_valid: int = 365,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed CA cert for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_signed_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    cn: str = "Test Signer",
    days_valid: int = 365,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a cert signed by a CA for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _build_fake_pe32_with_authenticode(pkcs7_blob: bytes) -> bytes:
    """Build a minimal PE32 binary with an Authenticode signature table."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    pe_offset = 64
    struct.pack_into("<I", dos_header, 0x3C, pe_offset)

    pe_sig = b"PE\x00\x00"
    coff_header = bytearray(20)
    optional_magic = struct.pack("<H", 0x10B)  # PE32
    optional_rest = bytearray(94)  # pad to reach data dirs at offset 96
    # 16 data directory entries (128 bytes), security is index 4
    data_dirs = bytearray(128)
    # Security entry at index 4: VA and Size
    cert_table_offset = (
        len(dos_header) + len(pe_sig) + len(coff_header) + 2 + len(optional_rest) + len(data_dirs)
    )
    win_cert = struct.pack("<IHH", len(pkcs7_blob) + 8, 0x0200, 0x0002) + pkcs7_blob
    struct.pack_into("<II", data_dirs, 4 * 8, cert_table_offset, len(win_cert))

    pe_data = (
        dos_header + pe_sig + coff_header + optional_magic + optional_rest + data_dirs + win_cert
    )
    return bytes(pe_data)


def _make_pkcs7_from_certs(
    signer_key: rsa.RSAPrivateKey,
    signer_cert: x509.Certificate,
    additional_certs: list[x509.Certificate] | None = None,
) -> bytes:
    """Create a minimal PKCS#7 SignedData blob containing certificates."""
    from cryptography.hazmat.primitives.serialization import pkcs7

    builder = pkcs7.PKCS7SignatureBuilder().set_data(b"test content")
    builder = builder.add_signer(signer_cert, signer_key, hashes.SHA256())
    if additional_certs:
        for cert in additional_certs:
            builder = builder.add_certificate(cert)
    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


class TestVersion:
    def test_version_format(self) -> None:
        parts = VERIFICATION_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


class TestErrors:
    def test_hierarchy(self) -> None:
        assert issubclass(VerificationParseError, VerificationError)
        assert issubclass(VerificationTrustError, VerificationError)

    def test_message_attribute(self) -> None:
        exc = VerificationError("test")
        assert exc.message == "test"


class TestTrustStore:
    def test_empty_store(self) -> None:
        store = TrustStore()
        assert len(store) == 0

    def test_add_certificate(self) -> None:
        _key, cert = _generate_self_signed_cert()
        store = TrustStore()
        store.add_certificate(cert)
        assert len(store) == 1
        assert store.roots[0] == cert

    def test_from_pem_file(self, tmp_path: Path) -> None:
        _key, cert = _generate_self_signed_cert()
        pem_path = tmp_path / "root.pem"
        pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        store = TrustStore.from_pem_file(pem_path)
        assert len(store) == 1

    def test_from_directory(self, tmp_path: Path) -> None:
        _key1, cert1 = _generate_self_signed_cert(cn="CA 1")
        _key2, cert2 = _generate_self_signed_cert(cn="CA 2")
        (tmp_path / "ca1.pem").write_bytes(cert1.public_bytes(serialization.Encoding.PEM))
        (tmp_path / "ca2.crt").write_bytes(cert2.public_bytes(serialization.Encoding.PEM))
        store = TrustStore.from_directory(tmp_path)
        assert len(store) == 2

    def test_from_nonexistent_directory(self, tmp_path: Path) -> None:
        store = TrustStore.from_directory(tmp_path / "nope")
        assert len(store) == 0

    def test_system_store_loads(self) -> None:
        store = TrustStore.system_store()
        assert len(store) > 0


class TestVerifySignature:
    def test_file_not_found(self, tmp_path: Path) -> None:
        store = TrustStore()
        result = verify_signature(tmp_path / "nonexistent.bin", store)
        assert not result.verified
        assert result.error is not None
        assert "Cannot read" in result.error

    def test_file_too_small(self, tmp_path: Path) -> None:
        small = tmp_path / "tiny.bin"
        small.write_bytes(b"\x00" * 10)
        store = TrustStore()
        result = verify_signature(small, store)
        assert not result.verified
        assert "too small" in (result.error or "")

    def test_no_signature_structure(self, tmp_path: Path) -> None:
        notsigned = tmp_path / "plain.bin"
        notsigned.write_bytes(b"\x00" * 1024)
        store = TrustStore()
        result = verify_signature(notsigned, store)
        assert not result.verified
        assert "No recognizable" in (result.error or "")

    def test_valid_pe32_self_signed(self, tmp_path: Path) -> None:
        ca_key, ca_cert = _generate_self_signed_cert(cn="Test CA")
        signer_key, signer_cert = _generate_signed_cert(ca_key, ca_cert, cn="Firmware Signer")
        pkcs7_blob = _make_pkcs7_from_certs(signer_key, signer_cert, [ca_cert])
        pe_data = _build_fake_pe32_with_authenticode(pkcs7_blob)
        pe_path = tmp_path / "signed.exe"
        pe_path.write_bytes(pe_data)

        store = TrustStore()
        store.add_certificate(ca_cert)
        result = verify_signature(pe_path, store)

        assert result.verified
        assert result.signer == "Firmware Signer"
        assert result.cert_expiry is not None
        assert result.chain_length >= 2

    def test_untrusted_signer(self, tmp_path: Path) -> None:
        ca_key, ca_cert = _generate_self_signed_cert(cn="Untrusted CA")
        signer_key, signer_cert = _generate_signed_cert(ca_key, ca_cert, cn="Bad Signer")
        pkcs7_blob = _make_pkcs7_from_certs(signer_key, signer_cert, [ca_cert])
        pe_data = _build_fake_pe32_with_authenticode(pkcs7_blob)
        pe_path = tmp_path / "untrusted.exe"
        pe_path.write_bytes(pe_data)

        store = TrustStore()  # empty — nothing trusted
        result = verify_signature(pe_path, store)

        assert not result.verified
        assert result.signer == "Bad Signer"
        assert result.error is not None
        assert "trusted root" in result.error

    def test_result_dataclass_fields(self, tmp_path: Path) -> None:
        ca_key, ca_cert = _generate_self_signed_cert(cn="Fields CA")
        signer_key, signer_cert = _generate_signed_cert(ca_key, ca_cert, cn="Fields Signer")
        pkcs7_blob = _make_pkcs7_from_certs(signer_key, signer_cert, [ca_cert])
        pe_data = _build_fake_pe32_with_authenticode(pkcs7_blob)
        pe_path = tmp_path / "fields.exe"
        pe_path.write_bytes(pe_data)

        store = TrustStore()
        store.add_certificate(ca_cert)
        result = verify_signature(pe_path, store)

        assert isinstance(result, SignatureVerificationResult)
        assert isinstance(result.verified, bool)
        assert isinstance(result.signer, str)
        assert isinstance(result.cert_expiry, datetime)
        assert isinstance(result.chain_length, int)
