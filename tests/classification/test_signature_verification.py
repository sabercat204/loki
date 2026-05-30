"""Tests for signature verification integration in the classification pipeline."""

from __future__ import annotations

import struct
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from loki.classification import classify_components
from loki.models import ClassificationConfig, ExtractedComponent
from loki.verification import TrustStore


def _generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_signer(
    ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Firmware Signer")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _make_signed_pe32(
    signer_key: rsa.RSAPrivateKey,
    signer_cert: x509.Certificate,
    ca_cert: x509.Certificate,
) -> bytes:
    from cryptography.hazmat.primitives.serialization import pkcs7

    pkcs7_blob = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"firmware content")
        .add_signer(signer_cert, signer_key, hashes.SHA256())
        .add_certificate(ca_cert)
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_header = bytearray(20)
    optional_magic = struct.pack("<H", 0x10B)
    optional_rest = bytearray(94)
    data_dirs = bytearray(128)
    cert_table_offset = (
        len(dos_header) + len(pe_sig) + len(coff_header) + 2 + len(optional_rest) + len(data_dirs)
    )
    win_cert = struct.pack("<IHH", len(pkcs7_blob) + 8, 0x0200, 0x0002) + pkcs7_blob
    struct.pack_into("<II", data_dirs, 4 * 8, cert_table_offset, len(win_cert))
    return bytes(
        dos_header + pe_sig + coff_header + optional_magic + optional_rest + data_dirs + win_cert
    )


def _make_rules_dir(tmp_path: Path) -> Path:
    import yaml

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "default.yaml").write_text(
        yaml.dump(
            {
                "taxonomy_version": "1.0.0",
                "rules": [
                    {
                        "rule_id": "type.unknown.catch",
                        "axis": "type",
                        "matcher": {"size": {"min": 0}},
                        "effect": {
                            "label": "UNKNOWN",
                            "confidence": 0.1,
                            "method": "HEURISTIC",
                            "evidence": "fallback",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return rules_dir


class TestSignatureVerificationIntegration:
    def test_verified_when_trust_store_provided(self, tmp_path: Path) -> None:
        ca_key, ca_cert = _generate_ca()
        signer_key, signer_cert = _generate_signer(ca_key, ca_cert)
        pe_data = _make_signed_pe32(signer_key, signer_cert, ca_cert)

        comp_path = tmp_path / "signed.efi"
        comp_path.write_bytes(pe_data)

        component = ExtractedComponent(
            component_id=uuid.uuid4(),
            source_image_id=uuid.uuid4(),
            offset="0x0",
            size=len(pe_data),
            raw_hash="c" * 64,
            raw_path=str(comp_path),
        )

        rules_dir = _make_rules_dir(tmp_path)
        config = ClassificationConfig(
            taxonomy_version="1.0.0",
            confidence_threshold=0.6,
            rules_path=str(rules_dir),
        )

        store = TrustStore()
        store.add_certificate(ca_cert)

        result = classify_components([component], config, trust_store=store)
        assert len(result.records) == 1
        sig = result.records[0].signature_info
        assert sig is not None
        assert sig.present is True
        assert sig.verified is True
        assert sig.signer == "Firmware Signer"
        assert sig.cert_expiry is not None

    def test_not_verified_without_trust_store(self, tmp_path: Path) -> None:
        ca_key, ca_cert = _generate_ca()
        signer_key, signer_cert = _generate_signer(ca_key, ca_cert)
        pe_data = _make_signed_pe32(signer_key, signer_cert, ca_cert)

        comp_path = tmp_path / "signed.efi"
        comp_path.write_bytes(pe_data)

        component = ExtractedComponent(
            component_id=uuid.uuid4(),
            source_image_id=uuid.uuid4(),
            offset="0x0",
            size=len(pe_data),
            raw_hash="c" * 64,
            raw_path=str(comp_path),
        )

        rules_dir = _make_rules_dir(tmp_path)
        config = ClassificationConfig(
            taxonomy_version="1.0.0",
            confidence_threshold=0.6,
            rules_path=str(rules_dir),
        )

        result = classify_components([component], config)
        assert len(result.records) == 1
        sig = result.records[0].signature_info
        assert sig is not None
        assert sig.present is True
        assert sig.verified is False
        assert sig.signer is None

    def test_untrusted_signer_not_verified(self, tmp_path: Path) -> None:
        ca_key, ca_cert = _generate_ca()
        signer_key, signer_cert = _generate_signer(ca_key, ca_cert)
        pe_data = _make_signed_pe32(signer_key, signer_cert, ca_cert)

        comp_path = tmp_path / "signed.efi"
        comp_path.write_bytes(pe_data)

        component = ExtractedComponent(
            component_id=uuid.uuid4(),
            source_image_id=uuid.uuid4(),
            offset="0x0",
            size=len(pe_data),
            raw_hash="c" * 64,
            raw_path=str(comp_path),
        )

        rules_dir = _make_rules_dir(tmp_path)
        config = ClassificationConfig(
            taxonomy_version="1.0.0",
            confidence_threshold=0.6,
            rules_path=str(rules_dir),
        )

        empty_store = TrustStore()
        result = classify_components([component], config, trust_store=empty_store)
        assert len(result.records) == 1
        sig = result.records[0].signature_info
        assert sig is not None
        assert sig.present is True
        assert sig.verified is False
        assert sig.signer == "Firmware Signer"
