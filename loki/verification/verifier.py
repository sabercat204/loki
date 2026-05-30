"""Core signature verification logic.

Extracts PKCS#7 blobs from PE32 Authenticode and UEFI auth wrappers,
parses the embedded X.509 certificate chain, verifies against a trust
store, and returns signer + expiry information.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from loki.verification.errors import VerificationParseError, VerificationTrustError
from loki.verification.trust_store import TrustStore

__all__: list[str] = ["SignatureVerificationResult", "verify_signature"]

_MAX_READ_BYTES: int = 10 << 20  # 10 MiB for verification (larger than detection)


@dataclass(frozen=True)
class SignatureVerificationResult:
    """Result of verifying a component's code signature."""

    verified: bool
    signer: str | None
    cert_expiry: datetime | None
    chain_length: int
    error: str | None = None


def verify_signature(
    raw_path: Path,
    trust_store: TrustStore,
) -> SignatureVerificationResult:
    """Verify the code signature of a component at raw_path.

    Attempts PE32 Authenticode extraction first, then UEFI auth wrapper.
    Returns a result with verified=True only if the signer certificate
    chains back to a root in the trust store.
    """
    try:
        data = raw_path.read_bytes()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return SignatureVerificationResult(
            verified=False,
            signer=None,
            cert_expiry=None,
            chain_length=0,
            error=f"Cannot read file: {exc}",
        )

    if len(data) < 64:
        return SignatureVerificationResult(
            verified=False,
            signer=None,
            cert_expiry=None,
            chain_length=0,
            error="File too small for signature detection",
        )

    pkcs7_blob = _extract_pe32_pkcs7(data)
    if pkcs7_blob is None:
        pkcs7_blob = _extract_uefi_pkcs7(data)

    if pkcs7_blob is None:
        return SignatureVerificationResult(
            verified=False,
            signer=None,
            cert_expiry=None,
            chain_length=0,
            error="No recognizable signature structure found",
        )

    try:
        certs = _parse_pkcs7_certs(pkcs7_blob)
    except VerificationParseError as exc:
        return SignatureVerificationResult(
            verified=False,
            signer=None,
            cert_expiry=None,
            chain_length=0,
            error=exc.message,
        )

    if not certs:
        return SignatureVerificationResult(
            verified=False,
            signer=None,
            cert_expiry=None,
            chain_length=0,
            error="No certificates found in signature",
        )

    signer_cert = certs[0]
    signer_cn = _extract_cn(signer_cert)
    cert_expiry = signer_cert.not_valid_after_utc

    try:
        chain = _build_chain(signer_cert, certs, trust_store)
        verified = True
        error = None
    except VerificationTrustError as exc:
        verified = False
        chain = [signer_cert]
        error = exc.message

    return SignatureVerificationResult(
        verified=verified,
        signer=signer_cn,
        cert_expiry=cert_expiry,
        chain_length=len(chain),
        error=error,
    )


def _extract_pe32_pkcs7(data: bytes) -> bytes | None:
    """Extract the Authenticode PKCS#7 blob from PE32/PE32+ data."""
    if data[:2] != b"MZ":
        return None
    if len(data) < 0x40:
        return None

    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if e_lfanew + 4 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None

    optional_header_start = e_lfanew + 4 + 20
    if optional_header_start + 2 > len(data):
        return None
    magic = struct.unpack("<H", data[optional_header_start : optional_header_start + 2])[0]

    if magic == 0x10B:
        data_dirs_start = optional_header_start + 96
    elif magic == 0x20B:
        data_dirs_start = optional_header_start + 112
    else:
        return None

    security_offset = data_dirs_start + (4 * 8)
    if security_offset + 8 > len(data):
        return None
    virtual_address, size = struct.unpack("<II", data[security_offset : security_offset + 8])
    if virtual_address == 0 or size == 0:
        return None

    if virtual_address + size > len(data):
        return None

    # WIN_CERTIFICATE structure: dwLength (4) + wRevision (2) + wCertificateType (2) + bCertificate
    cert_table = data[virtual_address : virtual_address + size]
    if len(cert_table) < 8:
        return None
    _dw_length, _w_revision, w_cert_type = struct.unpack("<IHH", cert_table[:8])
    # Type 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    if w_cert_type != 0x0002:
        return None
    return cert_table[8:]


def _extract_uefi_pkcs7(data: bytes) -> bytes | None:
    """Extract PKCS#7 from a UEFI EFI_FIRMWARE_IMAGE_AUTHENTICATION wrapper."""
    import uuid as _uuid

    guid_bytes = _uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le
    # Search for the GUID in the first 80 bytes
    idx = data[:96].find(guid_bytes)
    if idx < 0:
        return None

    # The PKCS#7 data follows the GUID (16 bytes)
    pkcs7_start = idx + 16
    if pkcs7_start >= len(data):
        return None
    return data[pkcs7_start:]


def _parse_pkcs7_certs(blob: bytes) -> list[Certificate]:
    """Parse X.509 certificates from a DER-encoded PKCS#7 blob."""
    from cryptography.hazmat.primitives.serialization import pkcs7

    try:
        certs = pkcs7.load_der_pkcs7_certificates(blob)
        return list(certs)
    except Exception as exc:
        raise VerificationParseError(f"Failed to parse PKCS#7 certificates: {exc}") from exc


def _extract_cn(cert: Certificate) -> str | None:
    """Extract the Common Name from a certificate's subject."""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            value = cn_attrs[0].value
            return str(value) if value else None
    except Exception:
        pass
    return None


def _build_chain(
    signer: Certificate,
    intermediates: list[Certificate],
    trust_store: TrustStore,
) -> list[Certificate]:
    """Build and verify a certificate chain from signer to a trusted root.

    Returns the full chain (signer -> intermediates -> root) on success.
    Raises VerificationTrustError if no chain can be built.
    """
    chain: list[Certificate] = [signer]
    current = signer
    seen_subjects: set[bytes] = {current.subject.public_bytes(serialization.Encoding.DER)}
    max_depth = 10

    for _ in range(max_depth):
        if _is_trusted_root(current, trust_store):
            return chain

        issuer = _find_issuer(current, intermediates, trust_store)
        if issuer is None:
            break

        issuer_subject_der = issuer.subject.public_bytes(serialization.Encoding.DER)
        if issuer_subject_der in seen_subjects:
            break
        seen_subjects.add(issuer_subject_der)

        if not _verify_signature_on_cert(current, issuer):
            raise VerificationTrustError(
                f"Signature verification failed: "
                f"{_extract_cn(current)} not signed by {_extract_cn(issuer)}"
            )

        chain.append(issuer)
        current = issuer

    if _is_trusted_root(current, trust_store):
        return chain

    raise VerificationTrustError(
        f"Certificate chain does not terminate at a trusted root. Last cert: {_extract_cn(current)}"
    )


def _is_trusted_root(cert: Certificate, trust_store: TrustStore) -> bool:
    """Check if cert is in the trust store (by subject + public key match)."""
    cert_subject_der = cert.subject.public_bytes(serialization.Encoding.DER)
    cert_pubkey_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    for root in trust_store.roots:
        root_subject_der = root.subject.public_bytes(serialization.Encoding.DER)
        if root_subject_der != cert_subject_der:
            continue
        root_pubkey_der = root.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if root_pubkey_der == cert_pubkey_der:
            return True
    return False


def _find_issuer(
    cert: Certificate,
    candidates: list[Certificate],
    trust_store: TrustStore,
) -> Certificate | None:
    """Find the issuer of cert among candidates and trust store roots."""
    issuer_der = cert.issuer.public_bytes(serialization.Encoding.DER)
    all_certs = [*candidates, *trust_store.roots]
    for candidate in all_certs:
        subject_der = candidate.subject.public_bytes(serialization.Encoding.DER)
        if subject_der == issuer_der:
            return candidate
    return None


def _verify_signature_on_cert(child: Certificate, issuer: Certificate) -> bool:
    """Verify that issuer's key signed child's certificate."""
    pub_key = issuer.public_key()
    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm or hashes.SHA256(),
            )
            return True
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm or hashes.SHA256()),
            )
            return True
    except (InvalidSignature, Exception):
        return False
    return False
