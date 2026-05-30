"""Signature verification subsystem — certificate parsing and chain verification."""

from __future__ import annotations

from loki.verification.errors import (
    VerificationError,
    VerificationParseError,
    VerificationTrustError,
)
from loki.verification.trust_store import TrustStore
from loki.verification.verifier import SignatureVerificationResult, verify_signature
from loki.verification.version import VERIFICATION_VERSION

__all__: list[str] = [
    "VERIFICATION_VERSION",
    "SignatureVerificationResult",
    "TrustStore",
    "VerificationError",
    "VerificationParseError",
    "VerificationTrustError",
    "verify_signature",
]
