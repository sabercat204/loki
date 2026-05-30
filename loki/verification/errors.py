"""Typed exception hierarchy for the verification subsystem."""

from __future__ import annotations

__all__: list[str] = [
    "VerificationError",
    "VerificationParseError",
    "VerificationTrustError",
]


class VerificationError(Exception):
    """Root exception for the verification subsystem."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class VerificationParseError(VerificationError):
    """Failed to parse signature structure from component bytes."""


class VerificationTrustError(VerificationError):
    """Certificate chain verification failed against the trust store."""
