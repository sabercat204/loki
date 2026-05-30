"""Trust-anchor resolution for external feed content verification."""

from __future__ import annotations

import hashlib
from importlib.resources import files
from pathlib import Path

from loki.feeds.errors import FeedsConfigError, FeedsSignatureError

__all__: list[str] = [
    "TrustAnchor",
    "resolve_trust_anchor",
]


class TrustAnchor:
    """Resolved trust-anchor material."""

    def __init__(self, material: bytes, identity: str, source: str) -> None:
        self.material = material  # The hash-pin content
        self.identity = identity  # SHA-256 fingerprint of the material itself
        self.source = source  # "package-embedded" or "operator-override"

    def verify_bundle(self, bundle_bytes: bytes, verification_artifact: bytes) -> None:
        """Verify the bundle against this trust anchor.

        For hash-pin scheme (D1): computes SHA-256 of bundle_bytes and compares
        against the expected hash stored in verification_artifact.

        Raises FeedsSignatureError on mismatch.
        """
        expected_hash = verification_artifact.decode("utf-8").strip().lower()
        actual_hash = hashlib.sha256(bundle_bytes).hexdigest().lower()

        if actual_hash != expected_hash:
            raise FeedsSignatureError(
                f"Bundle hash mismatch: expected {expected_hash}, got {actual_hash}"
            )


def resolve_trust_anchor(trust_anchor_path: str | None) -> TrustAnchor:
    """Resolve the trust anchor per D4-D hybrid logic.

    - None or "" -> load package-embedded default at loki/feeds/_trust_anchor.pem
    - non-empty string -> load file at that path

    Raises FeedsConfigError on missing/unreadable/unparseable file.
    """
    if not trust_anchor_path:
        # Load package-embedded default.
        try:
            anchor_resource = files("loki.feeds").joinpath("_trust_anchor.pem")
            material = anchor_resource.read_bytes()
        except (OSError, TypeError) as exc:
            raise FeedsConfigError(f"Failed to load package-embedded trust anchor: {exc}") from exc
        source = "package-embedded"
    else:
        # Load from operator-specified path.
        path = Path(trust_anchor_path)
        if not path.exists():
            raise FeedsConfigError(f"Trust anchor file does not exist: {trust_anchor_path}")
        try:
            material = path.read_bytes()
        except OSError as exc:
            raise FeedsConfigError(
                f"Failed to read trust anchor file {trust_anchor_path}: {exc}"
            ) from exc
        source = "operator-override"

    identity = hashlib.sha256(material).hexdigest()

    return TrustAnchor(material=material, identity=identity, source=source)
