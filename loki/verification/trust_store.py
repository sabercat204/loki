"""Trust store for signature chain verification."""

from __future__ import annotations

import logging
from pathlib import Path

from cryptography import x509
from cryptography.x509 import Certificate

__all__: list[str] = ["TrustStore"]

_logger = logging.getLogger(__name__)


class TrustStore:
    """Collection of trusted root CA certificates for chain verification.

    Supports loading from:
    - A directory of PEM-encoded certificate files
    - Individual PEM file paths
    - Direct Certificate objects
    """

    def __init__(self) -> None:
        self._roots: list[Certificate] = []

    @classmethod
    def from_directory(cls, path: Path) -> TrustStore:
        """Load all .pem and .crt files from a directory."""
        store = cls()
        if not path.is_dir():
            _logger.warning("Trust store directory not found: %s", path)
            return store

        for cert_file in sorted(path.glob("*.pem")):
            store._load_pem_file(cert_file)
        for cert_file in sorted(path.glob("*.crt")):
            store._load_pem_file(cert_file)
        return store

    @classmethod
    def from_pem_file(cls, path: Path) -> TrustStore:
        """Load certificates from a single PEM file (may contain multiple)."""
        store = cls()
        store._load_pem_file(path)
        return store

    @classmethod
    def system_store(cls) -> TrustStore:
        """Load the system's default CA bundle.

        Falls back to an empty store if the system bundle can't be located.
        """
        import ssl

        store = cls()
        context = ssl.create_default_context()
        der_certs = context.get_ca_certs(binary_form=True)
        for der_data in der_certs:
            try:
                cert = x509.load_der_x509_certificate(der_data)
                store._roots.append(cert)
            except Exception:
                continue
        _logger.info("Loaded %d system root certificates", len(store._roots))
        return store

    def add_certificate(self, cert: Certificate) -> None:
        """Add a trusted root certificate directly."""
        self._roots.append(cert)

    @property
    def roots(self) -> list[Certificate]:
        """Return the list of trusted root certificates."""
        return list(self._roots)

    def __len__(self) -> int:
        return len(self._roots)

    def _load_pem_file(self, path: Path) -> None:
        """Load one or more PEM-encoded certs from a file."""
        try:
            pem_data = path.read_bytes()
            certs = x509.load_pem_x509_certificates(pem_data)
            self._roots.extend(certs)
        except Exception as exc:
            _logger.warning("Failed to load certificate from %s: %s", path, exc)
