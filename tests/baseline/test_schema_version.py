"""Tests for the Schema_Version constants (task 3)."""

from __future__ import annotations

import re

from loki.baseline.schema import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    is_supported_schema_version,
)


def test_schema_version_matches_semver() -> None:
    assert re.match(r"^\d+\.\d+\.\d+$", SCHEMA_VERSION)


def test_schema_version_is_in_supported_set() -> None:
    """v1 supports exactly one Schema_Version (R4.2)."""
    assert SCHEMA_VERSION in SUPPORTED_SCHEMA_VERSIONS
    assert len(SUPPORTED_SCHEMA_VERSIONS) == 1


def test_supported_set_is_frozen() -> None:
    """The constant is immutable so callers can't sneak entries in at runtime."""
    assert isinstance(SUPPORTED_SCHEMA_VERSIONS, frozenset)


def test_is_supported_accepts_current_version() -> None:
    assert is_supported_schema_version(SCHEMA_VERSION) is True


def test_is_supported_rejects_unknown_version() -> None:
    assert is_supported_schema_version("0.0.0") is False
    assert is_supported_schema_version("999.0.0") is False


def test_is_supported_rejects_non_string() -> None:
    """Defensive: a corrupted envelope might surface a non-string here."""
    assert is_supported_schema_version(None) is False
    assert is_supported_schema_version(42) is False
    assert is_supported_schema_version(["1.0.0"]) is False
