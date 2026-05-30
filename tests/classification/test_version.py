"""Tests for ``CLASSIFICATION_VERSION``.

Covers Requirement 1.5: the constant is a string in
``^\\d+\\.\\d+\\.\\d+$`` semver form.
"""

from __future__ import annotations

import re

from loki.classification import CLASSIFICATION_VERSION
from loki.classification.version import CLASSIFICATION_VERSION as DIRECT_IMPORT

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def test_classification_version_is_a_string() -> None:
    assert isinstance(CLASSIFICATION_VERSION, str)


def test_classification_version_matches_semver() -> None:
    assert _SEMVER_RE.match(CLASSIFICATION_VERSION) is not None


def test_classification_version_reexport_matches_direct_import() -> None:
    """The package re-export and the direct import return the same value."""
    assert CLASSIFICATION_VERSION == DIRECT_IMPORT
