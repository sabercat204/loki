"""Tests for ``loki.analysis.version``.

Covers task 2 acceptance: the constant exists, is a string, and matches
the semver pattern contracted by R1.5.
"""

from __future__ import annotations

import re

from loki.analysis import ANALYSIS_VERSION
from loki.analysis import version as version_module

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def test_analysis_version_exists() -> None:
    assert ANALYSIS_VERSION is not None


def test_analysis_version_is_string() -> None:
    assert isinstance(ANALYSIS_VERSION, str)


def test_analysis_version_matches_semver() -> None:
    assert _SEMVER_RE.match(ANALYSIS_VERSION) is not None


def test_analysis_version_re_exported() -> None:
    assert ANALYSIS_VERSION is version_module.ANALYSIS_VERSION
