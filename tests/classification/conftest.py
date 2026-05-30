"""Pytest fixtures for the classification subsystem tests.

Wires the deterministic builders from
``tests.classification.fixtures`` into pytest fixtures used
across the suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loki.classification.rules.schema import RuleSet
from loki.models import ExtractedComponent
from tests.classification.fixtures import build_components, build_rule_files


@pytest.fixture
def synthetic_components() -> list[ExtractedComponent]:
    """Default-shape synthetic component sequence (4 outer components)."""
    return build_components()


@pytest.fixture
def synthetic_components_with_inner() -> list[ExtractedComponent]:
    """Synthetic component sequence with alternating inner / outer components.

    Useful for tests that need to verify the pipeline doesn't
    branch on ``source_image_id`` (R7.1).
    """
    return build_components(count=4, include_inner=True)


@pytest.fixture
def synthetic_rules_dir(tmp_path: Path) -> Path:
    """A ``tmp_path`` containing the default synthetic rule files.

    Returns the rules directory; the expected ``RuleSet`` is
    available via the ``synthetic_rule_set`` fixture (which uses
    the same builder).
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir)
    return rules_dir


@pytest.fixture
def synthetic_rule_set(tmp_path: Path) -> RuleSet:
    """The expected ``RuleSet`` produced by the synthetic rule files.

    Useful for tests that want to assert the loader produces the
    expected in-memory shape. Uses its own ``tmp_path`` subdir so
    the ``synthetic_rules_dir`` and ``synthetic_rule_set`` fixtures
    don't share state.
    """
    rules_dir = tmp_path / "expected-rules"
    rules_dir.mkdir()
    return build_rule_files(rules_dir)


__all__ = [
    "synthetic_components",
    "synthetic_components_with_inner",
    "synthetic_rule_set",
    "synthetic_rules_dir",
]
