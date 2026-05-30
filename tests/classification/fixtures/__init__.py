"""Deterministic test fixtures for the classification subsystem.

Exports:

- ``build_components`` from
  ``tests.classification.fixtures.synthetic_components``: produces
  a deterministic sequence of ``ExtractedComponent`` instances.
- ``build_rule_files`` from
  ``tests.classification.fixtures.synthetic_rules``: writes a
  deterministic set of YAML rule files into a target directory
  and returns the expected ``RuleSet``.

Mirrors the fixture conventions from
``tests/extraction/fixtures`` and ``tests/baseline/fixtures``:
all UUIDs derived via ``uuid5`` from a small set of seeds, all
hashes deterministic from the index, no clock or network access.
"""

from tests.classification.fixtures.synthetic_components import build_components
from tests.classification.fixtures.synthetic_rules import build_rule_files

__all__ = ["build_components", "build_rule_files"]
