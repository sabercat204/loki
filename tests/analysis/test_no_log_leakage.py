"""Static AST audit of logger calls in ``loki.analysis`` (task 22).

Walks every ``.py`` under :mod:`loki.analysis`, finds every
``logger.{info, warning, error, debug, critical, exception}`` call,
and asserts that no format string or argument expression
references the Forbidden_Leakage_Field_Set by attribute path.

The Forbidden_Leakage_Field_Set inherits classification's set
(``component_id``, ``signature_info.signer``,
``BaselineRecord.source_image_hash``, axis ``evidence`` strings) and
extends it with analysis-specific entries per requirements.md
Glossary:

- ``FindingEvidence.matched_rule``
- ``FindingEvidence.matched_cve``
- ``FindingEvidence.matched_signature``
- ``FindingEvidence.raw_indicators``
- ``FindingRecord.title``
- ``FindingRecord.description``

Implements Property 50 (R20.3, R20.4, R20.5). The dynamic
complement lives in :mod:`tests.analysis.test_log_no_leakage`.

Mirrors :mod:`tests.classification.test_no_log_leakage`,
:mod:`tests.extraction.test_no_log_leakage`, and
:mod:`tests.baseline.test_no_log_leakage`.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.analysis

#: Logger method names that emit user-visible records.
_LOGGER_METHODS: frozenset[str] = frozenset(
    {"info", "warning", "error", "debug", "critical", "exception", "log"}
)

#: Attribute names that, when accessed in a logger call's arguments,
#: indicate forbidden leakage. Pairs are
#: (parent-name-substring, attribute-name); when the parent name
#: substring is empty, the attribute alone triggers the check.
_FORBIDDEN_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    # Inherited from classification:
    ("", "component_id"),
    ("", "source_image_id"),
    ("", "source_image_hash"),
    ("signature_info", "signer"),
    ("type_axis", "evidence"),
    ("vendor_axis", "evidence"),
    ("security_axis", "evidence"),
    ("mutability_axis", "evidence"),
    # Added by analysis-engine:
    ("evidence", "matched_rule"),
    ("evidence", "matched_cve"),
    ("evidence", "matched_signature"),
    ("evidence", "raw_indicators"),
    # title / description on FindingRecord. Match any chain ending
    # in ``finding.title`` or ``finding.description``; the parent
    # substring "finding" catches the typical access pattern
    # (e.g. ``finding.title`` or ``f.title``).
    ("finding", "title"),
    ("finding", "description"),
)


def _iter_source_files() -> Iterator[Path]:
    package_root = Path(loki.analysis.__path__[0])
    yield from package_root.rglob("*.py")


def _module_name_for(path: Path) -> str:
    package_root = Path(loki.analysis.__path__[0]).parent.parent
    relative = path.relative_to(package_root)
    return ".".join(relative.with_suffix("").parts)


@pytest.fixture(scope="module")
def source_files() -> list[Path]:
    return sorted(_iter_source_files())


def _is_logger_call(node: ast.Call) -> bool:
    """Return True for ``logger.<method>(...)`` calls.

    Matches both ``logger.info(...)`` and ``self._logger.info(...)``
    style call sites by checking only the method name.
    """
    if not isinstance(node.func, ast.Attribute):
        return False
    return node.func.attr in _LOGGER_METHODS


def _attribute_chain(node: ast.AST) -> list[str]:
    """Return the dotted attribute chain for an Attribute node.

    ``record.signature_info.signer`` → ``["record", "signature_info", "signer"]``.
    Non-attribute / non-Name leaves yield an empty list.
    """
    chain: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        chain.append(current.id)
    chain.reverse()
    return chain


def _violations_in_call(call: ast.Call) -> list[tuple[str, str]]:
    """Walk a logger-call's args / keywords for forbidden attributes."""
    violations: list[tuple[str, str]] = []
    nodes_to_inspect: list[ast.AST] = []
    nodes_to_inspect.extend(call.args)
    for kw in call.keywords:
        if kw.value is not None:
            nodes_to_inspect.append(kw.value)

    for arg in nodes_to_inspect:
        for sub in ast.walk(arg):
            if not isinstance(sub, ast.Attribute):
                continue
            chain = _attribute_chain(sub)
            if not chain:
                continue
            chain_str = ".".join(chain)
            tail_attr = chain[-1]
            for parent_substring, forbidden_attr in _FORBIDDEN_ATTRIBUTES:
                if tail_attr != forbidden_attr:
                    continue
                if parent_substring == "":
                    violations.append(
                        (chain_str, f"references forbidden attribute {forbidden_attr!r}")
                    )
                    break
                parent_chain = chain[:-1]
                if any(parent_substring in part for part in parent_chain):
                    violations.append(
                        (
                            chain_str,
                            f"references forbidden attribute {parent_substring}.{forbidden_attr}",
                        )
                    )
                    break
    return violations


def test_source_files_were_found(source_files: list[Path]) -> None:
    assert len(source_files) >= 12


def test_no_logger_call_references_forbidden_attributes(source_files: list[Path]) -> None:
    """No logger.<method>(...) call references a Forbidden_Leakage_Field."""
    violations: list[tuple[str, int, str, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_logger_call(node):
                for chain_str, reason in _violations_in_call(node):
                    violations.append((module_name, node.lineno, chain_str, reason))
    assert violations == [], "logger calls reference forbidden attributes:\n  " + "\n  ".join(
        f"{m}:{ln} '{c}' — {r}" for m, ln, c, r in violations
    )


def test_at_least_one_logger_call_exists(source_files: list[Path]) -> None:
    """Sanity check: the AST walker actually finds logger calls.

    R20.1 (run-start INFO) + R20.2 (run-end INFO) make at least
    two logger calls live in the pipeline. Pin the lower bound.
    """
    found_calls = 0
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_logger_call(node):
                found_calls += 1
    assert found_calls >= 2, (
        f"expected at least 2 logger calls in loki.analysis, found {found_calls}"
    )
