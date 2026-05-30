"""Static AST audit of logger calls in ``loki.classification`` (task 19).

Walks every ``.py`` under :mod:`loki.classification`, finds every
``logger.{info, warning, error, debug, critical, exception}`` call,
and asserts that no format string or argument expression
references the Forbidden_Leakage_Field_Set by attribute path:

- ``component.component_id`` / ``record.component_id``
- ``signature_info.signer`` (or ``record.signature_info.signer``)
- ``record.source_image_id`` / ``component.source_image_id``
- Any ``AxisClassification.evidence`` access (matched as
  ``*.evidence`` where the parent attribute name suggests an
  axis: ``type_axis``, ``vendor_axis``, ``security_axis``,
  ``mutability_axis``).

Implements Property 40 (R13.5 + R13.6). The dynamic complement
lives in :mod:`tests.classification.test_log_no_leakage`.

The Forbidden_Leakage_Field_Set is design-locked. Adding a new
forbidden field requires updating both this audit and the
design's "Logging strategy" section.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.classification

#: Logger method names that emit user-visible records.
_LOGGER_METHODS: frozenset[str] = frozenset(
    {"info", "warning", "error", "debug", "critical", "exception", "log"}
)

#: Attribute names that, when accessed in a logger call's arguments,
#: indicate forbidden leakage. Pairs are
#: (parent-name-substring, attribute-name); when the parent name
#: substring is empty, the attribute alone triggers the check.
_FORBIDDEN_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    ("", "component_id"),
    ("", "source_image_id"),
    ("signature_info", "signer"),
    ("type_axis", "evidence"),
    ("vendor_axis", "evidence"),
    ("security_axis", "evidence"),
    ("mutability_axis", "evidence"),
)


def _iter_source_files() -> Iterator[Path]:
    package_root = Path(loki.classification.__path__[0])
    yield from package_root.rglob("*.py")


def _module_name_for(path: Path) -> str:
    package_root = Path(loki.classification.__path__[0]).parent.parent
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
    """Walk a logger-call's args / keywords for forbidden attributes.

    Returns a list of ``(attribute_chain_str, reason)`` violations.
    """
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
                    # Bare attribute match: e.g. ``component.component_id``.
                    violations.append(
                        (chain_str, f"references forbidden attribute {forbidden_attr!r}")
                    )
                    break
                # Match when the parent_substring appears anywhere
                # in the chain before the tail.
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
    assert len(source_files) > 8


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

    If the audit finds zero logger calls, it would trivially pass
    even when leakage exists. Pin the lower bound: the pipeline
    construction summary, run-start, run-end, and per-component
    failure WARNING all log; that's at least 4 logger calls.
    """
    found_calls = 0
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_logger_call(node):
                found_calls += 1
    assert found_calls >= 4, (
        f"expected at least 4 logger calls in loki.classification, found {found_calls}"
    )
