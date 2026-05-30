"""Static AST audit of logger calls in ``loki.feeds`` (task 18).

Walks every ``.py`` under :mod:`loki.feeds`, finds every
``logger.{info, warning, error, debug, critical, exception}`` call,
and asserts no format string or argument expression references the
Forbidden_Leakage_Field_Set.

The Forbidden_Leakage_Field_Set for the feeds subsystem (R13.1):

- ``trust_anchor_path`` and trust-anchor file contents
- ``component_id``, ``source_image_id``, ``source_image_hash``
- ``raw_hash``, ``content_hash``, ``firmware_guid``
- ``vendor_axis.evidence``, ``type_axis.evidence``
- ``security_axis.evidence``, ``mutability_axis.evidence``
- ``signature_info.signer``
- Classification/baseline/extraction record fields
- Environment variables

Mirrors :mod:`tests.analysis.test_no_log_leakage`.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.feeds

_LOGGER_METHODS: frozenset[str] = frozenset(
    {"info", "warning", "error", "debug", "critical", "exception", "log"}
)

_FORBIDDEN_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    ("", "component_id"),
    ("", "source_image_id"),
    ("", "source_image_hash"),
    ("", "raw_hash"),
    ("", "content_hash"),
    ("", "firmware_guid"),
    ("", "trust_anchor_path"),
    ("signature_info", "signer"),
    ("type_axis", "evidence"),
    ("vendor_axis", "evidence"),
    ("security_axis", "evidence"),
    ("mutability_axis", "evidence"),
)


def _iter_source_files() -> Iterator[Path]:
    package_root = Path(loki.feeds.__path__[0])
    yield from package_root.rglob("*.py")


def _module_name_for(path: Path) -> str:
    package_root = Path(loki.feeds.__path__[0]).parent.parent
    relative = path.relative_to(package_root)
    return ".".join(relative.with_suffix("").parts)


@pytest.fixture(scope="module")
def source_files() -> list[Path]:
    return sorted(_iter_source_files())


def _is_logger_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    return node.func.attr in _LOGGER_METHODS


def _attribute_chain(node: ast.AST) -> list[str]:
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
                            f"references forbidden {parent_substring}.{forbidden_attr}",
                        )
                    )
                    break
    return violations


def test_source_files_were_found(source_files: list[Path]) -> None:
    assert len(source_files) >= 11


def test_no_logger_call_references_forbidden_attributes(
    source_files: list[Path],
) -> None:
    """No logger call references a Forbidden_Leakage_Field."""
    violations: list[tuple[str, int, str, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_logger_call(node):
                for chain_str, reason in _violations_in_call(node):
                    violations.append((module_name, node.lineno, chain_str, reason))
    assert violations == [], "logger calls reference forbidden attributes:\n  " + "\n  ".join(
        f"{m}:{ln} '{c}' -- {r}" for m, ln, c, r in violations
    )


def test_at_least_one_logger_call_exists(source_files: list[Path]) -> None:
    """Sanity check: the AST walker finds logger calls in loki.feeds."""
    found_calls = 0
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_logger_call(node):
                found_calls += 1
    assert found_calls >= 1, f"expected at least 1 logger call in loki.feeds, found {found_calls}"
