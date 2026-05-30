"""Static AST audit of the classify CLI surface for side channels (task 17).

Mirrors the pattern from :mod:`tests.analysis.test_no_side_channels`.
The audit walks two AST scopes:

1. The full :mod:`loki.classify_helpers` module.
2. The single ``_handle_classify`` function from :mod:`loki.cli`.

The OTHER handlers in :mod:`loki.cli` (``_handle_extract``,
``_handle_baseline_*``, ``_handle_gui``) may legitimately use
``time.time()`` or ``datetime.now()`` for non-deterministic
purposes; the contract is that the classify-CLI surface alone
stays free of side channels. Asserts:

- No imports of ``random``, ``secrets``, ``socket``, ``urllib``,
  ``urllib.request``, ``urllib.parse``, ``requests``, or ``httpx``.
- No direct or imported access to ``os.environ``.
- No ``time.time()`` / ``datetime.now()`` calls. The CLI's
  duration measurement uses ``time.monotonic()`` exclusively
  per design Performance plan + R4.2's ``<S>`` field.
- ``time.monotonic()``, ``time.perf_counter()``,
  ``signal.signal``, ``signal.getsignal``, and the standard
  ``logging`` module are explicitly allowed.

Implements the determinism contract pinned by R9.5 (no
environmental side channels affect Stdout_Result contents).
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki

_FORBIDDEN_IMPORTS: frozenset[str] = frozenset(
    {
        "random",
        "secrets",
        "socket",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "requests",
        "httpx",
    }
)

#: Forbidden ``time.*`` functions. ``time.monotonic`` and
#: ``time.perf_counter`` are explicitly allowed; the CLI uses
#: ``time.monotonic()`` for the duration measurement (R4.2).
_TIME_FORBIDDEN_FUNCS: frozenset[tuple[str, str]] = frozenset(
    {
        ("time", "time"),
    }
)

#: Forbidden ``datetime.*`` functions. ``datetime.now()`` is the
#: typical leak; the CLI does not consume the current wall-clock
#: time at all.
_DATETIME_FORBIDDEN_FUNCS: frozenset[tuple[str, str]] = frozenset(
    {
        ("datetime", "now"),
        ("datetime", "utcnow"),
    }
)


def _classify_helpers_path() -> Path:
    """Resolve the absolute path to ``loki/classify_helpers.py``."""
    package_root = Path(loki.__path__[0])
    return package_root / "classify_helpers.py"


def _cli_path() -> Path:
    """Resolve the absolute path to ``loki/cli.py``."""
    package_root = Path(loki.__path__[0])
    return package_root / "cli.py"


def _extract_handle_classify_subtree(cli_source: str) -> ast.FunctionDef:
    """Parse ``loki/cli.py`` and return the ``_handle_classify`` FunctionDef.

    Raises ``LookupError`` if the function is not found, which
    would indicate a structural change to ``cli.py`` that this
    audit does not yet account for.
    """
    tree = ast.parse(cli_source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_handle_classify":
            return node
    raise LookupError("_handle_classify not found in loki/cli.py")


def _iter_audit_subtrees() -> Iterator[tuple[str, ast.AST]]:
    """Yield ``(label, subtree)`` pairs for the two audit scopes.

    The label is used in failure messages so violations are
    attributable to the offending subtree.
    """
    helpers_source = _classify_helpers_path().read_text(encoding="utf-8")
    yield "loki.classify_helpers", ast.parse(helpers_source)

    cli_source = _cli_path().read_text(encoding="utf-8")
    yield "loki.cli._handle_classify", _extract_handle_classify_subtree(cli_source)


@pytest.fixture(scope="module")
def audit_subtrees() -> list[tuple[str, ast.AST]]:
    return list(_iter_audit_subtrees())


def test_audit_subtrees_were_found(audit_subtrees: list[tuple[str, ast.AST]]) -> None:
    """Sanity check: both audit scopes resolved."""
    labels = [label for label, _ in audit_subtrees]
    assert "loki.classify_helpers" in labels
    assert "loki.cli._handle_classify" in labels


def test_no_forbidden_module_imports(
    audit_subtrees: list[tuple[str, ast.AST]],
) -> None:
    """No classify-CLI surface imports a banned dependency."""
    violations: list[tuple[str, int, str]] = []
    for label, subtree in audit_subtrees:
        for node in ast.walk(subtree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in _FORBIDDEN_IMPORTS:
                        violations.append((label, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module in _FORBIDDEN_IMPORTS:
                    violations.append((label, node.lineno, node.module or ""))
    assert violations == [], f"forbidden module imports found in classify-CLI surface: {violations}"


def test_no_os_environ_access(
    audit_subtrees: list[tuple[str, ast.AST]],
) -> None:
    """No classify-CLI surface reads from ``os.environ`` (env-var side channel)."""
    violations: list[tuple[str, int]] = []
    for label, subtree in audit_subtrees:
        for node in ast.walk(subtree):
            if isinstance(node, ast.Attribute):
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr == "environ"
                ):
                    violations.append((label, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.module == "os":
                    for alias in node.names:
                        if alias.name == "environ":
                            violations.append((label, node.lineno))
    assert violations == [], f"os.environ access in classify-CLI surface: {violations}"


def test_no_forbidden_time_calls(
    audit_subtrees: list[tuple[str, ast.AST]],
) -> None:
    """``time.time()`` is forbidden; ``time.monotonic()`` is allowed.

    The CLI uses ``time.monotonic()`` for the duration
    measurement (R4.2's ``<S>`` field). ``time.time()`` would
    introduce wall-clock dependence; reject it.
    """
    violations: list[tuple[str, int, str]] = []
    for label, subtree in audit_subtrees:
        for node in ast.walk(subtree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _TIME_FORBIDDEN_FUNCS
                ):
                    violations.append((label, node.lineno, f"{func.value.id}.{func.attr}"))
    assert violations == [], f"forbidden time.* calls in classify-CLI surface: {violations}"


def test_no_datetime_now_calls(
    audit_subtrees: list[tuple[str, ast.AST]],
) -> None:
    """``datetime.now()`` and ``datetime.utcnow()`` are forbidden."""
    violations: list[tuple[str, int, str]] = []
    for label, subtree in audit_subtrees:
        for node in ast.walk(subtree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _DATETIME_FORBIDDEN_FUNCS
                ):
                    violations.append((label, node.lineno, f"{func.value.id}.{func.attr}"))
    assert violations == [], f"forbidden datetime.* calls in classify-CLI surface: {violations}"


def test_classify_cli_surface_actually_uses_time_monotonic() -> None:
    """Affirmative check: the classify-CLI surface uses ``time.monotonic()``.

    Belt-and-braces complement to
    :func:`test_no_forbidden_time_calls`. If the CLI ever stops
    measuring duration, the slow-marker performance test in
    task 21 would be measuring nothing.
    """
    cli_source = _cli_path().read_text(encoding="utf-8")
    handle_classify = _extract_handle_classify_subtree(cli_source)

    found_monotonic = False
    for node in ast.walk(handle_classify):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func = node.func
            if (
                isinstance(func.value, ast.Name)
                and func.value.id == "time"
                and func.attr == "monotonic"
            ):
                found_monotonic = True
                break

    assert found_monotonic, (
        "_handle_classify no longer calls time.monotonic; the duration "
        "measurement (R4.2) appears to have moved or been removed."
    )
