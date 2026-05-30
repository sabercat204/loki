"""Static AST audit of ``loki.baseline`` for forbidden side channels (task 15).

Walks every ``.py`` under :mod:`loki.baseline` and fails on:

- ``import os.environ`` / ``from os import environ``
- ``import random`` / ``import secrets``
- ``import socket`` / ``import urllib`` / ``import requests`` / ``import httpx``
- direct ``time.time()`` / ``time.monotonic()`` / ``time.perf_counter()`` /
  ``time.monotonic_ns()`` / ``datetime.now()`` calls outside the explicitly-
  allowed module (:mod:`loki.baseline.store`)
- ``os.environ`` attribute access anywhere in the package

Implements Property 32 (R9.5 + R9.6): no environmental side channels
affect Baseline_File contents. Catches regressions where someone
reaches for ``os.environ.get`` to thread configuration past the
:class:`BaselineConfig` boundary, or imports ``random`` / ``secrets``
to disambiguate temp-file suffixes (the store uses an
:func:`os.getpid` + monotonic counter pattern instead, see
``store._next_temp_suffix``).

The persistence subsystem doesn't have a dedicated ``timing.py``
module like extraction does. Clock access is restricted to
:mod:`loki.baseline.store`, which uses:

- :func:`time.monotonic` for the load-duration counter.
- :func:`datetime.now` (with ``tz=UTC``) for the envelope's
  ``written_at`` field.

Both calls are explicitly sanctioned by Property 32. The audit
encodes that exception by allow-listing the ``loki.baseline.store``
module name.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.baseline

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

_CLOCK_FORBIDDEN_FUNCS: frozenset[tuple[str, str]] = frozenset(
    {
        ("time", "time"),
        ("time", "monotonic"),
        ("time", "perf_counter"),
        ("time", "monotonic_ns"),
        ("datetime", "now"),
    }
)

#: Modules where the persistence subsystem is allowed to consult the
#: clock. The handoff is explicit: clock access is restricted to
#: ``store.py``'s ``datetime.now(tz=UTC)`` for ``written_at`` and
#: ``time.monotonic()`` for the load-duration counter.
_ALLOWED_CLOCK_MODULES: frozenset[str] = frozenset({"loki.baseline.store"})


def _iter_source_files() -> Iterator[Path]:
    package_root = Path(loki.baseline.__path__[0])
    yield from package_root.rglob("*.py")


def _module_name_for(path: Path) -> str:
    """Map a filesystem path under loki/baseline/ to a dotted module name."""
    package_root = Path(loki.baseline.__path__[0]).parent.parent  # repo root
    relative = path.relative_to(package_root)
    return ".".join(relative.with_suffix("").parts)


@pytest.fixture(scope="module")
def source_files() -> list[Path]:
    return sorted(_iter_source_files())


def test_source_files_were_found(source_files: list[Path]) -> None:
    """Sanity check: the AST walker actually found something to audit."""
    # The persistence subsystem ships eight modules at the time of
    # writing (``__init__``, ``concurrency``, ``envelope``, ``errors``,
    # ``naming``, ``quarantine``, ``schema``, ``store``). Five is a
    # comfortable lower bound that catches "AST walker found
    # nothing" regressions without locking in an exact count.
    assert len(source_files) > 5


def test_no_forbidden_module_imports(source_files: list[Path]) -> None:
    """No module under ``loki.baseline`` imports a banned dependency."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in _FORBIDDEN_IMPORTS:
                        violations.append((str(path), node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module in _FORBIDDEN_IMPORTS:
                    violations.append((str(path), node.lineno, node.module))
    assert violations == [], f"forbidden module imports found in loki.baseline: {violations}"


def test_no_os_environ_access(source_files: list[Path]) -> None:
    """No module reads from ``os.environ`` (would be an env-var side channel)."""
    violations: list[tuple[str, int]] = []
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                # Catch ``os.environ`` regardless of how the attribute
                # chain is built up.
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr == "environ"
                ):
                    violations.append((str(path), node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.module == "os":
                    for alias in node.names:
                        if alias.name == "environ":
                            violations.append((str(path), node.lineno))
    assert violations == [], f"os.environ access found in loki.baseline: {violations}"


def test_no_clock_calls_outside_allowed_modules(source_files: list[Path]) -> None:
    """``time.*`` and ``datetime.now()`` only allowed in ``store.py``.

    Direct clock calls anywhere else would smuggle the system clock
    into Baseline_File contents and break Property 32. The
    persistence subsystem only needs the clock in two places — the
    load-duration counter and the envelope's ``written_at`` field —
    both of which live in :mod:`loki.baseline.store`.
    """

    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name in _ALLOWED_CLOCK_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _CLOCK_FORBIDDEN_FUNCS
                ):
                    violations.append((module_name, node.lineno, f"{func.value.id}.{func.attr}"))
    assert violations == [], (
        f"forbidden clock calls outside {sorted(_ALLOWED_CLOCK_MODULES)}: {violations}"
    )


def test_store_module_is_the_only_clock_caller(source_files: list[Path]) -> None:
    """Affirmative check: the allow-listed module actually uses the clock.

    Belt-and-braces complement to
    :func:`test_no_clock_calls_outside_allowed_modules`. If
    ``store.py`` ever stops calling :func:`datetime.now` and
    :func:`time.monotonic`, the allow-list entry is dead weight and
    should be removed. This test catches that regression and forces
    a deliberate decision rather than letting the allow-list rot.
    """

    found_calls: dict[str, set[str]] = {}
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name not in _ALLOWED_CLOCK_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _CLOCK_FORBIDDEN_FUNCS
                ):
                    calls.add(f"{func.value.id}.{func.attr}")
        found_calls[module_name] = calls

    # The only allow-listed module today is loki.baseline.store, and
    # it must use both time.monotonic (load duration) and
    # datetime.now (envelope written_at). Drop the assertion when
    # the design changes to drop one of those.
    assert "loki.baseline.store" in found_calls
    assert "time.monotonic" in found_calls["loki.baseline.store"], (
        "loki.baseline.store no longer uses time.monotonic; "
        "remove the allow-list entry if the load-duration counter "
        "moved to a separate module."
    )
    assert "datetime.now" in found_calls["loki.baseline.store"], (
        "loki.baseline.store no longer uses datetime.now; "
        "remove the allow-list entry if written_at moved elsewhere."
    )
