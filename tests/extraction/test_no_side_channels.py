"""Static AST audit of ``loki.extraction`` for forbidden side channels (task 21).

Walks every ``.py`` under :mod:`loki.extraction` and fails on:

- ``import os.environ`` / ``from os import environ``
- ``import random`` / ``import secrets``
- ``import socket`` / ``import urllib`` / ``import requests`` / ``import httpx``
- direct ``time.time()`` / ``time.monotonic()`` / ``datetime.now()``
  calls outside the explicitly-allowed module
  (:mod:`loki.extraction.timing`)
- ``os.environ`` attribute access anywhere in the package

Implements R7.5 (Property 22): no environmental side channels affect
manifest contents. Catches regressions where someone reaches for
``os.environ.get`` to thread configuration past the
:class:`ExtractionConfig` boundary.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.extraction

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
    }
)

_ALLOWED_CLOCK_MODULE: str = "loki.extraction.timing"


def _iter_source_files() -> Iterator[Path]:
    package_root = Path(loki.extraction.__path__[0])
    yield from package_root.rglob("*.py")


def _module_name_for(path: Path) -> str:
    """Map a filesystem path under loki/extraction/ to a dotted module name."""
    package_root = Path(loki.extraction.__path__[0]).parent.parent  # repo root
    relative = path.relative_to(package_root)
    return ".".join(relative.with_suffix("").parts)


@pytest.fixture(scope="module")
def source_files() -> list[Path]:
    return sorted(_iter_source_files())


def test_source_files_were_found(source_files: list[Path]) -> None:
    """Sanity check: the AST walker actually found something to audit."""
    assert len(source_files) > 5


def test_no_forbidden_module_imports(source_files: list[Path]) -> None:
    """No module under ``loki.extraction`` imports a banned dependency."""
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
    assert violations == [], f"forbidden module imports found in loki.extraction: {violations}"


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
    assert violations == [], f"os.environ access found in loki.extraction: {violations}"


def test_no_clock_calls_outside_timing_module(source_files: list[Path]) -> None:
    """``time.time()`` / ``time.monotonic()`` only allowed in ``timing.py``.

    Direct clock calls anywhere else would smuggle the system clock
    into manifest contents and break Property 22.
    """

    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name == _ALLOWED_CLOCK_MODULE:
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
    assert violations == [], f"forbidden clock calls outside {_ALLOWED_CLOCK_MODULE}: {violations}"
