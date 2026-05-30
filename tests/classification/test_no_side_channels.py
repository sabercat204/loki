"""Static AST audit of ``loki.classification`` for forbidden side channels (task 18).

Walks every ``.py`` under :mod:`loki.classification` and fails on:

- ``import os.environ`` / ``from os import environ``
- ``import random`` / ``import secrets``
- ``import socket`` / ``import urllib`` / ``import requests`` / ``import httpx``
- direct ``time.time()`` / ``time.monotonic()`` / ``time.perf_counter()`` /
  ``time.monotonic_ns()`` calls outside the explicitly-allowed module
  (:mod:`loki.classification.timing`)
- ``datetime.now(...)`` calls outside the pipeline module
  (:mod:`loki.classification.pipeline` — the only place that
  records timestamps; the loader / matcher / classifier /
  signatures must not).
- ``os.environ`` attribute access anywhere in the package

Implements Property 41 (R8.4 + R8.5): no environmental side
channels affect classification record contents.

Mirrors :mod:`tests.extraction.test_no_side_channels` and
:mod:`tests.baseline.test_no_side_channels`.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.classification

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

_TIME_FORBIDDEN_FUNCS: frozenset[tuple[str, str]] = frozenset(
    {
        ("time", "time"),
        ("time", "monotonic"),
        ("time", "perf_counter"),
        ("time", "monotonic_ns"),
    }
)

#: Module where ``time.*`` clock access is allowed. The
#: classification subsystem follows the extraction pattern of
#: pinning all clock access to a single ``timing.py`` module that
#: exposes a ``Stopwatch`` context manager.
_ALLOWED_TIME_MODULE: str = "loki.classification.timing"

#: Module where ``datetime.now()`` access is allowed. Per the design,
#: the pipeline coordinator is the only place that captures the
#: run-start timestamp and the per-error timestamps. The loader,
#: matcher, classifier, and signature detector must not.
_ALLOWED_DATETIME_MODULE: str = "loki.classification.pipeline"


def _iter_source_files() -> Iterator[Path]:
    package_root = Path(loki.classification.__path__[0])
    yield from package_root.rglob("*.py")


def _module_name_for(path: Path) -> str:
    """Map a filesystem path under loki/classification/ to a dotted module name."""
    package_root = Path(loki.classification.__path__[0]).parent.parent  # repo root
    relative = path.relative_to(package_root)
    return ".".join(relative.with_suffix("").parts)


@pytest.fixture(scope="module")
def source_files() -> list[Path]:
    return sorted(_iter_source_files())


def test_source_files_were_found(source_files: list[Path]) -> None:
    """Sanity check: the AST walker actually found something to audit."""
    # The classification subsystem ships eleven modules at the time
    # of writing (``__init__``, ``api``, ``pipeline``, ``version``,
    # ``classifier``, ``signatures``, ``errors``, ``timing``, plus
    # the ``rules/`` subpackage's four files).
    assert len(source_files) > 8


def test_no_forbidden_module_imports(source_files: list[Path]) -> None:
    """No module under ``loki.classification`` imports a banned dependency."""
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
    assert violations == [], f"forbidden module imports found in loki.classification: {violations}"


def test_no_os_environ_access(source_files: list[Path]) -> None:
    """No module reads from ``os.environ`` (would be an env-var side channel)."""
    violations: list[tuple[str, int]] = []
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
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
    assert violations == [], f"os.environ access found in loki.classification: {violations}"


def test_no_time_calls_outside_timing_module(source_files: list[Path]) -> None:
    """``time.time()`` / ``time.monotonic()`` / etc only allowed in ``timing.py``."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name == _ALLOWED_TIME_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _TIME_FORBIDDEN_FUNCS
                ):
                    violations.append((module_name, node.lineno, f"{func.value.id}.{func.attr}"))
    assert violations == [], f"forbidden time.* calls outside {_ALLOWED_TIME_MODULE}: {violations}"


def test_no_datetime_now_outside_pipeline_module(source_files: list[Path]) -> None:
    """``datetime.now(...)`` only allowed in ``pipeline.py``.

    The pipeline coordinator captures the run-start timestamp
    (R1.6) and the per-error timestamps (R9.4); no other module
    in the subsystem may introduce wall-clock dependence.
    """
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name == _ALLOWED_DATETIME_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and func.value.id == "datetime"
                    and func.attr == "now"
                ):
                    violations.append((module_name, node.lineno, "datetime.now"))
    assert violations == [], (
        f"forbidden datetime.now calls outside {_ALLOWED_DATETIME_MODULE}: {violations}"
    )


def test_timing_module_actually_uses_clock(source_files: list[Path]) -> None:
    """Affirmative check: the allow-listed timing module actually uses time.*.

    Belt-and-braces complement to
    :func:`test_no_time_calls_outside_timing_module`. If
    ``timing.py`` ever stops calling ``time.monotonic()``, the
    allow-list entry is dead weight.
    """
    found_calls: set[str] = set()
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name != _ALLOWED_TIME_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in _TIME_FORBIDDEN_FUNCS
                ):
                    found_calls.add(f"{func.value.id}.{func.attr}")
    assert "time.monotonic" in found_calls, (
        f"{_ALLOWED_TIME_MODULE} no longer uses time.monotonic; "
        "remove the allow-list entry if the Stopwatch helper moved."
    )


def test_pipeline_module_actually_uses_datetime_now(source_files: list[Path]) -> None:
    """Affirmative check: pipeline.py actually calls datetime.now()."""
    found = False
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name != _ALLOWED_DATETIME_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (
                    isinstance(func.value, ast.Name)
                    and func.value.id == "datetime"
                    and func.attr == "now"
                ):
                    found = True
                    break
        if found:
            break
    assert found, (
        f"{_ALLOWED_DATETIME_MODULE} no longer uses datetime.now; "
        "remove the allow-list entry if run-start timestamps moved."
    )
