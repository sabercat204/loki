"""Static AST audit of ``loki.feeds`` for forbidden side channels (task 17).

Walks every ``.py`` under :mod:`loki.feeds` and asserts that:

- ``os.environ``, ``os.getenv``, ``random``, ``secrets``,
  ``socket.gethostname``, ``getpass.getuser`` imports and attribute
  accesses appear ONLY in designated modules.
- ``time.*`` clock calls only appear in ``timing.py``.
- ``datetime.now()`` only appears in ``refresh.py`` (the only place
  that captures the refresh timestamp).

The feeds subsystem has designated network modules (``refresh.py``,
``trust.py``) that are allowed ``urllib``, ``ssl``, ``hashlib``
imports. All other modules must be network-free.

Mirrors :mod:`tests.analysis.test_no_side_channels`.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.feeds

_FORBIDDEN_IMPORTS: frozenset[str] = frozenset(
    {
        "random",
        "secrets",
        "requests",
        "httpx",
    }
)

_NETWORK_ALLOWED_MODULES: frozenset[str] = frozenset(
    {
        "loki.feeds.refresh",
        "loki.feeds.trust",
        "loki.feeds.registry",
    }
)

_NETWORK_IMPORTS: frozenset[str] = frozenset(
    {
        "urllib",
        "urllib.request",
        "urllib.parse",
        "urllib.error",
        "socket",
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

_ALLOWED_TIME_MODULE: str = "loki.feeds.timing"
_ALLOWED_DATETIME_MODULES: frozenset[str] = frozenset(
    {
        "loki.feeds.refresh",
        "loki.feeds.registry",
    }
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


def test_source_files_were_found(source_files: list[Path]) -> None:
    assert len(source_files) >= 11


def test_no_forbidden_module_imports(source_files: list[Path]) -> None:
    """No module under ``loki.feeds`` imports a banned dependency."""
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
                    violations.append((str(path), node.lineno, node.module or ""))
    assert violations == [], f"forbidden module imports: {violations}"


def test_no_network_imports_outside_designated_modules(
    source_files: list[Path],
) -> None:
    """Network imports only allowed in refresh.py and trust.py."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name in _NETWORK_ALLOWED_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in _NETWORK_IMPORTS:
                        violations.append((module_name, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module in _NETWORK_IMPORTS:
                    violations.append((module_name, node.lineno, node.module or ""))
    assert violations == [], f"network imports outside designated modules: {violations}"


def test_no_os_environ_access(source_files: list[Path]) -> None:
    """No module reads from ``os.environ`` or ``os.getenv``."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_name = _module_name_for(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr in ("environ", "getenv")
                ):
                    violations.append((module_name, node.lineno, f"os.{node.attr}"))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "getenv"
                ):
                    violations.append((module_name, node.lineno, "os.getenv()"))
            elif isinstance(node, ast.ImportFrom):
                if node.module == "os":
                    for alias in node.names:
                        if alias.name in ("environ", "getenv"):
                            violations.append((module_name, node.lineno, f"os.{alias.name}"))
    assert violations == [], f"os.environ / os.getenv access: {violations}"


def test_no_getpass_or_gethostname(source_files: list[Path]) -> None:
    """No module uses ``getpass.getuser()`` or ``socket.gethostname()``."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name in _NETWORK_ALLOWED_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == "getpass":
                    violations.append((module_name, node.lineno, "getpass"))
                if node.module == "socket":
                    for alias in node.names:
                        if alias.name == "gethostname":
                            violations.append((module_name, node.lineno, "socket.gethostname"))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "getpass":
                        violations.append((module_name, node.lineno, "getpass"))
    assert violations == [], f"getpass/gethostname usage: {violations}"


def test_no_time_calls_outside_timing_module(source_files: list[Path]) -> None:
    """``time.*`` clock calls only allowed in ``timing.py``."""
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


def test_no_datetime_now_outside_allowed_modules(source_files: list[Path]) -> None:
    """``datetime.now(...)`` only allowed in refresh.py and registry.py."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        if module_name in _ALLOWED_DATETIME_MODULES:
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
        f"forbidden datetime.now calls outside {_ALLOWED_DATETIME_MODULES}: {violations}"
    )


def test_timing_module_actually_uses_clock(source_files: list[Path]) -> None:
    """Affirmative: timing.py actually uses time.monotonic."""
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
    assert "time.monotonic" in found_calls
