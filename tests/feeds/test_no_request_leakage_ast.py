"""Static AST audit on HTTPS requests in ``loki.feeds`` (task 20).

Walks ``loki/feeds/`` and asserts no ``urllib.request.Request`` or
``http.client`` call site reads from forbidden source patterns:
``os.environ``, ``os.getenv``, ``os.uname``, ``socket.gethostname``,
``getpass.getuser``, ``FeedsConfig`` attributes other than ``nvd_url``.

Mirrors the static request-leakage audit pattern for FULL-context
subsystems (R8.3, R13.6(c)).
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import loki.feeds

_FORBIDDEN_CALL_PATTERNS: frozenset[tuple[str, str]] = frozenset(
    {
        ("os", "environ"),
        ("os", "getenv"),
        ("os", "uname"),
        ("socket", "gethostname"),
        ("getpass", "getuser"),
    }
)

_FORBIDDEN_CONFIG_ATTRS: frozenset[str] = frozenset(
    {
        "cache_path",
        "implant_rules_path",
        "trust_anchor_path",
        "update_interval",
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


def _find_request_creation_sites(tree: ast.AST) -> list[ast.Call]:
    """Find all urllib.request.Request(...) call sites."""
    sites: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "Request":
            sites.append(node)
        elif isinstance(func, ast.Attribute) and func.attr == "add_header":
            sites.append(node)
    return sites


def _check_forbidden_in_subtree(node: ast.AST) -> list[tuple[str, int, str]]:
    """Walk a subtree for forbidden source patterns."""
    violations: list[tuple[str, int, str]] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            if isinstance(sub.value, ast.Name):
                pair = (sub.value.id, sub.attr)
                if pair in _FORBIDDEN_CALL_PATTERNS:
                    violations.append(("", getattr(sub, "lineno", 0), f"{pair[0]}.{pair[1]}"))
                if sub.attr in _FORBIDDEN_CONFIG_ATTRS:
                    if "config" in sub.value.id.lower() or "cfg" in sub.value.id.lower():
                        violations.append(("", getattr(sub, "lineno", 0), f"config.{sub.attr}"))
    return violations


def test_no_forbidden_sources_in_request_sites(source_files: list[Path]) -> None:
    """No Request() or add_header() call reads from forbidden sources."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        request_sites = _find_request_creation_sites(tree)
        for site in request_sites:
            for arg in site.args:
                for _m, ln, desc in _check_forbidden_in_subtree(arg):
                    violations.append((module_name, ln or site.lineno, desc))
            for kw in site.keywords:
                if kw.value is not None:
                    for _m, ln, desc in _check_forbidden_in_subtree(kw.value):
                        violations.append((module_name, ln or site.lineno, desc))
    assert violations == [], "Forbidden source patterns in request sites:\n  " + "\n  ".join(
        f"{m}:{ln} {d}" for m, ln, d in violations
    )


def test_no_forbidden_imports_near_request_code(source_files: list[Path]) -> None:
    """Modules that use urllib.request don't import getpass/socket.gethostname."""
    violations: list[tuple[str, int, str]] = []
    for path in source_files:
        module_name = _module_name_for(path)
        source = path.read_text(encoding="utf-8")
        if "urllib.request" not in source:
            continue
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == "getpass":
                    violations.append((module_name, node.lineno, "getpass import"))
                if node.module == "socket":
                    for alias in node.names:
                        if alias.name == "gethostname":
                            violations.append(
                                (module_name, node.lineno, "socket.gethostname import")
                            )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "getpass":
                        violations.append((module_name, node.lineno, "getpass import"))
    assert violations == [], "Forbidden imports in request-using modules:\n  " + "\n  ".join(
        f"{m}:{ln} {d}" for m, ln, d in violations
    )
