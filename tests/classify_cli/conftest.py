"""Pytest fixtures for the ``loki classify`` CLI subsystem tests.

Provides four bespoke fixtures used across the
``tests/classify_cli/`` suite:

- ``tmp_rules_path``: builds the smallest viable rules directory
  the classification rule loader accepts (one YAML file per axis).
- ``sample_manifest_json``: builds a small valid
  ``ExtractionManifest`` and returns its ``model_dump_json``
  serialization as a string.
- ``cli_argv``: helper that constructs an argv list for the
  ``classify`` subcommand so tests do not repeat the boilerplate.
- ``capture_classify_run``: wraps ``loki.cli.main(...)`` with
  ``capsys`` capture and returns a ``(exit_code, stdout, stderr)``
  triple. Per the design's "in-process invocation via
  ``loki.cli.main(["classify", ...])`` pattern; only the SIGINT
  end-to-end test (task 13) uses ``subprocess``.

Q1 from design.md is pinned by these bespoke fixtures rather
than re-exporting from ``tests/classification/conftest.py``: the
CLI tests stay self-contained.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from loki.cli import main as cli_main
from loki.models import (
    ExtractedComponent,
    ExtractionManifest,
    FirmwareImage,
)

# A stable seed namespace for deterministic UUID derivation so
# the same fixture call produces byte-identical IDs across runs
# and hosts. Distinct from any real-world component-ID derivation.
_FIXTURE_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.conftest")

# A fixed, deterministic GUID used as the matcher predicate value
# in every fixture rule. Picked so that real-world synthetic
# components never collide with it.
_FIXTURE_RULE_GUID = "00000000-0000-0000-0000-000000000001"

# A 64-character lowercase hex SHA-256 string used for the
# fixture firmware image's ``file_hash`` and the components'
# ``raw_hash``. Stable across runs; arbitrary value.
_FIXTURE_HEX64 = "a" * 64


def _build_rule_yaml(axis: str, label: str) -> dict[str, object]:
    """Build the smallest valid rule-file payload for one axis.

    A single rule with a ``guid`` matcher carrying the fixture
    GUID and an ``effect`` whose ``label`` is a valid member of
    the axis enum; ``confidence`` is at the model default of
    ``0.5``; ``method`` is the ``"RULE"`` literal.
    """
    return {
        "taxonomy_version": "1.0.0",
        "rules": [
            {
                "rule_id": f"fixture.{axis}.001",
                "axis": axis,
                "matcher": {"guid": _FIXTURE_RULE_GUID},
                "effect": {
                    "label": label,
                    "confidence": 0.5,
                    "method": "RULE",
                },
            }
        ],
    }


@pytest.fixture
def tmp_rules_path(tmp_path: Path) -> Path:
    """Build a small valid rules directory under ``tmp_path``.

    Writes one YAML file per axis (``type.yaml``, ``vendor.yaml``,
    ``security_posture.yaml``, ``mutability.yaml``) with a single
    rule each. Each rule's matcher uses a fixed fixture GUID that
    no synthetic ``ExtractedComponent`` produced by
    ``sample_manifest_json`` will match, so every component runs
    without any rule-firing side effects.

    Returns the absolute path to the rules directory; pass through
    verbatim to the CLI's ``--rules-path`` flag.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    payloads = {
        "type": "UEFI_DRIVER",
        "vendor": "INTEL",
        "security_posture": "SECURE",
        "mutability": "READONLY",
    }
    for axis, label in payloads.items():
        path = rules_dir / f"{axis}.yaml"
        with path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(
                _build_rule_yaml(axis, label),
                handle,
                sort_keys=True,
                default_flow_style=False,
            )
    return rules_dir


@pytest.fixture
def sample_manifest_json() -> str:
    """Build a small valid ``ExtractionManifest`` and return its JSON.

    Returns a UTF-8 string produced by
    ``manifest.model_dump_json(indent=2)``. The manifest carries
    a fixed ``FirmwareImage`` plus three deterministic
    ``ExtractedComponent`` records whose GUIDs do not collide with
    the ``tmp_rules_path`` fixture's matcher GUID; the resulting
    classification produces no rule-firing records.
    """
    image_id = uuid.uuid5(_FIXTURE_NAMESPACE, "source-image-0001")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/firmware.bin",
        file_hash=_FIXTURE_HEX64,
        file_size=4096,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components: list[ExtractedComponent] = [
        ExtractedComponent(
            component_id=uuid.uuid5(_FIXTURE_NAMESPACE, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512 + idx * 64,
            raw_hash=_FIXTURE_HEX64,
            component_type_hint=None,
            guid=str(uuid.uuid5(_FIXTURE_NAMESPACE, f"component-guid-{idx:04d}")),
            name=f"FIXTURE_{idx:03d}",
            raw_path=None,
        )
        for idx in range(3)
    ]
    manifest = ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        extractor_version="loki-test-fixture",
        extraction_errors=[],
    )
    return manifest.model_dump_json(indent=2)


@pytest.fixture
def cli_argv() -> Callable[..., list[str]]:
    """Return a helper for constructing ``classify`` argv lists.

    Usage::

        argv = cli_argv("manifest.json", rules_path="/tmp/rules")
        # → ["classify", "manifest.json", "--rules-path", "/tmp/rules"]

    Optional flags (``--taxonomy-version``, ``--progress``,
    ``--debug``, ``--summary-only``) are appended when supplied as
    keyword arguments. Tests use this to avoid repeating the
    five-flag boilerplate.
    """

    def _build(
        manifest: str,
        *,
        rules_path: str,
        taxonomy_version: str | None = None,
        progress: bool = False,
        debug: bool = False,
        summary_only: bool = False,
    ) -> list[str]:
        argv: list[str] = ["classify", manifest, "--rules-path", rules_path]
        if taxonomy_version is not None:
            argv.extend(["--taxonomy-version", taxonomy_version])
        if progress:
            argv.append("--progress")
        if debug:
            argv.append("--debug")
        if summary_only:
            argv.append("--summary-only")
        return argv

    return _build


@pytest.fixture
def capture_classify_run(
    capsys: pytest.CaptureFixture[str],
) -> Callable[[Sequence[str]], tuple[int, str, str]]:
    """Return a helper that runs ``loki.cli.main`` and captures output.

    The returned callable invokes ``loki.cli.main(argv)`` in-process
    and returns a ``(exit_code, stdout, stderr)`` triple drawn from
    ``capsys.readouterr()``. ``SystemExit`` raised by argparse
    (e.g. on missing ``--rules-path``) is caught and its ``code`` is
    returned as the exit code; non-int ``code`` values resolve to
    ``1`` per the standard ``sys.exit`` convention.

    Per design.md, this is the in-process invocation pattern used
    by every CLI test except the single SIGINT end-to-end test
    (task 13), which uses ``subprocess.Popen`` for true signal
    delivery.
    """

    def _run(argv: Sequence[str]) -> tuple[int, str, str]:
        try:
            exit_code = int(cli_main(list(argv)))
        except SystemExit as exc:
            code = exc.code
            if code is None:
                exit_code = 0
            elif isinstance(code, int):
                exit_code = code
            else:
                exit_code = 1
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return _run
