"""Integration smoke tests for the ``loki classify`` subcommand (task 22).

Two end-to-end probes that exercise the real CLI dispatcher and
the real classification library, with no monkeypatching.

1. ``test_classify_help_exits_zero``: the ``--help`` invocation
   exits with code 0 and stdout carries the documented flags +
   the ``manifest`` positional. Confirms the argparse wiring from
   task 10 is intact and ``build_parser()`` is calling
   ``_add_classify_subcommand(sub)`` (task 22 first checkbox).

2. ``test_classify_full_pipeline_smoke``: builds a 5-component
   manifest + a 4-rule rules dir and runs the full pipeline.
   Asserts exit 0; stdout parses as JSON with the documented
   ``["records", "errors"]`` key set; stderr carries the
   summary line matching the documented format.

This module is the final integration probe before the wave 7
final gate. Failures here indicate a regression in either the
argparse dispatch (task 10), the handler shell (task 11), or the
helpers (tasks 2-9). The contract being verified is "the CLI
runs end-to-end without crashing and emits the documented
shape", not "specific record contents" — the synthetic GUIDs
deliberately do not match the rule matchers, so each component
falls through to ``UNKNOWN`` axis labels via the library's
default-fallback path.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.cli import main as cli_main
from loki.models import (
    ExtractedComponent,
    ExtractionManifest,
    FirmwareImage,
)

#: Regex matching the documented summary line shape (R4.2). Same
#: pattern used in ``test_stderr_summary_emission.py``;
#: duplicated here to keep the smoke module self-contained.
_SUMMARY_RE = re.compile(
    r"^classify: (?P<n>\d+) records \((?P<k>\d+) need_review\), "
    r"(?P<e>\d+) errors, duration=(?P<s>\d+\.\d{4})s$"
)

#: Stable seed namespace for deterministic UUID derivation in this
#: module. Distinct from any other test module's namespace so the
#: synthetic component IDs never collide with rule matcher GUIDs
#: from ``conftest.py``'s ``tmp_rules_path`` fixture.
_SMOKE_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.smoke")

#: A fixed 64-character lowercase hex SHA-256 sentinel reused
#: across the synthetic FirmwareImage and components.
_SMOKE_HEX64 = "c" * 64


def _build_five_component_manifest_path(tmp_path: Path) -> Path:
    """Write a 5-component manifest JSON to ``tmp_path/manifest.json``.

    Mirrors the 5-component manifest builder from the cancellation
    and emission-discipline tests so the smoke run has a known
    shape. The components carry deterministic GUIDs that are
    distinct from the fixture rule's matcher GUID, so the rule
    loader runs without any rule firing on any component.
    """
    image_id = uuid.uuid5(_SMOKE_NAMESPACE, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-smoke/firmware.bin",
        file_hash=_SMOKE_HEX64,
        file_size=8192,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        ExtractedComponent(
            component_id=uuid.uuid5(_SMOKE_NAMESPACE, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512,
            raw_hash=_SMOKE_HEX64,
            component_type_hint=None,
            guid=str(uuid.uuid5(_SMOKE_NAMESPACE, f"guid-{idx:04d}")),
            name=f"SMOKE_{idx:03d}",
            raw_path=None,
        )
        for idx in range(5)
    ]
    manifest = ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        extractor_version="loki-smoke-fixture",
        extraction_errors=[],
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest_path


def test_classify_help_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``loki classify --help`` exits 0 and advertises the documented surface.

    argparse's ``--help`` calls ``sys.exit(0)`` after writing the
    help text to stdout; the SystemExit is caught here so the
    test assertions can run on the captured output. Confirms
    R12.1-R12.5: every flag has help text, the positional
    ``manifest`` is present, and the help-driven exit is clean.
    """
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["classify", "--help"])

    assert exc_info.value.code == 0, f"--help exit code should be 0; got {exc_info.value.code!r}"
    captured = capsys.readouterr()
    stdout = captured.out
    # The five flags advertised on the subcommand (R12.1-R12.4).
    assert "--rules-path" in stdout
    assert "--taxonomy-version" in stdout
    assert "--progress" in stdout
    assert "--debug" in stdout
    assert "--summary-only" in stdout
    # The positional argument (R12.2).
    assert "manifest" in stdout


def test_classify_full_pipeline_smoke(
    tmp_path: Path,
    tmp_rules_path: Path,
    cli_argv: Callable[..., list[str]],
    capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
) -> None:
    """End-to-end full-pipeline smoke: 5 components, 4 rules, exit 0.

    No monkeypatching: the real argparse parser, the real
    ``_handle_classify`` handler, and the real
    ``classify_components`` library all run. The synthetic
    component GUIDs do not match the fixture rule's matcher
    GUID, so every component falls through to ``UNKNOWN`` axis
    labels via the library's default-fallback path. The
    pipeline still emits one ``ClassificationRecord`` per
    component (5 records total). The synthetic components carry
    ``raw_path=None``, which trips the library's R5.6 dual-record
    contract: each component also produces one
    ``signature detection failed: raw_path missing``
    ``ClassificationError`` paired to the same ``component_id``.
    The smoke test pins the dual-record behavior here as the
    final integration probe before the wave 7 final gate.
    """
    manifest_path = _build_five_component_manifest_path(tmp_path)
    argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))

    exit_code, stdout, stderr = capture_classify_run(argv)

    # Clean exit on the success path.
    assert exit_code == 0, f"expected exit 0 from full smoke; got {exit_code!r}; stderr={stderr!r}"

    # Stdout parses as the documented shape with exactly the
    # ``["records", "errors"]`` key set in that order (R3.5).
    payload = json.loads(stdout)
    assert isinstance(payload, dict)
    assert list(payload.keys()) == ["records", "errors"], (
        f"expected exact key order ['records', 'errors']; got {list(payload.keys())!r}"
    )
    # 5 input components -> 5 records on the success path
    # (default-fallback to UNKNOWN axis labels does not suppress
    # record emission).
    assert len(payload["records"]) == 5, (
        f"expected 5 records for 5-component manifest; got "
        f"{len(payload['records'])} records; payload={payload!r}"
    )
    # R5.6 dual-record contract: every component with
    # ``raw_path=None`` emits a paired
    # "signature detection failed: raw_path missing" error
    # alongside its record. The synthetic components in this
    # smoke test all have ``raw_path=None``, so the error count
    # equals the record count and every error references one of
    # the input components' ids.
    assert len(payload["errors"]) == 5, (
        f"expected 5 R5.6 dual-record errors; got {len(payload['errors'])}; payload={payload!r}"
    )
    record_component_ids = {record["component_id"] for record in payload["records"]}
    error_component_ids = {error["component_id"] for error in payload["errors"]}
    assert error_component_ids == record_component_ids, (
        f"R5.6 dual-record contract: every error's component_id MUST "
        f"appear among the records' component_ids; "
        f"records={record_component_ids!r}; errors={error_component_ids!r}"
    )
    for error in payload["errors"]:
        assert error["error_message"] == "signature detection failed: raw_path missing"

    # Stderr carries exactly one summary line matching the
    # documented format (R4.1, R4.2, P57).
    summary_lines = [line for line in stderr.splitlines() if line.startswith("classify: ")]
    assert len(summary_lines) == 1, (
        f"expected exactly one summary line; got {summary_lines!r}; stderr={stderr!r}"
    )
    match = _SUMMARY_RE.match(summary_lines[0])
    assert match is not None, f"summary line did not match documented format: {summary_lines[0]!r}"
    assert match.group("n") == "5"
    # R5.6 dual-record contract surfaces in the summary line
    # too: 5 records + 5 paired errors.
    assert match.group("e") == "5"
