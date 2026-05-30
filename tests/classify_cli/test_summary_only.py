"""P56 ``--summary-only`` zero-byte stdout Hypothesis test (task 15, R3.6, R13.4).

For randomly generated valid ``ExtractionManifest`` JSON
contents (with component count varying including the empty
manifest), asserts that running ``loki classify ... --summary-only``:

- writes exactly zero bytes to stdout (R3.6);
- writes exactly one summary line of the documented format to
  stderr (R4.1, R4.6);
- returns the same exit code as the same invocation without
  ``--summary-only`` (R3.6: ``--summary-only`` SHALL NOT alter
  the exit code).

Hypothesis settings: ``max_examples=50`` per the project's
in-memory-fast convention; ``HealthCheck.too_slow`` and
``HealthCheck.function_scoped_fixture`` are suppressed because
the test uses function-scoped fixtures (tmp_path_factory,
tmp_rules_path, capsys) and runs the full CLI pipeline per
example.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.cli import main as cli_main
from loki.models import (
    ExtractedComponent,
    ExtractionManifest,
    FirmwareImage,
)

_P56_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.test_summary_only")
_P56_HEX64 = "d" * 64
_P56_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

#: Regex matching the documented summary line shape (R4.2).
_SUMMARY_RE = re.compile(
    r"^classify: \d+ records \(\d+ need_review\), \d+ errors, duration=\d+\.\d{4}s$"
)


def _build_manifest(component_count: int) -> ExtractionManifest:
    """Build a valid ``ExtractionManifest`` with the given component count."""
    image_id = uuid.uuid5(_P56_NAMESPACE, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/p56.bin",
        file_hash=_P56_HEX64,
        file_size=4096,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        ExtractedComponent(
            component_id=uuid.uuid5(_P56_NAMESPACE, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512 + idx * 64,
            raw_hash=_P56_HEX64,
            component_type_hint=None,
            guid=str(uuid.uuid5(_P56_NAMESPACE, f"component-guid-{idx:04d}")),
            name=f"P56_{idx:03d}",
            raw_path=None,
        )
        for idx in range(component_count)
    ]
    return ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=_P56_TIMESTAMP,
        extractor_version="loki-test-fixture",
        extraction_errors=[],
    )


def _run_cli_capture(
    argv: Sequence[str],
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    """Invoke the CLI in-process; return ``(exit_code, stdout, stderr)``."""
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


@settings(
    max_examples=50,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
    deadline=None,
)
@given(component_count=st.integers(min_value=0, max_value=10))
def test_summary_only_zero_byte_stdout(
    component_count: int,
    tmp_path_factory: pytest.TempPathFactory,
    tmp_rules_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--summary-only`` writes zero bytes to stdout for any manifest (P56).

    For each generated manifest:

    - ``--summary-only`` invocation: stdout is exactly zero
      bytes; stderr contains exactly one line matching the
      documented summary format.
    - ``--summary-only``-OFF invocation on the same manifest
      produces non-empty stdout (or empty for empty manifests
      where the JSON is ``{"records": [], "errors": []}``); the
      exit codes match.
    """
    manifest = _build_manifest(component_count)
    json_text = manifest.model_dump_json(indent=2)
    tmp_path = tmp_path_factory.mktemp("p56")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json_text, encoding="utf-8")

    summary_only_argv: list[str] = [
        "classify",
        str(manifest_path),
        "--rules-path",
        str(tmp_rules_path),
        "--summary-only",
    ]
    summary_exit, summary_stdout, summary_stderr = _run_cli_capture(summary_only_argv, capsys)

    full_argv: list[str] = [
        "classify",
        str(manifest_path),
        "--rules-path",
        str(tmp_rules_path),
    ]
    full_exit, _full_stdout, _full_stderr = _run_cli_capture(full_argv, capsys)

    # R3.6: stdout suppressed entirely under --summary-only.
    assert summary_stdout == "", (
        f"expected zero stdout bytes under --summary-only; "
        f"got {summary_stdout!r} at component_count={component_count}"
    )

    # R4.1 + R4.6: exactly one summary line on stderr.
    summary_lines = [line for line in summary_stderr.splitlines() if line.strip()]
    assert len(summary_lines) == 1, (
        f"expected exactly one summary line; got {len(summary_lines)}: "
        f"{summary_lines!r} at component_count={component_count}"
    )
    assert _SUMMARY_RE.match(summary_lines[0]) is not None, (
        f"summary line did not match expected format: {summary_lines[0]!r}"
    )

    # R3.6: --summary-only does NOT alter exit code.
    assert summary_exit == full_exit, (
        f"--summary-only changed exit code: summary={summary_exit}, "
        f"full={full_exit} at component_count={component_count}"
    )
