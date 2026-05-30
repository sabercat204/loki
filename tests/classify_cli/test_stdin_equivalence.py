"""P53 stdin-or-file equivalence Hypothesis test (task 14, R9.2, R13.1).

For randomly generated valid ``ExtractionManifest`` JSON
contents, asserts that running ``loki classify <path>`` and
``loki classify -`` (with the same JSON piped to stdin) produce
byte-equal stdout after stripping the per-record ``timestamp``
field. The two invocations differ only in the input mode; their
output should be identical because ``_load_manifest`` converges
on the same ``text`` variable before JSON parsing for both
modes.

Hypothesis settings: ``max_examples=25`` per the project's
full-pipeline convention; ``HealthCheck.too_slow`` and
``HealthCheck.function_scoped_fixture`` are suppressed because
the test uses function-scoped fixtures (tmp_path, tmp_rules_path,
capsys) and runs the full CLI pipeline per example.
"""

from __future__ import annotations

import io
import sys
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
from tests.classify_cli._helpers import strip_record_timestamps

# A stable namespace for deterministic UUID derivation in this
# test module; the same Hypothesis input produces byte-identical
# UUIDs across runs.
_P53_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.test_stdin_equivalence")
_P53_HEX64 = "c" * 64
_P53_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _build_manifest(component_count: int) -> ExtractionManifest:
    """Build a small ``ExtractionManifest`` parameterized by component count.

    Uses deterministic ``uuid5`` derivation so the same
    component_count produces byte-identical IDs across runs.
    GUIDs do not collide with the ``tmp_rules_path`` fixture's
    matcher GUID, so no rules fire; the result has zero records
    and zero errors regardless of the input shape.
    """
    image_id = uuid.uuid5(_P53_NAMESPACE, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/p53.bin",
        file_hash=_P53_HEX64,
        file_size=4096,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        ExtractedComponent(
            component_id=uuid.uuid5(_P53_NAMESPACE, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512 + idx * 64,
            raw_hash=_P53_HEX64,
            component_type_hint=None,
            guid=str(uuid.uuid5(_P53_NAMESPACE, f"component-guid-{idx:04d}")),
            name=f"P53_{idx:03d}",
            raw_path=None,
        )
        for idx in range(component_count)
    ]
    return ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=_P53_TIMESTAMP,
        extractor_version="loki-test-fixture",
        extraction_errors=[],
    )


def _run_cli_capture(argv: Sequence[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    """Invoke the CLI in-process; return ``(exit_code, stdout)``.

    Stderr is discarded; this property cares only about stdout
    determinism. ``SystemExit`` from argparse resolves to the
    integer exit code.
    """
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
    return exit_code, captured.out


@settings(
    max_examples=25,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
    deadline=None,
)
@given(component_count=st.integers(min_value=0, max_value=5))
def test_file_and_stdin_modes_produce_equal_stdout(
    component_count: int,
    tmp_path_factory: pytest.TempPathFactory,
    tmp_rules_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """File-vs-stdin equivalence holds for every generated manifest (P53).

    Hypothesis parameterizes the component count over [0, 5];
    for each generated manifest, the test serializes it to JSON,
    writes the JSON to a tempfile, runs ``loki classify <path>``
    and ``loki classify -`` (with the same JSON piped via
    ``monkeypatch.setattr(sys, 'stdin', io.StringIO(...))``),
    and asserts the parsed stdout (with timestamps stripped)
    matches between the two invocations.

    Both invocations also need to produce equal exit codes.
    """
    manifest = _build_manifest(component_count)
    json_text = manifest.model_dump_json(indent=2)

    # File mode invocation.
    tmp_path = tmp_path_factory.mktemp("p53")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json_text, encoding="utf-8")

    file_argv: list[str] = [
        "classify",
        str(manifest_path),
        "--rules-path",
        str(tmp_rules_path),
    ]
    file_exit, file_stdout = _run_cli_capture(file_argv, capsys)

    # Stdin mode invocation. Replace sys.stdin with a StringIO
    # whose ``isatty`` returns False so the TTY guard does not
    # trip.
    fake_stdin = io.StringIO(json_text)
    monkeypatch.setattr(sys, "stdin", fake_stdin)

    stdin_argv: list[str] = [
        "classify",
        "-",
        "--rules-path",
        str(tmp_rules_path),
    ]
    stdin_exit, stdin_stdout = _run_cli_capture(stdin_argv, capsys)

    # Equivalence on exit codes.
    assert file_exit == stdin_exit, (
        f"file mode exit {file_exit}; stdin mode exit {stdin_exit}; "
        f"component_count={component_count}"
    )
    # Equivalence on stdout (modulo timestamps).
    file_payload = strip_record_timestamps(file_stdout)
    stdin_payload = strip_record_timestamps(stdin_stdout)
    assert file_payload == stdin_payload, (
        f"file vs stdin payload diverged at component_count={component_count}; "
        f"file={file_payload!r}; stdin={stdin_payload!r}"
    )
