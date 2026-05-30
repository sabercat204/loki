"""Tests for the ``loki extract`` CLI subcommand (task 25)."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from loki.cli import build_parser, main
from loki.extraction.extractors.base import clear_registry
from tests.extraction.fixtures import synthetic_microcode, synthetic_uefi_volume


@pytest.fixture(autouse=True)
def _registry_isolation() -> Iterator[None]:
    clear_registry()
    yield
    clear_registry()


def test_extract_subcommand_appears_in_parser_help() -> None:
    """``loki --help`` advertises the extract subcommand."""
    parser = build_parser()
    formatted = parser.format_help()
    assert "extract" in formatted


def test_extract_help_describes_arguments() -> None:
    """``loki extract --help`` documents path + the three optional flags."""
    parser = build_parser()
    # Pull the subparser for ``extract`` directly out of the dispatcher.
    extract_parser = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            extract_parser = action.choices.get("extract")
            break
    assert extract_parser is not None
    help_text = extract_parser.format_help()
    assert "path" in help_text
    assert "--output-dir" in help_text
    assert "--max-component-size" in help_text
    assert "--timeout-per-component" in help_text


def test_extract_happy_path_emits_manifest_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Extracting the synthetic UEFI volume produces JSON on stdout."""
    binary = synthetic_uefi_volume.build(tmp_path / "fixture")
    output_dir = tmp_path / "out"

    exit_code = main(
        [
            "extract",
            str(binary),
            "--output-dir",
            str(output_dir),
            "--max-component-size",
            "10000000",
            "--timeout-per-component",
            "30",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["total_components"] == 1
    assert payload["extractor_version"] == "0.1.0"
    # Diagnostic counters land on stderr.
    assert "1 components" in captured.err
    assert "duration=" in captured.err
    # raw_path was populated because --output-dir was given.
    assert payload["components"][0]["raw_path"] is not None


def test_extract_without_output_dir_leaves_raw_path_null(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No ``--output-dir`` means raw_path stays null in the manifest."""
    binary = synthetic_microcode.build(tmp_path / "fixture")
    exit_code = main(["extract", str(binary)])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert all(c["raw_path"] is None for c in payload["components"])


def test_extract_missing_path_returns_nonzero_with_clean_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Missing path produces exit code 2 and a single-line stderr message."""
    exit_code = main(["extract", str(tmp_path / "nonexistent.rom")])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == ""  # no manifest on stdout for failed runs
    assert "loki extract:" in captured.err
    assert "path does not exist" in captured.err
    # No Python traceback bleeds out.
    assert "Traceback" not in captured.err


def test_extract_empty_file_returns_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty input also exits non-zero with a clean error."""
    target = tmp_path / "empty.rom"
    target.write_bytes(b"")
    exit_code = main(["extract", str(target)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "file is empty" in captured.err
    assert "Traceback" not in captured.err


def test_extract_unrecognized_format_still_succeeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Out-of-scope format yields exit code 0 plus a manifest with one error."""
    target = tmp_path / "garbage.rom"
    target.write_bytes(b"\x00" * 4096)
    exit_code = main(["extract", str(target)])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_components"] == 0
    assert any(
        "OUT_OF_SCOPE_FORMAT" in err["error_message"] for err in payload["extraction_errors"]
    )


# ---------------------------------------------------------------------
# --progress flag
# ---------------------------------------------------------------------


def test_extract_progress_emits_lines_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--progress`` writes one line per ProgressEvent to stderr."""
    binary = synthetic_uefi_volume.build(tmp_path / "fixture")

    exit_code = main(
        [
            "extract",
            str(binary),
            "--progress",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    # Manifest JSON still goes to stdout untouched.
    payload = json.loads(captured.out)
    assert payload["total_components"] == 1
    # Stderr has at least one progress line per phase plus the summary.
    stderr_lines = captured.err.strip().split("\n")
    progress_lines = [line for line in stderr_lines if line.startswith("[")]
    # input-check + detect + extract + manifest_summary line. We
    # don't pin the exact count because the pipeline emits a
    # variable number of "extract" events depending on component
    # count, but we expect at least three distinct phases.
    phases = {line.split("]", 1)[0].strip("[ ") for line in progress_lines}
    assert "input-check" in phases
    assert "detect" in phases
    assert "extract" in phases


def test_extract_progress_off_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without ``--progress``, stderr only carries the summary line."""
    binary = synthetic_uefi_volume.build(tmp_path / "fixture")

    exit_code = main(["extract", str(binary)])

    assert exit_code == 0
    captured = capsys.readouterr()
    stderr_lines = captured.err.strip().split("\n")
    progress_lines = [line for line in stderr_lines if line.startswith("[")]
    # No progress events should fire when the flag is off.
    assert progress_lines == []
    # Summary line is still present.
    assert any("components" in line and "duration=" in line for line in stderr_lines)


def test_extract_progress_does_not_pollute_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The manifest JSON on stdout is unchanged when ``--progress`` is on.

    Pipe-friendliness contract: callers piping
    ``loki extract --progress`` into ``jq`` (or any other JSON
    consumer) shouldn't see progress noise mixed into stdout.
    Compares the component ids — those are deterministic from
    the firmware bytes — rather than the full JSON, since
    timestamps drift legitimately between runs.
    """
    binary = synthetic_uefi_volume.build(tmp_path / "fixture")

    exit_code_off = main(["extract", str(binary)])
    assert exit_code_off == 0
    stdout_off = json.loads(capsys.readouterr().out)

    exit_code_on = main(["extract", str(binary), "--progress"])
    assert exit_code_on == 0
    stdout_on = json.loads(capsys.readouterr().out)

    # Component ids are deterministic; timestamps are not. Compare
    # the deterministic surface to confirm --progress doesn't
    # corrupt the manifest payload itself.
    ids_off = sorted(c["component_id"] for c in stdout_off["components"])
    ids_on = sorted(c["component_id"] for c in stdout_on["components"])
    assert ids_off == ids_on
    assert stdout_off["total_components"] == stdout_on["total_components"]
    assert stdout_off["source_image"]["file_hash"] == stdout_on["source_image"]["file_hash"]
