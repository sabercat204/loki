"""Tests for the ``loki baseline`` CLI subcommand group (task 18).

Covers happy + error paths for each of the five subcommands:
``list``, ``show``, ``import``, ``export``, ``delete``. Every test
isolates itself on ``tmp_path`` via the ``--storage-path`` flag so
the user's real baseline directory is never touched.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.baseline.envelope import serialize
from loki.baseline.naming import filename_for
from loki.baseline.schema import SCHEMA_VERSION
from loki.cli import build_parser, main
from loki.models import BaselineRecord
from tests.baseline.fixtures import synthetic_baseline


def _seed(storage: Path, record: BaselineRecord) -> Path:
    """Drop a Baseline_File into ``storage`` so subcommands can find it."""
    payload = serialize(
        record,
        schema_version=SCHEMA_VERSION,
        written_at=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
        written_by_extractor_version="loki-test-0.1",
    )
    file_path = storage / filename_for(record)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(payload)
    return file_path


# ---------------------------------------------------------------------
# Parser smoke checks
# ---------------------------------------------------------------------


def test_baseline_subcommand_appears_in_parser_help() -> None:
    """``loki --help`` advertises the baseline subcommand group."""
    parser = build_parser()
    formatted = parser.format_help()
    assert "baseline" in formatted


def test_baseline_help_lists_five_subcommands() -> None:
    """``loki baseline --help`` lists list/show/import/export/delete."""
    parser = build_parser()
    # argparse exposes child parsers via the _SubParsersAction's choices.
    import argparse

    baseline_parser = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            baseline_parser = action.choices.get("baseline")
            break
    assert baseline_parser is not None
    help_text = baseline_parser.format_help()
    for name in ("list", "show", "import", "export", "delete"):
        assert name in help_text


# ---------------------------------------------------------------------
# loki baseline list
# ---------------------------------------------------------------------


def test_list_empty_directory_prints_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty Storage_Directory produces empty stdout and exit 0."""
    exit_code = main(["baseline", "--storage-path", str(tmp_path), "list"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_list_sorts_by_vendor_model_version(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.2: rows are ordered by (vendor, model, firmware_version)."""
    a = synthetic_baseline.build(vendor="ZENITH", model="Z9", firmware_version="3.0")
    b = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="1.0")
    c = synthetic_baseline.build(vendor="ACME", model="X1", firmware_version="2.0")
    for record in (a, b, c):
        _seed(tmp_path, record)

    exit_code = main(["baseline", "--storage-path", str(tmp_path), "list"])
    assert exit_code == 0
    out_lines = capsys.readouterr().out.strip().split("\n")
    assert len(out_lines) == 3
    # Each row's first column is baseline_id; second is vendor.
    vendors = [line.split("\t")[1] for line in out_lines]
    versions = [line.split("\t")[3] for line in out_lines]
    assert vendors == ["ACME", "ACME", "ZENITH"]
    assert versions[:2] == ["1.0", "2.0"]


def test_list_reports_quarantine_summary_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.3: quarantined files surface as a stderr summary; exit code stays 0."""
    record = synthetic_baseline.build()
    _seed(tmp_path, record)
    (tmp_path / "broken.yaml").write_bytes(b"::: not yaml :::")

    exit_code = main(["baseline", "--storage-path", str(tmp_path), "list"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "quarantined: 1" in captured.err
    # The good baseline still surfaces on stdout.
    assert str(record.baseline_id) in captured.out


# ---------------------------------------------------------------------
# loki baseline show
# ---------------------------------------------------------------------


def test_show_prints_baseline_as_indented_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.4: show emits ``model_dump_json(indent=2)`` to stdout."""
    record = synthetic_baseline.build()
    _seed(tmp_path, record)

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(tmp_path),
            "show",
            str(record.baseline_id),
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["baseline_id"] == str(record.baseline_id)
    assert payload["vendor"] == record.vendor
    # ``indent=2`` round-trip: the raw stdout has line breaks.
    assert "\n  " in captured.out


def test_show_unknown_baseline_id_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.5: unknown baseline_id exits 2 with stderr message."""
    unknown = uuid.uuid4()
    exit_code = main(["baseline", "--storage-path", str(tmp_path), "show", str(unknown)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "loki baseline show" in captured.err
    assert str(unknown) in captured.err


def test_show_invalid_uuid_returns_2() -> None:
    """A non-UUID baseline_id surfaces as exit 2 before any I/O."""
    with pytest.raises(SystemExit) as excinfo:
        main(["baseline", "--storage-path", "/tmp", "show", "not-a-uuid"])
    assert excinfo.value.code == 2


# ---------------------------------------------------------------------
# loki baseline import
# ---------------------------------------------------------------------


def test_import_loads_and_saves_into_storage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.6: import loads a foreign Baseline_File and saves into the store."""
    record = synthetic_baseline.build()
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    foreign_file = _seed(foreign, record)

    storage = tmp_path / "storage"
    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(storage),
            "import",
            str(foreign_file),
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == filename_for(record)
    # The new file exists in the Storage_Directory.
    assert (storage / filename_for(record)).exists()
    # The foreign file is left untouched.
    assert foreign_file.exists()


def test_import_malformed_file_returns_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A malformed source file surfaces as a serialization error (exit 3)."""
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"::: not yaml :::")
    storage = tmp_path / "storage"

    exit_code = main(["baseline", "--storage-path", str(storage), "import", str(bad)])
    assert exit_code == 3
    captured = capsys.readouterr()
    assert "loki baseline import" in captured.err
    assert "malformed yaml" in captured.err


def test_import_into_existing_collision_returns_5(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Importing onto an existing canonical filename raises exit 5 (already-exists).

    The store's save path raises ``BaselineAlreadyExistsError`` when
    a Baseline_File at the canonical location already exists and
    the importer didn't load it first.
    """
    record = synthetic_baseline.build()
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    foreign_file = _seed(foreign, record)
    # Pre-seed the canonical filename in the storage dir.
    storage = tmp_path / "storage"
    storage.mkdir()
    (storage / filename_for(record)).write_bytes(b"pre-existing\n")

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(storage),
            "import",
            str(foreign_file),
        ]
    )
    assert exit_code == 5
    assert "already exists" in capsys.readouterr().err


# ---------------------------------------------------------------------
# loki baseline export
# ---------------------------------------------------------------------


def test_export_writes_baseline_file_to_arbitrary_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.7: export writes a Baseline_File at the dest path."""
    record = synthetic_baseline.build()
    storage = tmp_path / "storage"
    _seed(storage, record)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    dest = elsewhere / "my-export.yaml"

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(storage),
            "export",
            str(record.baseline_id),
            str(dest),
        ]
    )
    assert exit_code == 0
    assert dest.exists()
    assert capsys.readouterr().out.strip() == str(dest.resolve())
    # The exported file round-trips through the YAML envelope.
    import yaml

    parsed = yaml.safe_load(dest.read_bytes())
    assert parsed["baseline"]["baseline_id"] == str(record.baseline_id)
    assert parsed["schema_version"] == SCHEMA_VERSION


def test_export_unknown_baseline_id_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unknown baseline_id exits 2 without writing anything."""
    unknown = uuid.uuid4()
    dest = tmp_path / "out.yaml"

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(tmp_path),
            "export",
            str(unknown),
            str(dest),
        ]
    )
    assert exit_code == 2
    assert not dest.exists()
    assert "loki baseline export" in capsys.readouterr().err


def test_export_to_missing_parent_returns_6(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dest path whose parent doesn't exist surfaces as exit 6 (unwritable)."""
    record = synthetic_baseline.build()
    storage = tmp_path / "storage"
    _seed(storage, record)
    # ``does-not-exist`` is missing — the atomic-write step trips
    # an OSError that the store converts to
    # ``BaselineStorageUnwritableError``.
    dest = tmp_path / "does-not-exist" / "out.yaml"

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(storage),
            "export",
            str(record.baseline_id),
            str(dest),
        ]
    )
    assert exit_code == 6
    assert "loki baseline export" in capsys.readouterr().err


# ---------------------------------------------------------------------
# loki baseline delete
# ---------------------------------------------------------------------


def test_delete_with_yes_skips_prompt_and_removes_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6.9: ``--yes`` skips the prompt and removes the file."""
    record = synthetic_baseline.build()
    file_path = _seed(tmp_path, record)
    assert file_path.exists()

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(tmp_path),
            "delete",
            "--yes",
            str(record.baseline_id),
        ]
    )
    assert exit_code == 0
    assert not file_path.exists()
    assert capsys.readouterr().out.strip() == str(file_path.resolve())


def test_delete_without_yes_prompts_and_proceeds_on_y(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6.8: prompt accepts ``y`` and proceeds with the delete."""
    record = synthetic_baseline.build()
    file_path = _seed(tmp_path, record)
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(tmp_path),
            "delete",
            str(record.baseline_id),
        ]
    )
    assert exit_code == 0
    assert not file_path.exists()


def test_delete_without_yes_cancels_on_anything_else(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R6.8: any input other than ``y`` cancels the delete."""
    record = synthetic_baseline.build()
    file_path = _seed(tmp_path, record)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(tmp_path),
            "delete",
            str(record.baseline_id),
        ]
    )
    assert exit_code == 0
    # File still exists because the user said no.
    assert file_path.exists()
    assert "cancelled" in capsys.readouterr().err


def test_delete_unknown_baseline_id_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unknown baseline_id exits 2."""
    unknown = uuid.uuid4()
    exit_code = main(
        [
            "baseline",
            "--storage-path",
            str(tmp_path),
            "delete",
            "--yes",
            str(unknown),
        ]
    )
    assert exit_code == 2
    assert "loki baseline delete" in capsys.readouterr().err


# ---------------------------------------------------------------------
# Cross-cutting: the CLI never touches the user's real baseline dir
# ---------------------------------------------------------------------


def test_storage_path_flag_is_required(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Omitting ``--storage-path`` surfaces as an argparse error.

    Tests should never accidentally hit the user's real baseline
    directory; making the flag mandatory is the cheap defense.
    """
    with pytest.raises(SystemExit):
        main(["baseline", "list"])
    captured = capsys.readouterr()
    assert "--storage-path" in captured.err
