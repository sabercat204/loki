"""Tests for ``_load_manifest`` covering R1.2-R1.8.

Pins the file-vs-stdin equivalence on the input side, the
TTY guard on stdin (R1.5, D4 default — fires FIRST when the
positional argument is the literal ``-``), the file-readability
catch (R1.6), the JSON-parse catch (R1.7), and the Pydantic
strict-mode validation catch (R1.8). The stdout-side equivalence
property (P53) is pinned by a separate Hypothesis test in
``test_stdin_equivalence.py`` (task 14).

All tests invoke ``_load_manifest`` directly; the handler-level
integration is exercised by tests under ``test_exit_codes.py``
(task 11).
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from loki.classify_helpers import _load_manifest
from loki.models.firmware import ExtractionManifest


class TestLoadManifestFilePath:
    """File-path input tests (R1.2, R1.3, R1.6)."""

    def test_valid_file_returns_manifest(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
    ) -> None:
        """A valid file path resolves to an ``ExtractionManifest``."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        result = _load_manifest(str(manifest_path))

        assert isinstance(result, ExtractionManifest)
        assert result.total_components == 3

    def test_missing_path_returns_exit_code_2(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A path that does not exist resolves to exit code 2 (R1.6)."""
        missing_path = tmp_path / "does-not-exist.json"

        result = _load_manifest(str(missing_path))

        assert result == 2
        captured = capsys.readouterr()
        assert "cannot read manifest" in captured.err
        assert str(missing_path) in captured.err

    def test_directory_path_returns_exit_code_2(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A path that is a directory cannot be read; exit code 2 (R1.6)."""
        dir_path = tmp_path / "a-dir"
        dir_path.mkdir()

        result = _load_manifest(str(dir_path))

        assert result == 2
        captured = capsys.readouterr()
        assert "cannot read manifest" in captured.err

    def test_invalid_json_returns_exit_code_2(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A file whose contents are not valid JSON yields exit 2 (R1.7)."""
        bad_path = tmp_path / "bad.json"
        bad_path.write_text("{this is not json", encoding="utf-8")

        result = _load_manifest(str(bad_path))

        assert result == 2
        captured = capsys.readouterr()
        assert "manifest is not valid JSON" in captured.err

    def test_pydantic_validation_failure_returns_exit_code_2(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A JSON document missing a required ``ExtractionManifest`` field

        yields exit 2 with a bounded validation summary on stderr (R1.8,
        R10.4). The summary format mirrors
        ``loki/classification/pipeline.py:_summarize``: error count plus
        the first error's loc and msg, no field values reproduced.
        """
        # Drop the required ``source_image`` field; Pydantic strict
        # mode flags it as missing.
        broken_path = tmp_path / "broken.json"
        broken_path.write_text(
            (
                "{"
                '"components": [],'
                '"extraction_timestamp": "2026-01-01T00:00:00+00:00",'
                '"extractor_version": "x"'
                "}"
            ),
            encoding="utf-8",
        )

        result = _load_manifest(str(broken_path))

        assert result == 2
        captured = capsys.readouterr()
        assert "manifest failed validation" in captured.err
        # Bounded summary: error count appears, error message
        # references the missing required field.
        assert "error(s)" in captured.err


class TestLoadManifestStdin:
    """Stdin input tests (R1.4, R1.5)."""

    def test_tty_guard_fires_first(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """When stdin is a TTY, exit 2 immediately (R1.5, D4 default).

        The guard fires BEFORE any read attempt, so an interactive
        operator who typed ``loki classify -`` sees the error
        instantly rather than blocking on a stdin read that will
        never complete.
        """
        # Make stdin look like a TTY without actually reading from it.
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        result = _load_manifest("-")

        assert result == 2
        captured = capsys.readouterr()
        assert "stdin is a TTY" in captured.err
        assert "pipe a manifest or pass a path" in captured.err

    def test_stdin_success_returns_manifest(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sample_manifest_json: str,
    ) -> None:
        """Piped stdin contents validate to an ``ExtractionManifest`` (R1.4)."""
        # Replace sys.stdin with a StringIO whose isatty() returns False.
        fake_stdin = io.StringIO(sample_manifest_json)
        monkeypatch.setattr(sys, "stdin", fake_stdin)

        result = _load_manifest("-")

        assert isinstance(result, ExtractionManifest)
        assert result.total_components == 3

    def test_stdin_invalid_json_returns_exit_code_2(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Stdin with invalid JSON yields exit 2 (R1.7) on the same path."""
        fake_stdin = io.StringIO("{not json")
        monkeypatch.setattr(sys, "stdin", fake_stdin)

        result = _load_manifest("-")

        assert result == 2
        captured = capsys.readouterr()
        assert "manifest is not valid JSON" in captured.err
