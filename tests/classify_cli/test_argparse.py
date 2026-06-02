"""Argparse-level acceptance tests for ``loki classify`` (R1.10, R2.2, P54).

Verifies that:

- argparse rejects an invocation missing ``--rules-path`` with
  exit 2 (R2.2 + P54 — argparse's standard error-handling path).
- argparse accepts the four-flag baseline
  (``classify <manifest> --rules-path <dir>``) without raising.
- argparse rejects two positional arguments per R1.10 (the
  ``manifest`` positional is single-valued in v1).

These tests do not invoke the handler; they exercise argparse
parsing only. The handler is exercised by the exit-code tests
in ``test_exit_codes.py`` (task 11).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loki.cli import build_parser


class TestArgparseAcceptsBaseline:
    """Acceptance tests for the four-flag baseline (R1.1, R2.1)."""

    def test_baseline_invocation_parses_cleanly(self) -> None:
        """``classify <manifest> --rules-path <dir>`` parses without raising."""
        parser = build_parser()
        args = parser.parse_args(["classify", "manifest.json", "--rules-path", "/tmp/rules"])
        assert args.command == "classify"
        assert args.manifest == "manifest.json"
        # ``--rules-path`` is type=Path; compare via ``Path`` equality so
        # the assertion is platform-agnostic (Windows renders this as
        # ``\tmp\rules`` while POSIX renders it as ``/tmp/rules``;
        # ``Path`` equality treats them as the same path).
        assert args.rules_path == Path("/tmp/rules")
        # Defaults applied correctly.
        assert args.taxonomy_version == "1.0.0"
        assert args.progress is False
        assert args.debug is False
        assert args.summary_only is False

    def test_stdin_dash_invocation_parses_cleanly(self) -> None:
        """``classify - --rules-path <dir>`` parses without raising (R1.4)."""
        parser = build_parser()
        args = parser.parse_args(["classify", "-", "--rules-path", "/tmp/rules"])
        # The literal ``-`` survives because ``manifest`` is type=str,
        # not type=Path.
        assert args.manifest == "-"

    def test_all_optional_flags_parse_cleanly(self) -> None:
        """All four boolean / string flags can be combined without errors."""
        parser = build_parser()
        args = parser.parse_args(
            [
                "classify",
                "manifest.json",
                "--rules-path",
                "/tmp/rules",
                "--taxonomy-version",
                "2.0.0",
                "--progress",
                "--debug",
                "--summary-only",
            ]
        )
        assert args.taxonomy_version == "2.0.0"
        assert args.progress is True
        assert args.debug is True
        assert args.summary_only is True


class TestArgparseRejects:
    """Rejection tests for malformed invocations (R1.10, R2.2, P54)."""

    def test_missing_rules_path_exits_2(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Missing ``--rules-path`` triggers argparse exit 2 (R2.2, P54).

        ``argparse``'s standard error-handling raises ``SystemExit(2)``
        with the message
        ``error: the following arguments are required: --rules-path``.
        """
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["classify", "manifest.json"])
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "--rules-path" in captured.err

    def test_missing_manifest_exits_2(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Missing positional ``manifest`` triggers argparse exit 2 (P54)."""
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["classify", "--rules-path", "/tmp/rules"])
        assert excinfo.value.code == 2

    def test_two_positional_arguments_rejected(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Two positionals trigger argparse exit 2 (R1.10).

        The CLI accepts exactly one positional ``manifest`` value;
        multi-manifest fan-in is out of scope per R1.10.
        """
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(
                [
                    "classify",
                    "a.json",
                    "b.json",
                    "--rules-path",
                    "/tmp/rules",
                ]
            )
        assert excinfo.value.code == 2

    def test_unknown_flag_rejected(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An unknown flag (e.g. ``--from-firmware``) triggers argparse exit 2.

        Pinned because R1.10's "no ``--from-firmware`` in v1"
        claim is structurally enforced by argparse: the flag is
        not declared, so any invocation that includes it bounces
        out with exit 2.
        """
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(
                [
                    "classify",
                    "manifest.json",
                    "--rules-path",
                    "/tmp/rules",
                    "--from-firmware",
                    "/tmp/fw.bin",
                ]
            )
        assert excinfo.value.code == 2
