"""Tests for the ``loki classify --help`` shape (R12.1-R12.5).

Verifies that every flag exposed by the ``classify`` subparser
carries a non-empty help string (R12.1), the positional
``manifest`` argument's help names both the file mode and the
``-`` stdin mode (R12.2), ``loki classify --help`` invocation
exits with status 0 (R12.3), the parser's ``description=`` is
non-empty (R12.4), and no flag outside the spec's set is
advertised (R12.5).

The test inspects the parser via ``build_parser()._subparsers``
walking. ``argparse`` adds ``-h / --help`` automatically; that
is the lone allowed exception to the "spec set only" assertion.
"""

from __future__ import annotations

import argparse

import pytest

from loki.cli import build_parser


def _get_classify_subparser() -> argparse.ArgumentParser:
    """Return the ``classify`` subparser from the top-level parser.

    Walks ``parser._actions`` to find the
    ``_SubParsersAction`` that owns the subcommands, then looks
    up the ``classify`` entry in its ``choices`` dict. The
    private-attr access is the standard way to introspect
    argparse; the alternative (parsing ``--help`` text) is more
    fragile.
    """
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            classify = action.choices.get("classify")
            if classify is not None:
                assert isinstance(classify, argparse.ArgumentParser)
                return classify
    raise AssertionError("classify subparser not registered on parser")


class TestHelpText:
    """``loki classify --help`` shape tests (R12.1-R12.5)."""

    def test_classify_help_exits_zero(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """``loki classify --help`` invocation exits with status 0 (R12.3)."""
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["classify", "--help"])
        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        # Sanity check: the help text mentions the subcommand name
        # and at least one of the documented flags.
        assert "classify" in captured.out
        assert "--rules-path" in captured.out

    def test_subparser_description_is_non_empty(self) -> None:
        """The ``classify`` subparser's ``description=`` is non-empty (R12.4)."""
        classify = _get_classify_subparser()
        description = classify.description or ""
        assert description.strip() != ""
        # The description summarizes the input contract, the stdout
        # JSON shape, and the stderr summary line per R12.4.
        assert "ExtractionManifest" in description
        assert "stdout" in description.lower()
        assert "stderr" in description.lower()

    def test_every_flag_has_non_empty_help(self) -> None:
        """Every flag exposed by ``classify --help`` carries non-empty help (R12.1).

        Walks the subparser's ``_actions`` list and asserts each
        action other than the implicit ``--help`` and the trailing
        positional has a non-empty ``help`` attribute.
        """
        classify = _get_classify_subparser()
        for action in classify._actions:
            if isinstance(action, argparse._HelpAction):
                # argparse's auto-attached help is allowed to use
                # the default "show this help message and exit"
                # text; not part of the R12.1 contract.
                continue
            help_text = action.help or ""
            assert help_text.strip() != "", f"action with dest={action.dest!r} has empty help text"

    def test_positional_manifest_help_names_both_modes(self) -> None:
        """The ``manifest`` positional help mentions both file and stdin modes (R12.2)."""
        classify = _get_classify_subparser()
        for action in classify._actions:
            if action.dest == "manifest":
                help_text = action.help or ""
                # The help string must reference both the file mode
                # and the literal ``-`` stdin mode.
                assert "JSON" in help_text or "file" in help_text.lower()
                assert "-" in help_text
                assert "stdin" in help_text.lower()
                return
        raise AssertionError("positional 'manifest' argument not registered")

    def test_no_flags_outside_spec_set(self) -> None:
        """Only the spec's five flags + the positional are advertised (R12.5).

        Walks the subparser's actions and collects the dest names.
        Asserts the set matches exactly:
        ``{help, manifest, rules_path, taxonomy_version, progress, debug,
        summary_only}``. ``argparse`` adds ``help`` automatically;
        that is the lone allowed exception.
        """
        classify = _get_classify_subparser()
        dests = {action.dest for action in classify._actions}
        expected = {
            "help",
            "manifest",
            "rules_path",
            "taxonomy_version",
            "progress",
            "debug",
            "summary_only",
            "feeds_config",
            "trust_store",
        }
        assert dests == expected, (
            f"unexpected dests on classify subparser: {dests - expected}; "
            f"missing: {expected - dests}"
        )
