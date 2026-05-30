"""Exit-code resolution tests for ``_handle_classify`` (R8.1-R8.7, P54).

Pins the exit-code totality contract: every code path resolves to
one of ``{0, 2, 3, 4, 5, 6, 130}``. Per-typed-error coverage uses
``monkeypatch`` to inject a ``classify_components`` shim that
raises each documented exception class, then verifies the stderr
message format and the returned exit code.

R4.5 emission discipline is also pinned: the typed-error message
line is emitted on whole-run failures and the summary line is
NOT emitted; conversely the summary line IS emitted on success
paths (R4.1).

R3.7 serialization-error coverage uses ``monkeypatch`` to make
``_serialize_result`` raise ``TypeError``; verifies stderr
message + exit 3.

The ``capture_classify_run`` fixture wraps ``loki.cli.main`` with
``capsys`` capture; per the design's "in-process invocation"
pattern.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from loki.classification import ClassificationResult
from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationPipelineError,
    ClassificationRuleError,
)


def _empty_result() -> ClassificationResult:
    """Return an empty ``ClassificationResult`` for monkeypatched returns."""
    return ClassificationResult(records=[], errors=[])


class TestExitCodeTotality:
    """Every code path resolves to ``{0, 2, 3, 4, 5, 6, 130}`` (R8.1, P54)."""

    def test_success_path_returns_zero(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A clean run with monkeypatched library returns exit 0 (R8.1)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            return _empty_result()

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        assert exit_code in {0, 2, 3, 4, 5, 6, 130}
        # Summary line emitted on success (R4.1).
        assert "classify: 0 records (0 need_review), 0 errors" in stderr

    def test_bad_input_returns_two(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        """A nonexistent manifest path returns exit 2 (R1.6 + R8.1)."""
        argv = cli_argv(
            str(tmp_path / "does-not-exist.json"),
            rules_path=str(tmp_rules_path),
        )
        exit_code, _stdout, _stderr = capture_classify_run(argv)

        assert exit_code == 2
        assert exit_code in {0, 2, 3, 4, 5, 6, 130}


class TestTypedErrorMapping:
    """Each typed exception maps to the correct exit code + stderr line.

    R8.3: ClassificationConfigError -> exit 6.
    R8.4: ClassificationRuleError   -> exit 5.
    R8.5: ClassificationPipelineError (catchall) -> exit 4.
    R8.6: any other Exception (unexpected) -> exit 4.
    """

    def test_config_error_returns_six(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ClassificationConfigError -> exit 6 with documented stderr line (R8.3)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            raise ClassificationConfigError(tmp_rules_path, "missing rules dir")

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 6
        assert "loki classify: configuration error:" in stderr
        # R4.5: summary line NOT emitted on whole-run failure.
        assert "classify: " not in stderr or "configuration error:" in stderr
        # More precise: the summary line uses the prefix
        # "classify: <N> records" specifically.
        assert "records (" not in stderr

    def test_rule_error_returns_five(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ClassificationRuleError -> exit 5 with documented stderr line (R8.4)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            raise ClassificationRuleError(
                tmp_rules_path / "type.yaml",
                "fixture.type.001",
                "bad effect label",
            )

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 5
        assert "loki classify: rule error:" in stderr
        # R4.5: summary line NOT emitted on whole-run failure.
        assert "records (" not in stderr

    def test_pipeline_error_returns_four(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ClassificationPipelineError catchall -> exit 4 (R8.5).

        The base class is caught directly here; subclasses
        (ConfigError, RuleError) are handled by their dedicated
        ``except`` clauses earlier in the chain.
        """
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            raise ClassificationPipelineError("generic pipeline failure")

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 4
        assert "loki classify: pipeline error:" in stderr
        # R4.5: summary line NOT emitted on whole-run failure.
        assert "records (" not in stderr

    def test_unexpected_exception_returns_four(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unexpected ``Exception`` -> exit 4 with the documented format (R8.6).

        Format: ``loki classify: unexpected error: <type>: <message>``.
        """
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            raise RuntimeError("unexpected boom")

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 4
        # R8.6 format: "unexpected error: <type>: <message>".
        assert "loki classify: unexpected error: RuntimeError: unexpected boom" in stderr
        # R4.5: summary line NOT emitted on whole-run failure.
        assert "records (" not in stderr


class TestSerializationError:
    """R3.7: serialization failure -> exit 3 with ``failed to serialize`` line."""

    def test_serialize_typeerror_returns_three(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_serialize_result`` raising ``TypeError`` -> exit 3 (R3.7)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            return _empty_result()

        def _broken_serialize(result: ClassificationResult) -> str:
            raise TypeError("non-serializable object in records")

        monkeypatch.setattr("loki.classification.classify_components", _fake)
        monkeypatch.setattr(
            "loki.classify_helpers._serialize_result",
            _broken_serialize,
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, stdout, stderr = capture_classify_run(argv)

        assert exit_code == 3
        assert "loki classify: failed to serialize result:" in stderr
        # The partial JSON SHALL NOT have been written to stdout
        # (R3.7 explicit clause).
        assert stdout == ""
        # R4.5: summary line NOT emitted (the serialization-error
        # path returns before Step 7).
        assert "records (" not in stderr

    def test_serialize_valueerror_returns_three(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_serialize_result`` raising ``ValueError`` -> exit 3 (R3.7).

        Two error classes are caught at the serialization site:
        ``TypeError`` (non-serializable type) and ``ValueError``
        (bad value despite ``model_dump(mode="json")``).
        """
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            return _empty_result()

        def _broken_serialize(result: ClassificationResult) -> str:
            raise ValueError("invalid value during json.dumps")

        monkeypatch.setattr("loki.classification.classify_components", _fake)
        monkeypatch.setattr(
            "loki.classify_helpers._serialize_result",
            _broken_serialize,
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, stdout, stderr = capture_classify_run(argv)

        assert exit_code == 3
        assert "loki classify: failed to serialize result:" in stderr
        assert stdout == ""


class TestSummaryLineEmissionDiscipline:
    """R4.1, R4.5: summary IS emitted on success, NOT on whole-run failure."""

    def test_summary_emitted_on_success(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A success path emits exactly one summary line (R4.1)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            return _empty_result()

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        # The summary line carries the documented format.
        assert "classify: 0 records (0 need_review), 0 errors, duration=" in stderr

    def test_summary_not_emitted_on_config_error(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No summary line on whole-run config-error failure (R4.5)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            raise ClassificationConfigError(tmp_rules_path, "boom")

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 6
        # Stricter R4.5 check: the literal summary-line prefix
        # "classify: <N> records" SHALL NOT appear.
        assert "records (" not in stderr

    def test_summary_not_emitted_on_serialization_error(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No summary line on serialization-error failure (R4.5)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            return _empty_result()

        def _broken_serialize(result: ClassificationResult) -> str:
            raise TypeError("boom")

        monkeypatch.setattr("loki.classification.classify_components", _fake)
        monkeypatch.setattr(
            "loki.classify_helpers._serialize_result",
            _broken_serialize,
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 3
        assert "records (" not in stderr


class TestSummaryOnlyFlag:
    """``--summary-only`` suppresses stdout, retains the summary line (R3.6)."""

    def test_summary_only_skips_stdout(
        self,
        tmp_path: Path,
        sample_manifest_json: str,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--summary-only`` writes zero bytes to stdout (R3.6)."""
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(sample_manifest_json, encoding="utf-8")

        def _fake(*args: object, **kwargs: object) -> ClassificationResult:
            return _empty_result()

        monkeypatch.setattr("loki.classification.classify_components", _fake)

        argv = cli_argv(
            str(manifest_path),
            rules_path=str(tmp_rules_path),
            summary_only=True,
        )
        exit_code, stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        # R3.6: stdout suppressed entirely.
        assert stdout == ""
        # The summary line still goes to stderr.
        assert "classify: 0 records (0 need_review), 0 errors" in stderr
