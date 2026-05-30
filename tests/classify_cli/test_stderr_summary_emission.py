"""P57 Stderr_Summary_Line emission discipline test (task 16, R4.1, R4.5, R4.6, R13.5).

Pins the four-case emission contract: the summary line is
emitted on every successful run, every partially-cancelled run,
and every per-component-error run; it is NOT emitted on
whole-run failures.

The four cases:

(a) Successful run -> exit 0, summary line emitted.
(b) Partially-cancelled run (cancellation at iteration 2 of 5)
    -> exit 130, summary line emitted with N-1 records.
(c) Per-component-error run -> exit 0, summary line emitted
    (per-component errors are non-fatal per R6.6).
(d) Whole-run failure (ClassificationConfigError) -> exit 6,
    summary line NOT emitted.

Each case monkeypatches the library's ``classify_components``
to inject the desired outcome at the appropriate point.
``test_stderr_summary.py`` (task 9) covered the format string
at the helper level; this module covers the handler-level
emission discipline.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.classification import (
    CancellationToken,
    ClassificationResult,
    ProgressCallback,
)
from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationError,
)
from loki.classify_helpers import _CancelFlag
from loki.models import ExtractedComponent
from loki.models.classification import (
    AxisClassification,
    ClassificationRecord,
)
from loki.models.config import ClassificationConfig
from loki.models.enums import ClassificationMethod

# Canonical run timestamp for synthetic records produced by
# the fakes in this module.
_RUN_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

#: Regex matching the documented summary line shape (R4.2). Captures
#: the four interpolated values for case-specific assertions.
_SUMMARY_RE = re.compile(
    r"^classify: (?P<n>\d+) records \((?P<k>\d+) need_review\), "
    r"(?P<e>\d+) errors, duration=(?P<s>\d+\.\d{4})s$"
)


def _build_axis(label: str) -> AxisClassification:
    """Synthetic axis with confidence above the needs_review threshold."""
    return AxisClassification(
        label=label,
        confidence=0.95,
        evidence=[],
        method=ClassificationMethod.RULE,
    )


def _build_record(component: ExtractedComponent) -> ClassificationRecord:
    """Synthetic ``ClassificationRecord`` for a component."""
    return ClassificationRecord(
        component_id=component.component_id,
        source_image_id=component.source_image_id,
        extraction_offset=component.offset,
        timestamp=_RUN_TIMESTAMP,
        type_axis=_build_axis("UEFI_DRIVER"),
        vendor_axis=_build_axis("INTEL"),
        security_axis=_build_axis("SECURE"),
        mutability_axis=_build_axis("READONLY"),
        cve_matches=[],
        suspicion_triggers=[],
        classification_version="loki-test",
        overrides=[],
    )


def _success_classify_factory() -> Callable[..., ClassificationResult]:
    """Build a fake that returns a record per input component (case a)."""

    def _fake(
        components: Sequence[ExtractedComponent],
        config: ClassificationConfig,
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
        **_kwargs: object,
    ) -> ClassificationResult:
        records = [_build_record(c) for c in components]
        return ClassificationResult(records=records, errors=[])

    return _fake


def _per_component_error_classify_factory() -> Callable[..., ClassificationResult]:
    """Build a fake that records per-component errors but returns exit 0 (case c).

    Mirrors the upstream library's per-component-error contract
    (R9.3 of classification-pipeline): errors are non-fatal and
    accumulate inside ``ClassificationResult.errors``; the
    library does not raise. The CLI handler treats this as a
    success path for exit-code purposes (R6.6).
    """

    def _fake(
        components: Sequence[ExtractedComponent],
        config: ClassificationConfig,
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
        **_kwargs: object,
    ) -> ClassificationResult:
        records: list[ClassificationRecord] = []
        errors: list[ClassificationError] = []
        for index, component in enumerate(components):
            if index == 1:
                # Inject a per-component error for the second
                # component; carry on with the rest.
                errors.append(
                    ClassificationError(
                        component_id=component.component_id,
                        error_message="synthetic per-component failure",
                        timestamp=_RUN_TIMESTAMP,
                    )
                )
                continue
            records.append(_build_record(component))
        return ClassificationResult(records=records, errors=errors)

    return _fake


def _cancellation_classify_factory(
    *,
    cancel_at_index: int,
    cancel_flag: _CancelFlag,
) -> Callable[..., ClassificationResult]:
    """Build a fake that flips the cancel flag at iteration K (case b).

    Mirrors the cancellation pattern from ``test_cancellation.py``:
    at iteration ``cancel_at_index`` the fake flips the test-owned
    ``cancel_flag.value`` to True and re-checks the cancel
    callback so the current iteration is cancelled rather than
    the next one. K-1 records get appended before the
    Cancellation_Marker is recorded.
    """

    def _fake(
        components: Sequence[ExtractedComponent],
        config: ClassificationConfig,
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
        **_kwargs: object,
    ) -> ClassificationResult:
        records: list[ClassificationRecord] = []
        errors: list[ClassificationError] = []
        for index, component in enumerate(components, start=1):
            if cancel is not None and cancel():
                errors.append(
                    ClassificationError(
                        component_id=None,
                        error_message="classification cancelled by caller",
                        timestamp=_RUN_TIMESTAMP,
                    )
                )
                break
            if index == cancel_at_index:
                cancel_flag.value = True
                if cancel is not None and cancel():
                    errors.append(
                        ClassificationError(
                            component_id=None,
                            error_message="classification cancelled by caller",
                            timestamp=_RUN_TIMESTAMP,
                        )
                    )
                    break
            records.append(_build_record(component))
        return ClassificationResult(records=records, errors=errors)

    return _fake


def _config_error_classify_factory(
    rules_path: Path,
) -> Callable[..., ClassificationResult]:
    """Build a fake that raises ClassificationConfigError (case d)."""

    def _fake(
        components: Sequence[ExtractedComponent],
        config: ClassificationConfig,
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
        **_kwargs: object,
    ) -> ClassificationResult:
        raise ClassificationConfigError(rules_path, "synthetic taxonomy mismatch")

    return _fake


def _install_test_sigint_handler_factory(
    cancel_flag: _CancelFlag,
) -> Callable[[], tuple[_CancelFlag, Callable[[], None]]]:
    """Replacement for ``_install_sigint_handler`` returning a known flag."""

    def _factory() -> tuple[_CancelFlag, Callable[[], None]]:
        return cancel_flag, lambda: None

    return _factory


def _build_five_component_manifest_path(tmp_path: Path) -> Path:
    """Write a 5-component manifest JSON to ``tmp_path/manifest.json``.

    The 5-component count matches the cancellation parameterization
    from ``test_cancellation.py`` so the partial-cancellation case
    has predictable record counts.
    """
    from loki.models import ExtractionManifest, FirmwareImage

    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.p57")
    image_id = uuid.uuid5(namespace, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/p57.bin",
        file_hash="e" * 64,
        file_size=8192,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        ExtractedComponent(
            component_id=uuid.uuid5(namespace, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512,
            raw_hash="e" * 64,
            component_type_hint=None,
            guid=str(uuid.uuid5(namespace, f"guid-{idx:04d}")),
            name=f"P57_{idx:03d}",
            raw_path=None,
        )
        for idx in range(5)
    ]
    manifest = ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=_RUN_TIMESTAMP,
        extractor_version="loki-test-fixture",
        extraction_errors=[],
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest_path


class TestStderrSummaryEmissionDiscipline:
    """Four-case parameterized P57 emission discipline (R4.1, R4.5, R4.6)."""

    def test_a_success_emits_summary(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Case (a): clean success run -> exit 0, summary emitted (R4.1)."""
        manifest_path = _build_five_component_manifest_path(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _success_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        # Exactly one summary line, matching the documented format.
        summary_lines = [ln for ln in stderr.splitlines() if ln.startswith("classify: ")]
        assert len(summary_lines) == 1, f"expected exactly one summary line; got {summary_lines}"
        match = _SUMMARY_RE.match(summary_lines[0])
        assert match is not None, f"summary line shape mismatch: {summary_lines[0]!r}"
        # Five components -> five records on the success path.
        assert match.group("n") == "5"
        assert match.group("e") == "0"

    def test_b_partial_cancellation_emits_summary(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Case (b): cancellation at iteration 2 -> exit 130, summary emitted."""
        manifest_path = _build_five_component_manifest_path(tmp_path)

        cancel_flag = _CancelFlag(value=False)
        monkeypatch.setattr(
            "loki.classify_helpers._install_sigint_handler",
            _install_test_sigint_handler_factory(cancel_flag),
        )
        monkeypatch.setattr(
            "loki.classification.classify_components",
            _cancellation_classify_factory(
                cancel_at_index=2,
                cancel_flag=cancel_flag,
            ),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 130
        # Summary emitted on the partial-cancellation path (R4.1, R4.6).
        summary_lines = [ln for ln in stderr.splitlines() if ln.startswith("classify: ")]
        assert len(summary_lines) == 1
        match = _SUMMARY_RE.match(summary_lines[0])
        assert match is not None
        # cancel_at_index=2 yields N-1 = 1 record.
        assert match.group("n") == "1"
        # The cancellation marker is the single error.
        assert match.group("e") == "1"

    def test_c_per_component_error_emits_summary(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Case (c): per-component error -> exit 0, summary emitted (R6.6)."""
        manifest_path = _build_five_component_manifest_path(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _per_component_error_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        # R6.6: per-component errors are non-fatal; exit 0 holds.
        assert exit_code == 0
        summary_lines = [ln for ln in stderr.splitlines() if ln.startswith("classify: ")]
        assert len(summary_lines) == 1
        match = _SUMMARY_RE.match(summary_lines[0])
        assert match is not None
        # 5 inputs - 1 error = 4 records, 1 error.
        assert match.group("n") == "4"
        assert match.group("e") == "1"

    def test_d_whole_run_failure_does_not_emit_summary(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Case (d): ClassificationConfigError -> exit 6, NO summary line (R4.5)."""
        manifest_path = _build_five_component_manifest_path(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _config_error_classify_factory(tmp_rules_path),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 6
        # R4.5: NO summary line on whole-run failure.
        summary_lines = [ln for ln in stderr.splitlines() if ln.startswith("classify: ")]
        assert summary_lines == [], (
            f"summary line MUST NOT be emitted on whole-run failure; got {summary_lines}"
        )
        # The typed-error message line IS emitted (R8.3).
        assert "loki classify: configuration error:" in stderr
