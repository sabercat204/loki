"""Determinism + R5.6 dual-record passthrough tests (task 20, R9.1-R9.6).

Pins the deterministic-output contract for the classify CLI:

- R9.1 / R9.2: same manifest contents + same rules dir + same
  taxonomy version produce byte-equal stdout (after stripping
  per-record timestamp). Two invocations on the same inputs
  yield identical stdout payloads.
- R9.2 (file vs stdin pin): a non-Hypothesis example test
  reaffirms what P53 (in ``test_stdin_equivalence.py``) covers
  generatively.
- R9.5: environment-derived values (env vars in particular) do
  NOT appear in stdout. Uses ``monkeypatch.setenv`` with a
  distinctive sentinel and asserts the sentinel does not leak.
- R5.6 dual-record passthrough: when the library emits both a
  ``ClassificationRecord`` and a ``ClassificationError`` for
  the same ``component_id`` (the missing-bytes signature-detection
  case), the CLI passes both through without collapse. The test
  monkeypatches ``classify_components`` to emit the dual record
  so the CLI's PASSTHROUGH is what is being pinned, not the
  library's emission.
- R9.6: the stdout JSON deserializes to a dict with exactly the
  keys ``["records", "errors"]``.

The CLI's stdout is deterministic by design (R3.5 dict-literal
key ordering, R3.4 single-newline termination, model_dump(mode=
"json") for primitive normalization). This module verifies the
property holds in practice across a few representative inputs.
"""

from __future__ import annotations

import io
import json
import sys
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
from loki.classification.errors import ClassificationError
from loki.models import ExtractedComponent
from loki.models.classification import (
    AxisClassification,
    ClassificationRecord,
)
from loki.models.config import ClassificationConfig
from loki.models.enums import ClassificationMethod
from tests.classify_cli._helpers import strip_record_timestamps

#: Distinctive env-var value used as a leakage probe in R9.5.
_ENV_LEAK_SENTINEL = "leaked-value-deadbeef-9c5"

#: Run-start timestamp shared across synthetic records for
#: byte-equality comparisons.
_RUN_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _build_axis(label: str) -> AxisClassification:
    return AxisClassification(
        label=label,
        confidence=0.95,
        evidence=[],
        method=ClassificationMethod.RULE,
    )


def _build_record(component: ExtractedComponent) -> ClassificationRecord:
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
    """Build a fake that emits one record per input component."""

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


def _dual_record_classify_factory() -> Callable[..., ClassificationResult]:
    """Build a fake emitting the R5.6 dual-record case for the first component.

    For the first input component, emits BOTH a
    ``ClassificationRecord`` AND a ``ClassificationError`` for
    that component's ``component_id`` (the missing-bytes
    signature-detection case from upstream R5.6). The CLI's
    passthrough contract (R3.8) requires both halves to appear
    in their respective lists without collapse.
    """

    def _fake(
        components: Sequence[ExtractedComponent],
        config: ClassificationConfig,
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
        **_kwargs: object,
    ) -> ClassificationResult:
        if not components:
            return ClassificationResult(records=[], errors=[])
        first = components[0]
        records = [_build_record(first)]
        errors = [
            ClassificationError(
                component_id=first.component_id,
                error_message="signature: missing bytes",
                timestamp=_RUN_TIMESTAMP,
            )
        ]
        return ClassificationResult(records=records, errors=errors)

    return _fake


def _build_three_component_manifest_path(tmp_path: Path) -> Path:
    """Write a 3-component manifest JSON used across the determinism tests."""
    from loki.models import ExtractionManifest, FirmwareImage

    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.determinism")
    image_id = uuid.uuid5(namespace, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/determinism.bin",
        file_hash="f" * 64,
        file_size=4096,
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
            raw_hash="f" * 64,
            component_type_hint=None,
            guid=str(uuid.uuid5(namespace, f"guid-{idx:04d}")),
            name=f"DET_{idx:03d}",
            raw_path=None,
        )
        for idx in range(3)
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


class TestDeterministicStdout:
    """R9.1: same inputs produce byte-equal stdout (modulo timestamps)."""

    def test_two_invocations_produce_byte_equal_stdout(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two CLI runs on identical inputs produce identical stdout."""
        manifest_path = _build_three_component_manifest_path(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _success_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        first_exit, first_stdout, _first_stderr = capture_classify_run(argv)
        second_exit, second_stdout, _second_stderr = capture_classify_run(argv)

        assert first_exit == 0
        assert second_exit == 0
        first_payload = strip_record_timestamps(first_stdout)
        second_payload = strip_record_timestamps(second_stdout)
        assert first_payload == second_payload


class TestFileStdinExampleEquivalence:
    """R9.2 example pin: file mode == stdin mode (non-Hypothesis)."""

    def test_file_and_stdin_modes_produce_equal_stdout(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """File-mode stdout matches stdin-mode stdout (R9.2 example).

        P53 (in test_stdin_equivalence.py) covers this generatively
        via Hypothesis; this test pins the same property as a
        stable example so the contract is visible without Hypothesis.
        """
        manifest_path = _build_three_component_manifest_path(tmp_path)
        json_text = manifest_path.read_text(encoding="utf-8")

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _success_classify_factory(),
        )

        # File mode.
        file_argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        file_exit, file_stdout, _ = capture_classify_run(file_argv)

        # Stdin mode. Replace sys.stdin with a StringIO that
        # advertises non-TTY so the guard does not trip.
        fake_stdin = io.StringIO(json_text)
        monkeypatch.setattr(sys, "stdin", fake_stdin)

        stdin_argv = cli_argv("-", rules_path=str(tmp_rules_path))
        stdin_exit, stdin_stdout, _ = capture_classify_run(stdin_argv)

        assert file_exit == stdin_exit == 0
        assert strip_record_timestamps(file_stdout) == strip_record_timestamps(stdin_stdout)


class TestNoEnvironmentLeakage:
    """R9.5: environment-derived values do not appear in stdout."""

    def test_env_var_does_not_appear_in_stdout(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A distinctive env-var sentinel does not appear in stdout."""
        manifest_path = _build_three_component_manifest_path(tmp_path)

        monkeypatch.setenv("LOKI_TEST_ENV_VAR", _ENV_LEAK_SENTINEL)
        monkeypatch.setattr(
            "loki.classification.classify_components",
            _success_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, stdout, _stderr = capture_classify_run(argv)

        assert exit_code == 0
        assert _ENV_LEAK_SENTINEL not in stdout, f"env-var sentinel leaked into stdout: {stdout!r}"


class TestStdoutResultShape:
    """R9.6: Stdout_Result deserializes to a dict with the canonical keys."""

    def test_stdout_keys_are_records_and_errors(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Stdout_Result top-level keys are exactly ``["records", "errors"]``."""
        manifest_path = _build_three_component_manifest_path(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _success_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, stdout, _stderr = capture_classify_run(argv)

        assert exit_code == 0
        payload = json.loads(stdout)
        assert isinstance(payload, dict)
        assert list(payload.keys()) == ["records", "errors"]


class TestDualRecordPassthrough:
    """R5.6 dual-record passthrough: both halves appear without collapse."""

    def test_dual_record_appears_in_stdout(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both ``ClassificationRecord`` and ``ClassificationError`` survive.

        The CLI's passthrough contract (R3.8) requires both
        halves of the R5.6 dual-record case to appear in their
        respective lists without collapse, deduplication, or
        filtering. The fake monkeypatched classify_components
        emits exactly that case for the first input component.
        """
        manifest_path = _build_three_component_manifest_path(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _dual_record_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, stdout, _stderr = capture_classify_run(argv)

        assert exit_code == 0
        payload = json.loads(stdout)
        # One record + one error, both for the same component_id.
        assert len(payload["records"]) == 1
        assert len(payload["errors"]) == 1
        record_cid = payload["records"][0]["component_id"]
        error_cid = payload["errors"][0]["component_id"]
        assert record_cid == error_cid, (
            f"dual-record component_id should match across record and error; "
            f"got record={record_cid!r}, error={error_cid!r}"
        )
        assert payload["errors"][0]["error_message"] == "signature: missing bytes"
