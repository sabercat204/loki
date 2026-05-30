"""Deterministic in-process cancellation contract tests (P55, R6).

Pins the cooperative-cancellation contract specified by R6 +
P55 of ``classification-cli/requirements.md``: when the
classification library observes a True ``CancellationToken``
between per-component iterations, it appends a single
Cancellation_Marker to ``ClassificationResult.errors`` and
returns; the CLI handler observes ``cancel_flag.value == True``
after the library returns and resolves to exit code 130. The
records produced before cancellation are preserved.

These tests are deterministic: no real SIGINT is delivered.
The companion subprocess-based SIGINT end-to-end test lives in
``test_sigint_e2e.py`` (task 13) and verifies the same contract
holds when an OS-level signal triggers the flag flip.

Q2 from design.md is pinned by using module-level test
functions with ``@pytest.mark.parametrize``; no class wrapping.
"""

from __future__ import annotations

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
from loki.classify_helpers import _CancelFlag
from loki.models import ExtractedComponent
from loki.models.classification import (
    AxisClassification,
    ClassificationRecord,
    SignatureInfo,
)
from loki.models.config import ClassificationConfig
from loki.models.enums import ClassificationMethod

# A canonical run-start timestamp for the synthetic records the
# fake classify_components produces. Fixed across all parameter
# values so the test is deterministic.
_RUN_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _build_axis(label: str) -> AxisClassification:
    """Build a synthetic ``AxisClassification`` with the given label.

    Uses ``confidence=0.95`` so the resulting
    ``ClassificationRecord.composite_confidence`` (the min of the
    four axes) lands above the model layer's 0.60
    ``needs_review`` threshold; the synthetic records produced
    here therefore have ``needs_review=False`` and the summary
    line's ``<K>`` segment renders as ``0 need_review``.
    """
    return AxisClassification(
        label=label,
        confidence=0.95,
        evidence=[],
        method=ClassificationMethod.RULE,
    )


def _build_record(component: ExtractedComponent) -> ClassificationRecord:
    """Build a synthetic ``ClassificationRecord`` for a component.

    The label values are valid axis-enum members; the record is
    fully validated by Pydantic strict mode at construction.
    """
    return ClassificationRecord(
        component_id=component.component_id,
        source_image_id=component.source_image_id,
        extraction_offset=component.offset,
        timestamp=_RUN_TIMESTAMP,
        type_axis=_build_axis("UEFI_DRIVER"),
        vendor_axis=_build_axis("INTEL"),
        security_axis=_build_axis("SECURE"),
        mutability_axis=_build_axis("READONLY"),
        signature_info=SignatureInfo(
            present=False,
            verified=False,
            signer=None,
            cert_expiry=None,
        ),
        cve_matches=[],
        suspicion_triggers=[],
        classification_version="loki-test",
        overrides=[],
    )


def _build_fake_classify(
    *,
    cancel_at_index: int,
    cancel_flag: _CancelFlag,
) -> Callable[..., ClassificationResult]:
    """Build a fake ``classify_components`` mirroring the cancellation contract.

    The fake mirrors the real library's per-iteration cancel
    poll documented in ``loki/classification/pipeline.py``: at
    the start of each iteration (1-based), it checks the cancel
    callback and breaks if True. When iteration index reaches
    ``cancel_at_index``, the fake flips ``cancel_flag.value`` to
    True before checking; the next iteration's check then
    returns True, the fake appends the canonical
    Cancellation_Marker to errors, and breaks.

    The records appended before cancellation are real,
    Pydantic-validated ``ClassificationRecord`` instances
    matching the components' ``component_id`` / ``source_image_id``
    / ``offset`` fields.

    Returns the fake closure suitable for
    ``monkeypatch.setattr("loki.classification.classify_components", ...)``.
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
            # Cooperative cancellation poll at the start of the
            # iteration body, matching the real library's pattern.
            if cancel is not None and cancel():
                errors.append(
                    ClassificationError(
                        component_id=None,
                        error_message="classification cancelled by caller",
                        timestamp=datetime.now(tz=UTC),
                    )
                )
                break

            # When we are about to process the iteration where
            # cancellation is requested, flip the flag now so the
            # NEXT iteration's poll will return True. This
            # mirrors the real-world flow: the CLI's SIGINT
            # handler flips the flag asynchronously, and the
            # library observes it on the next iteration boundary.
            #
            # Special case for cancel_at_index == 1: we want the
            # very first iteration to be cancelled with no
            # records produced. Flip the flag BEFORE building the
            # record, then rely on a synchronous re-check of
            # cancel() rather than appending the record.
            if index == cancel_at_index:
                cancel_flag.value = True
                # Re-check cancellation synchronously so the
                # current iteration is cancelled rather than
                # the next one. This matches the contract that
                # K-1 records are produced when cancel_at_index
                # is K (cancel_at_index=1 yields zero records).
                if cancel is not None and cancel():
                    errors.append(
                        ClassificationError(
                            component_id=None,
                            error_message="classification cancelled by caller",
                            timestamp=datetime.now(tz=UTC),
                        )
                    )
                    break

            records.append(_build_record(component))

        return ClassificationResult(records=records, errors=errors)

    return _fake


def _install_test_sigint_handler_factory(
    cancel_flag: _CancelFlag,
) -> Callable[[], tuple[_CancelFlag, Callable[[], None]]]:
    """Build a replacement for ``_install_sigint_handler`` that returns a known flag.

    The returned factory ignores the actual SIGINT machinery and
    returns the test-owned ``cancel_flag`` plus a no-op restore.
    Patched into ``loki.classify_helpers._install_sigint_handler``
    via ``monkeypatch.setattr``; cli.py's lazy ``from
    loki.classify_helpers import _install_sigint_handler`` picks
    up the patch at the time the handler runs.
    """

    def _factory() -> tuple[_CancelFlag, Callable[[], None]]:
        return cancel_flag, lambda: None

    return _factory


@pytest.mark.parametrize("cancel_at_index", list(range(1, 6)))
def test_cancellation_at_index_produces_partial_result(
    cancel_at_index: int,
    tmp_path: Path,
    sample_manifest_json: str,
    tmp_rules_path: Path,
    cli_argv: Callable[..., list[str]],
    capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation at iteration K leaves K-1 records + 1 marker (P55, R6.1-R6.7).

    For each cancellation index in [1, 5] over a synthetic
    5-component manifest, the test injects:

    1. A test-owned ``_CancelFlag`` exposed via a monkeypatched
       ``_install_sigint_handler`` factory (so the handler's
       post-return ``if cancel_flag.value`` check sees the flag
       the test controls).
    2. A fake ``classify_components`` that flips the flag at
       iteration K and appends the canonical Cancellation_Marker
       per the real library's contract.

    Asserts the partial-result invariants:

    * ``len(records) == cancel_at_index - 1`` (R6.7).
    * ``errors[-1].component_id is None`` (R6.7).
    * ``errors[-1].error_message == "classification cancelled by caller"`` (R6.7).
    * Stdout parses as JSON with exactly the keys
      ``["records", "errors"]`` (R3.5 + R6.3).
    * Exit code is 130 (R6.3, R8.1).
    * ``len(records)`` in JSON matches the expected count.
    """
    import json

    manifest_path = tmp_path / "manifest.json"
    # The sample_manifest_json fixture builds a 3-component
    # manifest. Synthesize a 5-component manifest here so the
    # cancel-at-index parametrization exercises the full [1, 5]
    # range. Reusing the fixture's image header keeps the
    # ExtractionManifest validation simple.
    import uuid

    from loki.models import ExtractionManifest, FirmwareImage

    fixture_namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.cancellation")
    image_id = uuid.uuid5(fixture_namespace, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/cancellation.bin",
        file_hash="b" * 64,
        file_size=8192,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        ExtractedComponent(
            component_id=uuid.uuid5(fixture_namespace, f"component-{idx:04d}"),
            source_image_id=image_id,
            offset=f"0x{(idx * 0x1000):x}",
            size=512,
            raw_hash="b" * 64,
            component_type_hint=None,
            guid=str(uuid.uuid5(fixture_namespace, f"guid-{idx:04d}")),
            name=f"FIXTURE_{idx:03d}",
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
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    # The test-owned cancel flag. Starts False; the fake
    # classify_components flips it to True at iteration
    # cancel_at_index.
    cancel_flag = _CancelFlag(value=False)

    # Patch _install_sigint_handler to return our flag + a no-op
    # restore. cli.py uses a lazy `from loki.classify_helpers
    # import _install_sigint_handler` inside _handle_classify, so
    # patching the source module attribute before invocation is
    # picked up at handler runtime.
    monkeypatch.setattr(
        "loki.classify_helpers._install_sigint_handler",
        _install_test_sigint_handler_factory(cancel_flag),
    )

    # Patch classify_components with the fake. The fake honors
    # the cancel callback and produces synthetic records.
    fake_classify = _build_fake_classify(
        cancel_at_index=cancel_at_index,
        cancel_flag=cancel_flag,
    )
    monkeypatch.setattr("loki.classification.classify_components", fake_classify)

    argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
    exit_code, stdout, stderr = capture_classify_run(argv)

    # R6.3: cooperative cancellation resolves to exit 130.
    assert exit_code == 130, (
        f"expected exit 130 at cancel_at_index={cancel_at_index}; got {exit_code}; "
        f"stderr={stderr!r}"
    )

    # R3.5 + R6.3: Stdout_Result still parses as JSON with the
    # canonical key set.
    payload = json.loads(stdout)
    assert list(payload.keys()) == ["records", "errors"], (
        f"unexpected key set: {list(payload.keys())}"
    )

    # P55 + R6.7: K-1 records produced; one canonical
    # Cancellation_Marker as the last error entry.
    assert len(payload["records"]) == cancel_at_index - 1, (
        f"expected {cancel_at_index - 1} records at cancel_at_index="
        f"{cancel_at_index}; got {len(payload['records'])}"
    )
    assert len(payload["errors"]) >= 1, "expected at least one error entry"
    last_error = payload["errors"][-1]
    assert last_error["component_id"] is None, (
        f"Cancellation_Marker.component_id must be None; got {last_error!r}"
    )
    assert last_error["error_message"] == "classification cancelled by caller", (
        f"Cancellation_Marker.error_message must be the canonical string; got {last_error!r}"
    )

    # R4.1 + P57: summary line emitted on the partial-cancellation
    # path. The format mirrors the success path; the records count
    # equals cancel_at_index - 1.
    assert f"classify: {cancel_at_index - 1} records (0 need_review)" in stderr


def test_cancellation_with_summary_only_emits_no_stdout(
    tmp_path: Path,
    sample_manifest_json: str,
    tmp_rules_path: Path,
    cli_argv: Callable[..., list[str]],
    capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--summary-only`` + cancellation: zero stdout, summary on stderr, exit 130.

    Pins the R3.6 + R6.3 interaction: even when cancellation
    fires, ``--summary-only`` still suppresses the stdout JSON
    object; the stderr summary line is emitted; the exit code is
    130 (cancellation observed).
    """
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(sample_manifest_json, encoding="utf-8")

    cancel_flag = _CancelFlag(value=False)

    monkeypatch.setattr(
        "loki.classify_helpers._install_sigint_handler",
        _install_test_sigint_handler_factory(cancel_flag),
    )

    fake_classify = _build_fake_classify(
        cancel_at_index=2,
        cancel_flag=cancel_flag,
    )
    monkeypatch.setattr("loki.classification.classify_components", fake_classify)

    argv = cli_argv(
        str(manifest_path),
        rules_path=str(tmp_rules_path),
        summary_only=True,
    )
    exit_code, stdout, stderr = capture_classify_run(argv)

    # R3.6: stdout suppressed entirely under --summary-only.
    assert stdout == "", f"expected zero stdout bytes; got {stdout!r}"
    # R6.3: cancellation observed -> exit 130.
    assert exit_code == 130, f"expected exit 130; got {exit_code}; stderr={stderr!r}"
    # R4.1 + R4.6: summary line emitted on stderr; cancel_at_index=2
    # over a 3-component sample manifest yields 1 record.
    assert "classify: 1 records (0 need_review)" in stderr
