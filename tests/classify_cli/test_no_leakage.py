"""No-leakage audits for the classify CLI surface (tasks 18 + 19, P58, R10).

Two audits in one module, in two test classes per design Q2:

- :class:`TestNoLeakageStaticAudit` (task 18): walks
  :mod:`loki.classify_helpers` AST asserting no f-string or
  ``str.format(...)`` interpolation on a stderr-bound write
  references any value from the Forbidden_Leakage_Field_Set.
  Mirrors :mod:`tests.classification.test_no_log_leakage`.

- :class:`TestNoLeakageDynamicAudit` (task 19): runs the CLI
  end-to-end against a manifest with components carrying
  known-forbidden values; captures stderr; asserts none of the
  forbidden values appear. Three sub-cases: default, ``--debug``
  enabled, ``--progress`` enabled.

The Forbidden_Leakage_Field_Set (per upstream R13.5 + this
spec's R10):

- ``ClassificationRecord.component_id`` /
  ``ExtractedComponent.component_id`` (whitelist exception:
  Progress_Line emitter MAY interpolate ``event.component_id``)
- ``SignatureInfo.signer``
- ``BaselineRecord.source_image_hash`` (the parent firmware
  image's ``file_hash``)
- ``AxisClassification.evidence``
"""

from __future__ import annotations

import ast
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import loki

if TYPE_CHECKING:
    from loki.classification import ClassificationResult
    from loki.models import ExtractedComponent

#: Logger / stderr-bound function names that, when seen as the
#: target of a Call, identify a stderr-write site whose argument
#: tree is forbidden from interpolating leakage fields.
_STDERR_WRITE_FUNCS: frozenset[str] = frozenset(
    {"info", "warning", "error", "debug", "critical", "exception", "log"}
)

#: Bare attribute names that, when accessed in any expression
#: feeding a stderr-bound write, indicate forbidden leakage.
#: Pairs are ``(parent-name-substring, attribute-name)``; an
#: empty parent-substring matches any parent.
_FORBIDDEN_ATTRIBUTES: tuple[tuple[str, str], ...] = (
    ("", "component_id"),
    ("signature_info", "signer"),
    ("source_image", "file_hash"),
    ("", "source_image_hash"),
    ("type_axis", "evidence"),
    ("vendor_axis", "evidence"),
    ("security_axis", "evidence"),
    ("mutability_axis", "evidence"),
)

#: Functions in ``loki.classify_helpers`` where the
#: ``component_id`` whitelist exception applies (the
#: Progress_Line emitter per R10.2).
_PROGRESS_WHITELIST_FUNCS: frozenset[str] = frozenset({"_build_progress_callback"})


def _classify_helpers_path() -> Path:
    """Resolve the absolute path to ``loki/classify_helpers.py``."""
    package_root = Path(loki.__path__[0])
    return package_root / "classify_helpers.py"


def _attribute_chain(node: ast.AST) -> list[str]:
    """Return the dotted attribute chain for an Attribute / Name node.

    ``record.signature_info.signer`` -> ``["record", "signature_info", "signer"]``.
    Returns an empty list for leaves that are neither Name nor Attribute.
    """
    chain: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        chain.append(current.id)
    chain.reverse()
    return chain


def _is_stderr_print(call: ast.Call) -> bool:
    """Return True for ``print(..., file=sys.stderr)`` calls.

    Matches the actual stderr-write idiom used by
    :mod:`loki.classify_helpers`.
    """
    if not isinstance(call.func, ast.Name) or call.func.id != "print":
        return False
    for kw in call.keywords:
        if kw.arg != "file":
            continue
        chain = _attribute_chain(kw.value)
        if chain == ["sys", "stderr"]:
            return True
    return False


def _is_stderr_write(call: ast.Call) -> bool:
    """Return True for ``sys.stderr.write(...)`` calls."""
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "write":
        return False
    chain = _attribute_chain(call.func.value)
    return chain == ["sys", "stderr"]


def _is_logger_method_call(call: ast.Call) -> bool:
    """Return True for ``<logger>.<method>(...)`` calls.

    Matches both ``logger.info(...)`` and
    ``logging.getLogger(...).info(...)`` style calls by
    checking the method name only. The classify_helpers module
    uses ``logging.StreamHandler`` to attach a handler but does
    not call any logger method directly; this audit catches a
    future regression where a helper logs through the
    ``loki.classification`` logger and accidentally interpolates
    a forbidden field.
    """
    if not isinstance(call.func, ast.Attribute):
        return False
    return call.func.attr in _STDERR_WRITE_FUNCS


def _violations_in_call(
    call: ast.Call,
    *,
    enclosing_funcs: Sequence[str],
) -> list[tuple[str, str]]:
    """Walk a stderr-bound call's args / keywords for forbidden attributes.

    Returns a list of ``(attribute_chain_str, reason)`` tuples.
    The whitelist exception (Progress_Line component_id) is
    applied via ``enclosing_funcs``: when any ancestor function
    is in ``_PROGRESS_WHITELIST_FUNCS``, ``component_id``
    interpolation is allowed (R10.2).
    """
    violations: list[tuple[str, str]] = []
    nodes_to_inspect: list[ast.AST] = []
    nodes_to_inspect.extend(call.args)
    for kw in call.keywords:
        if kw.value is not None:
            nodes_to_inspect.append(kw.value)

    in_progress_whitelist = any(name in _PROGRESS_WHITELIST_FUNCS for name in enclosing_funcs)

    for arg in nodes_to_inspect:
        for sub in ast.walk(arg):
            if not isinstance(sub, ast.Attribute):
                continue
            chain = _attribute_chain(sub)
            if not chain:
                continue
            chain_str = ".".join(chain)
            tail_attr = chain[-1]
            for parent_substring, forbidden_attr in _FORBIDDEN_ATTRIBUTES:
                if tail_attr != forbidden_attr:
                    continue
                # Whitelist: component_id is allowed in the
                # Progress_Line emitter per R10.2.
                if (
                    forbidden_attr == "component_id"
                    and parent_substring == ""
                    and in_progress_whitelist
                ):
                    break
                if parent_substring == "":
                    violations.append(
                        (chain_str, f"references forbidden attribute {forbidden_attr!r}")
                    )
                    break
                parent_chain = chain[:-1]
                if any(parent_substring in part for part in parent_chain):
                    violations.append(
                        (
                            chain_str,
                            f"references forbidden attribute {parent_substring}.{forbidden_attr}",
                        )
                    )
                    break
    return violations


def _enclosing_function_names(
    call: ast.Call,
    parent_map: dict[ast.AST, ast.AST],
) -> list[str]:
    """Walk parents of ``call`` collecting every enclosing FunctionDef name.

    Returns the chain from innermost to outermost. Used to
    apply the Progress_Line whitelist (R10.2): the closure
    inside ``_build_progress_callback`` is named ``_emit``, but
    the whitelist applies whenever any ancestor is in
    ``_PROGRESS_WHITELIST_FUNCS``.
    """
    chain: list[str] = []
    current: ast.AST | None = parent_map.get(call)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            chain.append(current.name)
        current = parent_map.get(current)
    return chain


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Build a child -> parent mapping for ``tree``."""
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    return parent_map


class TestNoLeakageStaticAudit:
    """P58 part 1: static AST audit of ``loki.classify_helpers``."""

    def test_no_forbidden_attribute_in_stderr_writes(self) -> None:
        """No stderr-bound write interpolates a Forbidden_Leakage_Field.

        Walks every ``print(..., file=sys.stderr)`` call,
        every ``sys.stderr.write(...)`` call, and every
        ``logger.<method>(...)`` call in
        :mod:`loki.classify_helpers`. For each call's arguments,
        looks for attribute access whose tail is in the
        Forbidden_Leakage_Field_Set. Whitelist: the Progress_Line
        emitter MAY interpolate ``event.component_id`` per R10.2.
        """
        source = _classify_helpers_path().read_text(encoding="utf-8")
        tree = ast.parse(source)
        parent_map = _build_parent_map(tree)

        violations: list[tuple[str, int, str, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                _is_stderr_print(node) or _is_stderr_write(node) or _is_logger_method_call(node)
            ):
                continue
            enclosing_funcs = _enclosing_function_names(node, parent_map)
            innermost = enclosing_funcs[0] if enclosing_funcs else "<module>"
            for chain_str, reason in _violations_in_call(node, enclosing_funcs=enclosing_funcs):
                violations.append((innermost, node.lineno, chain_str, reason))

        assert violations == [], (
            "stderr-bound writes reference forbidden attributes:\n  "
            + "\n  ".join(f"{fn}:{ln} '{c}' - {r}" for fn, ln, c, r in violations)
        )

    def test_at_least_one_stderr_write_exists(self) -> None:
        """Sanity check: the audit actually finds stderr-bound writes.

        If the audit finds zero stderr-bound writes, it would
        trivially pass even when leakage exists. The classify_helpers
        module emits at least the manifest-validation messages
        (R1.5-R1.8) on stderr; that's at least 4 ``print`` calls.
        """
        source = _classify_helpers_path().read_text(encoding="utf-8")
        tree = ast.parse(source)

        found = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _is_stderr_print(node) or _is_stderr_write(node):
                found += 1

        assert found >= 4, (
            f"expected at least 4 stderr-bound writes in classify_helpers; found {found}"
        )

    def test_progress_callback_whitelist_is_active(self) -> None:
        """Affirmative check: the whitelist applies to the Progress_Line emitter.

        The audit's whitelist for ``component_id`` MUST cover
        the ``_build_progress_callback`` function. If the function
        ever stops interpolating ``event.component_id``, the
        whitelist entry is dead weight. This test confirms the
        actual classify_helpers source still exercises the
        whitelist (i.e. the Progress_Line emitter still
        references ``event.component_id`` somewhere).
        """
        source = _classify_helpers_path().read_text(encoding="utf-8")
        tree = ast.parse(source)

        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_build_progress_callback":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Attribute) and sub.attr == "component_id":
                        chain = _attribute_chain(sub)
                        if chain and chain[0] == "event":
                            found = True
                            break
                break

        assert found, (
            "_build_progress_callback no longer references event.component_id; "
            "the whitelist exception in the no-leakage audit is dead weight."
        )


# ---------------------------------------------------------------------
# Task 19: dynamic stderr-capture audit (P58 part 2)
# ---------------------------------------------------------------------

#: Sentinel string for ``signature_info.signer``. Lowercase
#: so it survives any case-folding in the rendering pipeline.
_FORBIDDEN_SIGNER = "evil_token_signer"

#: Sentinel string for ``AxisClassification.evidence`` entries.
_FORBIDDEN_EVIDENCE_TOKEN = "EVIDENCE_TOKEN_PROHIBITED"

#: 64-character lowercase hex matching the model layer's
#: ``file_hash`` validator. The literal "deadbeef" prefix is the
#: leakage probe; if it appears anywhere in stderr, the test
#: fails.
_FORBIDDEN_SOURCE_IMAGE_HASH = "deadbeefcafebabe" + ("0" * 48)


def _build_leakage_manifest(tmp_path: Path) -> Path:
    """Write a manifest carrying ``_FORBIDDEN_SOURCE_IMAGE_HASH`` as file_hash.

    The component_id and source_image_id are deterministic
    UUIDs derived from the fixture namespace; they do NOT
    contain the leakage sentinels, so any appearance of those
    UUIDs in stderr is also a leakage event but is harder to
    correlate. The strongest probes are the signer / evidence
    / source_image_hash sentinels, which are intentionally
    distinctive substrings.
    """
    from loki.models import ExtractionManifest, FirmwareImage

    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tests.classify_cli.no_leakage_dynamic")
    image_id = uuid.uuid5(namespace, "image")
    image = FirmwareImage(
        image_id=image_id,
        file_path="/tmp/loki-fixture/leakage.bin",
        file_hash=_FORBIDDEN_SOURCE_IMAGE_HASH,
        file_size=4096,
        vendor="ACME",
        model="X1",
        firmware_version="1.0.0",
    )
    components = [
        # Single component is enough; the leakage probes are
        # the synthetic record's signer / evidence values
        # injected via the monkeypatched classify_components.
        _build_component(namespace, image_id, idx=0)
    ]
    manifest = ExtractionManifest(
        source_image=image,
        components=components,
        extraction_timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        extractor_version="loki-test-fixture",
        extraction_errors=[],
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest_path


def _build_component(
    namespace: uuid.UUID,
    image_id: uuid.UUID,
    *,
    idx: int,
) -> ExtractedComponent:
    """Build an ``ExtractedComponent`` carrying no leakage tokens itself.

    The component_id and guid are deterministic UUIDs; the
    leakage probes live on the synthetic ``ClassificationRecord``
    produced by the monkeypatched ``classify_components``, not
    on the input.
    """
    from loki.models import ExtractedComponent

    return ExtractedComponent(
        component_id=uuid.uuid5(namespace, f"component-{idx:04d}"),
        source_image_id=image_id,
        offset=f"0x{(idx * 0x1000):x}",
        size=512,
        raw_hash=_FORBIDDEN_SOURCE_IMAGE_HASH,
        component_type_hint=None,
        guid=str(uuid.uuid5(namespace, f"guid-{idx:04d}")),
        name=f"LEAKAGE_{idx:03d}",
        raw_path=None,
    )


def _leakage_classify_factory() -> Callable[..., ClassificationResult]:
    """Build a fake ``classify_components`` whose records carry leakage tokens.

    The fake produces one ``ClassificationRecord`` per input
    component. Each record carries:

    - ``signature_info.signer = _FORBIDDEN_SIGNER`` (the
      ``signer`` field is in the Forbidden_Leakage_Field_Set).
    - ``type_axis.evidence = [_FORBIDDEN_EVIDENCE_TOKEN]`` (the
      ``evidence`` field is in the Forbidden_Leakage_Field_Set).

    The record's ``component_id`` and ``source_image_id`` come
    from the input component; those are also in the
    Forbidden_Leakage_Field_Set but for the dynamic audit they
    serve as a secondary probe.
    """
    from loki.classification import (
        CancellationToken,
        ClassificationResult,
        ProgressCallback,
    )
    from loki.classification.errors import ClassificationError as _ClassErr
    from loki.models.classification import (
        AxisClassification,
        ClassificationRecord,
        SignatureInfo,
    )
    from loki.models.config import ClassificationConfig as _Config
    from loki.models.enums import ClassificationMethod

    def _build_axis(label: str, *, with_evidence: bool) -> AxisClassification:
        return AxisClassification(
            label=label,
            confidence=0.95,
            evidence=[_FORBIDDEN_EVIDENCE_TOKEN] if with_evidence else [],
            method=ClassificationMethod.RULE,
        )

    def _build_record(component: ExtractedComponent) -> ClassificationRecord:
        return ClassificationRecord(
            component_id=component.component_id,
            source_image_id=component.source_image_id,
            extraction_offset=component.offset,
            timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
            type_axis=_build_axis("UEFI_DRIVER", with_evidence=True),
            vendor_axis=_build_axis("INTEL", with_evidence=False),
            security_axis=_build_axis("SECURE", with_evidence=False),
            mutability_axis=_build_axis("READONLY", with_evidence=False),
            signature_info=SignatureInfo(
                present=True,
                verified=True,
                signer=_FORBIDDEN_SIGNER,
                cert_expiry=None,
            ),
            cve_matches=[],
            suspicion_triggers=[],
            classification_version="loki-test",
            overrides=[],
        )

    def _fake(
        components: Sequence[ExtractedComponent],
        config: _Config,
        *,
        progress: ProgressCallback | None = None,
        cancel: CancellationToken | None = None,
        **_kwargs: object,
    ) -> ClassificationResult:
        records = [_build_record(c) for c in components]
        # Fire the progress callback once per record so the
        # --progress sub-case sees something on stderr.
        if progress is not None:
            from loki.classification import ProgressEvent

            for index, record in enumerate(records, start=1):
                progress(
                    ProgressEvent(
                        index=index,
                        total=len(records),
                        component_id=str(record.component_id),
                    )
                )
        errors: list[_ClassErr] = []
        return ClassificationResult(records=records, errors=errors)

    return _fake


class TestNoLeakageDynamicAudit:
    """P58 part 2: dynamic stderr-capture audit (R7.7, R10.1-R10.5).

    Three sub-cases verify that the Forbidden_Leakage_Field_Set
    sentinel values do NOT appear in stderr:

    - default invocation (no flags);
    - ``--debug`` invocation (R7.7: even at DEBUG level, no
      forbidden value leaks);
    - ``--progress`` invocation (R10.2: ``component_id`` is the
      whitelisted exception on Progress_Line, but no other
      forbidden value leaks).
    """

    def _assert_no_leakage(self, stderr: str) -> None:
        """Assert the three forbidden sentinels do not appear in stderr.

        ``component_id`` is intentionally NOT in the assertion
        list because R10.2 whitelists ``component_id`` on the
        Progress_Line. The dedicated --progress sub-case
        verifies the whitelist scope.
        """
        assert _FORBIDDEN_SIGNER not in stderr, (
            f"Forbidden signer sentinel leaked into stderr: {stderr!r}"
        )
        assert _FORBIDDEN_EVIDENCE_TOKEN not in stderr, (
            f"Forbidden evidence sentinel leaked into stderr: {stderr!r}"
        )
        # Match against the leading bytes of the source image
        # hash; matching the full 64-char value is unnecessary
        # because the prefix is the leakage probe.
        forbidden_hash_prefix = _FORBIDDEN_SOURCE_IMAGE_HASH[:16]
        assert forbidden_hash_prefix not in stderr, (
            f"Forbidden source_image_hash prefix leaked into stderr: {stderr!r}"
        )

    def test_default_invocation_does_not_leak(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Default invocation: no Forbidden_Leakage_Field value in stderr."""
        manifest_path = _build_leakage_manifest(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _leakage_classify_factory(),
        )

        argv = cli_argv(str(manifest_path), rules_path=str(tmp_rules_path))
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        self._assert_no_leakage(stderr)

    def test_debug_flag_does_not_leak(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--debug`` invocation: even at DEBUG level no leak (R7.7)."""
        manifest_path = _build_leakage_manifest(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _leakage_classify_factory(),
        )

        argv = cli_argv(
            str(manifest_path),
            rules_path=str(tmp_rules_path),
            debug=True,
        )
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        self._assert_no_leakage(stderr)

    def test_progress_flag_only_emits_component_id(
        self,
        tmp_path: Path,
        tmp_rules_path: Path,
        cli_argv: Callable[..., list[str]],
        capture_classify_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--progress`` invocation: only component_id leaks via Progress_Line.

        R10.2 whitelists ``component_id`` on the Progress_Line.
        The other Forbidden_Leakage_Field values
        (signer, evidence, source_image_hash) MUST NOT appear
        anywhere on stderr including the Progress_Line stream.
        """
        manifest_path = _build_leakage_manifest(tmp_path)

        monkeypatch.setattr(
            "loki.classification.classify_components",
            _leakage_classify_factory(),
        )

        argv = cli_argv(
            str(manifest_path),
            rules_path=str(tmp_rules_path),
            progress=True,
        )
        exit_code, _stdout, stderr = capture_classify_run(argv)

        assert exit_code == 0
        self._assert_no_leakage(stderr)

        # Affirmative check: the Progress_Line stream actually
        # fired, so the negative assertion above is meaningful.
        # The Progress_Line format is ``[<index>/<total>] <component_id>``.
        progress_lines = [ln for ln in stderr.splitlines() if ln.startswith("[")]
        assert len(progress_lines) >= 1, (
            f"expected at least one Progress_Line; got stderr={stderr!r}"
        )
