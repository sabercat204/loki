"""Internal helpers for the ``loki classify`` subcommand handler.

This module hosts the seven helper shapes that ``_handle_classify``
in ``loki.cli`` composes during a ``loki classify`` run:
``_CancelFlag`` (the cooperative-cancellation flag the SIGINT
handler flips), ``_load_manifest`` (manifest ingestion plus
TTY/JSON/Pydantic validation), ``_install_sigint_handler`` (the
process-level SIGINT handler with restoration), ``_install_debug_logger``
(scoped ``loki.classification`` logger configuration for ``--debug``),
``_build_progress_callback`` (the per-component stderr emitter for
``--progress``), ``_serialize_result`` (the indented JSON renderer
for the ``ClassificationResult``), and ``_format_summary_line``
(the one-line stderr counts summary).

Per the design's D1 + D6 defaults, these helpers live in their own
module rather than inline in ``loki/cli.py`` (D1: ``cli.py`` would
otherwise balloon past 1000 lines), and use single-leading-underscore
names with no ``__all__`` (D6: helpers are not a public API; they
exist to keep the handler readable). Importers reach into them via
``from loki.classify_helpers import ...``; the module is not
re-exported from ``loki/__init__.py``.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from loki.classification import ClassificationResult, ProgressCallback
from loki.models.firmware import ExtractionManifest

#: Exit-code taxonomy for ``loki classify`` typed errors. Mirrors
#: ``loki extract``'s "2 = bad input, 3 = serialization, 4 = pipeline"
#: pattern, extended for classification-specific subclasses. The
#: closed exit-code set is ``{0, 2, 3, 4, 5, 6, 130}`` per the
#: design's exit-code resolution table (P54 totality).
_CLASSIFY_EXIT_CODES: dict[str, int] = {
    "BadInput": 2,
    "SerializationError": 3,
    "ClassificationPipelineError": 4,
    "UnexpectedException": 4,
    "ClassificationRuleError": 5,
    "ClassificationConfigError": 6,
    "Sigint": 130,
}


@dataclass
class _CancelFlag:
    """Mutable boolean flag flipped by the SIGINT handler (R6.1).

    Used as a single-instance per ``_handle_classify`` invocation;
    the cancel callback closure reads ``flag.value`` between the
    library's per-component iterations (R6.2). The no-lock
    contract is safe because the SIGINT handler runs on the main
    thread synchronously between iterations and the CLI is
    single-threaded per upstream R1.7 + this spec's R1.11.
    """

    value: bool = False


def _load_manifest(manifest_arg: str) -> ExtractionManifest | int:
    """Resolve and validate the manifest source per R1.2-R1.8.

    Returns either a validated ``ExtractionManifest`` (success
    path) or an exit code (``2``) when the input is malformed.
    The integer-return-on-failure pattern (D7 default) keeps the
    handler linear; the handler tests ``isinstance(result, int)``
    to branch.

    The TTY guard (R1.5) fires as the first action when
    ``manifest_arg == "-"``. This is a deliberate ordering choice
    (D4 default): an interactive operator who typed
    ``loki classify -`` and forgot what the ``-`` meant gets the
    TTY-guard error message immediately rather than waiting
    silently for input that never arrives.
    """
    if manifest_arg == "-":
        # R1.5: TTY guard FIRST, before any read.
        if sys.stdin.isatty():
            print(
                "loki classify: stdin is a TTY; pipe a manifest or pass a path",
                file=sys.stderr,
            )
            return 2
        # Stdin read: piped input never raises, so no try/except
        # is needed; the TTY guard above catches the interactive
        # case which would otherwise block.
        text = sys.stdin.read()
    else:
        # R1.3, R1.6: file path mode.
        path = Path(manifest_arg)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError) as exc:
            print(
                f"loki classify: cannot read manifest: {manifest_arg}: {exc}",
                file=sys.stderr,
            )
            return 2

    # R1.7: JSON parse. We do an explicit ``json.loads`` first so a
    # ``JSONDecodeError`` resolves to the dedicated R1.7 stderr
    # message, distinct from R1.8's validation summary; then we
    # discard ``payload`` and feed the original ``text`` to
    # ``model_validate_json``. The latter is the correct Pydantic v2
    # JSON-round-trip path under ``strict=True`` because JSON has no
    # UUID/datetime primitives and ``model_validate(payload, strict=True)``
    # would otherwise reject every string-encoded UUID and ISO-8601
    # timestamp emitted by ``model_dump_json``.
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        print(
            f"loki classify: manifest is not valid JSON: {exc}",
            file=sys.stderr,
        )
        return 2

    # R1.8: Pydantic strict validation via the JSON-aware entry
    # point. The error summary is bounded (error count + first
    # error's loc + first error's msg) to honor R10.4's no-leakage
    # discipline; the full Pydantic rendering can include arbitrary
    # input values that may carry Forbidden_Leakage_Field_Set
    # entries. Mirrors the bounded-summary pattern at
    # ``loki/classification/pipeline.py:_summarize``.
    try:
        return ExtractionManifest.model_validate_json(text, strict=True)
    except ValidationError as exc:
        errors = exc.errors()
        if not errors:
            summary = f"{exc.error_count()} error(s)"
        else:
            first = errors[0]
            loc = ".".join(str(part) for part in first.get("loc", ()))
            msg = first.get("msg", "validation error")
            summary = f"{exc.error_count()} error(s); first at {loc!r}: {msg}"
        print(
            f"loki classify: manifest failed validation: {summary}",
            file=sys.stderr,
        )
        return 2


def _install_sigint_handler() -> tuple[_CancelFlag, Callable[[], None]]:
    """Install a process-level SIGINT handler that flips the Cancel_Flag (R6.1).

    Returns a ``(cancel_flag, restore)`` pair. The caller MUST
    invoke ``restore()`` from a ``finally`` block so the previous
    SIGINT disposition is reinstated; failure to restore would
    leave the flag-flipping handler installed in the parent
    process, which is wrong for any embedded test harness.

    R6.5: a second SIGINT after the flag is already True is a
    no-op for the cancellation contract — the handler simply
    re-flips the True flag to True. No special handling needed.
    """
    cancel_flag = _CancelFlag(value=False)

    def _handler(signum: int, frame: object) -> None:  # pragma: no cover - signal
        cancel_flag.value = True

    previous = signal.signal(signal.SIGINT, _handler)

    def _restore() -> None:
        signal.signal(signal.SIGINT, previous)

    return cancel_flag, _restore


def _install_debug_logger(*, enabled: bool) -> Callable[[], None]:
    """Configure the ``loki.classification`` logger for ``--debug`` (R7.2-R7.5).

    When ``enabled``, raises the logger's level to
    ``logging.DEBUG``, sets ``propagate = False`` (D3 default),
    and attaches a stderr ``StreamHandler`` only if no handler
    is already present (R7.3). Returns a restore callable that
    undoes every change made; the restore is idempotent and safe
    to call from a ``finally`` block whether or not ``enabled``
    was ``True``.

    R7.5: when ``enabled`` is False, no logger state is touched
    and the returned restore is a no-op.

    R7.6: only the ``loki.classification`` logger is configured;
    ``loki.baseline``, ``loki.extraction``, ``loki.analysis``,
    and the root logger are not touched.
    """
    if not enabled:
        return lambda: None

    logger = logging.getLogger("loki.classification")
    previous_level = logger.level
    previous_propagate = logger.propagate
    handler_added: logging.Handler | None = None

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        # R7.3: attach a stderr StreamHandler only when no
        # handler is already configured. Use a minimal formatter;
        # the library's no-leakage discipline (R10.5 / upstream
        # R13.5) prevents the library from logging any value
        # from the Forbidden_Leakage_Field_Set, so the formatter
        # does not need to filter.
        new_handler = logging.StreamHandler(sys.stderr)
        new_handler.setLevel(logging.DEBUG)
        new_handler.setFormatter(logging.Formatter("%(name)s [%(levelname)s] %(message)s"))
        logger.addHandler(new_handler)
        handler_added = new_handler

    def _restore() -> None:
        if handler_added is not None:
            logger.removeHandler(handler_added)
            handler_added.close()
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate

    return _restore


def _build_progress_callback(*, enabled: bool) -> ProgressCallback | None:
    """Return a stderr-line emitter when ``enabled``, else ``None`` (R5.1-R5.4).

    The callback formats each ``ProgressEvent`` as
    ``[<index>/<total>] <component_id>`` followed by a single
    newline, written to ``sys.stderr`` with ``flush=True`` so the
    stream is observable in real time when stderr is connected to
    a terminal (R5.4). When ``enabled`` is ``False``, returns
    ``None`` so the library receives no callback (R5.3).

    R5.6 + R10.2: ``component_id`` is the deliberate
    Forbidden_Leakage_Field_Set exception confined to the
    Progress_Line; no other field from the
    Forbidden_Leakage_Field_Set is interpolated. The
    ``ProgressEvent`` dataclass exposes only ``index``,
    ``total``, and ``component_id`` so this is structurally
    enforced by the upstream API.

    R5.7: stderr-write failures (e.g. ``BrokenPipeError``)
    propagate out of the callback; the design Layer 2 catchall
    in the handler maps them to exit 4. The callback does not
    try/except internally.

    R5.8: the upstream library invokes the callback only after a
    ``ClassificationRecord`` is appended to ``records``; per-
    component error paths skip the call. Consequently the count
    of Progress_Lines on stderr equals the count of records, not
    the input component count.
    """
    if not enabled:
        return None

    from loki.classification import ProgressEvent

    def _emit(event: ProgressEvent) -> None:
        print(
            f"[{event.index}/{event.total}] {event.component_id}",
            file=sys.stderr,
            flush=True,
        )

    return _emit


def _serialize_result(result: ClassificationResult) -> str:
    """Serialize a ``ClassificationResult`` into the Stdout_Result form (R3).

    Returns a single string ending in exactly one trailing newline
    (R3.4). Top-level key order is exactly ``["records", "errors"]``
    (R3.5) regardless of the underlying dataclass field order so
    two runs on the same inputs produce byte-identical stdout
    (modulo per-record ``timestamp`` per upstream R8.1). Records
    and errors are serialized via ``model_dump(mode="json")`` so
    that ``UUID``, ``datetime``, and enum fields render as
    JSON-compatible primitives without Pydantic strict-mode
    round-trip surprises.

    R3.5's key-order determinism is structural: dict literals in
    Python 3.7+ preserve insertion order, ``json.dumps`` honors
    that order, and the literal below pins the order at the
    source.
    """
    payload: dict[str, list[dict[str, object]]] = {
        "records": [record.model_dump(mode="json") for record in result.records],
        "errors": [error.model_dump(mode="json") for error in result.errors],
    }
    return json.dumps(payload, indent=2) + "\n"


def _format_summary_line(
    result: ClassificationResult,
    *,
    duration_seconds: float,
) -> str:
    """Format the Stderr_Summary_Line per R4.2.

    Format: ``classify: <N> records (<K> need_review),
    <E> errors, duration=<S>s``. No trailing newline; the caller
    appends via ``print(..., file=sys.stderr)``.

    R4.3 deferral: NO ``rules_loaded=<R>`` segment (G2-B
    applied). The library exposes the rule count only on the
    internal ``ClassificationPipeline._rules`` attribute (private
    per upstream R12.4); a future revision adds the field once
    the public surface carries it.

    R4.4: the parenthesized ``(<K> need_review)`` segment is
    emitted verbatim regardless of K's value; no conditional
    formatting.

    R4.7 no-leakage: only integer counts and a duration appear
    in the output. No value drawn from the
    Forbidden_Leakage_Field_Set is interpolated.
    """
    n_records = len(result.records)
    k_need_review = sum(1 for record in result.records if record.needs_review)
    e_errors = len(result.errors)
    return (
        f"classify: {n_records} records ({k_need_review} need_review), "
        f"{e_errors} errors, duration={duration_seconds:.4f}s"
    )
