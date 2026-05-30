
# Design Document — Classification CLI

## Overview

The Classification CLI extends the existing top-level ``loki`` console script with a new ``classify`` subcommand that reads a previously-saved ``ExtractionManifest`` JSON document, runs the classification library against it, and writes a single ``ClassificationResult`` JSON object to stdout plus a one-line counts summary to stderr. The CLI is intentionally a thin shell over ``loki.classification.classify_components``: it does not run extraction itself, does not persist its output to disk, and does not expose any classification decision the library does not already make.

The subsystem is **synchronous**, **single-threaded**, **deterministic** (same manifest contents + same Rules_Directory contents + same ``--taxonomy-version`` value + same Classification_CLI version ⇒ byte-identical Stdout_Result modulo each `ClassificationRecord.timestamp` field per upstream R8.1), **honest** about partial outcomes (the R5.6 dual-record contract is preserved verbatim; per-component errors don't suppress the rest of the run; cooperative cancellation produces a partial result rather than a traceback), and **disciplined** about leakage (the ``Forbidden_Leakage_Field_Set`` discipline from upstream R13.5 extends to every line the CLI emits on stderr, with the single ``component_id`` exception confined to ``--progress`` output).

The shape mirrors the existing ``loki extract`` and ``loki baseline`` handlers in ``loki/loki/cli.py``: a single module-scope ``_CLASSIFY_EXIT_CODES`` mapping table, a lazy-imported handler function (``_handle_classify``), an internal helper that builds the progress callback, an internal helper that wires SIGINT to the Cancel_Flag, and a small set of pure functions that serialize the result and assemble the summary line. Each non-trivial design choice cites the acceptance criteria it satisfies (e.g. ``R6.3`` = Requirement 6 acceptance criterion 3 from ``.kiro/specs/classification-cli/requirements.md``).

## Goals and non-goals

### Goals

- Deliver a stable ``loki classify`` subcommand on the top-level ``loki`` console script (R1.1).
- Read an ``ExtractionManifest`` either from a file path or from stdin via ``-`` (R1.2-R1.4, R1.5).
- Pass ``manifest.components`` to ``classify_components`` without mutation (R1.9).
- Require ``--rules-path``; default ``--taxonomy-version`` to ``"1.0.0"``; pin ``confidence_threshold`` to ``0.6`` internally (R2).
- Emit a single indented JSON object on stdout with stable ``["records", "errors"]`` key ordering (R3).
- Emit a single ``classify: <N> records (<K> need_review), <E> errors, duration=<S>s`` line on stderr (R4).
- Stream ``[<index>/<total>] <component_id>`` lines under ``--progress``, exactly one per successfully-classified component (R5).
- Install a SIGINT handler that flips the Cancel_Flag, restores the previous handler on exit, and lets the library's cooperative-cancellation contract surface the partial result + exit ``130`` (R6).
- Scope ``--debug`` to the ``loki.classification`` logger only, with ``propagate = False`` for the duration of the run (R7).
- Map every typed error in the upstream hierarchy to exactly one of ``{0, 2, 3, 4, 5, 6, 130}`` (R8).
- Preserve the R5.6 dual-record contract verbatim; preserve determinism modulo per-record timestamp; preserve file-vs-stdin equivalence (R9).
- Extend the no-leakage discipline to every CLI-emitted stderr path; preserve the ``component_id``-on-Progress_Line exception (R10).
- Bound CLI overhead beyond the library to ≤200 ms wall-clock on a 256-component / 256-rule manifest (R11.1).
- Provide ``loki classify --help`` self-documentation for every flag (R12).
- Pin contracts via P53-P58 plus deterministic in-process cancellation tests (R13).

### Non-goals (explicit)

- **Running extraction in the same process.** No ``--from-firmware`` flag in v1; UNIX composition is the integration story (intro out-of-scope; R1.10).
- **Persisting ``ClassificationResult`` to disk.** No ``--output-file`` flag; stdout redirection is the UNIX way.
- **Validating rule files outside of a real run.** No ``loki classify rules-check`` subcommand; rule errors surface naturally on a normal classify invocation as exit code 5 (R8.4).
- **A pretty-printing subcommand.** No ``loki classify show``; ``jq`` covers the use case.
- **Exposing ``confidence_threshold``.** Pinned internally to 0.6; the library doesn't consume it in v1 (R2.6, upstream R4.10).
- **Reading config from ``LokiConfig.from_yaml(...)``.** ``--rules-path`` is mandatory; no fallback path (R2.3).
- **Streaming JSONL output.** The library API is non-streaming; the CLI mirrors that (R11.4).
- **GUI integration.** OT-LK-004 is a separate spec.
- **Surfacing a ``rules_loaded`` count in the summary line.** Deferred until the public ``ClassificationResult`` carries the count (R4.3).

## Constraints carried forward

- Python 3.12 baseline. All new code must satisfy ``mypy --strict``, ``ruff check``, and ``ruff format`` clean.
- Pydantic v2 strict mode for ``ExtractionManifest`` ingestion (R1.3, R1.4, R1.8); ``ClassificationConfig`` construction (R2.1).
- The CLI must not import from ``loki.gui``; ``loki classify`` SHALL run cleanly in headless environments without PyQt6 (parallel constraint to upstream R1.8).
- Logging via the stdlib ``logging`` module under the logger name ``loki.classification`` (the library's existing logger; the CLI does not introduce a new logger name).
- Stay free of ``random`` / ``secrets`` / ``socket`` / network-library imports. The CLI uses ``time.monotonic()`` for the duration measurement (R4.2 ``<S>`` field), which is the only allowed time/clock surface; ``datetime.now()`` is not used by the CLI itself.
- Property numbering picks up at **P53** per the platform-wide convention (model layer 1-11, extraction 12-22, baseline-persistence 23-32, classification 33-42, analysis 43-52, classification-cli 53-58).

## Components and Interfaces

This section catalogues the public surface (a registered subcommand on the existing ``loki`` parser), the internal helpers, and the typed-error → exit-code mapping. The module layout in §Architecture below shows where each component lives.

The four interface families are:

1. **Subcommand registration** (extends ``loki/loki/cli.py``): adds ``loki classify`` to the existing ``argparse`` dispatcher. No new module import surface; consumers run ``loki classify ...`` from the shell.
2. **Internal handler** (``loki/loki/cli.py``): ``_handle_classify`` coordinates manifest ingestion → SIGINT setup → debug-logger setup → library invocation → SIGINT teardown → debug-logger teardown → stdout/stderr emission → exit-code resolution.
3. **Internal helpers** (``loki/loki/classify_helpers.py``, new module): ``_load_manifest``, ``_install_sigint_handler``, ``_install_debug_logger``, ``_serialize_result``, ``_build_progress_callback``, ``_format_summary_line``, ``_classify_exit_codes`` mapping. Pure functions where possible; lifecycle managers where state must be threaded.
4. **No new public Python API surface.** The CLI is a script entry point. Helper functions in ``classify_helpers.py`` are module-internal (single leading-underscore pattern); they're not re-exported.

The detailed code-shape for each family follows under ``## Architecture``.

## Architecture

### Module layout

```
loki/
├── loki/
│   ├── cli.py                    # extended: build_parser() registers `classify`
│   │                             # subcommand; new _handle_classify() handler
│   └── classify_helpers.py       # NEW: helper functions + _CLASSIFY_EXIT_CODES table
└── tests/
    └── classify_cli/             # NEW: pytest suite for the CLI subsystem
        ├── __init__.py
        ├── conftest.py           # shared fixtures: tmp_rules_path, sample_manifest_json
        ├── test_argparse.py      # P54 (exit-code totality on argparse failures)
        ├── test_input_paths.py   # R1.2-R1.8 (file path + stdin + TTY guard + bad input)
        ├── test_rules_path.py    # R2.1-R2.7 (mandatory flag, taxonomy default, error mapping)
        ├── test_stdout_shape.py  # R3.1-R3.8 + P53 stdin/file equivalence
        ├── test_stderr_summary.py # R4.1-R4.7 + P57 emission discipline
        ├── test_progress.py      # R5.1-R5.8
        ├── test_cancellation.py  # R6.1-R6.7 + P55 in-process Cancel_Flag contract
        ├── test_sigint_e2e.py    # R6.1-R6.7 example-based subprocess test (separate from P55)
        ├── test_debug_flag.py    # R7.1-R7.8 (logger lifecycle + propagate=False)
        ├── test_exit_codes.py    # R8.1-R8.7 + P54 totality
        ├── test_determinism.py   # R9.1-R9.6 + R5.6 dual-record passthrough
        ├── test_no_leakage.py    # R10.1-R10.5 + P58 (static + dynamic audit on stderr)
        ├── test_performance.py   # R11.1 slow-marker (wrapper-only timing)
        ├── test_help_text.py     # R12.1-R12.5 (`loki classify --help` shape)
        └── test_summary_only.py  # R3.6 + P56 (`--summary-only` zero-byte stdout)
```

### Subcommand registration

The existing ``build_parser()`` in ``loki/loki/cli.py`` already wires ``gui``, ``extract``, and ``baseline`` subcommands by calling subparser builders. We add a new ``_add_classify_subcommand(sub)`` invocation alongside ``_add_baseline_subcommands(sub)`` and a matching builder function that registers all five flags + the positional argument:

```python
# loki/loki/cli.py (additions)

def _add_classify_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Wire up the ``loki classify`` subcommand (Requirement 1).

    Registers the positional ``manifest`` argument plus the five
    v1 flags: ``--rules-path`` (mandatory), ``--taxonomy-version``
    (optional, default ``"1.0.0"``), ``--progress``, ``--debug``,
    ``--summary-only``.
    """
    classify_parser = sub.add_parser(
        "classify",
        help="Classify a saved ExtractionManifest against a rules directory.",
        description=(
            "Read an ExtractionManifest (path or '-' for stdin), run the "
            "classification library against the rules directory, and emit "
            "a JSON {records, errors} object to stdout plus a counts "
            "summary line to stderr. Composes with `loki extract` via "
            "shell pipelines."
        ),
    )
    classify_parser.add_argument(
        "manifest",
        type=str,
        help=(
            "Path to an ExtractionManifest JSON file, or '-' to read "
            "the manifest from stdin."
        ),
    )
    classify_parser.add_argument(
        "--rules-path",
        type=Path,
        required=True,
        metavar="DIR",
        help="Path to the directory containing classification rule YAML files (mandatory).",
    )
    classify_parser.add_argument(
        "--taxonomy-version",
        type=str,
        default="1.0.0",
        metavar="VERSION",
        help='Taxonomy version to enforce against the rule files (default: "1.0.0").',
    )
    classify_parser.add_argument(
        "--progress",
        action="store_true",
        help=(
            "Stream one line per successfully-classified component to "
            "stderr (`[index/total] component_id`); stdout JSON is unchanged."
        ),
    )
    classify_parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Emit DEBUG-level records from the loki.classification logger "
            "to stderr for the duration of this run; does not modify stdout."
        ),
    )
    classify_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress the stdout JSON object; emit only the stderr summary line.",
    )
    classify_parser.set_defaults(handler=_handle_classify)
```

The ``classify`` subparser inherits ``prog="loki classify"`` from argparse's default (``parent_prog`` + ``subparser_name``); R12.3's contract is satisfied by the default behavior.

### Internal handler — ``_handle_classify``

The handler coordinates the full lifecycle. Lazy imports keep ``loki --version``, ``loki gui``, ``loki extract``, and ``loki baseline`` invocations free of the classification library's import cost (mirrors the existing handlers' pattern).

```python
# loki/loki/cli.py (additions)

def _handle_classify(args: argparse.Namespace) -> int:
    """Run ``classify_components`` on the supplied manifest and emit JSON.

    Lifecycle:

    1. Resolve the manifest source (file path vs. stdin), guard
       against TTY-on-stdin, ingest + Pydantic-validate (R1.2-R1.8).
    2. Build the ``ClassificationConfig`` (R2.1, R2.5, R2.6).
    3. Set up the SIGINT handler (R6.1) — preserved for restoration.
    4. Set up the ``--debug`` logger scope (R7.2-R7.5) if requested.
    5. Invoke ``classify_components`` with the wired callbacks
       (R1.9, R5.2, R6.2).
    6. Catch and map typed errors per Requirement 8.
    7. Restore the SIGINT handler (R6.1).
    8. Restore the ``--debug`` logger state (R7.2-R7.5).
    9. Serialize the result to stdout (R3) unless ``--summary-only`` (R3.6).
    10. Emit the summary line on stderr (R4) on success or partial cancellation.
    11. Return the resolved exit code.
    """
    # Imports lazy so `loki --version`, `loki gui`, `loki extract`,
    # and `loki baseline` don't pay the classification import cost.
    from loki.classify_helpers import (
        _CLASSIFY_EXIT_CODES,
        _build_progress_callback,
        _format_summary_line,
        _install_debug_logger,
        _install_sigint_handler,
        _load_manifest,
        _serialize_result,
    )
    from loki.classification import (
        ClassificationConfigError,
        ClassificationPipelineError,
        ClassificationRuleError,
        classify_components,
    )
    from loki.models import ClassificationConfig

    # Step 1: ingest the manifest. Errors here exit 2 directly.
    manifest_or_exit_code = _load_manifest(args.manifest)
    if isinstance(manifest_or_exit_code, int):
        return manifest_or_exit_code
    manifest = manifest_or_exit_code

    # Step 2: build the ClassificationConfig (R2.1, R2.5, R2.6).
    # confidence_threshold pinned to 0.6 (model default; R2.6 / D2 default).
    config = ClassificationConfig(
        taxonomy_version=args.taxonomy_version,
        confidence_threshold=0.6,
        rules_path=str(args.rules_path),
    )

    # Step 3: SIGINT handler (R6.1).
    cancel_flag, restore_sigint = _install_sigint_handler()

    # Step 4: --debug logger scope (R7.2-R7.5).
    restore_debug_logger = _install_debug_logger(enabled=args.debug)

    # Step 5: invoke the library.
    progress_callback = _build_progress_callback(enabled=args.progress)
    sigint_observed = False
    started_at = time.monotonic()
    try:
        try:
            result = classify_components(
                manifest.components,
                config,
                progress=progress_callback,
                cancel=lambda: cancel_flag.value,
            )
            duration_seconds = time.monotonic() - started_at
        except ClassificationConfigError as exc:
            # R8.3
            print(f"loki classify: configuration error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationConfigError"]
        except ClassificationRuleError as exc:
            # R8.4
            print(f"loki classify: rule error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationRuleError"]
        except ClassificationPipelineError as exc:
            # R8.5
            print(f"loki classify: pipeline error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationPipelineError"]
        except Exception as exc:
            # R8.6
            print(
                f"loki classify: unexpected error: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return _CLASSIFY_EXIT_CODES["UnexpectedException"]
    finally:
        # Steps 7+8: restore handlers regardless of success or
        # exception path (R6.1, R7.2-R7.5).
        restore_debug_logger()
        restore_sigint()

    sigint_observed = cancel_flag.value

    # Step 9: serialize result to stdout (R3) unless --summary-only (R3.6).
    if not args.summary_only:
        try:
            sys.stdout.write(_serialize_result(result))
        except Exception as exc:
            # R3.7 / R8.1 exit code 3
            print(f"loki classify: failed to serialize result: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["SerializationError"]

    # Step 10: emit the summary line on stderr (R4).
    print(
        _format_summary_line(result, duration_seconds=duration_seconds),
        file=sys.stderr,
    )

    # Step 11: resolve exit code (R6.3 vs. R8 success).
    return 130 if sigint_observed else 0
```

The handler is intentionally linear — each step has a single responsibility, and the ``finally`` block ensures handler restoration even on unexpected exceptions. The ``Cancel_Flag`` is passed via a tiny wrapper object (defined in ``classify_helpers.py``) so the lambda can mutate it without rebinding.

### Internal helpers — ``loki/loki/classify_helpers.py``

A single new module holds the helper functions and the exit-code table. Module-private (single-underscore-prefixed names; no ``__all__``); not re-exported from ``loki/__init__.py`` or anywhere else. Mirrors the pattern that ``_BASELINE_EXIT_CODES`` already uses inline in ``cli.py``, but we hoist the helpers into their own module to keep ``cli.py`` from ballooning past 1,500 lines.

#### Exit-code table (R8.1)

```python
# loki/loki/classify_helpers.py

#: Exit-code taxonomy for ``loki classify`` typed errors. Mirrors
#: ``loki extract``'s "2 = bad input, 3 = serialization, 4 = pipeline"
#: pattern extended for classification-specific subclasses.
_CLASSIFY_EXIT_CODES: dict[str, int] = {
    "BadInput": 2,
    "SerializationError": 3,
    "ClassificationPipelineError": 4,
    "UnexpectedException": 4,
    "ClassificationRuleError": 5,
    "ClassificationConfigError": 6,
    "Sigint": 130,
}
```

The ``BadInput`` entry isn't currently used as a dictionary lookup; the manifest-ingestion path (Step 1 above) returns ``2`` directly when ``_load_manifest`` resolves to an integer. The entry is kept as documentation of the closed exit-code set for the design's typed-error totality property (P54).

#### ``_load_manifest`` (R1.2-R1.8)

```python
# loki/loki/classify_helpers.py

def _load_manifest(
    manifest_arg: str,
) -> ExtractionManifest | int:
    """Resolve and validate the manifest source per R1.2-R1.8.

    Returns either a validated ``ExtractionManifest`` (success path)
    or an exit code (``2``) when the input is malformed. The
    integer-return-on-failure pattern keeps the handler linear; the
    handler tests ``isinstance(result, int)`` to branch.

    The TTY guard (R1.5) fires as the first action when
    ``manifest_arg == "-"``. This is a deliberate ordering choice:
    an interactive operator who typed ``loki classify -`` and then
    forgot what the ``-`` meant gets the TTY-guard error message
    immediately rather than waiting silently for input that never
    arrives (per design-phase note in requirements.md introduction).
    """
    from loki.models import ExtractionManifest

    if manifest_arg == "-":
        # R1.5: TTY guard FIRST, before any read.
        if sys.stdin.isatty():
            print(
                "loki classify: stdin is a TTY; pipe a manifest or pass a path",
                file=sys.stderr,
            )
            return 2
        try:
            text = sys.stdin.read()
        except OSError as exc:
            print(f"loki classify: cannot read stdin: {exc}", file=sys.stderr)
            return 2
    else:
        # R1.3: file path mode.
        path = Path(manifest_arg)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError) as exc:
            print(
                f"loki classify: cannot read manifest: {manifest_arg}: {exc}",
                file=sys.stderr,
            )
            return 2

    # R1.7: JSON parse.
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        print(
            f"loki classify: manifest is not valid JSON: {exc}",
            file=sys.stderr,
        )
        return 2

    # R1.8: Pydantic strict validation.
    try:
        return ExtractionManifest.model_validate(payload, strict=True)
    except ValidationError as exc:
        # Bound the message length so a multi-error ValidationError
        # doesn't dump pages of context (no-leakage discipline R10).
        first_error = exc.errors()[0]
        loc = ".".join(str(part) for part in first_error.get("loc", ()))
        msg = first_error.get("msg", "validation error")
        print(
            f"loki classify: manifest failed validation: "
            f"{exc.error_count()} error(s); first at {loc!r}: {msg}",
            file=sys.stderr,
        )
        return 2
```

The ``ValidationError`` summarization mirrors the pattern already used in ``loki/classification/pipeline.py:_summarize`` — bounded, single-line, no field values reproduced.

#### ``_install_sigint_handler`` (R6.1)

The Cancel_Flag is a tiny mutable container so the cancel callback closure can read its current value without rebinding:

```python
# loki/loki/classify_helpers.py

@dataclass
class _CancelFlag:
    """Mutable boolean flag flipped by the SIGINT handler.

    Used as a single-instance per ``_handle_classify`` invocation;
    the cancel callback closure reads ``flag.value`` between the
    library's per-component iterations (R6.2).
    """
    value: bool = False


def _install_sigint_handler() -> tuple[_CancelFlag, Callable[[], None]]:
    """Install a SIGINT handler that flips the Cancel_Flag (R6.1).

    Returns a ``(_CancelFlag, restore)`` pair. The caller MUST call
    ``restore()`` in a ``finally`` block to put the previous SIGINT
    handler back; failure to restore would leave the flag-flipping
    handler installed in the parent process, which is wrong for any
    embedded test harness.

    R6.5: a second SIGINT after the flag is already True is a no-op
    — the handler stays installed but the flag is already True, so
    the library's next cancel poll continues to return True.
    """
    cancel_flag = _CancelFlag(value=False)

    def _handler(signum: int, frame: object) -> None:  # pragma: no cover - signal
        cancel_flag.value = True

    previous = signal.signal(signal.SIGINT, _handler)

    def _restore() -> None:
        signal.signal(signal.SIGINT, previous)

    return cancel_flag, _restore
```

The ``_handler`` is excluded from coverage because pytest's signal-injection patterns are environment-dependent; the in-process P55 test exercises the same flag-flip mechanism directly via the cancel callback rather than via SIGINT delivery.

#### ``_install_debug_logger`` (R7.2-R7.5)

The lifecycle of the ``--debug`` flag's effect on the ``loki.classification`` logger is recorded as four steps: capture the previous level, propagate, and handler set; install our own; run; restore. The restore function is returned as a closure so the handler doesn't have to re-derive what it changed.

```python
# loki/loki/classify_helpers.py

def _install_debug_logger(*, enabled: bool) -> Callable[[], None]:
    """Configure the ``loki.classification`` logger for ``--debug`` (R7.2-R7.5).

    When ``enabled``:
    - Set level to ``logging.DEBUG`` (R7.2).
    - Set ``propagate = False`` (R7.4 — added in HARDEN).
    - Attach a stderr ``StreamHandler`` only if no handler is
      already attached (R7.3).

    Returns a ``restore`` callable that undoes every change made.
    The restore is idempotent and safe to call from a ``finally``
    block whether or not ``enabled`` was True.

    Logger ``loki.classification`` is the library's own logger
    (see ``loki/classification/pipeline.py:62``); the CLI does not
    introduce a new logger name.
    """
    logger = logging.getLogger("loki.classification")
    if not enabled:
        # R7.5: when --debug is not set, do nothing.
        return lambda: None

    previous_level = logger.level
    previous_propagate = logger.propagate
    handler_added: logging.Handler | None = None

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        handler_added = logging.StreamHandler(sys.stderr)
        handler_added.setLevel(logging.DEBUG)
        # Use a minimal formatter; the leakage discipline (R10.5)
        # prevents the library from logging anything from the
        # Forbidden_Leakage_Field_Set, so the formatter doesn't
        # need to filter.
        handler_added.setFormatter(logging.Formatter("%(name)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler_added)

    def _restore() -> None:
        if handler_added is not None:
            logger.removeHandler(handler_added)
            handler_added.close()
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate

    return _restore
```

Note that the restore function captures ``handler_added`` by closure, so it knows whether to remove a handler we added vs. leave a pre-existing one alone (R7.3's "SHALL NOT attach a second handler" clause).

#### ``_build_progress_callback`` (R5.1-R5.5)

Mirrors the existing ``_build_progress_callback`` for ``loki extract`` in ``cli.py:295``, adapted for ``ProgressEvent`` shape:

```python
# loki/loki/classify_helpers.py

def _build_progress_callback(
    *, enabled: bool,
) -> ProgressCallback | None:
    """Return a stderr-line emitter when ``enabled``, else ``None`` (R5.1-R5.4).

    The callback formats each ``ProgressEvent`` as a single line
    on stderr in the form ``[index/total] component_id``. Stdout
    JSON is unchanged regardless (R5.5).

    The library's progress callback fires only on
    successfully-classified components per upstream R12.1 + the
    pipeline's loop control flow at
    ``loki/classification/pipeline.py:213``; R5.8 contracts that
    the CLI mirrors that behavior without modification, so the
    Progress_Line count equals the record count, not the input
    component count.
    """
    if not enabled:
        return None

    def _emit(event: ProgressEvent) -> None:
        # R10.2: component_id is the deliberate exception on the
        # Progress_Line; do NOT add any other field from the
        # Forbidden_Leakage_Field_Set.
        print(
            f"[{event.index}/{event.total}] {event.component_id}",
            file=sys.stderr,
            flush=True,  # R5.4: real-time visibility
        )

    return _emit
```

#### ``_serialize_result`` (R3.1-R3.7)

Single function that serializes a ``ClassificationResult`` into the indented JSON shape contracted by R3:

```python
# loki/loki/classify_helpers.py

def _serialize_result(result: ClassificationResult) -> str:
    """Serialize a ``ClassificationResult`` into the Stdout_Result form (R3).

    Returns a single string ending in exactly one trailing newline
    (R3.4). Key order on the top-level object is exactly
    ``["records", "errors"]`` (R3.5).

    Records and errors are serialized via
    ``model_dump(mode="json")`` so that ``UUID``, ``datetime``,
    and enum fields render as JSON-compatible primitives without
    Pydantic strict-mode round-trip surprises.
    """
    payload: dict[str, list[dict[str, object]]] = {
        "records": [r.model_dump(mode="json") for r in result.records],
        "errors": [e.model_dump(mode="json") for e in result.errors],
    }
    return json.dumps(payload, indent=2) + "\n"
```

#### ``_format_summary_line`` (R4.2)

```python
# loki/loki/classify_helpers.py

def _format_summary_line(
    result: ClassificationResult,
    *,
    duration_seconds: float,
) -> str:
    """Format the Stderr_Summary_Line per R4.2 (post-HARDEN).

    Format: ``classify: <N> records (<K> need_review),
    <E> errors, duration=<S>s``. No trailing newline; the caller
    appends via ``print(..., file=sys.stderr)``.

    R4.3: ``rules_loaded=<R>`` is intentionally omitted from v1;
    the library exposes the count only on the internal
    ``ClassificationPipeline._rules`` attribute, which is private
    per upstream R12.4. A future revision will extend this format
    once the public surface carries the count.

    R4.7: no value drawn from the Forbidden_Leakage_Field_Set
    appears here. The four interpolated values are integer counts
    and a duration only.
    """
    n_records = len(result.records)
    k_need_review = sum(1 for r in result.records if r.needs_review)
    e_errors = len(result.errors)
    return (
        f"classify: {n_records} records ({k_need_review} need_review), "
        f"{e_errors} errors, duration={duration_seconds:.4f}s"
    )
```

### Exit-code resolution

The mapping is pinned by the dictionary table plus the linear branches in ``_handle_classify``. Every code path in the handler (after manifest ingestion) resolves through one of:

| Source | Triggering exception or condition | Exit code | Requirement |
|---|---|---|---|
| ``_load_manifest`` returns int | TTY-on-stdin, file unreadable, JSON parse failure, Pydantic ValidationError, missing ``--rules-path`` (caught by argparse) | 2 | R1.5-R1.8, R2.2, R8.1 |
| ``_serialize_result`` raises | ``json.dumps`` error, ``UnicodeEncodeError``, etc. | 3 | R3.7, R8.1 |
| ``classify_components`` raises ``ClassificationConfigError`` | taxonomy mismatch, rules dir missing | 6 | R8.3 |
| ``classify_components`` raises ``ClassificationRuleError`` | bad rule schema | 5 | R8.4 |
| ``classify_components`` raises any other ``ClassificationPipelineError`` | (catchall) | 4 | R8.5 |
| ``classify_components`` raises any other ``Exception`` | unexpected | 4 | R8.6 |
| Cancel_Flag observed | SIGINT delivered + library returned with marker | 130 | R6.3, R8.1 |
| Successful run | (default) | 0 | R8.1 |

Property P54 (exit-code totality) asserts this mapping is total: every code path resolves through one of these lines, no path leaks an exit code outside ``{0, 2, 3, 4, 5, 6, 130}``.

### Sequence walkthrough

The handler proceeds linearly; the most non-trivial sequence is the cancellation path. Here is the full sequence with cancellation inserted at component index 5 of 10:

```
Operator types:    loki classify foo.json --rules-path /etc/loki/rules
                   (process started)

argparse parses:   args.manifest = "foo.json"
                   args.rules_path = Path("/etc/loki/rules")
                   args.taxonomy_version = "1.0.0"
                   args.progress = False
                   args.debug = False
                   args.summary_only = False
                   args.handler = _handle_classify

main() dispatches to _handle_classify(args).

_handle_classify:
  Step 1: manifest = _load_manifest("foo.json")
          → reads file, parses JSON, validates ExtractionManifest
          → manifest.components has 10 records.
  Step 2: config = ClassificationConfig(taxonomy_version="1.0.0",
                                        confidence_threshold=0.6,
                                        rules_path="/etc/loki/rules")
  Step 3: cancel_flag, restore_sigint = _install_sigint_handler()
          → cancel_flag.value = False
          → previous SIGINT handler captured for restoration.
  Step 4: restore_debug_logger = _install_debug_logger(enabled=False)
          → returns no-op restorer.
  Step 5: started_at = time.monotonic()
          progress_callback = _build_progress_callback(enabled=False)
                             → None
          classify_components(manifest.components, config,
                              progress=None, cancel=lambda: cancel_flag.value)
            └ runs synchronously; iterates components 1..10.
              At iteration 5, OPERATOR PRESSES CTRL-C.
              SIGINT delivered to handler → cancel_flag.value = True.
              Library finishes component 5's record, then before
              starting component 6, polls cancel() → True.
              Library appends Cancellation_Marker to errors list,
              breaks out of loop, returns ClassificationResult with
              5 records + 1 cancellation error.
          duration_seconds = time.monotonic() - started_at
                          ≈ 0.42 (library duration; CLI overhead negligible)
  finally: restore_debug_logger()  # no-op
           restore_sigint()        # SIGINT handler restored to previous
  sigint_observed = cancel_flag.value  → True
  Step 9: sys.stdout.write(_serialize_result(result))
          → emits {"records": [...5 records...],
                   "errors": [...1 cancellation marker...]}
            with indent=2 + trailing newline.
  Step 10: print("classify: 5 records (2 need_review), 1 errors,
                  duration=0.4231s",
                 file=sys.stderr)
  Step 11: return 130 (sigint_observed is True)

main() returns 130 → process exits 130.
```

The sequence for a normal (non-cancelled) run is identical except Step 5 sees ``cancel_flag.value`` stay False throughout, and Step 11 returns 0.

The sequence for an error run (e.g. ``ClassificationConfigError``) takes the ``except ClassificationConfigError`` branch in Step 5, prints the typed-error message, returns 6, skips Steps 9 and 10 entirely. R4.5 contracts that no Stderr_Summary_Line is emitted on whole-run failures.

### Concurrency model

There is no concurrency in the CLI handler. ``classify_components`` runs synchronously on the calling thread per upstream R1.7; the SIGINT handler is the only other entry point, and it does no work beyond a flag flip. Python's ``signal`` module guarantees handler delivery on the main thread (the only thread the CLI uses), so the Cancel_Flag's lack of a lock is safe.

R1.11 contracts that the CLI does not spawn worker threads, asyncio tasks, or process pools in v1.

### Determinism contract

Per R9.1, the CLI's stdout SHALL be byte-equal across two invocations on the same inputs after stripping the per-record ``timestamp`` field. The deterministic sources of variation are:

1. ``ClassificationRecord.timestamp`` — set by the library to the run's start time per upstream R1.6. Strip via ``json`` post-processing in P53's test harness; no CLI-side change.
2. The Stderr_Summary_Line's ``duration=<S>s`` field — wall-clock duration, varies run-to-run. P57 checks the line's *presence and shape* but doesn't check the duration's stability.

P53 (stdin-or-file equivalence) and P54 (exit-code totality) are pinned by deterministic in-process tests; P55 (cancellation contract) is pinned by a deterministic in-process test using a synthetic ``CancellationToken`` plus one example-based subprocess test for the SIGINT end-to-end behavior; P56 (``--summary-only``) is a deterministic test parameterized over manifest record counts; P57 (Stderr_Summary_Line emission discipline) is a four-case parametrized test (success, partial-cancellation, per-component-error, whole-run failure) that asserts exactly one line on the first three and zero on the fourth; P58 (no-leakage on stderr) is a static AST audit + dynamic stderr-capture audit pinning the Forbidden_Leakage_Field_Set on every CLI-emitted stderr path.

### No-leakage discipline (R10)

The CLI extends the library's no-leakage discipline (upstream R13.5) to its own stderr surface. Two audits implement this:

- **Static AST audit** at ``tests/classify_cli/test_no_leakage.py``: walks the ``classify_helpers.py`` module's AST, asserts no ``f"..."`` or ``str.format(...)`` call in the helper functions interpolates any value drawn from the Forbidden_Leakage_Field_Set on a stderr-bound write. The whitelist is ``component_id`` on the Progress_Line emitter only (R10.2). Mirrors the pattern at ``tests/classification/test_no_log_leakage.py``.

- **Dynamic stderr-capture audit** at ``tests/classify_cli/test_no_leakage.py`` (same file, separate test class): runs ``loki classify`` end-to-end against a manifest with components carrying known forbidden values (e.g. a synthetic ``signature_info.signer = "evil"``), captures stderr via pytest's ``capsys`` fixture, asserts that "evil" never appears anywhere in the captured stderr. This is the contract-level audit; it pairs the AST audit's syntactic check with a behavioral check.

The ``--debug`` flag's added handler does NOT bypass the audit (R7.7); the library's logger discipline at R13.5 of upstream is unconditional on log level, so a DEBUG record is no more permissive than an INFO record.

### Performance plan (R11.1)

The wrapper-only timing measurement is the contract: the slow-marker test at ``tests/classify_cli/test_performance.py`` times each wrapper step explicitly:

```python
# Pseudocode for the slow-marker test
@pytest.mark.slow
def test_cli_overhead_under_200ms():
    # Build a 256-component synthetic manifest.
    manifest = _build_manifest(component_count=256)
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(manifest.model_dump_json())

    # Build a 256-rule synthetic rules dir.
    rules_path = _build_rules_dir(rule_count=256)

    # Time the wrapper steps explicitly.
    parse_t0 = time.monotonic()
    parser = build_parser()
    args = parser.parse_args(["classify", str(manifest_path), "--rules-path", str(rules_path)])
    parse_t1 = time.monotonic()

    load_t0 = time.monotonic()
    manifest_loaded = _load_manifest(str(manifest_path))
    load_t1 = time.monotonic()

    serialize_t0 = time.monotonic()
    fake_result = ClassificationResult(records=[...], errors=[])
    _ = _serialize_result(fake_result)
    serialize_t1 = time.monotonic()

    cli_overhead = (parse_t1 - parse_t0) + (load_t1 - load_t0) + (serialize_t1 - serialize_t0)
    assert cli_overhead < 0.200, f"CLI overhead {cli_overhead:.3f}s exceeds 200ms budget"
```

The library's own time inside ``classify_components`` is explicitly excluded from the CLI overhead measurement; this avoids any future drift in the library's internal duration reporting from leaking into the CLI's contract (R11.1 post-HARDEN).

R11.3's working-set bound is SHOULD-level; no test enforces it in v1. A future ``tracemalloc``-based audit may add enforcement.

### Test infrastructure inheritance

The test suite at ``tests/classify_cli/`` follows the project's existing patterns:

- ``conftest.py`` provides shared fixtures: a ``tmp_rules_path`` fixture builds a small valid rules dir under ``tmp_path``; a ``sample_manifest_json`` fixture builds a small valid ``ExtractionManifest`` and returns its JSON-serialized form; a ``no_blocking_dialogs`` fixture is unnecessary (no GUI surface).
- ``--strict-markers`` is set in ``pyproject.toml`` and the slow marker is registered; ``test_performance.py`` is the only ``@pytest.mark.slow`` user in this subsystem.
- ``filterwarnings = ["error"]`` in ``pyproject.toml`` carries forward; CLI tests should not emit any ``DeprecationWarning``.
- The static AST audit at ``test_no_leakage.py`` mirrors ``tests/classification/test_no_log_leakage.py`` exactly; the dynamic audit pairs it.
- Hypothesis settings: P53 uses ``max_examples=25`` (full-pipeline equivalence test); P56 uses ``max_examples=50`` (parameterized over manifest record counts; in-memory fast). P55 is a deterministic test, not a Hypothesis property; ``max_examples`` doesn't apply.

## Data Models

### No model layer changes

The CLI introduces no new Pydantic models. It consumes:

- ``ExtractionManifest`` from ``loki.models.firmware`` (read on the input side).
- ``ClassificationConfig`` from ``loki.models.config`` (constructed in Step 2; passed to the library).
- ``ClassificationResult``, ``ClassificationRecord``, ``ClassificationError``, ``ProgressEvent`` from ``loki.classification`` (consumed on the output side).
- ``ClassificationConfigError``, ``ClassificationRuleError``, ``ClassificationPipelineError`` from ``loki.classification`` (caught in Step 5).

No new ``StrEnum``, no new dataclass beyond the internal ``_CancelFlag`` helper. No model layer changes are needed for v1.

The ``_CancelFlag`` is intentionally a tiny dataclass with one mutable field rather than a ``threading.Event`` — the CLI is single-threaded, the SIGINT handler runs on the main thread synchronously between the library's per-component iterations, and a no-lock mutable-bool is the simplest correct shape.

## Correctness Properties

The CLI's correctness is pinned by six property contracts (P53-P58) plus the deterministic in-process tests for cancellation and exit-code totality. P53-P58 are designated in `requirements.md` Requirement 13 and traced here to specific design elements:

### Property 53: Stdin-or-file equivalence

Pinned by a Hypothesis test at `tests/classify_cli/test_stdout_shape.py` that, for randomly generated valid `ExtractionManifest` JSON contents, asserts `loki classify <path>` and `cat <path> | loki classify -` produce byte-equal stdout after stripping the per-record `timestamp` field. Design element: `_load_manifest`'s symmetric handling of file vs. stdin (both paths converge on the same `text` variable before JSON parse).

**Validates: Requirements 9.2, 13.1**

### Property 54: Exit-code totality

Pinned by a parameterized test at `tests/classify_cli/test_exit_codes.py` that, for every error class in the `ClassificationPipelineError` hierarchy (currently `ClassificationConfigError`, `ClassificationRuleError`, plus the catchall `ClassificationPipelineError`) plus every input-validation failure mode listed in Requirements 1 and 2 plus the `--summary-only` and successful-run paths, asserts the resulting exit code is exactly one of `{0, 2, 3, 4, 5, 6, 130}`. Design element: the `_CLASSIFY_EXIT_CODES` table + the linear branches in `_handle_classify`'s Step 5 + the table in §Exit-code resolution above.

**Validates: Requirements 8.1, 8.2, 13.2**

### Property 55: Cancel_Flag-driven cancellation contract

Pinned by a deterministic in-process test at `tests/classify_cli/test_cancellation.py` that, for cancellation indices `[1, total]`, passes a synthetic `CancellationToken` returning `True` at the configured iteration and asserts the contract holds (Cancellation_Marker is the last entry, has `error_message="classification cancelled by caller"` and `component_id is None`, the Stdout_Result still parses as valid JSON, and the handler's exit-code resolution returns 130). The end-to-end SIGINT behavior is covered by a separate example-based subprocess test at `tests/classify_cli/test_sigint_e2e.py` using `subprocess.send_signal()` with a deterministic wait condition. Design element: `_install_sigint_handler` + `_CancelFlag` + Step 11's `return 130 if sigint_observed`.

**Validates: Requirements 6.1-6.7, 13.3**

### Property 56: --summary-only zero-byte stdout

Pinned by a Hypothesis test at `tests/classify_cli/test_summary_only.py` that, for randomly generated valid manifests of any record count (including the empty manifest), asserts `loki classify ... --summary-only` writes zero bytes to stdout. Design element: Step 9's `if not args.summary_only` guard around `sys.stdout.write`.

**Validates: Requirements 3.6, 13.4**

### Property 57: Stderr_Summary_Line emission discipline

Pinned by a four-case parameterized test at `tests/classify_cli/test_stderr_summary.py` that asserts: on every successful run, partially-cancelled run, and per-component-error run, the summary line is emitted exactly once; on every whole-run failure (exit 4/5/6), it is not emitted. Design element: Step 10's unconditional emit on success-or-cancellation paths + the absence of a Step-10-equivalent in the typed-error branches at Step 5.

**Validates: Requirements 4.1, 4.5, 4.6, 13.5**

### Property 58: No-leakage on stderr

Pinned by paired static + dynamic audits at `tests/classify_cli/test_no_leakage.py`. Design elements: the static audit walks `classify_helpers.py`'s AST asserting no f-string interpolation of forbidden fields on stderr-bound writes; the dynamic audit runs the CLI with a manifest carrying known-forbidden values and asserts they don't appear in captured stderr. The `component_id` exception on Progress_Line is whitelisted in both audits.

**Validates: Requirements 10.1-10.5, 13.6**

The two cross-cutting properties P54 and P58 are the ones most likely to catch regressions during implementation; P53 and P56 are equivalence-checks that will flag any unintended side effect of input-mode or summary-flag changes; P55 and P57 are emission-discipline checks that pin behavior the CLI promises but the upstream library doesn't directly verify.

## Error Handling

The CLI's error handling has three concentric layers, mapped to exit codes per the table in §Exit-code resolution:

### Layer 1 — Input validation (exit 2)

`_load_manifest` performs every input check before invoking the library:

- TTY guard on stdin (R1.5): the first action when `manifest_arg == "-"`. Stdout is not opened; the library is never reached. Stderr message: `loki classify: stdin is a TTY; pipe a manifest or pass a path`.
- File readability (R1.6): caught via `OSError` / `FileNotFoundError` on `path.read_text(encoding="utf-8")`. Stderr message: `loki classify: cannot read manifest: <path>: <reason>`.
- JSON parse (R1.7): caught via `json.JSONDecodeError`. Stderr message: `loki classify: manifest is not valid JSON: <decoder error>`.
- Pydantic strict validation (R1.8): caught via `ValidationError`. Stderr message: `loki classify: manifest failed validation: <error count>; first at <loc>: <msg>` (bounded; no field values reproduced per R10.4).
- Missing `--rules-path`: caught by `argparse` itself; argparse prints its standard error and calls `sys.exit(2)`. The handler does not see the args namespace; `_handle_classify` is never invoked.

Layer 1 errors return the literal `2` from `_load_manifest` (or are caught by argparse before the handler runs). The handler's `isinstance(manifest_or_exit_code, int)` branch returns the exit code directly without invoking the library.

### Layer 2 — Library invocation errors (exit 3-6)

Step 5 of the handler catches the library's typed exception hierarchy in a chain of `except` clauses, ordered from most-specific to least-specific:

```python
try:
    result = classify_components(...)
except ClassificationConfigError as exc:    # exit 6
    print(f"loki classify: configuration error: {exc}", file=sys.stderr)
    return 6
except ClassificationRuleError as exc:      # exit 5
    print(f"loki classify: rule error: {exc}", file=sys.stderr)
    return 5
except ClassificationPipelineError as exc:  # exit 4 (catchall)
    print(f"loki classify: pipeline error: {exc}", file=sys.stderr)
    return 4
except Exception as exc:                    # exit 4 (unexpected)
    print(f"loki classify: unexpected error: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 4
```

The order matters. `ClassificationConfigError` and `ClassificationRuleError` are subclasses of `ClassificationPipelineError`; if the catchall came first, the more-specific subclass would never match. Putting the catchall after the specific subclasses preserves the contracts in R8.3 / R8.4 / R8.5.

The unexpected-exception branch (R8.6) is the safety net. It maps to exit 4 (same as the pipeline catchall) so the closed exit-code set stays `{0, 2, 3, 4, 5, 6, 130}`. The error message includes the exception type to make the unexpected case distinguishable from the expected catchall in operator logs.

The serialization error (exit 3, R3.7 / R8.1) is caught at Step 9, after the library has returned successfully but JSON construction fails. The library's typed errors and the serialization error are mutually exclusive; the linear handler structure makes this obvious.

### Layer 3 — Cancellation (exit 130)

R6's cooperative-cancellation contract is a return-path, not a throw-path. The library returns a complete `ClassificationResult` containing the Cancellation_Marker; the handler observes `cancel_flag.value == True` after the library returns and resolves to exit 130 instead of 0. No exception is raised; no error path is taken.

The `finally` block restores the SIGINT handler and the debug-logger state regardless of which path was taken — including the cancellation path where no exception was raised. This guarantees that the operator's signal-handling environment is restored even when the CLI is invoked from an embedded Python harness (e.g. a future test that drives `loki classify` in-process via `main()`).

### What's intentionally not handled

- **Errors during stderr writes (e.g. closed pipe to `tee` or `head -1`)**. The CLI does not catch `BrokenPipeError` on stderr writes. This is by design: a broken stderr is operationally meaningful (the operator's downstream tool went away), and the Python default — let the exception propagate, which the catchall converts to exit 4 — is the correct behavior. R5.7 contracts that `BrokenPipeError` from the progress callback maps to exit 4 via the catchall path.

- **Errors during stdout writes (e.g. closed pipe)**. Same posture. The serialization error path (R3.7) is for `json.dumps` failures, not for stream-write failures after the JSON is constructed; a broken stdout pipe propagates through the catchall and exits 4. This may surprise operators who expect "broken pipe" to exit 0 (the bash convention for `... | head -1`); R6.5's "no double-Ctrl-C short-circuit" note implies the CLI is willing to be loud about non-success. Worth flagging in CLI help text if any operator requests it.

- **Signal handlers other than SIGINT**. SIGTERM, SIGHUP, SIGPIPE: not handled by the CLI; default Python signal disposition applies. R6 only contracts SIGINT; future revisions may add SIGTERM-as-cancellation if a CI use case emerges.

## Testing Strategy

The test suite at `tests/classify_cli/` follows the project's existing patterns and inherits the gates documented in the upstream `loki/HANDOFF.md` (1211 baseline tests, mypy --strict, ruff, slow-marker performance suite, offscreen GUI smoke). The CLI-specific structure:

### Test taxonomy

The 15-file structure under `tests/classify_cli/` (listed in §Module layout) groups tests by requirement boundary. Each requirement's acceptance criteria are pinned by exactly one or two test files; cross-cutting concerns (no-leakage, exit-code totality) get their own files because they span multiple requirements.

### Test types in use

- **Example-based unit tests** for individual helpers: `_load_manifest` against synthetic JSON payloads, `_format_summary_line` against synthetic results, `_serialize_result` round-trip checks. These dominate the count of test functions.
- **Hypothesis property tests** for P53 (stdin-or-file equivalence) and P56 (`--summary-only` zero-byte stdout). `max_examples=25` for P53 (full-pipeline equivalence; expensive); `max_examples=50` for P56 (in-memory; cheap).
- **Deterministic in-process tests** for P55 (Cancel_Flag contract) and P54 (exit-code totality). Not Hypothesis properties because the cancellation index space and the typed-error space are small enough to enumerate explicitly.
- **One example-based subprocess test** for the SIGINT end-to-end behavior. Uses `subprocess.Popen` + `send_signal(SIGINT)` with a deterministic wait condition. This is the only place we run the CLI as a subprocess; everywhere else uses in-process invocation via `loki.cli.main(["classify", ...])`.
- **Static AST audit** at `test_no_leakage.py` for P58. Walks `classify_helpers.py`'s AST asserting no f-string interpolation of forbidden fields on stderr-bound writes; whitelist is `component_id` on the Progress_Line emitter only.
- **Dynamic stderr-capture audit** at `test_no_leakage.py` (separate test class). Runs the CLI end-to-end via `loki.cli.main(...)` against a manifest with known-forbidden values, captures stderr via `capsys`, asserts the forbidden values do not appear in the captured stderr.
- **Slow-marker performance test** at `test_performance.py`. Measures wrapper-only timing (not the library's internal time); enforces R11.1's 200ms budget.

### Hypothesis settings

The CLI tests use the project's standard Hypothesis settings: `suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture]`, `max_examples=50` for in-memory matcher properties, `max_examples=25` for full-pipeline properties. P53 (full-pipeline equivalence) runs at `max_examples=25`; P56 (parameterized over manifest record counts) runs at `max_examples=50`. P55 is deterministic, not Hypothesis-based.

### Test fixtures

The shared fixtures in `tests/classify_cli/conftest.py`:

- `tmp_rules_path`: builds a small valid rules dir under `tmp_path` with three rules covering each axis (`type`, `vendor`, `security_posture`, `mutability`). Borrows shape from `tests/classification/conftest.py` but is bespoke to keep the CLI tests self-contained.
- `sample_manifest_json`: builds a small valid `ExtractionManifest` with five components and returns its JSON-serialized form (string). Parametrizable for tests that need varying record counts.
- `cli_argv`: helper to construct argv lists like `["classify", "manifest.json", "--rules-path", "/tmp/rules"]` so tests don't repeat the boilerplate.
- `capture_classify_run`: helper that wraps `loki.cli.main(...)` with stdout/stderr capture and returns a `(exit_code, stdout, stderr)` triple. Mirrors what `subprocess` would give without the subprocess overhead.

### Coverage targets

Every acceptance criterion in `requirements.md` MUST be covered by at least one assertion. The traceability table in §Per-requirement traceability above maps each requirement to the test file responsible. Tasks at task-breakdown phase will turn this into an explicit per-criterion checklist.

The test count target is approximately 60-80 test functions across the 15 files; this is conservative for a 13-requirement spec but accounts for the parameterization that several files do (P54's typed-error enumeration, P56's record-count parameterization, the four-case Stderr_Summary_Line discipline test).

### Verification gates inheritance

The CLI subsystem's verification gates are exactly the project's existing four:

1. `pytest -q` baseline (currently 1211; CLI adds approximately 60-80; new baseline approximately 1271-1291).
2. `mypy --strict loki tests scripts` clean.
3. `ruff check` + `ruff format --check` clean.
4. Offscreen GUI smoke (unaffected; CLI does not import PyQt6).

Plus the slow-marker run when running the performance suite explicitly (`pytest -m slow`).

Each of these is a design judgment that the spec records explicitly so a future revision can revert cheaply if the underlying preference changes. They mirror the analysis-engine's D1-D8 convention.

- **D1 — Single new module ``classify_helpers.py`` rather than inlining helpers in ``cli.py``.** ``cli.py`` is already 700+ lines; adding 200+ more for the classify handler would push past 1,000. The new module keeps the existing handler patterns visible without forcing a larger refactor of ``cli.py``. Reverting (inlining) is a single-file move.

- **D2 — ``_CancelFlag`` is a tiny ``@dataclass`` rather than a ``threading.Event`` or a ``list[bool]``.** The dataclass shape is the most readable; threading machinery is overkill for a single-thread no-lock contract. Reverting to ``threading.Event`` is a one-line type change at the helper definition; the cancel-callback closure is unchanged.

- **D3 — ``--debug`` sets ``propagate = False`` always when enabled.** Alternatives (auto-detect via ``getEffectiveLevel()``, leave propagate alone) were considered in the TENSION pass and rejected. Setting propagate to False guarantees DEBUG records surface exactly once on the CLI's stderr handler, regardless of what the user has configured at root or at intermediate loggers. The cost is that externally-attached handlers on parent loggers are silenced for the run's duration; this is well-bounded and recoverable. Reverting is a one-line removal in ``_install_debug_logger``.

- **D4 — TTY guard fires as the first action when manifest is ``-``.** Checked in the requirements introduction's design-phase notes; the helper places it before ``sys.stdin.read()`` so an interactive operator sees the error message instantly rather than waiting forever. Reverting is a reordering of the two lines.

- **D5 — Exit-code 4 catches both ``ClassificationPipelineError`` (catchall) and unexpected ``Exception``.** R8.5 + R8.6 contract this. The two are distinguished by their stderr message prefix (``pipeline error:`` vs. ``unexpected error: <type>:``). Reverting (splitting unexpected exceptions into a separate code 7) requires a spec amendment to R8.1.

- **D6 — Helper module is module-private (single-leading-underscore names; no ``__all__``).** The CLI's helpers are not a public API; they exist to make the handler readable. Promoting any helper to the public API requires a spec amendment because the function's stability becomes a contract.

- **D7 — Manifest ingestion (Step 1) returns ``int`` on failure rather than raising.** Keeps the handler linear; no nested ``try/except`` in the input-validation paths. The success-vs-failure branch is a single ``isinstance`` check in the handler. Reverting (raise typed errors instead) is a one-helper change.

The non-blocking design-phase implementation notes from requirements.md introduction (TTY check ordering, double-Ctrl-C user education, OT-LK-006 forward thread) are documented inline in the relevant sections above and not repeated as separate D-numbered defaults.

## Per-requirement traceability

A sketch of which acceptance criteria each design element satisfies. Detailed per-criterion mapping happens at task-breakdown time:

- **Req 1 (subcommand registration + manifest input):** ``_add_classify_subcommand``, ``_load_manifest`` (Steps 1, 5).
- **Req 2 (rules-path + taxonomy):** ``--rules-path required=True``, ``--taxonomy-version default="1.0.0"``, ``ClassificationConfig(confidence_threshold=0.6)`` in Step 2.
- **Req 3 (stdout JSON shape + summary-only):** ``_serialize_result``; Step 9's ``if not args.summary_only`` guard.
- **Req 4 (stderr summary line):** ``_format_summary_line``; Step 10's unconditional emit on success or partial cancellation.
- **Req 5 (--progress flag):** ``_build_progress_callback`` + Step 5's ``classify_components(progress=...)`` argument.
- **Req 6 (SIGINT cancellation):** ``_install_sigint_handler`` + ``_CancelFlag`` + Step 11's ``return 130 if sigint_observed``.
- **Req 7 (--debug flag):** ``_install_debug_logger`` (R7.2-R7.5 lifecycle).
- **Req 8 (exit-code taxonomy):** ``_CLASSIFY_EXIT_CODES`` + Step 5's typed-error branches + the table in §Exit-code resolution.
- **Req 9 (determinism + R5.6 dual-record):** library passthrough; verified by P53.
- **Req 10 (no-leakage):** verified by static + dynamic audit at ``tests/classify_cli/test_no_leakage.py``; verified by P58.
- **Req 11 (performance):** wrapper-only timing test at ``tests/classify_cli/test_performance.py``.
- **Req 12 (help text):** every flag's ``help=...`` argument in ``_add_classify_subcommand``.
- **Req 13 (properties P53-P58):** test files under ``tests/classify_cli/``; explicit P53-P58 designation in test names or docstrings.

## Open questions deferred to task-breakdown phase

- **Q1 — Test fixture sharing.** Should ``tests/classify_cli/conftest.py`` build its own rules-dir fixture or reuse ``tests/classification/conftest.py``'s strategy generators? Reuse risks coupling; bespoke risks divergence. Default proposal: a thin re-export from ``tests/classification/conftest.py`` for the rule generators, plus a CLI-specific manifest fixture.

- **Q2 — pytest test class organization.** Existing ``tests/classification/`` uses module-level test functions; ``tests/gui/`` uses test classes. The CLI's complexity (lifecycle helpers + per-flag tests + properties + audits) suggests classes for grouping. Default proposal: classes for ``test_no_leakage.py`` (paired static + dynamic audits in one file naturally splits into two classes); functions everywhere else.

- **Q3 — How to detect ``loki classify`` is being run inside a CI environment vs. interactively.** Probably out of scope for v1 — the TTY guard is sufficient — but a ``--no-tty-guard`` flag for shell scripts that pipe nothing to stdin (e.g. via ``</dev/null``) might be useful. Default proposal: defer to a future spec amendment if any operator requests it.

These three open questions are not blocking — sensible defaults exist for each, and the task-breakdown phase pins them through implementation choices.

## Summary

The Classification CLI is a thin, deterministic, single-file-handler shell over the existing classification library. The design adds approximately 200 source lines (handler + helpers + subcommand registration) and approximately 800 test lines (15 test files covering every requirement). It introduces no new Pydantic models, no new public APIs, and no new logger names. It mirrors the existing ``loki extract`` and ``loki baseline`` patterns precisely so a reader of ``cli.py`` will find the new code in the expected shape.

The seven design defaults (D1-D7) are documented for future revertability. The three open questions (Q1-Q3) are deferred to the task-breakdown phase with sensible defaults proposed.

The DRAFT requirements doc is HARDEN'd (per the operator's tag in the round preceding this design conversation); this design.md is therefore the BIND target for the next round (tasks.md), and any further amendment to requirements.md goes through an explicit FRAY before BIND.

---

**End of design.md.**
