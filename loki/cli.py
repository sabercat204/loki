"""Top-level CLI for Loki.

Subcommands:

- ``loki gui`` — launch the PyQt6 desktop app.
- ``loki extract`` — run the firmware extraction pipeline against a
  binary on disk and emit a JSON manifest.
- ``loki baseline list / show / import / export / delete`` — curate
  the persisted Baseline_Files under a Storage_Directory.

Additional subcommands (classification, analysis) land alongside
their respective subsystems.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import sys
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from loki.baseline import BaselineStore
    from loki.extraction import ProgressEvent

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    """Build the ``argparse`` parser for the ``loki`` CLI."""

    try:
        version = importlib.metadata.version("loki")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - dev install
        version = "0.0.0+unknown"

    parser = argparse.ArgumentParser(
        prog="loki",
        description="Loki firmware analysis platform.",
    )
    parser.add_argument("--version", action="version", version=f"loki {version}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    gui_parser = sub.add_parser("gui", help="Launch the desktop GUI.")
    gui_parser.set_defaults(handler=_handle_gui)

    extract_parser = sub.add_parser(
        "extract",
        help="Extract a firmware binary into a JSON ExtractionManifest.",
        description=(
            "Run the firmware extraction pipeline on the supplied binary. "
            "Prints the validated ExtractionManifest as JSON to stdout; "
            "diagnostic counters (tools_available, duration_seconds) go "
            "to stderr."
        ),
    )
    extract_parser.add_argument(
        "path",
        type=Path,
        help="Path to the firmware binary on disk.",
    )
    extract_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Directory under which raw component bytes are written "
            "as `0x{offset:x}-{raw_hash}.bin`. Created if missing. "
            "When omitted, raw bytes are not written and "
            "ExtractedComponent.raw_path stays null."
        ),
    )
    extract_parser.add_argument(
        "--max-component-size",
        type=int,
        default=50_000_000,
        metavar="BYTES",
        help="Skip components larger than this many bytes (default: 50 MB).",
    )
    extract_parser.add_argument(
        "--timeout-per-component",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Per-component wall-clock timeout in seconds (default: 60).",
    )
    extract_parser.add_argument(
        "--progress",
        action="store_true",
        help=(
            "Emit one line per ProgressEvent to stderr while extraction "
            "runs. Useful when extracting large binaries from a terminal "
            "where the wait would otherwise be silent. The manifest "
            "JSON on stdout is unchanged."
        ),
    )
    extract_parser.set_defaults(handler=_handle_extract)

    _add_baseline_subcommands(sub)
    _add_classify_subcommand(sub)
    _add_analyze_subcommand(sub)
    _add_feeds_subcommand(sub)
    _add_fleet_subcommand(sub)

    return parser


def _add_baseline_subcommands(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Wire up the ``loki baseline`` subcommand group (R6).

    Five v1 subcommands: ``list``, ``show``, ``import``, ``export``,
    ``delete``. Each takes a mandatory ``--storage-path`` flag at
    the group level so tests can isolate themselves on
    ``tmp_path`` and never touch the user's real baseline
    directory.
    """

    baseline = sub.add_parser(
        "baseline",
        help="Curate persisted Baseline_Files under a Storage_Directory.",
        description=(
            "Group of subcommands for managing baselines on disk: "
            "list, show, import, export, delete."
        ),
    )
    baseline.add_argument(
        "--storage-path",
        type=Path,
        required=True,
        metavar="DIR",
        help=(
            "Path to the Storage_Directory. Created if missing. "
            "Required for every baseline subcommand so tests and "
            "scripts never hit the user's real baseline directory."
        ),
    )
    baseline_sub = baseline.add_subparsers(
        dest="baseline_command",
        required=True,
        metavar="SUBCOMMAND",
    )

    list_parser = baseline_sub.add_parser(
        "list",
        help="List every baseline in the Storage_Directory.",
        description=(
            "Loads the Storage_Directory and prints one row per "
            "baseline ordered by (vendor, model, firmware_version). "
            "Quarantined files surface in a stderr summary line. "
            "Exits 0 even when the Quarantine_Set is non-empty (R6.3)."
        ),
    )
    list_parser.set_defaults(handler=_handle_baseline_list)

    show_parser = baseline_sub.add_parser(
        "show",
        help="Print one baseline as indented JSON.",
        description=(
            "Looks up the baseline by ID and prints "
            "BaselineRecord.model_dump_json(indent=2) to stdout. "
            "Exits 2 if no baseline matches (R6.5)."
        ),
    )
    show_parser.add_argument(
        "baseline_id",
        type=str,
        help="UUID of the baseline to show.",
    )
    show_parser.set_defaults(handler=_handle_baseline_show)

    import_parser = baseline_sub.add_parser(
        "import",
        help="Import a Baseline_File into the Storage_Directory.",
        description=(
            "Loads a single Baseline_File from anywhere on disk, "
            "validates it, and saves it into the Storage_Directory. "
            "Prints the resulting Baseline_Filename to stdout (R6.6)."
        ),
    )
    import_parser.add_argument(
        "path",
        type=Path,
        help="Path to a Baseline_File to import.",
    )
    import_parser.set_defaults(handler=_handle_baseline_import)

    export_parser = baseline_sub.add_parser(
        "export",
        help="Export a baseline to an arbitrary path.",
        description=(
            "Looks up the baseline by ID and atomically writes a "
            "Baseline_File to the destination using the same "
            "envelope and Atomic_Write contract as save (R6.7). "
            "The destination's parent directory must already exist."
        ),
    )
    export_parser.add_argument(
        "baseline_id",
        type=str,
        help="UUID of the baseline to export.",
    )
    export_parser.add_argument(
        "dest",
        type=Path,
        help="Destination path for the exported Baseline_File.",
    )
    export_parser.set_defaults(handler=_handle_baseline_export)

    delete_parser = baseline_sub.add_parser(
        "delete",
        help="Delete a baseline from the Storage_Directory.",
        description=(
            "Looks up the baseline by ID, prompts for confirmation, "
            "and removes the corresponding Baseline_File (R6.8). "
            "Pass --yes to skip the prompt (R6.9)."
        ),
    )
    delete_parser.add_argument(
        "baseline_id",
        type=str,
        help="UUID of the baseline to delete.",
    )
    delete_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt.",
    )
    delete_parser.set_defaults(handler=_handle_baseline_delete)


def _add_classify_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Wire up the ``loki classify`` subcommand (R1, R2, R12).

    Registers the positional ``manifest`` argument plus the five
    v1 flags: ``--rules-path`` (mandatory), ``--taxonomy-version``
    (optional, default ``"1.0.0"``), ``--progress``, ``--debug``,
    ``--summary-only``. Every flag carries a non-empty help string
    per R12.1; the positional carries help that names both the
    file mode and the ``-`` stdin mode (R12.2). The ``description``
    summarizes the input contract, the stdout JSON shape, and the
    stderr summary line (R12.4).

    The handler is wired to the ``_handle_classify`` stub here;
    task 11 replaces the stub with the full lifecycle.
    """

    classify_parser = sub.add_parser(
        "classify",
        help="Classify a saved ExtractionManifest against a rules directory.",
        description=(
            "Read an ExtractionManifest (path or '-' for stdin), run the "
            "classification library against the rules directory, and emit "
            "a single indented JSON object {records, errors} to stdout "
            "plus a one-line summary "
            "'classify: <N> records (<K> need_review), <E> errors, "
            "duration=<S>s' to stderr. Composes with `loki extract` via "
            "shell pipelines."
        ),
    )
    classify_parser.add_argument(
        "manifest",
        type=str,
        help=("Path to an ExtractionManifest JSON file, or '-' to read the manifest from stdin."),
    )
    classify_parser.add_argument(
        "--rules-path",
        type=Path,
        required=True,
        metavar="DIR",
        help=(
            "Path to the directory containing classification rule "
            "YAML files (mandatory). Passed through verbatim to "
            "ClassificationConfig.rules_path."
        ),
    )
    classify_parser.add_argument(
        "--taxonomy-version",
        type=str,
        default="1.0.0",
        metavar="VERSION",
        help=(
            "Taxonomy version pin to enforce against the rule files "
            '(default: "1.0.0"). Passed through verbatim; mismatched '
            "values surface as ClassificationConfigError (exit 6)."
        ),
    )
    classify_parser.add_argument(
        "--progress",
        action="store_true",
        help=(
            "Stream one line per successfully-classified component to "
            "stderr in the form `[index/total] component_id`; the "
            "stdout JSON object is unchanged."
        ),
    )
    classify_parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Emit DEBUG-level records from the loki.classification "
            "logger to stderr for the duration of this run; stdout is "
            "unchanged. Restores the previous logger state on exit."
        ),
    )
    classify_parser.add_argument(
        "--summary-only",
        action="store_true",
        help=(
            "Suppress the stdout JSON object; emit only the stderr "
            "summary line. Useful for CI smoke runs that only need "
            "the counts."
        ),
    )
    classify_parser.add_argument(
        "--feeds-config",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to a loki config YAML containing a 'feeds' section. "
            "When supplied, CVE lookup is performed for each classified "
            "component and cve_matches is populated on the output records."
        ),
    )
    classify_parser.add_argument(
        "--trust-store",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Path to a directory of PEM/CRT root CA certificates for "
            "signature chain verification. When supplied, components with "
            "detected signatures are verified and SignatureInfo.verified/"
            "signer/cert_expiry are populated."
        ),
    )
    classify_parser.set_defaults(handler=_handle_classify)


def _add_analyze_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Wire up the ``loki analyze`` subcommand."""
    analyze_parser = sub.add_parser(
        "analyze",
        help="Run the analysis engine against a classified manifest.",
        description=(
            "Load a JSON manifest (ExtractionManifest), classify its "
            "components, then run the analysis engine against a baseline "
            "registry. Prints the validated ImageAnalysisReport as JSON "
            "to stdout; a one-line summary goes to stderr."
        ),
    )
    analyze_parser.add_argument(
        "manifest",
        type=Path,
        help="Path to a JSON ExtractionManifest file.",
    )
    analyze_parser.add_argument(
        "--baseline-path",
        type=Path,
        required=True,
        metavar="DIR",
        help="Path to the baseline storage directory.",
    )
    analyze_parser.add_argument(
        "--rules-path",
        type=Path,
        required=True,
        metavar="DIR",
        help="Path to the classification rules directory.",
    )
    analyze_parser.add_argument(
        "--taxonomy-version",
        type=str,
        default="1.0.0",
        metavar="VERSION",
        help='Taxonomy version for classification rules (default: "1.0.0").',
    )
    analyze_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress stdout JSON; emit only the stderr summary.",
    )
    analyze_parser.add_argument(
        "--trust-store",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Path to a directory of PEM/CRT root CA certificates for "
            "signature chain verification during classification."
        ),
    )
    analyze_parser.set_defaults(handler=_handle_analyze)


def _add_feeds_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Wire up the ``loki feeds`` subcommand group."""
    from loki.feeds.cli import register_feeds_subcommand

    register_feeds_subcommand(sub)


def _add_fleet_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Wire up the ``loki fleet`` subcommand group."""
    from loki.fleet.cli import register_fleet_subcommand

    register_fleet_subcommand(sub)


def _handle_gui(_args: argparse.Namespace) -> int:
    # Imported lazily so `loki --version` doesn't pay the PyQt6 import cost.
    from loki.gui.app import run

    return run()


def _handle_extract(args: argparse.Namespace) -> int:
    """Run ``extract_firmware`` and emit the manifest as JSON.

    Translates :class:`InvalidInputError` and
    :class:`ManifestConstructionError` into clean one-line stderr
    messages with non-zero exit codes (no Python traceback).
    """

    # Imported lazily so `loki --version` and `loki gui` don't pay the
    # uefi_firmware import cost.

    from loki.extraction import (
        ExtractionPipelineError,
        InvalidInputError,
        ManifestConstructionError,
        extract_firmware,
    )
    from loki.models import ExtractionConfig

    config = ExtractionConfig(
        default_output_dir=str(args.output_dir) if args.output_dir else "",
        max_component_size=int(args.max_component_size),
        timeout_per_component=int(args.timeout_per_component),
    )

    progress_callback = _build_progress_callback(args.progress)

    try:
        result = extract_firmware(args.path, config, progress=progress_callback)
    except InvalidInputError as exc:
        print(f"loki extract: {exc}", file=sys.stderr)
        return 2
    except ManifestConstructionError as exc:
        print(f"loki extract: manifest construction failed: {exc}", file=sys.stderr)
        return 3
    except ExtractionPipelineError as exc:
        print(f"loki extract: pipeline error: {exc}", file=sys.stderr)
        return 4

    sys.stdout.write(result.manifest.model_dump_json(indent=2))
    sys.stdout.write("\n")

    summary = {
        "tools_available": result.tools_available,
        "duration_seconds": round(result.duration_seconds, 4),
        "components": result.manifest.total_components,
        "errors": len(result.manifest.extraction_errors),
    }
    print(
        f"extract: {summary['components']} components, {summary['errors']} errors, "
        f"duration={summary['duration_seconds']}s, "
        f"tools_available={summary['tools_available']}",
        file=sys.stderr,
    )
    return 0


def _handle_classify(args: argparse.Namespace) -> int:
    """Run the loki classify subcommand (R1, R2, R3, R6, R7, R8 wiring).

    Linear lifecycle per design.md:
      Step 1: manifest ingestion (``_load_manifest``)
      Step 2: ``ClassificationConfig`` construction
      Step 3: SIGINT handler installation
      Step 4: debug logger setup
      Step 5: library invocation with try/except chain
      Step 6: stdout serialization (gated on ``--summary-only``)
      Step 7: stderr summary line emission (success or partial-cancellation)
      Step 8: exit code resolution (130 if cancelled, else 0)

    The ``finally`` block restores both lifecycle objects (debug
    logger + SIGINT handler) regardless of path. Whole-run
    failures (config / rule / pipeline / unexpected) print a
    typed-error stderr line and return early; the summary line
    is suppressed on those paths per R4.5.
    """
    # Lazy imports per project pattern (loki --version, loki gui,
    # loki extract, and loki baseline don't pay the classify import
    # cost).
    import time

    from loki.classification import classify_components
    from loki.classification.errors import (
        ClassificationConfigError,
        ClassificationPipelineError,
        ClassificationRuleError,
    )
    from loki.classify_helpers import (
        _CLASSIFY_EXIT_CODES,
        _format_summary_line,
        _install_debug_logger,
        _install_sigint_handler,
        _load_manifest,
        _serialize_result,
    )
    from loki.classify_helpers import (
        _build_progress_callback as _build_classify_progress_callback,
    )
    from loki.models import ClassificationConfig

    # Step 1: Manifest ingestion. Returns ExtractionManifest or int (exit code).
    manifest_or_exit = _load_manifest(args.manifest)
    if isinstance(manifest_or_exit, int):
        return manifest_or_exit
    manifest = manifest_or_exit

    # Step 2: ClassificationConfig construction.
    # confidence_threshold is pinned at 0.6 in v1 per R2.6: the
    # field is reserved for the analysis engine's review-flag
    # policy; no --confidence-threshold flag in v1.
    config = ClassificationConfig(
        taxonomy_version=args.taxonomy_version,
        confidence_threshold=0.6,
        rules_path=str(args.rules_path),
    )

    # Step 2b: Optional feeds registry construction.
    feeds_registry = None
    if getattr(args, "feeds_config", None) is not None:
        from loki.feeds.errors import FeedsConfigError
        from loki.feeds.registry import FeedRegistry
        from loki.models.config import LokiConfig

        try:
            loki_config = LokiConfig.from_yaml(args.feeds_config)
        except Exception as exc:
            print(f"loki classify: feeds configuration error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationConfigError"]
        try:
            feeds_registry = FeedRegistry.from_config(loki_config.feeds)
        except FeedsConfigError as exc:
            print(f"loki classify: feeds configuration error: {exc.message}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationConfigError"]

    # Step 2c: Optional trust store construction.
    trust_store = None
    if getattr(args, "trust_store", None) is not None:
        from loki.verification import TrustStore

        trust_store = TrustStore.from_directory(args.trust_store)

    # Step 3 + 4: lifecycle setup.
    cancel_flag, restore_sigint = _install_sigint_handler()
    restore_debug = _install_debug_logger(enabled=args.debug)
    progress_callback = _build_classify_progress_callback(enabled=args.progress)

    # cancel_token is a small lambda that the library polls
    # between iterations. Uses cancel_flag.value as its source
    # of truth.
    def _cancel_token() -> bool:
        return cancel_flag.value

    start = time.monotonic()

    try:
        # Step 5: library invocation. Ordered except clauses:
        # most-specific first (ConfigError, RuleError) before
        # catchall (PipelineError) before unexpected (Exception).
        # Each except prints its documented stderr message and
        # returns the appropriate exit code.
        try:
            result = classify_components(
                manifest.components,
                config,
                progress=progress_callback,
                cancel=_cancel_token,
                feeds=feeds_registry,
                source_image=manifest.source_image if feeds_registry else None,
                trust_store=trust_store,
            )
        except ClassificationConfigError as exc:
            print(f"loki classify: configuration error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationConfigError"]
        except ClassificationRuleError as exc:
            print(f"loki classify: rule error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationRuleError"]
        except ClassificationPipelineError as exc:
            print(f"loki classify: pipeline error: {exc}", file=sys.stderr)
            return _CLASSIFY_EXIT_CODES["ClassificationPipelineError"]
        except Exception as exc:
            # D5 default: pipeline catchall and unexpected
            # Exception both -> exit 4.
            print(
                f"loki classify: unexpected error: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return _CLASSIFY_EXIT_CODES["UnexpectedException"]

        # Step 6: stdout serialization (gated on --summary-only).
        if not args.summary_only:
            try:
                rendered = _serialize_result(result)
            except (TypeError, ValueError) as exc:
                # R3.7: serialization failure is exit 3.
                print(
                    f"loki classify: failed to serialize result: {exc}",
                    file=sys.stderr,
                )
                return _CLASSIFY_EXIT_CODES["SerializationError"]
            sys.stdout.write(rendered)

        # Step 7: stderr summary line. Emitted on success path
        # AND on partial-cancellation path. Skipped on whole-run
        # failure paths (those return early via the except
        # clauses above).
        duration = time.monotonic() - start
        print(
            _format_summary_line(result, duration_seconds=duration),
            file=sys.stderr,
        )

        # Step 8: exit code resolution.
        if cancel_flag.value:
            return _CLASSIFY_EXIT_CODES["Sigint"]
        return 0
    finally:
        # Restore lifecycle objects regardless of path. Python's
        # finally guarantees this runs even when an except clause
        # returned.
        restore_debug()
        restore_sigint()


def _build_progress_callback(
    enabled: bool,
) -> Callable[[ProgressEvent], None] | None:
    """Return a stderr-line emitter when ``enabled``, else ``None``.

    The callback formats each :class:`ProgressEvent` as a single
    line on stderr in the form
    ``[phase] index/estimated message``. The manifest JSON on
    stdout is unchanged regardless of whether progress is on,
    keeping pipe-friendliness intact.
    """

    if not enabled:
        return None

    def _emit(event: ProgressEvent) -> None:
        # Pad ``component_index`` so the running counter aligns
        # visually as the run progresses; cap at 5 digits since
        # 100k+ components is far beyond the v1 budget.
        index_field = f"{event.component_index:>5}"
        estimated_field = f"{event.components_estimated:<5}"
        print(
            f"[{event.phase:>10}] {index_field}/{estimated_field} {event.message}",
            file=sys.stderr,
            flush=True,
        )

    return _emit


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``loki`` console script."""

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


# ---------------------------------------------------------------------
# loki baseline ... handlers (Task 18)
# ---------------------------------------------------------------------


#: Exit-code taxonomy for ``loki baseline`` typed errors. Mirrors
#: ``loki extract``'s pattern of "2 = bad input, 3 = serialization,
#: 4 = pipeline" extended with persistence-specific codes.
_BASELINE_EXIT_CODES: dict[str, int] = {
    "BaselineNotFoundError": 2,
    "BaselineSerializationError": 3,
    "BaselineConcurrentModificationError": 4,
    "BaselineAlreadyExistsError": 5,
    "BaselineStorageUnwritableError": 6,
}


def _build_baseline_store(args: argparse.Namespace) -> BaselineStore:
    """Construct a ``BaselineStore`` from the ``--storage-path`` flag.

    Imports are local so ``loki --version``, ``loki gui``, and
    ``loki extract`` don't pay the persistence-import cost.
    """
    from loki.baseline import BaselineStore
    from loki.models import BaselineConfig

    config = BaselineConfig(storage_path=str(args.storage_path), auto_match=False)
    return BaselineStore(config)


def _parse_baseline_id(value: str) -> uuid.UUID:
    """Parse a string into a ``UUID``, raising :class:`SystemExit` on failure."""
    try:
        return uuid.UUID(value)
    except ValueError:
        print(f"loki baseline: invalid baseline_id: {value}", file=sys.stderr)
        raise SystemExit(2) from None


def _print_baseline_error(prefix: str, exc: Exception) -> int:
    """Print ``exc`` to stderr and return the matching exit code."""
    name = type(exc).__name__
    code = _BASELINE_EXIT_CODES.get(name, 1)
    print(f"{prefix}: {exc}", file=sys.stderr)
    return code


def _handle_baseline_list(args: argparse.Namespace) -> int:
    """``loki baseline list`` — load + print sorted rows (R6.2-R6.3)."""
    from loki.baseline import BaselineStoreError

    try:
        store = _build_baseline_store(args)
        result = store.load()
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline list", exc)

    rows = sorted(
        result.registry.baselines,
        key=lambda r: (r.vendor, r.model, r.firmware_version),
    )
    for record in rows:
        # Tab-separated columns; consumers can pipe through ``cut``
        # or ``column -t`` for prettier display.
        print(
            "\t".join(
                [
                    str(record.baseline_id),
                    record.vendor,
                    record.model,
                    record.firmware_version,
                    record.baseline_version,
                    record.created_timestamp.isoformat(),
                ]
            )
        )
    if len(result.quarantine) > 0:
        # R6.3: trailing summary line on stderr; exit code stays 0.
        print(f"quarantined: {len(result.quarantine)}", file=sys.stderr)
    return 0


def _handle_baseline_show(args: argparse.Namespace) -> int:
    """``loki baseline show {baseline_id}`` — print one record as JSON (R6.4-R6.5)."""
    from loki.baseline import BaselineNotFoundError, BaselineStoreError

    target_id = _parse_baseline_id(args.baseline_id)
    try:
        store = _build_baseline_store(args)
        result = store.load()
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline show", exc)

    record = result.registry.get_by_id(target_id)
    if record is None:
        # R6.5: not-found surfaces as exit 2 with a clean stderr line.
        return _print_baseline_error(
            "loki baseline show",
            BaselineNotFoundError(target_id),
        )

    sys.stdout.write(record.model_dump_json(indent=2))
    sys.stdout.write("\n")
    return 0


def _handle_baseline_import(args: argparse.Namespace) -> int:
    """``loki baseline import {path}`` — load_one + save (R6.6)."""
    from loki.baseline import BaselineStoreError

    try:
        store = _build_baseline_store(args)
        record = store.load_one(args.path)
        dest = store.save(record)
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline import", exc)

    print(dest.name)
    return 0


def _handle_baseline_export(args: argparse.Namespace) -> int:
    """``loki baseline export {baseline_id} {dest}`` — load + export (R6.7)."""
    from loki.baseline import BaselineNotFoundError, BaselineStoreError

    target_id = _parse_baseline_id(args.baseline_id)
    try:
        store = _build_baseline_store(args)
        result = store.load()
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline export", exc)

    record = result.registry.get_by_id(target_id)
    if record is None:
        return _print_baseline_error(
            "loki baseline export",
            BaselineNotFoundError(target_id),
        )

    try:
        dest = store.export(record, args.dest)
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline export", exc)

    print(dest)
    return 0


def _handle_baseline_delete(args: argparse.Namespace) -> int:
    """``loki baseline delete {baseline_id} [--yes]`` (R6.8-R6.9)."""
    from loki.baseline import BaselineNotFoundError, BaselineStoreError

    target_id = _parse_baseline_id(args.baseline_id)
    try:
        store = _build_baseline_store(args)
        result = store.load()
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline delete", exc)

    record = result.registry.get_by_id(target_id)
    if record is None:
        return _print_baseline_error(
            "loki baseline delete",
            BaselineNotFoundError(target_id),
        )

    if not args.yes:
        # R6.8: prompt with the exact phrasing the spec mandates.
        # Anything other than ``y`` cancels — ``Y`` and ``yes`` are
        # accepted as conveniences but the spec prescribes the
        # ``y`` minimum.
        prompt = f"Delete {target_id}? [y/N] "
        try:
            answer = input(prompt)
        except EOFError:
            answer = ""
        if answer.strip().lower() not in {"y", "yes"}:
            print("loki baseline delete: cancelled", file=sys.stderr)
            return 0

    try:
        removed = store.delete(target_id)
    except BaselineStoreError as exc:
        return _print_baseline_error("loki baseline delete", exc)

    print(removed)
    return 0


def _handle_analyze(args: argparse.Namespace) -> int:
    """Run the analysis engine against a classified manifest.

    Steps:
      1. Load manifest from JSON file
      2. Load baseline registry
      3. Classify the manifest's components
      4. Run analyze_image
      5. Output report JSON to stdout + summary to stderr
    """
    import time

    from loki.analysis import analyze_image
    from loki.analysis.errors import AnalysisError
    from loki.baseline import BaselineStore
    from loki.baseline.errors import BaselineStoreError
    from loki.classification import classify_components
    from loki.classification.errors import ClassificationPipelineError
    from loki.models import BaselineConfig, ClassificationConfig, ExtractionManifest
    from loki.models.config import AnalysisConfig
    from loki.models.enums import SeverityLevel

    # Step 1: Load manifest.
    manifest_path: Path = args.manifest
    if not manifest_path.exists():
        print(f"loki analyze: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    try:
        text = manifest_path.read_text(encoding="utf-8")
        manifest = ExtractionManifest.model_validate_json(text)
    except Exception as exc:
        print(f"loki analyze: invalid manifest: {exc}", file=sys.stderr)
        return 2

    # Step 2: Load baseline registry.
    baseline_path: Path = args.baseline_path
    if not baseline_path.is_dir():
        print(f"loki analyze: baseline directory not found: {baseline_path}", file=sys.stderr)
        return 2

    try:
        store = BaselineStore(BaselineConfig(storage_path=str(baseline_path), auto_match=True))
        load_result = store.load()
        registry = load_result.registry
    except BaselineStoreError as exc:
        print(f"loki analyze: baseline error: {exc}", file=sys.stderr)
        return 3

    # Step 3: Classify.
    rules_path: Path = args.rules_path
    config = ClassificationConfig(
        taxonomy_version=args.taxonomy_version,
        confidence_threshold=0.6,
        rules_path=str(rules_path),
    )

    trust_store = None
    if getattr(args, "trust_store", None) is not None:
        from loki.verification import TrustStore

        trust_store = TrustStore.from_directory(args.trust_store)

    try:
        classification_result = classify_components(
            manifest.components, config, trust_store=trust_store
        )
    except ClassificationPipelineError as exc:
        print(f"loki analyze: classification error: {exc}", file=sys.stderr)
        return 4

    # Step 4: Run analysis.
    analysis_config = AnalysisConfig(
        severity_weights={
            "type": 0.25,
            "vendor": 0.25,
            "security_posture": 0.30,
            "mutability": 0.20,
        },
        default_severity_threshold=SeverityLevel.MEDIUM,
    )

    start = time.monotonic()
    try:
        report = analyze_image(
            target_records=classification_result.records,
            registry=registry,
            target_image=manifest.source_image,
            config=analysis_config,
        )
    except AnalysisError as exc:
        print(f"loki analyze: analysis error: {exc}", file=sys.stderr)
        return 5

    duration = time.monotonic() - start

    # Step 5: Output.
    if not args.summary_only:
        sys.stdout.write(report.model_dump_json(indent=2))
        sys.stdout.write("\n")

    summary = (
        f"analyze: posture={report.posture_rating.value}, "
        f"{len(report.findings)} findings, "
        f"duration={duration:.4f}s"
    )
    print(summary, file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
