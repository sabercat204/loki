# Requirements Document

## Introduction

The Classification CLI is the LOKI subsystem that wires the existing
classification library (``from loki.classification import
classify_components``) onto the top-level ``loki`` console script as a
new ``loki classify`` subcommand. It closes OT-LK-003 from
``loom-loki.md`` § 5 Open Threads: v1 of the classification pipeline
shipped only the library API, leaving operators to invoke
classification from Python scripts. This subsystem adds the missing
shell entry point so that classification slots into the same
UNIX-pipeline composition pattern as the existing ``loki extract``
and ``loki baseline`` subcommands.

The CLI is intentionally a thin shell over the library API. It does
not run extraction itself, does not persist its output to disk, and
does not expose any classification decision the library does not
already make. Its job is to read an ``ExtractionManifest`` (the JSON
document that ``loki extract`` writes to stdout), call
``classify_components`` against a caller-supplied rules directory, and
emit the resulting ``ClassificationResult`` as a single JSON object on
stdout plus a one-line counts summary on stderr.

This spec covers the CLI surface only:

- The ``loki classify`` subcommand registration on the existing
  ``loki`` dispatcher at ``loki/loki/cli.py``.
- The positional input contract: a path to an ``ExtractionManifest``
  JSON file, or ``-`` to read JSON from stdin.
- The required ``--rules-path`` flag and the optional
  ``--taxonomy-version`` flag.
- The stdout JSON shape (a single indented object mirroring
  ``ClassificationResult``) and the ``--summary-only`` opt-out.
- The stderr counts summary line (records, ``needs_review`` tally,
  errors, duration, rules loaded).
- The ``--progress`` flag and the per-component progress line stream
  on stderr.
- The ``--debug`` flag and its scoped effect on the
  ``loki.classification`` logger.
- SIGINT handling and cooperative cancellation, mapping the library's
  cancellation contract (R1.9 of classification-pipeline) to a 130
  exit code.
- The exit-code taxonomy and the typed-error to exit-code mapping.
- Determinism, round-trip equivalence between the file and stdin
  input modes, and the dual-record visibility contract from R5.6 of
  classification-pipeline.
- The no-leakage discipline on stderr lines.
- Performance bounds on the CLI's overhead beyond the library.

It does not cover:

- Running extraction in the same process. There is no
  ``--from-firmware`` flag in v1; ``loki extract`` and ``loki
  classify`` compose via the shell, not via shared in-process state.
  Out of scope.
- Persisting ``ClassificationResult`` to disk. There is no
  ``--output-file`` flag; stdout redirection is the UNIX way. Out of
  scope.
- Validating rule files outside of a real classification run. There
  is no ``loki classify rules-check`` subcommand. Out of scope; a
  future spec may add it.
- A ``loki classify show`` pretty-print subcommand. ``jq`` is the
  standard tool for poking at JSON; replicating it is out of scope.
- Exposing ``ClassificationConfig.confidence_threshold``. The
  classification library does not consume the field in v1 (R4.10 of
  classification-pipeline); adding a CLI flag would give operators a
  knob that does nothing. Out of scope.
- Reading configuration from ``LokiConfig.from_yaml(...)`` or any
  other config file. ``--rules-path`` is mandatory; there is no
  fallback to XDG defaults or to a project-level config file. Out of
  scope.
- Auto-detecting YAML manifests. ``loki extract`` only emits JSON;
  the CLI accepts only JSON input. Out of scope.
- A streaming JSONL output mode. The library API is not streaming;
  the CLI mirrors that shape. Out of scope.
- GUI integration. OT-LK-004 is its own spec.
- Schema migration of the ``ExtractionManifest`` envelope across
  extraction versions. The CLI delegates manifest validation to
  Pydantic strict mode; cross-version compatibility is the model
  layer's concern. Out of scope.

The shape and quality bar mirror ``baseline-persistence/requirements.md``
(the closest precedent for a CLI surface integrated into a larger
subsystem) and the upstream contract this CLI wraps,
``classification-pipeline/requirements.md``. Determinism, the typed
exception mapping, the stdout-stays-machine-readable discipline, and
the no-leakage logging audit all carry forward from the upstream
subsystem.

Carry-forward platform constraints: Python 3.12 baseline; Pydantic v2
strict; ``mypy --strict`` clean; ``ruff check`` and ``ruff format``
clean. Property numbering in this spec starts at P53; previous specs
end at P52 (analysis-engine).

Design-phase implementation notes (not requirements; tracked here so
the design conversation has the right starting context):

- The ``isatty()`` check on stdin (Requirement 1.5) SHALL be the
  first I/O action when the positional ``manifest`` value is the
  literal ``-``, so an interactive operator who typed
  ``loki classify -`` and forgot what the ``-`` meant gets the
  TTY-guard error message immediately rather than waiting silently
  for input that never arrives.
- The ``loki classify`` console script's bash users may find
  double-Ctrl-C surprising (Requirement 6.5 makes it a no-op);
  the v1 ``--help`` text or the project README SHOULD note that
  the operator must wait for cooperative cancellation to surface
  the partial result.
- The ``ExtractionManifest`` envelope has no ``schema_version``
  field today, unlike the baseline-persistence envelope (R4 of
  baseline-persistence). Cross-version manifest compatibility is
  out of scope for this spec; tracked as a future thread
  OT-LK-006 ``ExtractionManifest schema migration`` analogous to
  OT-LK-005 for baseline schema migration.

## Glossary

- **Classification_CLI**: The subsystem specified by this document.
  The ``loki classify`` subcommand registered on the top-level
  ``loki`` argparse dispatcher at ``loki/loki/cli.py``.
- **Manifest_Source**: The positional argument to ``loki classify``.
  Either a path to a JSON file on disk that deserializes into an
  ``ExtractionManifest`` per the model layer's strict validators, or
  the literal ``-``, which directs the Classification_CLI to read
  the same JSON shape from stdin.
- **Rules_Directory**: The directory referred to by the
  ``--rules-path`` flag. Passed through verbatim to
  ``ClassificationConfig.rules_path`` and consumed by the
  classification library per Requirement 2 of
  classification-pipeline.
- **Stdout_Result**: The single indented JSON object the
  Classification_CLI writes to stdout on a successful or partially
  cancelled run. Has exactly two top-level keys, ``records`` and
  ``errors``, each carrying a list of validated Pydantic objects
  serialized via ``model_dump(mode="json")``. Mirrors the
  ``ClassificationResult`` dataclass shape; the dataclass itself is
  ``@dataclass(frozen=True)`` rather than Pydantic, so the
  Classification_CLI performs the serialization explicitly.
- **Stderr_Summary_Line**: The single-line diagnostic the
  Classification_CLI writes to stderr at the end of every run that
  produces a Stdout_Result, of the form ``classify: <N> records
  (<K> need_review), <E> errors, duration=<S>s``. The
  ``rules_loaded`` count is intentionally not part of the v1
  summary line; the classification library exposes the count only
  on the internal ``ClassificationPipeline._rules`` attribute, not
  on the public ``ClassificationResult`` surface that
  ``classify_components`` returns. A future revision MAY extend
  this line once the public API grows a stable rules-loaded
  count.
- **Progress_Line**: One line per ``ProgressEvent`` written to
  stderr while ``--progress`` is enabled, of the form
  ``[<index>/<total>] <component_id>``. The stream is independent of
  Stdout_Result; enabling ``--progress`` SHALL NOT alter
  Stdout_Result.
- **Cancel_Flag**: A boolean flag that the Classification_CLI flips
  to ``True`` on receipt of SIGINT and that the
  Classification_CLI's cancellation callback returns to the
  classification library. Read by the library between components per
  R1.9 of classification-pipeline.
- **Cancellation_Marker**: The single ``ClassificationError`` record
  the classification library writes into ``ClassificationResult.errors``
  when the Cancel_Flag is observed (per R1.9 of classification-pipeline:
  ``error_message == "classification cancelled by caller"``). The
  Classification_CLI emits the partial Stdout_Result containing this
  marker and exits 130.
- **Debug_Logger_Scope**: The ``loki.classification`` logger and any
  loggers underneath it. ``--debug`` raises this logger's level to
  ``logging.DEBUG`` and attaches a stderr ``StreamHandler`` only if
  no handler is already configured; both effects last only for the
  duration of the run. Loggers outside this scope (notably
  ``loki.baseline``, ``loki.extraction``, etc.) are unaffected.
- **Forbidden_Leakage_Field_Set**: Identical to the set defined by
  Requirement 13.5 of classification-pipeline:
  ``ExtractedComponent.component_id`` and its mirrored
  ``ClassificationRecord.component_id``, ``SignatureInfo.signer``,
  the parent ``BaselineRecord.source_image_hash``, and any value
  carried in ``AxisClassification.evidence``. The
  Classification_CLI's ``--progress`` output is a deliberate
  exception for ``component_id`` only, mirroring the upstream
  library's caller-supplied-callback exception (Requirement 12.1
  of classification-pipeline).
- **Out_Of_Scope_Operation**: Anything beyond reading a manifest,
  invoking the classification library, and rendering its output as
  JSON plus a counts summary. Extraction, persistence,
  rules-without-a-run validation, and GUI integration are out of
  scope. Explicitly deferred.

## Requirements

### Requirement 1: Subcommand registration and the manifest input path

**User Story:** As a CLI user, I want a ``loki classify`` subcommand
that accepts a saved ``ExtractionManifest`` either as a path on disk
or as JSON on stdin, so that I can compose ``loki extract | loki
classify -`` in a single shell pipeline.

#### Acceptance Criteria

1. THE Classification_CLI SHALL register a ``classify`` subcommand
   on the top-level ``loki`` ``argparse`` dispatcher in
   ``loki/loki/cli.py`` so that ``loki classify --help`` works
   without any additional environment configuration.
2. THE Classification_CLI SHALL accept exactly one positional
   argument named ``manifest`` whose value is either a path to a
   file on disk or the literal single-character string ``-``.
3. WHEN the positional ``manifest`` value is a path to a file on
   disk, THE Classification_CLI SHALL open that file in text mode
   with UTF-8 encoding, read its full contents, parse the contents
   as JSON, and validate the parsed object as an
   ``ExtractionManifest`` via Pydantic strict mode.
4. WHEN the positional ``manifest`` value is the literal ``-``, THE
   Classification_CLI SHALL read the full contents of ``sys.stdin``
   in text mode, parse the contents as JSON, and validate the
   parsed object as an ``ExtractionManifest`` via Pydantic strict
   mode.
5. IF the positional ``manifest`` value is the literal ``-`` and
   ``sys.stdin.isatty()`` returns ``True``, THEN THE
   Classification_CLI SHALL print
   ``loki classify: stdin is a TTY; pipe a manifest or pass a path``
   to stderr and SHALL exit with status ``2`` without invoking the
   classification library.
6. IF the positional ``manifest`` value is a path that does not
   exist, is not a regular file, or cannot be opened for reading,
   THEN THE Classification_CLI SHALL print
   ``loki classify: cannot read manifest: <path>: <reason>`` to
   stderr and SHALL exit with status ``2`` without invoking the
   classification library.
7. IF the manifest contents fail JSON parsing, THEN THE
   Classification_CLI SHALL print
   ``loki classify: manifest is not valid JSON: <reason>`` to
   stderr and SHALL exit with status ``2`` without invoking the
   classification library.
8. IF the manifest contents parse as JSON but fail
   ``ExtractionManifest`` Pydantic strict validation, THEN THE
   Classification_CLI SHALL print
   ``loki classify: manifest failed validation: <pydantic error
   summary>`` to stderr and SHALL exit with status ``2`` without
   invoking the classification library.
9. WHEN the manifest validates successfully, THE Classification_CLI
   SHALL pass ``manifest.components`` (the list of
   ``ExtractedComponent`` records) to ``classify_components`` as
   the input sequence; the Classification_CLI SHALL NOT re-order,
   filter, or otherwise mutate the components before passing them
   to the library.
10. THE Classification_CLI SHALL NOT, in v1, accept any positional
    argument other than the ``manifest`` value, and SHALL NOT
    accept multiple positional arguments; multi-manifest fan-in is
    Out_Of_Scope_Operation.
11. THE Classification_CLI SHALL run synchronously on the calling
    thread and SHALL NOT spawn worker threads, asyncio tasks, or
    process pools in v1; the underlying classification library
    already runs synchronously per Requirement 1.7 of
    classification-pipeline.

### Requirement 2: Rules-path resolution and taxonomy-version handling

**User Story:** As a CLI user, I want the rules directory to be a
required, explicit flag (no fallback to a config file in v1) and the
taxonomy version to be optional with a sensible default, so that
``loki classify`` is loud about its rule set and quiet about its
schema version.

#### Acceptance Criteria

1. THE Classification_CLI SHALL accept a required ``--rules-path``
   flag whose value is a path to the Rules_Directory; the value
   SHALL be passed through verbatim to
   ``ClassificationConfig.rules_path``.
2. WHEN the ``--rules-path`` flag is omitted, THE
   Classification_CLI SHALL print the standard ``argparse``
   ``error: the following arguments are required: --rules-path``
   message to stderr and SHALL exit with status ``2`` without
   invoking the classification library.
3. THE Classification_CLI SHALL NOT, in v1, fall back to any
   value carried in a ``LokiConfig`` YAML file, in the
   ``XDG_CONFIG_HOME`` environment variable, in ``~/.loki/``, or
   in any other implicit location; ``--rules-path`` is the only
   way to specify the Rules_Directory.
4. THE Classification_CLI SHALL accept an optional
   ``--taxonomy-version`` flag whose value is a non-empty string;
   when omitted, the Classification_CLI SHALL pass the literal
   ``"1.0.0"`` to ``ClassificationConfig.taxonomy_version``.
5. THE Classification_CLI SHALL pass the resolved
   ``--taxonomy-version`` value through verbatim to
   ``ClassificationConfig.taxonomy_version`` without trimming
   whitespace, lower-casing, or otherwise normalizing it; if the
   value mismatches the rule files' ``taxonomy_version``, the
   classification library raises ``ClassificationConfigError`` per
   Requirement 2.6 of classification-pipeline and the
   Classification_CLI maps the error per Requirement 8.
6. THE Classification_CLI SHALL pin
   ``ClassificationConfig.confidence_threshold`` internally to the
   value ``0.6`` (the model layer's default) and SHALL NOT, in v1,
   expose any flag that lets the operator override it; the field
   is reserved for the analysis engine's review-flag policy per
   Requirement 4.10 of classification-pipeline.
7. IF the Rules_Directory does not exist, is not a directory, or
   is not readable by the current process, THEN the classification
   library raises ``ClassificationConfigError`` per Requirement 2.4
   of classification-pipeline and the Classification_CLI maps the
   error per Requirement 8 (exit code ``6``); the Classification_CLI
   SHALL NOT pre-validate the directory itself before constructing
   the pipeline.

### Requirement 3: Stdout result shape and ``--summary-only`` suppression

**User Story:** As a CLI user, I want a single, indented JSON object
on stdout that mirrors the ``ClassificationResult`` shape, so that I
can pipe the output into ``jq``, redirect it to a file, or feed it
into a downstream tool without parsing per-line records. I also want
a ``--summary-only`` flag for CI smoke runs that only need the counts
line.

#### Acceptance Criteria

1. WHEN ``--summary-only`` is not set and the classification library
   returns a ``ClassificationResult``, THE Classification_CLI SHALL
   write to stdout a single JSON object with exactly two top-level
   keys, ``records`` and ``errors``, in that order.
2. THE Classification_CLI SHALL serialize each
   ``ClassificationRecord`` in ``ClassificationResult.records`` via
   the equivalent of ``record.model_dump(mode="json")`` and SHALL
   place the serialized objects in the ``records`` list in the
   order returned by the library; the Classification_CLI SHALL NOT
   re-order, filter, or otherwise mutate the records.
3. THE Classification_CLI SHALL serialize each
   ``ClassificationError`` in ``ClassificationResult.errors`` via
   the equivalent of ``error.model_dump(mode="json")`` and SHALL
   place the serialized objects in the ``errors`` list in the
   order returned by the library.
4. THE Classification_CLI SHALL emit the Stdout_Result via
   ``json.dumps`` (or equivalent) with ``indent=2`` and SHALL
   terminate the output with exactly one trailing newline
   character.
5. THE Classification_CLI SHALL set the JSON top-level object's
   key order to exactly ``["records", "errors"]`` regardless of
   the underlying dataclass field order, so that two runs of the
   Classification_CLI on the same inputs produce byte-identical
   stdout (modulo the per-record ``timestamp`` field permitted by
   Requirement 9 of this spec and Requirement 8.1 of
   classification-pipeline).
6. WHEN ``--summary-only`` is set, THE Classification_CLI SHALL
   NOT write any byte to stdout (the ``json.dumps`` call SHALL be
   skipped entirely); ``--summary-only`` SHALL NOT alter the
   Stderr_Summary_Line, the Progress_Line stream, the
   Cancellation_Marker contract, or the exit code.
7. IF JSON serialization of the Stdout_Result fails for any
   reason (e.g. a ``ValueError`` from ``json.dumps`` on a
   non-serializable value despite ``model_dump(mode="json")``
   normalization), THEN THE Classification_CLI SHALL print
   ``loki classify: failed to serialize result: <reason>`` to
   stderr, SHALL NOT write any partial JSON to stdout, and SHALL
   exit with status ``3``.
8. THE Classification_CLI SHALL faithfully include in the
   ``records`` and ``errors`` lists both halves of the R5.6
   dual-record contract from classification-pipeline: when the
   library emits a ``ClassificationRecord`` and a
   ``ClassificationError`` for the same ``component_id`` (the
   missing-bytes signature-detection case), the
   Classification_CLI SHALL NOT collapse, deduplicate, or
   filter either record; both SHALL appear in their respective
   lists. This is documented behavior, not a bug.

### Requirement 4: Stderr counts summary line

**User Story:** As an operator running ``loki classify`` from a
script, I want one structured stderr line at the end of every run
that gives me the record count, the ``needs_review`` tally, the
error count, and the duration, so that my CI step can grep for it
without parsing the JSON.

#### Acceptance Criteria

1. WHEN the Classification_CLI completes a classification run that
   produces a ``ClassificationResult`` (whether the run finished
   naturally, was cancelled cooperatively per Requirement 6, or
   recorded per-component errors), THE Classification_CLI SHALL
   write exactly one Stderr_Summary_Line to ``sys.stderr`` after
   the Stdout_Result (or, when ``--summary-only`` is set, in place
   of the Stdout_Result).
2. THE Stderr_Summary_Line SHALL have the exact format
   ``classify: <N> records (<K> need_review), <E> errors,
   duration=<S>s`` followed by a single newline, where:
   - ``<N>`` is the count of records in
     ``ClassificationResult.records``.
   - ``<K>`` is the count of records in
     ``ClassificationResult.records`` whose ``needs_review``
     attribute is ``True``.
   - ``<E>`` is the count of errors in
     ``ClassificationResult.errors``.
   - ``<S>`` is the wall-clock duration of the
     ``classify_components`` call rounded to four decimal places.
3. THE Classification_CLI SHALL NOT, in v1, include a rules-loaded
   count in the Stderr_Summary_Line; the underlying classification
   library exposes the rule count only on the internal
   ``ClassificationPipeline._rules.rules`` attribute, which is
   private per the upstream classification spec's R12 integration
   surface contract. A future spec amendment MAY extend the
   Stderr_Summary_Line with a ``rules_loaded`` field once the
   public ``ClassificationResult`` (or an equivalent stable
   surface) carries the count.
4. WHEN ``<K>`` would render as the same value as ``<N>`` (every
   record needs review), THE Classification_CLI SHALL still emit
   the parenthesized ``(<K> need_review)`` segment verbatim;
   conditional formatting based on the value of ``<K>`` SHALL
   NOT be introduced.
5. THE Classification_CLI SHALL NOT emit the Stderr_Summary_Line
   when the run terminates without producing a
   ``ClassificationResult`` (i.e. when an exception listed in
   Requirement 8 is raised before
   ``classify_components`` returns and the exit code is one of
   ``4``, ``5``, ``6``); on those whole-run failures, only the
   typed-error message line per Requirement 8 SHALL appear on
   stderr.
6. THE Classification_CLI SHALL emit the Stderr_Summary_Line
   regardless of whether ``--progress`` or ``--debug`` is set;
   the line is unconditional on every successful, partially
   cancelled, or per-component-error run.
7. THE Stderr_Summary_Line SHALL NOT carry any value drawn from
   the Forbidden_Leakage_Field_Set; ``<N>``, ``<K>``, ``<E>``,
   and ``<S>`` are integer counts and a duration only.

### Requirement 5: ``--progress`` flag and per-component event stream

**User Story:** As an operator running ``loki classify`` against a
large manifest, I want a ``--progress`` flag that streams one line
per successfully-classified component to stderr, so that I can see
live throughput without the stdout JSON changing.

#### Acceptance Criteria

1. THE Classification_CLI SHALL accept an optional ``--progress``
   boolean flag (action ``store_true``, default ``False``).
2. WHEN ``--progress`` is set, THE Classification_CLI SHALL pass a
   ``ProgressCallback`` to ``classify_components`` that, on each
   invocation by the library, writes exactly one Progress_Line to
   ``sys.stderr`` of the form ``[<index>/<total>] <component_id>``
   followed by a single newline, where ``<index>``, ``<total>``,
   and ``<component_id>`` are taken from the ``ProgressEvent``
   dataclass fields verbatim.
3. WHEN ``--progress`` is not set, THE Classification_CLI SHALL
   pass ``progress=None`` to ``classify_components`` and SHALL
   write no Progress_Line to ``sys.stderr``.
4. THE Classification_CLI SHALL flush ``sys.stderr`` after each
   Progress_Line so that the stream is observable in real time
   when stderr is connected to a terminal.
5. THE Classification_CLI SHALL emit the Stdout_Result identically
   regardless of whether ``--progress`` is set; enabling
   ``--progress`` SHALL NOT alter the byte content of stdout.
6. THE Classification_CLI's Progress_Line SHALL NOT carry any
   field drawn from the Forbidden_Leakage_Field_Set other than
   ``component_id``; ``component_id`` is permitted on the
   Progress_Line as a deliberate exception, mirroring the upstream
   library's caller-supplied-callback exception per Requirement
   12.1 of classification-pipeline.
7. IF the ``ProgressCallback`` itself raises an exception while
   formatting or writing a Progress_Line (e.g.
   ``BrokenPipeError`` because stderr was closed), THEN the
   exception SHALL propagate out of the library invocation and
   the Classification_CLI SHALL exit per Requirement 8's catchall
   path (exit code ``4``); the Classification_CLI SHALL NOT
   silently swallow stderr-write failures.
8. THE Classification_CLI SHALL NOT, in v1, emit a Progress_Line
   for components whose classification fails (i.e. the
   per-component error path that records a ``ClassificationError``
   and continues without producing a ``ClassificationRecord``);
   the upstream library's ``ProgressCallback`` per R12.1 of
   classification-pipeline fires only on successfully-built
   records, and the Classification_CLI mirrors that behavior
   without modification. Consequently, the count of Progress_Lines
   on stderr SHALL equal the count of ``ClassificationRecord``
   entries in ``ClassificationResult.records``, not the input
   manifest's component count.

### Requirement 6: SIGINT handling and cooperative cancellation

**User Story:** As a CLI user, I want pressing Ctrl-C during a long
``loki classify`` run to surface a partial result on stdout (the
records classified so far, plus a single cancellation error) and
exit 130, instead of dumping a Python traceback or losing the
in-flight work.

#### Acceptance Criteria

1. WHEN the Classification_CLI is about to invoke
   ``classify_components``, THE Classification_CLI SHALL install a
   process-level handler for ``signal.SIGINT`` that flips an
   internal Cancel_Flag from ``False`` to ``True`` and returns
   without raising; the previous SIGINT handler SHALL be
   preserved and SHALL be restored after the library call returns
   or raises.
2. THE Classification_CLI SHALL pass a ``CancellationToken`` to
   ``classify_components`` that returns the current value of the
   Cancel_Flag; the library polls this between components per
   Requirement 1.9 of classification-pipeline.
3. WHEN the Cancel_Flag is observed by the library and the
   library returns a ``ClassificationResult`` containing a
   Cancellation_Marker, THE Classification_CLI SHALL emit the
   resulting Stdout_Result on stdout normally per Requirement 3
   (or skip stdout entirely under ``--summary-only`` per
   Requirement 3.6), SHALL emit the Stderr_Summary_Line per
   Requirement 4, and SHALL exit with status ``130``.
4. THE Classification_CLI SHALL NOT, on receipt of SIGINT, raise
   ``KeyboardInterrupt`` out of the library call, kill the
   process forcibly, or skip the partial-result emission; cooperative
   cancellation is the only contracted shutdown path.
5. WHEN SIGINT arrives a second time after the Cancel_Flag has
   already been flipped, THE Classification_CLI SHALL retain its
   installed handler and SHALL continue to run until the library
   returns; double-Ctrl-C SHALL NOT cause the Classification_CLI
   to short-circuit out of the partial-result emission.
6. WHEN the Classification_CLI completes without ever observing
   a SIGINT, THE Classification_CLI SHALL exit with the success
   code ``0`` regardless of whether
   ``ClassificationResult.errors`` is empty; per-component errors
   are not whole-run failures (Requirement 9.5 of
   classification-pipeline).
7. THE Cancellation_Marker contract from R1.9 of
   classification-pipeline SHALL hold without modification by the
   Classification_CLI: the marker is the last entry in
   ``ClassificationResult.errors``, its ``error_message`` equals
   ``"classification cancelled by caller"``, and its
   ``component_id`` is ``None`` (consistent with the implementation's
   ``component_id=None`` cancellation-marker construction at
   ``loki/classification/pipeline.py``); the Classification_CLI
   SHALL NOT inject, mutate, or reorder this record.

### Requirement 7: ``--debug`` flag and the ``loki.classification`` logger

**User Story:** As a developer debugging a misbehaving rule set, I
want a ``--debug`` flag that turns on DEBUG-level logging from the
classification library to stderr without changing the stdout JSON
or weakening the logger's no-leakage discipline.

#### Acceptance Criteria

1. THE Classification_CLI SHALL accept an optional ``--debug``
   boolean flag (action ``store_true``, default ``False``).
2. WHEN ``--debug`` is set, THE Classification_CLI SHALL set the
   level of the ``loki.classification`` logger to
   ``logging.DEBUG`` for the duration of the
   ``classify_components`` call and SHALL restore the previous
   level after the call returns or raises.
3. WHEN ``--debug`` is set and the ``loki.classification`` logger
   has no handler attached at the time the Classification_CLI is
   invoked, THE Classification_CLI SHALL attach a
   ``logging.StreamHandler`` writing to ``sys.stderr`` for the
   duration of the run and SHALL detach it after the run; WHEN a
   handler is already attached, the Classification_CLI SHALL NOT
   attach a second handler (avoiding duplicated lines under
   external logging configuration).
4. WHEN ``--debug`` is set, THE Classification_CLI SHALL set
   ``loki.classification.propagate = False`` for the duration of
   the run and SHALL restore the previous value of
   ``propagate`` after the run; this guarantees that DEBUG records
   surface exactly once on the Classification_CLI's stderr handler
   without double-logging through a parent logger that may itself
   have a DEBUG-capable handler attached.
5. WHEN ``--debug`` is not set, THE Classification_CLI SHALL NOT
   modify the ``loki.classification`` logger's level, handlers,
   filters, or ``propagate`` attribute; the logger retains
   whatever the runtime environment configured it with.
6. THE Classification_CLI's ``--debug`` flag SHALL NOT modify any
   logger outside the Debug_Logger_Scope; loggers under
   ``loki.baseline``, ``loki.extraction``, ``loki.analysis``, the
   root logger, and any caller-attached logger SHALL retain
   their pre-run level and handler configuration.
7. THE ``--debug`` flag SHALL NOT bypass the Forbidden_Leakage_Field_Set
   audit pinned by Requirement 13.5 of classification-pipeline;
   even at DEBUG level, the library SHALL NOT log any field in
   the Forbidden_Leakage_Field_Set, and the Classification_CLI's
   added handler SHALL NOT capture or relay any such field.
8. THE ``--debug`` flag SHALL NOT modify the Stdout_Result or the
   Stderr_Summary_Line; ``--debug`` interleaves DEBUG records on
   stderr but neither suppresses nor alters the contracted
   stdout and stderr output of any other requirement.

### Requirement 8: Exit-code taxonomy and typed-error mapping

**User Story:** As a CI script author, I want every code path in
the classification library's typed-error hierarchy to map to
exactly one stable exit code, so that my script can branch on
``$?`` reliably.

#### Acceptance Criteria

1. THE Classification_CLI SHALL exit with exactly one of the
   following exit codes on every invocation:
   - ``0``: successful run that produced a Stdout_Result.
   - ``2``: bad input. Manifest path missing or unreadable;
     manifest JSON does not parse; manifest fails Pydantic
     strict validation; ``--rules-path`` is missing from the
     argument vector; stdin requested via ``-`` but
     ``sys.stdin.isatty()`` is ``True``.
   - ``3``: serialization failure. Any exception raised during
     Stdout_Result construction (e.g. ``json.dumps`` ``ValueError``
     on a non-serializable value despite ``model_dump(mode="json")``
     normalization, ``UnicodeEncodeError`` from a stdout encoder,
     or any other error preventing complete stdout emission).
   - ``4``: pipeline error catchall. Any
     ``ClassificationPipelineError`` raised by
     ``classify_components`` that is not covered by exit codes
     ``5`` or ``6``, plus any unexpected exception that escapes
     the library call (including a propagating
     ``ProgressCallback`` write failure per Requirement 5.7).
   - ``5``: rule error.
     ``ClassificationRuleError`` from ``classify_components``
     (duplicate ``rule_id``, invalid matcher predicate, Effect
     label not a member of the axis enum, etc.).
   - ``6``: configuration error.
     ``ClassificationConfigError`` from ``classify_components``
     (taxonomy mismatch, Rules_Directory missing or unreadable,
     rules-file shape errors).
   - ``130``: SIGINT received and cancellation honored
     (Cancel_Flag observed by the library; cancellation marker
     in ``ClassificationResult.errors`` per Requirement 6).
2. THE Classification_CLI's exit-code mapping SHALL be a total
   function on the typed-error hierarchy: every error class
   under ``ClassificationPipelineError`` SHALL map to exactly
   one of ``{4, 5, 6}``, and every input-validation failure
   listed in Requirement 1 or Requirement 2 SHALL map to ``2``.
3. WHEN ``classify_components`` raises a
   ``ClassificationConfigError``, THE Classification_CLI SHALL
   print ``loki classify: configuration error: <message>`` to
   stderr and SHALL exit with status ``6``.
4. WHEN ``classify_components`` raises a
   ``ClassificationRuleError``, THE Classification_CLI SHALL
   print ``loki classify: rule error: <message>`` to stderr and
   SHALL exit with status ``5``.
5. WHEN ``classify_components`` raises any other
   ``ClassificationPipelineError`` subclass not covered by
   acceptance criteria 8.3 or 8.4, THE Classification_CLI SHALL
   print ``loki classify: pipeline error: <message>`` to stderr
   and SHALL exit with status ``4``.
6. WHEN ``classify_components`` or the Stdout_Result construction
   raises an unexpected ``Exception`` not covered by acceptance
   criteria 8.3 through 8.5 (e.g. a third-party library bug, an
   ``OSError`` mid-run), THE Classification_CLI SHALL print
   ``loki classify: unexpected error: <type>: <message>`` to
   stderr and SHALL exit with status ``4``; the Classification_CLI
   SHALL NOT, in v1, dump a Python traceback to stderr by
   default, and SHALL NOT swallow the exception silently.
7. THE Classification_CLI SHALL NOT, in v1, define any exit code
   outside the closed set ``{0, 2, 3, 4, 5, 6, 130}``; future
   additions require a spec amendment.

### Requirement 9: Determinism, round-trip, and dual-record visibility

**User Story:** As a tester and as the property-based test suite,
I want ``loki classify`` to produce identical stdout for identical
inputs (modulo the per-record ``timestamp``), to produce identical
stdout whether the manifest comes from a file or from stdin, and to
preserve the upstream library's R5.6 dual-record contract.

#### Acceptance Criteria

1. WHEN the Classification_CLI is invoked twice on the same
   manifest contents, the same Rules_Directory contents, the same
   ``--taxonomy-version`` value, and the same Classification_CLI
   version, THE Classification_CLI SHALL produce two
   Stdout_Result strings that are byte-equal after stripping the
   ``timestamp`` field on every record (the library populates
   ``ClassificationRecord.timestamp`` once per run per
   Requirement 1.6 of classification-pipeline; that field is the
   only contracted source of run-to-run variation).
2. WHEN the Classification_CLI is invoked once with a manifest
   read from a file and once with the byte-identical manifest
   read from stdin (via the ``-`` positional value), and all
   other arguments are identical, THE Classification_CLI SHALL
   produce two Stdout_Result strings that are byte-equal after
   stripping the per-record ``timestamp`` field.
3. THE Classification_CLI SHALL NOT, in v1, insert any
   environment-derived value into the Stdout_Result; the run
   start time, the user's hostname, the current working
   directory, and any environment variable SHALL NOT appear
   anywhere in stdout.
4. WHEN the input manifest contains a component whose raw bytes
   are unreadable (the R5.6 dual-record case from
   classification-pipeline), THE Classification_CLI SHALL emit
   the resulting ``ClassificationRecord`` in
   ``stdout.records`` and the corresponding
   ``ClassificationError`` in ``stdout.errors`` for the same
   ``component_id``; the Classification_CLI SHALL NOT collapse,
   deduplicate, or filter either record.
5. THE Classification_CLI SHALL NOT consult environment
   variables, the random number generator, the system clock
   (other than for the wall-clock duration measurement permitted
   by Requirement 4.2), or any network resource for any decision
   that affects the byte content of the Stdout_Result.
6. FOR ALL valid ``ExtractionManifest`` JSON inputs the
   Classification_CLI accepts, the Stdout_Result SHALL be valid
   JSON (parseable by ``json.loads``) and SHALL deserialize into
   a Python dict with exactly the keys ``["records", "errors"]``.

### Requirement 10: No-leakage extension and stderr discipline

**User Story:** As a security-minded reviewer, I want every line
the Classification_CLI writes to stderr — Progress_Line,
Stderr_Summary_Line, typed-error message, ``--debug`` log records
— to obey the same Forbidden_Leakage_Field_Set discipline as the
upstream classification library, with the single ``component_id``
exception already documented for caller-supplied callbacks.

#### Acceptance Criteria

1. THE Classification_CLI SHALL NOT, on any stderr path
   (Progress_Line, Stderr_Summary_Line, typed-error message,
   ``--debug``-attached handler output, or any other diagnostic
   the Classification_CLI emits directly), write any value drawn
   from ``ClassificationRecord.component_id`` (other than via the
   Progress_Line exception below), ``SignatureInfo.signer``, the
   parent ``BaselineRecord.source_image_hash``, or any value
   carried in ``AxisClassification.evidence``.
2. WHERE the Classification_CLI emits a Progress_Line under
   ``--progress``, the Progress_Line MAY include
   ``ProgressEvent.component_id`` per Requirement 5.6; this is
   the only field from the Forbidden_Leakage_Field_Set permitted
   on any Classification_CLI-emitted stderr path, and the
   permission applies only to the Progress_Line.
3. THE Classification_CLI SHALL NOT include any
   ``ClassificationRecord`` field, any
   ``ExtractedComponent`` field, or any rule-file content in
   the Stderr_Summary_Line; the line carries integer counts and
   a duration only per Requirement 4.6.
4. THE Classification_CLI SHALL NOT include any
   ``ClassificationRecord`` field, any
   ``ExtractedComponent`` field, or any rule-file content in
   any typed-error message printed per Requirement 8; the
   typed-error message carries the exception's own ``message``
   attribute and the offending path (where applicable) only.
5. THE Classification_CLI SHALL NOT, when ``--debug`` is set,
   bypass the Forbidden_Leakage_Field_Set audit; the library's
   no-leakage discipline (Requirement 13.5 of
   classification-pipeline) is unconditional on log level.

### Requirement 11: Performance bounds on CLI overhead

**User Story:** As an operator running ``loki classify`` against
realistic manifests, I want the CLI's overhead beyond the
underlying library to be bounded, so that the user-visible
latency of ``loki classify`` is dominated by the library's
classification work rather than by argparse parsing, JSON
loading, or JSON dumping.

#### Acceptance Criteria

1. WHEN the Classification_CLI is invoked on a manifest of up to
   256 components and a Rules_Directory of up to 256 rules, THE
   Classification_CLI SHALL add no more than 200 milliseconds of
   wall-clock overhead beyond the time spent inside
   ``classify_components`` itself, on a 2024-class developer
   laptop with a local SSD, as measured by a slow-marker test
   that times the surrounding wrapper code explicitly (manifest
   read + JSON decode + Pydantic validation +
   ``ClassificationConfig`` construction + Stdout_Result JSON
   serialization + stderr line emission), not by subtracting the
   library's internally-reported duration; the wrapper-only
   timing isolates the CLI's overhead from any future change to
   how the library reports its own duration.
2. THE Classification_CLI SHALL read the manifest's full text
   into memory in a single pass and SHALL parse the JSON in a
   single ``json.loads`` call; v1 SHALL NOT require an
   incremental or streaming JSON parser.
3. THE Classification_CLI SHOULD keep peak resident memory
   attributable to the CLI layer under a fixed working set of
   64 MiB plus the size of the Stdout_Result string and the
   loaded ``ExtractionManifest``; the library's own peak
   resident-memory budget per Requirement 11.4 of
   classification-pipeline is independent of the CLI's budget.
   This bound is operationally hard to verify without
   ``tracemalloc`` or ``resource.getrusage()`` instrumentation
   that the rest of the project does not currently use; a future
   revision MAY add a slow-marker test to enforce the bound.
4. THE Classification_CLI SHALL NOT, in v1, require a streaming
   JSON output mode; mirroring the library's non-streaming API
   (Requirement 1.7 of classification-pipeline), the
   Stdout_Result is constructed in full before any byte is
   written to stdout.

### Requirement 12: Help text and self-documentation contract

**User Story:** As a first-time CLI user, I want
``loki classify --help`` to list every flag with a one-line
description, so that I can discover the CLI surface without
reading this spec.

#### Acceptance Criteria

1. THE Classification_CLI SHALL register every flag defined by
   this spec (``--rules-path``, ``--taxonomy-version``,
   ``--progress``, ``--debug``, ``--summary-only``) with a
   non-empty ``help`` string in its ``argparse`` configuration
   so that ``loki classify --help`` lists each flag with a
   one-line description.
2. THE Classification_CLI SHALL expose the positional
   ``manifest`` argument with a non-empty ``help`` string that
   names both the file-path mode and the ``-`` stdin mode.
3. THE Classification_CLI's ``argparse`` parser SHALL set ``prog``
   such that ``loki classify --help`` shows the subcommand by its
   full invocation form (``loki classify``) rather than the bare
   module name.
4. THE Classification_CLI SHALL provide a non-empty
   ``description`` on the ``classify`` subparser that
   summarizes the input contract, the stdout JSON shape, and
   the stderr counts line in a single short paragraph, mirroring
   the style of the existing ``loki extract`` and
   ``loki baseline`` subparsers.
5. THE Classification_CLI SHALL NOT, in v1, advertise any flag
   not defined by this spec; future flags require a spec
   amendment.

### Requirement 13: Property-based test contracts

**User Story:** As the property-based test suite, I want the
Classification_CLI's contracts pinned by Hypothesis-style
properties starting at P53, so that the next subsystem picks up
sequential numbering without overlap.

#### Acceptance Criteria

1. THE Classification_CLI SHALL be covered by a property test
   designated **P53 (stdin-or-file equivalence)** that, for
   randomly generated valid ``ExtractionManifest`` JSON
   contents, asserts that ``loki classify <path>`` and
   ``cat <path> | loki classify -`` produce byte-equal
   Stdout_Result strings after stripping the per-record
   ``timestamp`` field.
2. THE Classification_CLI SHALL be covered by a property test
   designated **P54 (exit-code totality)** that, for every
   error class in the ``ClassificationPipelineError`` hierarchy
   plus every input-validation failure mode listed in
   Requirements 1 and 2, asserts that the resulting
   Classification_CLI exit code is exactly one of
   ``{0, 2, 3, 4, 5, 6, 130}``; the property SHALL fail if any
   code path leaks an exit code outside this set.
3. THE Classification_CLI SHALL be covered by a deterministic
   in-process test designated **P55 (Cancel_Flag-driven
   cancellation contract)** that, for the range of cancellation
   indices ``[1, total]`` (where ``total`` is the input
   manifest's component count), passes a synchronous
   ``CancellationToken`` callback returning ``True`` at the
   configured iteration and asserts: (a) the resulting
   ``ClassificationResult.errors`` list ends with exactly one
   Cancellation_Marker whose ``error_message`` equals
   ``"classification cancelled by caller"`` and whose
   ``component_id`` is ``None``; (b) the Stdout_Result still
   parses as valid JSON; (c) the Classification_CLI exit code
   path that handles the cancellation marker resolves to ``130``.
   The end-to-end SIGINT behavior (signal handler installation,
   handler restoration, and SIGINT delivery via
   ``subprocess.send_signal()``) SHALL be covered by a separate
   example-based subprocess test using a deterministic wait
   condition rather than a Hypothesis property; subprocess +
   signal timing is non-deterministic and unsuitable for
   property-based testing under the project's
   ``max_examples=25`` / ``max_examples=50`` Hypothesis budgets.
4. THE Classification_CLI SHALL be covered by a property test
   designated **P56 (``--summary-only`` empties stdout)** that,
   for randomly generated valid manifests of any record count
   (including the empty manifest), asserts that invoking
   ``loki classify ... --summary-only`` writes zero bytes to
   stdout regardless of the input record count, while still
   emitting the Stderr_Summary_Line per Requirement 4 and
   exiting with the same exit code that the same invocation
   without ``--summary-only`` would have produced.
5. THE Classification_CLI SHALL be covered by a property test
   designated **P57 (Stderr_Summary_Line emission discipline)**
   that asserts: (a) on every successful run (exit ``0``), the
   Stderr_Summary_Line is emitted exactly once; (b) on every
   partially cancelled run (exit ``130``), the
   Stderr_Summary_Line is emitted exactly once; (c) on every
   per-component-error run (exit ``0`` with non-empty
   ``ClassificationResult.errors``), the Stderr_Summary_Line is
   emitted exactly once; (d) on every whole-run failure (exit
   ``4``, ``5``, or ``6``), the Stderr_Summary_Line is not
   emitted at all.
6. THE Classification_CLI SHALL be covered by a property test
   designated **P58 (no-leakage on the Stderr_Summary_Line and
   Progress_Line)** that, for randomly generated manifests,
   asserts that no ``ClassificationRecord`` field, no
   ``SignatureInfo.signer`` value, no
   ``BaselineRecord.source_image_hash`` value, and no
   ``AxisClassification.evidence`` string appears in the
   Stderr_Summary_Line or in any Progress_Line, and that the
   only ``component_id`` substring on stderr originates from a
   Progress_Line emitted under ``--progress``.
7. THE property numbering for this spec SHALL start at P53
   and SHALL be sequential across the document; future specs
   pick up at P59 unless an amendment to this spec adds
   additional properties first.
