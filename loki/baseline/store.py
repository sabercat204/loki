"""``BaselineStore`` — public load/save/delete entry points.

Design references:

- R1: Storage layout and file naming.
- R2: Loading (Discovery_Scan + validation).
- R3: Saving (Atomic_Write + schema tagging).
- R5: Concurrency and external mutation.
- R6.6 / R7.4: single-file load (``load_one``).
- R6.7: export to arbitrary path (``export``).
- R6.8: delete by ``baseline_id``.

Tasks 9-12, 18 implement the constructor, load, save, single-file
load, delete, and export flows.
"""

from __future__ import annotations

import errno
import importlib.metadata
import logging
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from loki.baseline.concurrency import FileSnapshot, check_unchanged, snapshot
from loki.baseline.envelope import EnvelopeMalformedError, deserialize, serialize
from loki.baseline.errors import (
    BaselineAlreadyExistsError,
    BaselineNotFoundError,
    BaselineSerializationError,
    BaselineStorageUnwritableError,
)
from loki.baseline.naming import filename_for
from loki.baseline.quarantine import QuarantineEntry, QuarantineSet
from loki.baseline.schema import SCHEMA_VERSION, is_supported_schema_version
from loki.models import BaselineConfig, BaselineRecord, BaselineRegistry

__all__ = [
    "BaselineStore",
    "CancellationToken",
    "LoadProgressCallback",
    "LoadProgressEvent",
    "LoadResult",
]


_LOGGER = logging.getLogger("loki.baseline.store")

#: Maximum on-disk size of a Baseline_File before it gets quarantined
#: (R9.7). 16 MiB is comfortably more than any realistic baseline (a
#: 1024-classification baseline serializes to ~5 MiB) and small
#: enough to keep load memory bounded.
MAX_FILE_SIZE: int = 16 * 1024 * 1024


def _resolve_default_written_by() -> str:
    """Return the default ``written_by_extractor_version`` tag.

    Reads the ``loki`` package version via ``importlib.metadata`` so
    a future bump of the project version automatically flows through
    to every saved Baseline_File.
    """
    try:
        return f"loki-{importlib.metadata.version('loki')}"
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - dev install
        return "loki-unknown"


_DEFAULT_WRITTEN_BY: str = _resolve_default_written_by()

#: Per-process counter used to disambiguate Atomic_Write temp files
#: without reaching for the random module (R9.6 forbids it). Each
#: save owns its destination path so collisions are impossible by
#: construction; the counter only exists to keep the temp-file name
#: visibly distinct from the destination.
_TEMP_COUNTER = 0


def _next_temp_suffix() -> str:
    """Return an 8-hex-char suffix for the next Atomic_Write temp file."""
    global _TEMP_COUNTER
    _TEMP_COUNTER = (_TEMP_COUNTER + 1) & 0xFFFFFFFF
    return f"{os.getpid():04x}{_TEMP_COUNTER:04x}"


def _atomic_write(
    payload: bytes,
    dest: Path,
    *,
    error_path: Path,
    pre_replace_check: Callable[[], None] | None = None,
) -> None:
    """Write ``payload`` to ``dest`` atomically (R3.1-R3.3).

    Used by both :meth:`BaselineStore.save` (writes inside the
    Storage_Directory) and :meth:`BaselineStore.export` (writes to
    an arbitrary caller-chosen path). The protocol is identical:

    1. Write to a sibling temp file named
       ``{dest.name}.{8 hex chars}.tmp``.
    2. ``flush()`` and ``os.fsync()`` the file descriptor.
    3. Run ``pre_replace_check`` if supplied — this is where save
       runs the mtime/size check (R5.2).
    4. ``os.replace(tmp, dest)``.
    5. On any exception before replace, delete the temp file and
       re-raise.

    Args:
        payload: The bytes to write.
        dest: The destination path. Must exist or be createable.
        error_path: Path used in
            :class:`BaselineStorageUnwritableError` messages — the
            Storage_Directory for save, the dest's parent for
            export. Helps callers render the right diagnostic.
        pre_replace_check: Optional zero-arg callable run between
            ``fsync`` and ``os.replace``. If it raises, the temp
            file is cleaned up and the exception propagates.

    Raises:
        BaselineStorageUnwritableError: any ``OSError`` /
            ``PermissionError`` during the write/replace sequence
            converts to this typed error (R8.7).
    """

    tmp = dest.with_name(f"{dest.name}.{_next_temp_suffix()}.tmp")
    try:
        try:
            with tmp.open("wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            if pre_replace_check is not None:
                pre_replace_check()
            os.replace(tmp, dest)
        except PermissionError as exc:
            # R8.7: the destination directory is not writable.
            # Convert the bare OSError to the typed error the spec
            # mandates from the save entry point.
            raise BaselineStorageUnwritableError(
                error_path,
                errno=exc.errno or errno.EACCES,
            ) from exc
        except OSError as exc:
            # Other OSError shapes — read-only filesystem, no
            # space, etc. — also surface as not-writable. The
            # ``errno`` field discriminates for callers that want
            # to render different UIs.
            raise BaselineStorageUnwritableError(
                error_path,
                errno=exc.errno or errno.EIO,
            ) from exc
    except BaseException:
        # Any failure before replace: clean up the temp and
        # re-raise. R3.3.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - cleanup best-effort
            pass
        raise


@dataclass(frozen=True)
class LoadResult:
    """Tuple-shaped return for :meth:`BaselineStore.load`.

    R2.1. Returned by the load entry point so callers can inspect
    both the successfully loaded :class:`BaselineRegistry` *and* the
    set of files that were rejected during Discovery_Scan.
    """

    registry: BaselineRegistry
    quarantine: QuarantineSet
    duration_ms: float


@dataclass(frozen=True)
class LoadProgressEvent:
    """Structured progress event for :meth:`BaselineStore.load` (R2.8).

    Emitted exactly once before each Baseline_File is parsed in the
    Discovery_Scan loop. Files filtered out by the extension check
    (R1.4) do not produce events. The 1-based ``index`` and the
    static ``total`` let callers render a "{index}/{total}" status
    line without tracking progress state themselves.
    """

    path: Path
    index: int
    total: int


#: Optional progress callback type for :meth:`BaselineStore.load`.
#:
#: When supplied, the callback is invoked from the thread calling
#: ``load`` exactly once before each Baseline_File is parsed. R2.8.
LoadProgressCallback = Callable[[LoadProgressEvent], None]


#: Optional cancellation token type for :meth:`BaselineStore.load`.
#:
#: When supplied, the callback is polled between Baseline_Files in
#: the Discovery_Scan loop. Returning ``True`` causes the load to
#: stop and return the partial :class:`LoadResult` accumulated so
#: far. R2.9.
CancellationToken = Callable[[], bool]


@dataclass(frozen=True)
class _LoadSuccess:
    """Internal: a per-file parse that produced a validated record.

    Used by :meth:`BaselineStore._parse_file` to hand both the
    validated :class:`BaselineRecord` and the file's original raw
    bytes back to the caller without re-reading from disk.
    """

    record: BaselineRecord
    raw: bytes


@dataclass(frozen=True)
class _LoadFailure:
    """Internal: a per-file parse that failed validation.

    Carries the same ``reason`` string the bulk-load path writes
    into a :class:`QuarantineEntry` and, when available, the
    original raw bytes. ``raw`` is ``None`` when the file couldn't
    be read at all (e.g. permission error, oversized file).
    """

    reason: str
    raw: bytes | None


class BaselineStore:
    """Move :class:`BaselineRecord` instances between memory and disk.

    The constructor resolves the Storage_Directory path immediately
    and creates it with mode ``0o755`` if missing (R1.6). Construction
    does *not* trigger a Discovery_Scan; the caller invokes
    :meth:`load` when ready.

    Attributes:
        storage_path: Absolute resolved path to the Storage_Directory.
        schema_version: Current Schema_Version constant from
            :data:`loki.baseline.schema.SCHEMA_VERSION`. Exposed as a
            property so the CLI / GUI surface a stable string for
            diagnostics without poking at the schema module directly.
    """

    def __init__(self, config: BaselineConfig) -> None:
        raw = Path(config.storage_path).expanduser()
        try:
            raw.mkdir(parents=True, exist_ok=True, mode=0o755)
        except PermissionError as exc:
            raise BaselineStorageUnwritableError(
                raw,
                errno=exc.errno or errno.EACCES,
            ) from exc
        except OSError as exc:
            raise BaselineStorageUnwritableError(
                raw,
                errno=exc.errno or errno.EIO,
            ) from exc
        self._storage_path: Path = raw.resolve()
        self._snapshots: dict[uuid.UUID, FileSnapshot] = {}

        # The directory might already have existed but be unwritable
        # (e.g. mode 0o500). os.access is the cheap, race-prone check
        # we want here — the real test is whether ``os.replace`` works
        # at save time, but flagging up-front gives callers a typed
        # error before they construct anything else.
        if not os.access(self._storage_path, os.W_OK):
            raise BaselineStorageUnwritableError(
                self._storage_path,
                errno=errno.EACCES,
            )

    @property
    def storage_path(self) -> Path:
        """Absolute resolved path to the Storage_Directory."""
        return self._storage_path

    @property
    def schema_version(self) -> str:
        """Current on-disk Schema_Version (R4.6)."""
        return SCHEMA_VERSION

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(
        self,
        *,
        progress: LoadProgressCallback | None = None,
        cancel: CancellationToken | None = None,
    ) -> LoadResult:
        """Run Discovery_Scan and validate every Baseline_File.

        Implements R2 in full. Returns a :class:`LoadResult` carrying
        the validated :class:`BaselineRegistry` plus the
        :class:`QuarantineSet` of files that failed validation. On a
        truly unrecoverable error (e.g. the Storage_Directory was
        deleted between construction and load), raises a typed
        :class:`BaselineStorageUnwritableError`.

        Args:
            progress: Optional :data:`LoadProgressCallback` invoked
                from the calling thread exactly once before each
                Baseline_File is parsed (R2.8). Files filtered out
                by the Discovery_Scan extension check (R1.4) do not
                produce events.
            cancel: Optional :data:`CancellationToken` polled between
                Baseline_Files. When the token returns ``True`` the
                load stops, no further parsing or progress callbacks
                occur, and a :class:`LoadResult` carrying only the
                records and quarantine entries accumulated before
                cancellation is returned (R2.9). Cancellation is
                cooperative; an in-flight per-file parse is allowed
                to finish before the token is re-checked.

        Note:
            Per R2.10, omitting both callbacks produces a
            :class:`LoadResult` byte-equal under
            ``model_dump(mode="json")`` to a load with stub
            callbacks that record events but do not request
            cancellation. The callbacks have no observable effect
            on the result other than via cancellation.
        """

        started_at = time.monotonic()
        candidates = self._discovery_scan()
        total = len(candidates)
        _LOGGER.info(
            "baseline load starting path=%s candidates=%d",
            self._storage_path,
            total,
        )

        registry = BaselineRegistry()
        quarantine = QuarantineSet()
        seen_ids: set[uuid.UUID] = set()
        # Reset snapshots; load() is the source of truth for which
        # records the store knows about.
        self._snapshots.clear()

        cancelled = False
        for index, path in enumerate(candidates, start=1):
            # Cancellation check first (R2.9): on True, no progress
            # callback for the current file, no parse, just break.
            if cancel is not None and cancel():
                _LOGGER.info(
                    "baseline load cancelled at index=%d/%d path=%s",
                    index,
                    total,
                    path.name,
                )
                cancelled = True
                break

            # Progress event (R2.8): emitted before parse so the
            # status line shows the file currently being worked on,
            # not the file most recently completed.
            if progress is not None:
                progress(LoadProgressEvent(path=path, index=index, total=total))

            self._process_one(path, registry, quarantine, seen_ids)

        duration_ms = (time.monotonic() - started_at) * 1000.0
        _LOGGER.info(
            "baseline load finished loaded=%d quarantined=%d duration=%.1fms cancelled=%s",
            len(registry.baselines),
            len(quarantine),
            duration_ms,
            cancelled,
        )
        return LoadResult(
            registry=registry,
            quarantine=quarantine,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _discovery_scan(self) -> list[Path]:
        """List ``*.yaml`` files under the Storage_Directory.

        Sorts lexicographically so duplicate-baseline_id resolution
        (R2.7) is deterministic. Files at depth > 1 are ignored
        (R1.4).
        """

        try:
            entries = list(self._storage_path.iterdir())
        except FileNotFoundError as exc:
            raise BaselineStorageUnwritableError(
                self._storage_path,
                errno=exc.errno or errno.ENOENT,
            ) from exc
        candidates = sorted(
            (e for e in entries if e.is_file() and e.suffix == ".yaml"),
            key=lambda p: p.name,
        )
        return candidates

    def _process_one(
        self,
        path: Path,
        registry: BaselineRegistry,
        quarantine: QuarantineSet,
        seen_ids: set[uuid.UUID],
    ) -> None:
        """Inspect one Baseline_File: parse, validate, append or quarantine."""

        outcome = self._parse_file(path)
        if isinstance(outcome, _LoadFailure):
            self._quarantine(quarantine, path, outcome.reason, raw=outcome.raw)
            return

        record, raw = outcome.record, outcome.raw
        if record.baseline_id in seen_ids:
            # The duplicate check is part of the bulk-load contract
            # (R2.7), not the single-file path. ``_parse_file`` is
            # state-free so duplicate resolution lives here.
            self._quarantine(
                quarantine,
                path,
                "duplicate baseline_id",
                raw=raw,
            )
            return

        seen_ids.add(record.baseline_id)
        registry.baselines.append(record)
        self._snapshots[record.baseline_id] = snapshot(path)

    def _parse_file(self, path: Path) -> _LoadSuccess | _LoadFailure:
        """Stateless per-file parser shared by ``load`` and ``load_one``.

        Runs the full parse + validate sequence on a single
        ``*.yaml`` file. Returns a :class:`_LoadSuccess` carrying
        the validated :class:`BaselineRecord` and the original raw
        bytes on success, or a :class:`_LoadFailure` carrying the
        same reason string the bulk-load path would write into a
        :class:`QuarantineEntry`. Callers decide whether to
        quarantine (bulk load) or raise
        :class:`BaselineSerializationError` (single-file load).

        State is never mutated by this method — duplicate-id and
        snapshot bookkeeping live one layer up so ``load_one``
        doesn't accidentally pollute the registry.
        """

        # File-size check first so we never load oversized payloads
        # into memory (R9.7).
        try:
            stat = path.stat()
        except OSError as exc:
            return _LoadFailure(reason=f"could not stat: {exc}", raw=None)
        if stat.st_size > MAX_FILE_SIZE:
            return _LoadFailure(
                reason="file exceeds 16 MiB size limit",
                raw=None,
            )

        try:
            raw = path.read_bytes()
        except OSError as exc:
            return _LoadFailure(reason=f"could not read: {exc}", raw=None)

        try:
            envelope = deserialize(raw, path=path)
        except EnvelopeMalformedError as exc:
            return _LoadFailure(reason=exc.message, raw=raw)

        if not is_supported_schema_version(envelope.schema_version):
            return _LoadFailure(
                reason=f"unsupported schema_version: {envelope.schema_version}",
                raw=raw,
            )

        try:
            record = BaselineRecord.model_validate(
                envelope.baseline,
                strict=False,
            )
        except ValidationError as exc:
            # ``baseline_id`` validation surfaces as a ``ValidationError``
            # too; surface a more specific reason when that's the
            # only failure (R8.5).
            return _LoadFailure(
                reason=self._classify_validation_error(exc),
                raw=raw,
            )

        return _LoadSuccess(record=record, raw=raw)

    @staticmethod
    def _classify_validation_error(exc: ValidationError) -> str:
        """Map a Pydantic ValidationError to a quarantine reason string.

        R8.4-R8.5: a missing-or-malformed ``baseline_id`` surfaces as
        ``"invalid baseline_id"``; everything else surfaces as the
        generic ``"validation failed: {summary}"``.
        """

        errors = exc.errors()
        # When every error touches the ``baseline_id`` field, surface
        # the specific reason from R8.5.
        if errors and all(
            "baseline_id" in [str(loc) for loc in err.get("loc", ())] for err in errors
        ):
            return "invalid baseline_id"
        first = errors[0] if errors else {"msg": "validation failed"}
        loc = ".".join(str(part) for part in first.get("loc", ())) or "<root>"
        return f"validation failed: {loc}: {first.get('msg', 'unknown')}"

    @staticmethod
    def _quarantine(
        quarantine: QuarantineSet,
        path: Path,
        reason: str,
        *,
        raw: bytes | None,
    ) -> None:
        """Emit a quarantine entry plus a WARNING log record (R10.3)."""

        entry = QuarantineEntry(path=path, reason=reason, raw=raw)
        quarantine.add(entry)
        _LOGGER.warning(
            "baseline quarantine path=%s reason=%s",
            path,
            reason,
        )

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(
        self,
        record: BaselineRecord,
        *,
        force: bool = False,
        written_by: str | None = None,
    ) -> Path:
        """Atomic_Write ``record`` to its computed Baseline_Filename.

        Implements R3 + R5.3-R5.4 in full. Returns the absolute
        destination path on success.

        Args:
            record: The :class:`BaselineRecord` to write. Must pass
                Pydantic strict validation; failure raises
                :class:`BaselineSerializationError` *before* any disk
                write (R3.8).
            force: When ``True``, skip both the existence check
                (R5.3) and the mtime/size check (R5.2). Used by the
                GUI's "overwrite" confirmation dialog (R7.6).
            written_by: Optional tag for the envelope's
                ``written_by_extractor_version`` field. Defaults to
                ``"loki-{loki version}"``.

        Returns:
            Absolute path to the written Baseline_File.

        Raises:
            BaselineSerializationError: round-trip validation failed
                (R3.8) or the serialized payload exceeds 16 MiB
                (R9.8).
            BaselineAlreadyExistsError: ``force=False`` and the
                destination file exists but the store doesn't have a
                snapshot for ``record.baseline_id`` (R5.3).
            BaselineConcurrentModificationError: ``force=False`` and
                the destination's ``(mtime_ns, size)`` moved since
                the snapshot was recorded (R5.2).
            BaselineStorageUnwritableError: the Storage_Directory is
                no longer writable (R8.7).
        """

        # 1. Round-trip validation (R3.8).
        try:
            BaselineRecord.model_validate(
                record.model_dump(mode="json"),
                strict=False,
            )
        except ValidationError as exc:
            raise BaselineSerializationError(
                "BaselineRecord round-trip validation failed",
                cause=exc,
            ) from exc

        # 2. Resolve destination.
        canonical = filename_for(record)
        snapshot_for_id = self._snapshots.get(record.baseline_id)
        dest = self._resolve_destination(record, canonical, snapshot_for_id, force)

        # 3. Build envelope bytes (R3.4-R3.7).
        written_at = datetime.now(tz=UTC)
        try:
            payload = serialize(
                record,
                schema_version=SCHEMA_VERSION,
                written_at=written_at,
                written_by_extractor_version=(
                    written_by if written_by is not None else _DEFAULT_WRITTEN_BY
                ),
            )
        except ValueError as exc:
            raise BaselineSerializationError(
                f"envelope serialization failed: {exc}",
                cause=exc,
            ) from exc
        if len(payload) > MAX_FILE_SIZE:
            raise BaselineSerializationError(
                f"serialized baseline exceeds 16 MiB ({len(payload)} bytes); "
                f"split into smaller component manifests"
            )

        # 4. Atomic_Write (R3.1-R3.3) with the snapshot-mtime check
        # (R5.2) injected between fsync and replace.
        def _check_concurrency() -> None:
            if not force and snapshot_for_id is not None and dest.exists():
                check_unchanged(snapshot_for_id)

        _atomic_write(
            payload,
            dest,
            error_path=self._storage_path,
            pre_replace_check=_check_concurrency,
        )

        # 5. Re-snapshot dest so subsequent saves race-check against
        # the post-write state.
        self._snapshots[record.baseline_id] = snapshot(dest)

        _LOGGER.info(
            "baseline save id=%s vendor=%s model=%s firmware_version=%s path=%s",
            record.baseline_id,
            record.vendor,
            record.model,
            record.firmware_version,
            dest,
        )
        return dest

    def _resolve_destination(
        self,
        record: BaselineRecord,
        canonical: str,
        snapshot_for_id: FileSnapshot | None,
        force: bool,
    ) -> Path:
        """Pick the destination path for ``record`` (R5.3, R5.4).

        Three cases:

        - The store knows about ``record.baseline_id`` from a prior
          ``load()`` -> use the path stored in the snapshot (so the
          mtime check in :meth:`save` runs against the right file).
        - The store doesn't know about it but the canonical path is
          free -> use the canonical path.
        - The store doesn't know about it and the canonical path is
          taken -> raise ``BaselineAlreadyExistsError`` unless
          ``force=True``.
        """

        if snapshot_for_id is not None:
            return snapshot_for_id.path

        canonical_path = self._storage_path / canonical
        if canonical_path.exists() and not force:
            raise BaselineAlreadyExistsError(canonical_path)
        return canonical_path

    # ------------------------------------------------------------------
    # Single-file load + delete (Task 12)
    # ------------------------------------------------------------------

    def load_one(self, path: Path) -> BaselineRecord:
        """Load a single Baseline_File without touching the registry.

        Used by ``loki baseline import`` (R6.6) and the GUI's
        ``View → Open Baseline Registry…`` action (R7.4). Shares
        the parse + validate path with :meth:`load`, but raises
        :class:`BaselineSerializationError` on any failure rather
        than quarantining: the caller asked for *this specific file*
        so a soft failure isn't useful.

        The store's internal snapshot map is **not** updated by
        ``load_one`` — that bookkeeping is what
        :meth:`BaselineStore.save` would use to enforce R5.3, and
        a ``load_one`` call against an arbitrary path doesn't make
        the file "owned" by this store. To persist the loaded
        record into the Storage_Directory, follow ``load_one`` with
        :meth:`save`.

        Args:
            path: Filesystem path to a Baseline_File. May live
                outside the Storage_Directory.

        Returns:
            The Pydantic-validated :class:`BaselineRecord`.

        Raises:
            BaselineSerializationError: every per-file failure mode
                from the bulk-load path (malformed YAML, missing
                envelope keys, unsupported ``schema_version``,
                Pydantic validation failure, oversized file, I/O
                error). The original exception, if any, is attached
                via ``__cause__`` for callers that want to drill in.
        """

        resolved = Path(path)
        outcome = self._parse_file(resolved)
        if isinstance(outcome, _LoadFailure):
            raise BaselineSerializationError(f"failed to load {resolved}: {outcome.reason}")
        return outcome.record

    def delete(self, baseline_id: uuid.UUID) -> Path:
        """Remove the Baseline_File matching ``baseline_id`` from disk.

        Used by ``loki baseline delete`` (R6.8) and future GUI
        trash actions. Removes the file and clears the in-memory
        snapshot. Returns the path that was removed so callers can
        log it.

        Args:
            baseline_id: The :class:`uuid.UUID` of the
                :class:`BaselineRecord` whose file to remove. Must
                be present in the store's snapshot map (i.e. the
                store must have loaded it via :meth:`load` or
                written it via :meth:`save`).

        Returns:
            Absolute path to the file that was removed.

        Raises:
            BaselineNotFoundError: ``baseline_id`` is not present in
                the store's snapshot map, or the file at the
                expected path no longer exists on disk.
            BaselineStorageUnwritableError: the Storage_Directory
                exists but is no longer writable, or a permission
                error prevents removing the file (R8.7).
        """

        snap = self._snapshots.get(baseline_id)
        if snap is None:
            raise BaselineNotFoundError(baseline_id)

        path = snap.path
        try:
            path.unlink()
        except FileNotFoundError as exc:
            # Whoever wrote the file has since removed it. Drop the
            # stale snapshot so a follow-up save against the same
            # baseline_id treats the file as new (R5.3 semantics).
            self._snapshots.pop(baseline_id, None)
            raise BaselineNotFoundError(baseline_id, path=path) from exc
        except PermissionError as exc:
            raise BaselineStorageUnwritableError(
                path,
                errno=exc.errno or errno.EACCES,
            ) from exc
        except OSError as exc:
            raise BaselineStorageUnwritableError(
                path,
                errno=exc.errno or errno.EIO,
            ) from exc

        # Clear the snapshot only after a successful unlink so a
        # failed delete leaves the store's view of the world intact.
        self._snapshots.pop(baseline_id, None)
        _LOGGER.info(
            "baseline delete id=%s path=%s",
            baseline_id,
            path,
        )
        return path

    # ------------------------------------------------------------------
    # Export (Task 18)
    # ------------------------------------------------------------------

    def export(
        self,
        record: BaselineRecord,
        dest: Path,
        *,
        written_by: str | None = None,
    ) -> Path:
        """Atomic_Write ``record`` to ``dest`` outside the Storage_Directory.

        Used by ``loki baseline export`` (R6.7). Mirrors :meth:`save`
        in shape — round-trip validation, envelope serialization,
        atomic write — but writes to a caller-chosen path that
        does not have to live under :attr:`storage_path`. The
        store's snapshot bookkeeping is **not** updated since the
        exported file isn't owned by this store.

        Args:
            record: The :class:`BaselineRecord` to write.
            dest: Destination filesystem path. The parent directory
                must already exist (the export operation does not
                ``mkdir`` because the caller picked the path
                deliberately).
            written_by: Optional override for the envelope's
                ``written_by_extractor_version`` field. Defaults to
                ``"loki-{loki version}"``.

        Returns:
            The absolute resolved destination path.

        Raises:
            BaselineSerializationError: round-trip validation
                failed (R3.8) or the serialized payload exceeds 16
                MiB (R9.8).
            BaselineStorageUnwritableError: ``dest``'s parent
                directory is not writable, or any other OSError
                during the atomic-write sequence (R8.7).
        """

        resolved = Path(dest).expanduser().resolve()

        # 1. Round-trip validation (R3.8).
        try:
            BaselineRecord.model_validate(
                record.model_dump(mode="json"),
                strict=False,
            )
        except ValidationError as exc:
            raise BaselineSerializationError(
                "BaselineRecord round-trip validation failed",
                cause=exc,
            ) from exc

        # 2. Build envelope bytes (R3.4-R3.7).
        written_at = datetime.now(tz=UTC)
        try:
            payload = serialize(
                record,
                schema_version=SCHEMA_VERSION,
                written_at=written_at,
                written_by_extractor_version=(
                    written_by if written_by is not None else _DEFAULT_WRITTEN_BY
                ),
            )
        except ValueError as exc:
            raise BaselineSerializationError(
                f"envelope serialization failed: {exc}",
                cause=exc,
            ) from exc
        if len(payload) > MAX_FILE_SIZE:
            raise BaselineSerializationError(
                f"serialized baseline exceeds 16 MiB ({len(payload)} bytes); "
                f"split into smaller component manifests"
            )

        # 3. Atomic_Write (R3.1-R3.3) — no concurrency check
        # because export targets aren't tracked by the store.
        _atomic_write(
            payload,
            resolved,
            error_path=resolved.parent,
        )

        _LOGGER.info(
            "baseline export id=%s vendor=%s model=%s firmware_version=%s path=%s",
            record.baseline_id,
            record.vendor,
            record.model,
            record.firmware_version,
            resolved,
        )
        return resolved
