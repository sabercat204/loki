"""Public entry point for the extraction pipeline.

The single function callers need is :func:`extract_firmware`; the
data classes :class:`PipelineConfig`, :class:`ProgressEvent`, and
:class:`ExtractionResult` describe the surrounding shape.

Why a synchronous entry point? R8.5: v1 extraction runs on the
caller's thread. The GUI's "Extract Firmware Components" action
blocks the UI for the duration of the extraction; the CLI just
returns when extraction completes. Background-threading is deferred
until the pipeline is feature-complete.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from loki.extraction.detection import FormatKind, detect_formats
from loki.extraction.errors import (
    InvalidInputError,
)
from loki.extraction.extractors import register as register_extractors
from loki.extraction.extractors.base import ExtractorContext, dispatch_for
from loki.extraction.manifest import ManifestBuilder
from loki.extraction.streaming import StreamingHasher
from loki.extraction.timing import (
    Stopwatch,
    check_global_budget,
    global_timeout_budget,
)
from loki.extraction.tools import (
    ChipsecWrapper,
    UefiFirmwareWrapper,
    UefitoolWrapper,
)
from loki.extraction.tools.base import ToolStatus, ToolWrapper
from loki.models import ExtractionConfig, ExtractionManifest, FirmwareImage

__all__ = [
    "CancellationToken",
    "ExtractionResult",
    "PipelineConfig",
    "ProgressCallback",
    "ProgressEvent",
    "extract_firmware",
]

#: Pipeline version string. Bumped whenever the extractor output
#: format changes in a way that breaks `component_id` stability.
EXTRACTOR_VERSION: str = "0.1.0"

_LOGGER = logging.getLogger("loki.extraction.api")


# ---------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class ProgressEvent:
    """Structured progress event passed to the optional ``progress`` callback (R9.2).

    The pipeline emits one event per phase transition and one per
    component as it's added to the manifest.
    """

    phase: str
    """``"input-check" | "detect" | "extract" | "manifest"``."""

    component_index: int
    """1-based; 0 before any component started."""

    components_estimated: int
    """Detector's running estimate. Equals 0 during ``input-check``."""

    message: str
    """Short human-readable status."""


@dataclass(frozen=True)
class PipelineConfig:
    """Pipeline-internal projection of :class:`ExtractionConfig`.

    Built by :func:`extract_firmware` from the caller's
    :class:`ExtractionConfig`; not constructed by external callers in
    v1. Frozen so mutating it during a run is impossible.
    """

    default_output_dir: Path | None
    max_component_size: int
    timeout_per_component: float


@dataclass(frozen=True)
class ExtractionResult:
    """Wrapper around the manifest plus diagnostic counters.

    Attributes:
        manifest: Validated :class:`ExtractionManifest`.
        tools_available: ``{tool_name: was_available}`` from the
            startup probe (R4.4). Optional tools that were missing
            also produced one informational ``ExtractionError`` per
            R4.5.
        duration_seconds: Wall-clock duration of the extraction run.
    """

    manifest: ExtractionManifest
    tools_available: dict[str, bool] = field(default_factory=dict)
    duration_seconds: float = 0.0


ProgressCallback = Callable[[ProgressEvent], None]
CancellationToken = Callable[[], bool]


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------


def extract_firmware(
    path: Path,
    config: ExtractionConfig,
    *,
    progress: ProgressCallback | None = None,
    cancel: CancellationToken | None = None,
) -> ExtractionResult:
    """Extract a firmware binary into a validated :class:`ExtractionManifest`.

    Implements the pipeline flow from the design doc's "Architecture /
    Pipeline flow" section:

    1. Resolve and validate ``path`` (R1.2-R1.4).
    2. Build :class:`PipelineConfig` from ``config``.
    3. Probe required + optional tools (R4.4); required tool absence
       raises :class:`ExtractionPipelineError`.
    4. Hash the file via :class:`StreamingHasher` (R1.7, R8.2) and
       build a :class:`FirmwareImage`.
    5. Run :func:`detect_formats` over the peek window.
    6. For each detected format (outermost first), dispatch to the
       corresponding extractor; convert each ``CarvedComponent``
       via ``ManifestBuilder.add_component``; check ``cancel()``
       between components; emit progress events (R9.2-R9.4).
    7. Apply the global timeout budget (R5.9).
    8. Finalize the manifest and return.

    Args:
        path: Filesystem path to the firmware binary.
        config: Caller-supplied :class:`ExtractionConfig` (R9.7).
        progress: Optional callback invoked from the calling thread
            (R9.2-R9.3) on every phase change and per component.
        cancel: Optional callable returning ``True`` to request
            graceful shutdown between components (R9.4).

    Returns:
        :class:`ExtractionResult` containing the validated manifest,
        the tool-availability map from the probe, and the wall-clock
        duration.

    Raises:
        InvalidInputError: ``path`` is missing, not a regular file,
            or empty (R1.3, R1.4).
        ExtractionPipelineError: required tool ``uefi_firmware`` is
            missing (R4.5 only covers optional tools).
        ManifestConstructionError: final manifest failed Pydantic
            validation (R6.6).
    """

    register_extractors()

    stopwatch = Stopwatch()
    stopwatch.start()
    _emit_progress(progress, "input-check", 0, 0, f"validating {path}")
    resolved_path = _validate_input(path)
    pipeline_config = _to_pipeline_config(config)

    # Scratch directory owned by the pipeline; cleaned in the finally
    # block so a missed-cleanup bug can't leak temp files between runs.
    scratch_dir = Path(tempfile.mkdtemp(prefix="loki-extract-"))
    try:
        # Probe tools.
        wrappers, tools_available = _probe_tools()

        # Hash + image construction.
        hasher = StreamingHasher(resolved_path)
        file_hash, file_size, peek = hasher.hash_file()
        _LOGGER.info(
            "extraction starting path=%s size=%d head=%s",
            resolved_path,
            file_size,
            peek[:8].hex(),
        )

        source_image = FirmwareImage(
            file_path=str(resolved_path),
            file_hash=file_hash,
            file_size=file_size,
        )
        manifest_builder = ManifestBuilder(
            source_image=source_image,
            extractor_version=EXTRACTOR_VERSION,
            started_at=datetime.now(tz=UTC),
        )

        # Record one informational ExtractionError per missing
        # optional tool (R4.5).
        for wrapper in wrappers:
            if not wrapper.required and tools_available.get(wrapper.name) is False:
                manifest_builder.record_error(
                    error_kind="OPTIONAL_TOOL_MISSING",
                    message=(
                        f"[OPTIONAL_TOOL_MISSING] {wrapper.name} not "
                        f"available; falling back to required parser"
                    ),
                    offset=None,
                )

        # Detect.
        _emit_progress(progress, "detect", 0, 0, "scanning for known formats")
        detected = detect_formats(peek, file_size=file_size)
        format_kinds = [d.kind.value for d in detected]
        _LOGGER.info(
            "extraction detected formats=%s offsets=%s",
            format_kinds,
            [hex(d.offset) for d in detected],
        )

        if all(d.kind is FormatKind.UNKNOWN for d in detected):
            # R2.8: out-of-scope binary still produces a manifest.
            manifest_builder.record_error(
                error_kind="OUT_OF_SCOPE_FORMAT",
                message=(
                    f"[OUT_OF_SCOPE_FORMAT] {resolved_path} did not "
                    f"match any v1 supported container format; "
                    f"inspected {min(file_size, hasher.PEEK_SIZE)} "
                    f"bytes from offset 0"
                ),
                offset=None,
            )
            manifest = manifest_builder.finalize()
            duration = stopwatch.stop()
            _LOGGER.info(
                "extraction finished duration=%.3fs components=%d errors=%d",
                duration,
                len(manifest.components),
                len(manifest.extraction_errors),
            )
            return ExtractionResult(
                manifest=manifest,
                tools_available=tools_available,
                duration_seconds=duration,
            )

        # Build extractor context.
        uefi_firmware_wrapper: UefiFirmwareWrapper | None = next(
            (w for w in wrappers if isinstance(w, UefiFirmwareWrapper)),
            None,
        )
        ctx = ExtractorContext(
            binary_path=resolved_path,
            manifest_builder=manifest_builder,
            max_component_size=pipeline_config.max_component_size,
            output_dir=pipeline_config.default_output_dir,
            tools_available=tools_available,
            uefi_firmware=uefi_firmware_wrapper,
        )

        # Estimate the global timeout budget. We use a conservative
        # initial estimate of 1 component per detected format; the
        # budget grows as more components are seen.
        components_estimated = len(detected)
        budget = global_timeout_budget(pipeline_config.timeout_per_component, components_estimated)

        # Dispatch each detected format to its extractor.
        emitted = 0
        for det in detected:
            if det.kind is FormatKind.UNKNOWN:
                continue
            extractor = dispatch_for(det.kind)
            if extractor is None:
                manifest_builder.record_error(
                    error_kind="NO_EXTRACTOR",
                    message=(
                        f"[NO_EXTRACTOR] no extractor registered for "
                        f"format {det.kind.value} at offset "
                        f"0x{det.offset:x}"
                    ),
                    offset=det.offset,
                )
                continue

            for carve in extractor.extract(ctx, det.offset, det.length):
                # Cancellation check between components (R9.4).
                if cancel is not None and cancel():
                    manifest_builder.record_error(
                        error_kind="CANCELLED",
                        message="extraction cancelled by caller",
                        offset=None,
                    )
                    return _finalize(manifest_builder, tools_available, stopwatch)

                # Global timeout budget (R5.9).
                if not check_global_budget(stopwatch, budget):
                    manifest_builder.record_error(
                        error_kind="GLOBAL_TIMEOUT",
                        message=(
                            f"[GLOBAL_TIMEOUT] extraction exceeded global budget of {budget:.1f}s"
                        ),
                        offset=None,
                    )
                    return _finalize(manifest_builder, tools_available, stopwatch)

                raw_path = _write_carved_bytes(
                    pipeline_config.default_output_dir,
                    resolved_path,
                    carve.offset,
                    carve.size,
                )

                manifest_builder.add_component(
                    carve,
                    binary_path=resolved_path,
                    max_component_size=pipeline_config.max_component_size,
                    raw_path=raw_path,
                )

                # Inner components: walk the parent's decompressed
                # payload (when present) and emit one
                # ``ExtractedComponent`` per inner section. Inner
                # components carry a synthetic virtual image id
                # derived from the decompressed payload's hash so
                # they're linkable to their parent without
                # requiring a model-layer change.
                if carve.decompressed_payload is not None:
                    inner_count = _emit_inner_components(
                        manifest_builder=manifest_builder,
                        parent_carve=carve,
                        decompressed_payload=carve.decompressed_payload,
                        output_dir=pipeline_config.default_output_dir,
                        max_component_size=pipeline_config.max_component_size,
                        progress=progress,
                        components_estimated_ref=components_estimated,
                        emitted_ref=emitted,
                    )
                    emitted += inner_count

                emitted += 1
                # Re-budget as we learn the real component count.
                if emitted > components_estimated:
                    components_estimated = emitted
                    budget = global_timeout_budget(
                        pipeline_config.timeout_per_component,
                        components_estimated,
                    )
                _emit_progress(
                    progress,
                    "extract",
                    emitted,
                    max(components_estimated, emitted),
                    f"extracted component at 0x{carve.offset:x}",
                )

        return _finalize(manifest_builder, tools_available, stopwatch)

    finally:
        # Clean up scratch dir; tools may have written here even on error.
        shutil.rmtree(scratch_dir, ignore_errors=True)


# ---------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------


def _validate_input(path: Path) -> Path:
    """R1.2-R1.4: enforce input pre-conditions or raise."""

    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise InvalidInputError(resolved, "path does not exist")
    if not resolved.is_file():
        raise InvalidInputError(resolved, "path is not a regular file")
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise InvalidInputError(resolved, f"could not stat path: {exc}") from exc
    if size <= 0:
        raise InvalidInputError(resolved, "file is empty")
    return resolved.resolve()


def _to_pipeline_config(config: ExtractionConfig) -> PipelineConfig:
    """Project the caller's :class:`ExtractionConfig` into our internal shape."""

    output_dir: Path | None = None
    if config.default_output_dir:
        candidate = Path(config.default_output_dir).expanduser()
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # Touch a marker file to confirm writability, then drop it.
            marker = candidate / ".loki-extract-writable"
            marker.write_bytes(b"")
            marker.unlink()
            output_dir = candidate
        except OSError:
            # Per R3.13, an unwritable output dir is a soft failure;
            # raw_path stays None and other fields are still populated.
            output_dir = None
    return PipelineConfig(
        default_output_dir=output_dir,
        max_component_size=int(config.max_component_size),
        timeout_per_component=float(config.timeout_per_component),
    )


def _probe_tools() -> tuple[list[ToolWrapper], dict[str, bool]]:
    """Probe the required + optional tool wrappers.

    The required ``uefi_firmware`` wrapper raises if its package isn't
    importable (R4.5 only covers optional tools). Optional wrappers
    record a falsy entry in ``tools_available`` and the caller emits
    an informational :class:`ExtractionError`.
    """

    wrappers: list[ToolWrapper] = [
        UefiFirmwareWrapper(),
        UefitoolWrapper(),
        ChipsecWrapper(),
    ]
    available: dict[str, bool] = {}
    for wrapper in wrappers:
        status = wrapper.probe()
        available[wrapper.name] = status is ToolStatus.AVAILABLE
    return wrappers, available


def _emit_progress(
    callback: ProgressCallback | None,
    phase: str,
    index: int,
    estimated: int,
    message: str,
) -> None:
    """Invoke the progress callback if one was supplied (R9.2-R9.3)."""

    if callback is None:
        return
    callback(
        ProgressEvent(
            phase=phase,
            component_index=index,
            components_estimated=estimated,
            message=message,
        )
    )


def _finalize(
    builder: ManifestBuilder,
    tools_available: dict[str, bool],
    stopwatch: Stopwatch,
) -> ExtractionResult:
    """Build the :class:`ExtractionResult` and log the summary."""

    manifest = builder.finalize()
    duration = stopwatch.stop()
    _LOGGER.info(
        "extraction finished duration=%.3fs components=%d errors=%d",
        duration,
        len(manifest.components),
        len(manifest.extraction_errors),
    )
    return ExtractionResult(
        manifest=manifest,
        tools_available=tools_available,
        duration_seconds=duration,
    )


def _write_carved_bytes(
    output_dir: Path | None,
    binary_path: Path,
    offset: int,
    size: int,
) -> Path | None:
    """Write a carved component's bytes to ``{output_dir}/0x{offset:x}-{raw_hash}.bin``.

    Returns the absolute path or ``None`` when no output dir is
    configured (R3.12, R3.13). The filename is computed *after* the
    bytes are read so the determinism contract (R7.4) holds.
    """

    if output_dir is None:
        return None

    with binary_path.open("rb") as fh:
        fh.seek(offset)
        carved = fh.read(size)
    if len(carved) != size:  # pragma: no cover - guarded by streaming hasher
        return None

    import hashlib  # imported here to keep top-level deps minimal

    raw_hash = hashlib.sha256(carved).hexdigest()
    filename = f"0x{offset:x}-{raw_hash}.bin"
    out_path = (output_dir / filename).resolve()
    out_path.write_bytes(carved)
    return out_path


def _write_inner_bytes(
    output_dir: Path | None,
    parent_offset: int,
    inner_offset: int,
    inner_bytes: bytes,
    inner_raw_hash: str,
) -> Path | None:
    """Write inner-component bytes to disk under ``output_dir``.

    Filename convention:
    ``0x{parent_offset:x}-decompressed-0x{inner_offset:x}-{raw_hash}.bin``.

    The ``decompressed`` marker distinguishes inner-component files
    from outer-component files in the output directory listing.
    Returns ``None`` when ``output_dir`` is ``None``.
    """

    if output_dir is None:
        return None

    filename = f"0x{parent_offset:x}-decompressed-0x{inner_offset:x}-{inner_raw_hash}.bin"
    out_path = (output_dir / filename).resolve()
    out_path.write_bytes(inner_bytes)
    return out_path


def _emit_inner_components(
    *,
    manifest_builder: ManifestBuilder,
    parent_carve: object,  # ``CarvedComponent`` — typed loosely to dodge a circular import
    decompressed_payload: bytes,
    output_dir: Path | None,
    max_component_size: int,
    progress: ProgressCallback | None,
    components_estimated_ref: int,
    emitted_ref: int,
) -> int:
    """Walk a decompressed payload's sections and emit inner components.

    Returns the count of inner components actually appended to the
    manifest. Progress events are emitted per inner component so
    the GUI / CLI can show forward progress through deeply-nested
    decompressed buffers.
    """

    # Local imports keep the top-level api module's import surface
    # small and dodge potential circulars.
    import hashlib

    from loki.extraction.inner_carve import walk_decompressed_sections

    # ``parent_carve`` is typed loosely above; assert the concrete
    # type once and use the typed reference below.
    assert hasattr(parent_carve, "offset")
    parent_offset: int = parent_carve.offset

    # Hash the decompressed buffer once; reuse the digest for every
    # inner component's ``component_id`` derivation.
    decompressed_hash = hashlib.sha256(decompressed_payload).hexdigest()

    inner_emitted = 0
    for inner_carve in walk_decompressed_sections(decompressed_payload):
        inner_bytes = decompressed_payload[
            inner_carve.offset : inner_carve.offset + inner_carve.size
        ]
        inner_raw_hash = hashlib.sha256(inner_bytes).hexdigest()
        inner_raw_path = _write_inner_bytes(
            output_dir,
            parent_offset=parent_offset,
            inner_offset=inner_carve.offset,
            inner_bytes=inner_bytes,
            inner_raw_hash=inner_raw_hash,
        )
        component = manifest_builder.add_inner_component(
            offset=inner_carve.offset,
            size=inner_carve.size,
            raw_bytes=inner_bytes,
            decompressed_payload_hash=decompressed_hash,
            max_component_size=max_component_size,
            component_type_hint=inner_carve.component_type_hint,
            name=inner_carve.name,
            raw_path=inner_raw_path,
        )
        if component is not None:
            inner_emitted += 1
            _emit_progress(
                progress,
                "extract",
                emitted_ref + inner_emitted,
                max(components_estimated_ref, emitted_ref + inner_emitted),
                f"extracted inner component at 0x{inner_carve.offset:x} "
                f"(parent 0x{parent_offset:x})",
            )

    return inner_emitted
