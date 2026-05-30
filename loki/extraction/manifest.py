"""``ManifestBuilder``: accumulates components and errors, finalizes the manifest.

This is where carved components turn into validated
:class:`~loki.models.ExtractedComponent` records and where errors get
their stable identifiers. The builder is the *only* place in
``loki.extraction`` that constructs an :class:`~loki.models.ExtractionManifest`,
so every Pydantic strict validator runs before the value escapes the
subsystem (R6.1).

Lifecycle:

1. Caller constructs the builder with the source image, the
   pipeline's own version string, and the ``started_at`` wall-clock
   timestamp.
2. Per carved component, caller invokes :meth:`add_component`. For
   inner components extracted from a decompressed payload, caller
   invokes :meth:`add_inner_component` instead so the synthetic
   virtual-image-id and in-memory ``raw_hash`` are wired correctly.
3. Per failure, caller invokes :meth:`record_error`.
4. Caller invokes :meth:`finalize` exactly once and receives the
   validated :class:`~loki.models.ExtractionManifest`.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Union

from pydantic import ValidationError

from loki.extraction.errors import ManifestConstructionError
from loki.extraction.ids import derive_component_id, derive_error_component_id
from loki.extraction.streaming import streaming_sha256_slice
from loki.models import (
    LOKI_NAMESPACE,
    ExtractedComponent,
    ExtractionError,
    ExtractionManifest,
    FirmwareImage,
)

if TYPE_CHECKING:
    from loki.extraction.extractors.base import CarvedComponent

__all__ = [
    "CarvedComponentInput",
    "CarvedLike",
    "ManifestBuilder",
]


class CarvedComponentInput:
    """Lightweight input bundle for :meth:`ManifestBuilder.add_component`.

    Predates :class:`loki.extraction.extractors.base.CarvedComponent`
    and stays in place because the manifest builder's tests construct
    inputs directly without going through the extractor protocol.
    The two types share an identical field set; the manifest builder
    accepts either via the :data:`CarvedLike` union alias.
    """

    __slots__ = (
        "component_type_hint",
        "guid",
        "name",
        "offset",
        "size",
    )

    def __init__(
        self,
        *,
        offset: int,
        size: int,
        component_type_hint: str | None = None,
        guid: str | None = None,
        name: str | None = None,
    ) -> None:
        self.offset = offset
        self.size = size
        self.component_type_hint = component_type_hint
        self.guid = guid
        self.name = name


#: Either input shape :meth:`ManifestBuilder.add_component` accepts.
CarvedLike = Union[CarvedComponentInput, "CarvedComponent"]


class ManifestBuilder:
    """Accumulate carved components and errors, then assemble the manifest."""

    def __init__(
        self,
        *,
        source_image: FirmwareImage,
        extractor_version: str,
        started_at: datetime,
    ) -> None:
        if source_image.image_id is None:  # pragma: no cover - model auto-derives
            raise ValueError("source_image.image_id must be populated")
        self._source_image = source_image
        self._extractor_version = extractor_version
        self._started_at = started_at
        self._components: list[ExtractedComponent] = []
        self._errors: list[ExtractionError] = []
        self._seen_component_ids: set[uuid.UUID] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_component(
        self,
        carved: CarvedLike,
        *,
        binary_path: Path,
        max_component_size: int,
        raw_path: Path | None = None,
    ) -> ExtractedComponent | None:
        """Append a carved component as a validated :class:`ExtractedComponent`.

        Returns the appended component on success, or ``None`` when the
        component was skipped because its size exceeds
        ``max_component_size`` (R3.14). Skipped components leave a
        recorded :class:`ExtractionError` in their place so downstream
        consumers can see what was dropped.

        Args:
            carved: Input bundle from the extractor.
            binary_path: Path to the source firmware on disk; used to
                compute :attr:`ExtractedComponent.raw_hash` via
                :func:`streaming_sha256_slice`.
            max_component_size: Cap from
                :attr:`loki.models.ExtractionConfig.max_component_size`.
            raw_path: Optional path under
                ``ExtractionConfig.default_output_dir`` where the
                carved bytes were written; recorded as
                :attr:`ExtractedComponent.raw_path`. ``None`` when the
                pipeline isn't configured to dump components to disk
                (R3.13).
        """

        if carved.size <= 0:
            raise ValueError(f"carved.size must be > 0, got {carved.size}")
        if max_component_size <= 0:
            raise ValueError(f"max_component_size must be > 0, got {max_component_size}")

        if carved.size > max_component_size:
            self.record_error(
                error_kind="OVERSIZED_COMPONENT",
                message=(
                    f"[OVERSIZED_COMPONENT] component at 0x{carved.offset:x} "
                    f"has size {carved.size} which exceeds "
                    f"max_component_size={max_component_size}; skipped"
                ),
                offset=carved.offset,
            )
            return None

        raw_hash = streaming_sha256_slice(binary_path, carved.offset, carved.size)
        assert self._source_image.image_id is not None
        component_id = derive_component_id(
            source_image_hash=self._source_image.file_hash,
            offset=carved.offset,
            raw_hash=raw_hash,
        )
        if component_id in self._seen_component_ids:
            # Two carves with identical offset + raw_hash collide on
            # ``component_id``. Record an error and keep going so a
            # buggy extractor can't kill the whole run.
            self.record_error(
                error_kind="DUPLICATE_COMPONENT_ID",
                message=(
                    f"[DUPLICATE_COMPONENT_ID] two components share id "
                    f"{component_id} (offset 0x{carved.offset:x}); "
                    f"second occurrence dropped"
                ),
                offset=carved.offset,
            )
            return None

        component = ExtractedComponent(
            component_id=component_id,
            source_image_id=self._source_image.image_id,
            offset=f"0x{carved.offset:x}",
            size=carved.size,
            raw_hash=raw_hash,
            component_type_hint=carved.component_type_hint,
            guid=carved.guid,
            name=carved.name,
            raw_path=str(raw_path) if raw_path is not None else None,
        )
        self._components.append(component)
        self._seen_component_ids.add(component_id)
        return component

    def add_inner_component(
        self,
        *,
        offset: int,
        size: int,
        raw_bytes: bytes,
        decompressed_payload_hash: str,
        max_component_size: int,
        component_type_hint: str | None = None,
        name: str | None = None,
        raw_path: Path | None = None,
    ) -> ExtractedComponent | None:
        """Append an inner component carved from a decompressed payload.

        Used by the api when a parent ``CarvedComponent`` carries a
        ``decompressed_payload``. Inner components don't live in the
        source firmware binary; they live only inside the
        in-memory decompressed buffer. Three fields differ from the
        outer-component path:

        - ``raw_hash`` is computed from ``raw_bytes`` directly via
          :func:`hashlib.sha256` (no path slice).
        - ``source_image_hash`` for ``component_id`` derivation is
          ``decompressed_payload_hash`` — the SHA-256 of the parent's
          full decompressed payload. This guarantees inner-component
          IDs are stable across runs and don't collide with
          outer-component IDs (which use the source firmware's hash).
        - ``source_image_id`` on the resulting
          :class:`ExtractedComponent` is a synthetic
          ``uuid5(LOKI_NAMESPACE, decompressed_payload_hash)`` so
          inner components share an image-id within their parent's
          decompressed payload but stay distinct from the firmware
          file's ``image_id``.

        Args:
            offset: Offset of the inner component within the
                decompressed buffer (not the source binary).
            size: Inner component's byte length, including any
                section header bytes.
            raw_bytes: The inner component's bytes as carved from
                the decompressed buffer.
            decompressed_payload_hash: SHA-256 hex digest of the
                parent's full decompressed payload. The pipeline
                hashes the decompressed buffer once and reuses the
                digest for every inner component carved from it.
            max_component_size: Cap from
                :attr:`loki.models.ExtractionConfig.max_component_size`.
                Inner components that exceed it are skipped with an
                ``OVERSIZED_COMPONENT`` error, mirroring the outer
                code path (R3.14).
            component_type_hint: Type label from the inner-section
                walker (e.g. ``"INNER_SECTION_TYPE_PE32"``).
            name: UI-section name when the inner section has one;
                ``None`` otherwise.
            raw_path: Optional path under
                ``ExtractionConfig.default_output_dir`` where the
                inner-component bytes were written. ``None`` when
                the pipeline isn't dumping bytes.

        Returns:
            The appended :class:`ExtractedComponent` on success, or
            ``None`` when the component was skipped because its size
            exceeded ``max_component_size``.
        """

        if size <= 0:
            raise ValueError(f"size must be > 0, got {size}")
        if max_component_size <= 0:
            raise ValueError(f"max_component_size must be > 0, got {max_component_size}")
        if len(raw_bytes) != size:
            raise ValueError(
                f"raw_bytes length {len(raw_bytes)} does not match declared size {size}"
            )

        if size > max_component_size:
            self.record_error(
                error_kind="OVERSIZED_COMPONENT",
                message=(
                    f"[OVERSIZED_COMPONENT] inner component at 0x{offset:x} "
                    f"has size {size} which exceeds "
                    f"max_component_size={max_component_size}; skipped"
                ),
                offset=offset,
            )
            return None

        raw_hash = hashlib.sha256(raw_bytes).hexdigest()
        component_id = derive_component_id(
            source_image_hash=decompressed_payload_hash,
            offset=offset,
            raw_hash=raw_hash,
        )
        if component_id in self._seen_component_ids:
            self.record_error(
                error_kind="DUPLICATE_COMPONENT_ID",
                message=(
                    f"[DUPLICATE_COMPONENT_ID] two components share id "
                    f"{component_id} (inner offset 0x{offset:x}); "
                    f"second occurrence dropped"
                ),
                offset=offset,
            )
            return None

        # Synthesize the virtual image id from the decompressed
        # payload's hash (option 4B): same derivation pattern as
        # ``FirmwareImage.image_id`` so callers can recognize the
        # link without a new field on the model.
        virtual_image_id = uuid.uuid5(LOKI_NAMESPACE, decompressed_payload_hash)

        component = ExtractedComponent(
            component_id=component_id,
            source_image_id=virtual_image_id,
            offset=f"0x{offset:x}",
            size=size,
            raw_hash=raw_hash,
            component_type_hint=component_type_hint,
            guid=None,
            name=name,
            raw_path=str(raw_path) if raw_path is not None else None,
        )
        self._components.append(component)
        self._seen_component_ids.add(component_id)
        return component

    def record_error(
        self,
        *,
        error_kind: str,
        message: str,
        offset: int | None,
        component_id: uuid.UUID | None = None,
    ) -> ExtractionError:
        """Append an :class:`ExtractionError` to the manifest.

        When ``offset`` is supplied and ``component_id`` is ``None``,
        derives a stable ``component_id`` via
        :func:`derive_error_component_id` (R7.3). Whole-file errors
        leave ``component_id`` as ``None`` (R5.5).
        """

        if offset is not None and offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")
        if not message or not message.strip():
            raise ValueError("message must be non-empty")

        if component_id is None and offset is not None:
            component_id = derive_error_component_id(
                source_image_hash=self._source_image.file_hash,
                offset=offset,
                error_kind=error_kind,
            )

        error = ExtractionError(
            component_id=component_id,
            error_message=message,
            timestamp=datetime.now(tz=UTC),
        )
        self._errors.append(error)
        return error

    def finalize(self) -> ExtractionManifest:
        """Produce the validated :class:`ExtractionManifest`.

        Sorts components by ascending integer offset (R6.5), pins
        ``component_id`` uniqueness (R6.2), and converts any
        :class:`pydantic.ValidationError` into a
        :class:`ManifestConstructionError` so callers see a typed
        failure rather than a raw Pydantic error (R6.6).
        """

        ordered = sorted(self._components, key=lambda c: int(c.offset, 16))
        try:
            manifest = ExtractionManifest(
                source_image=self._source_image,
                components=ordered,
                extraction_timestamp=datetime.now(tz=UTC),
                extractor_version=self._extractor_version,
                extraction_errors=list(self._errors),
            )
        except ValidationError as exc:
            raise ManifestConstructionError(
                "ExtractionManifest validation failed",
                field_path=str(exc.errors()[0].get("loc")) if exc.errors() else None,
                cause=exc,
            ) from exc

        return manifest

    # ------------------------------------------------------------------
    # Read-only views (handy for tests)
    # ------------------------------------------------------------------

    @property
    def components(self) -> list[ExtractedComponent]:
        return list(self._components)

    @property
    def errors(self) -> list[ExtractionError]:
        return list(self._errors)
