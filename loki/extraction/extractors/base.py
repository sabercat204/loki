"""Extractor protocol, ``CarvedComponent`` dataclass, and dispatch helper.

The :class:`Extractor` protocol is the contract every per-format
strategy implements. Concrete extractors are added by tasks 13-17 and
register themselves via :func:`register_extractor`. Until then the
dispatcher returns ``None`` and the public entry point falls back to
recording an out-of-scope error.

Why a registry instead of imports? The pipeline's public entry point
must work even when only a subset of extractors are wired up (e.g.
during incremental development). A registry decouples the dispatcher
from the import order of concrete strategies.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from loki.extraction.detection import FormatKind

if TYPE_CHECKING:
    from loki.extraction.manifest import ManifestBuilder
    from loki.extraction.tools.uefi_firmware import UefiFirmwareWrapper

__all__ = [
    "CarvedComponent",
    "Extractor",
    "ExtractorContext",
    "clear_registry",
    "dispatch_for",
    "register_extractor",
    "registered_extractors",
]


@dataclass(frozen=True)
class CarvedComponent:
    """A single extractor output before manifest assembly.

    The :class:`~loki.extraction.manifest.ManifestBuilder` converts
    this into an :class:`~loki.models.ExtractedComponent`, deriving
    ``component_id`` deterministically (R7.2), computing ``raw_hash``
    via streaming slice (R3.8), and applying the
    ``max_component_size`` policy (R3.14).
    """

    offset: int
    """Absolute byte offset within the source firmware binary (R3.6)."""

    size: int
    """Exact byte length of the carved component as it lives in the source (R3.7)."""

    component_type_hint: str | None = None
    """Optional vendor / type label set by the extractor."""

    guid: str | None = None
    """Canonical lowercase 8-4-4-4-12 UUID when the component carries one (R3.10)."""

    name: str | None = None
    """UI-section name or vendor label, NUL-truncated (R3.11)."""

    decompressed_payload: bytes | None = None
    """Decompressed bytes when the section was a compressed wrapper.

    Only set by the UEFI volume extractor when a compressed section is
    successfully decompressed; the manifest builder uses this to carve
    the inner components in addition to the outer wrapper. ``None``
    for plain (non-compressed) sections.
    """


@dataclass(frozen=True)
class ExtractorContext:
    """Per-run state passed to every extractor.

    Concrete extractors receive this rather than a long parameter list
    so adding new state (e.g. a tool-availability map, progress
    callbacks) doesn't churn every signature. Frozen so extractors
    can't accidentally mutate global state.
    """

    binary_path: Path
    """Path to the source firmware binary on disk."""

    manifest_builder: ManifestBuilder
    """The pipeline's manifest builder; extractors hand ``CarvedComponent``s
    to it indirectly via ``ExtractorContext.manifest_builder.add_component(...)``."""

    max_component_size: int
    """Forwarded from :attr:`loki.models.ExtractionConfig.max_component_size`."""

    output_dir: Path | None = None
    """Optional directory under which raw component bytes are written
    (R3.12). ``None`` when the pipeline isn't configured to dump
    components to disk (R3.13)."""

    tools_available: dict[str, bool] = field(default_factory=dict)
    """Map of tool name to availability, populated by the pipeline."""

    uefi_firmware: UefiFirmwareWrapper | None = None
    """Pre-probed wrapper around the ``uefi_firmware`` package.

    Populated by :func:`extract_firmware` after :meth:`probe` succeeds
    so extractors can reach decompression helpers without re-importing
    the library. ``None`` only in test setups that build the context
    by hand and don't need decompression.
    """


@runtime_checkable
class Extractor(Protocol):
    """Per-format extractor strategy.

    Implementations are stateless (or own internal state only for the
    duration of a single :meth:`extract` call) and reentrant. They
    must never seek before ``offset`` or beyond ``offset + length``
    in the source binary.
    """

    name: ClassVar[str]
    """Short human-readable identifier (e.g. ``"uefi_volume"``)."""

    def supports(self, kind: FormatKind) -> bool:
        """Return whether this extractor handles ``kind``."""
        ...

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        """Yield carved components within ``[offset, offset + length)``.

        The pipeline owns the conversion to ``ExtractedComponent`` —
        extractors yield raw carves and the manifest builder handles
        validation, hashing, and id derivation.
        """
        ...


# ---------------------------------------------------------------------
# Registry / dispatch
# ---------------------------------------------------------------------


_REGISTRY: dict[FormatKind, Extractor] = {}


def register_extractor(kind: FormatKind, extractor: Extractor) -> None:
    """Register ``extractor`` as the strategy for ``kind``.

    A second registration for the same ``kind`` replaces the first;
    that's deliberate so test fixtures can swap in stubs without
    fighting the dispatcher. Concrete extractors call this at module
    import time; tests can also call :func:`clear_registry` to start
    from an empty state.
    """

    _REGISTRY[kind] = extractor


def dispatch_for(kind: FormatKind) -> Extractor | None:
    """Return the registered :class:`Extractor` for ``kind`` or ``None``."""

    return _REGISTRY.get(kind)


def registered_extractors() -> dict[FormatKind, Extractor]:
    """Return a shallow copy of the current registry (for diagnostics / tests)."""

    return dict(_REGISTRY)


def clear_registry() -> None:
    """Empty the registry. Test-only helper; production code never calls this."""

    _REGISTRY.clear()
