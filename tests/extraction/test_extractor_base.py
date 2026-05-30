"""Tests for the extractor base protocol + dispatch helper (task 12)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest

from loki.extraction.detection import FormatKind
from loki.extraction.extractors.base import (
    CarvedComponent,
    Extractor,
    ExtractorContext,
    clear_registry,
    dispatch_for,
    register_extractor,
    registered_extractors,
)
from loki.extraction.manifest import ManifestBuilder
from loki.models import FirmwareImage


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    """Each test starts with an empty registry and leaves it empty."""
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def manifest_builder(tmp_path: Path) -> ManifestBuilder:
    binary = tmp_path / "fw.bin"
    binary.write_bytes(b"x" * 1024)
    image = FirmwareImage(
        file_path=str(binary),
        file_hash="a" * 64,
        file_size=binary.stat().st_size,
    )
    return ManifestBuilder(
        source_image=image,
        extractor_version="0.1.0",
        started_at=datetime.now(tz=UTC),
    )


class _StubExtractor:
    """Concrete extractor used to drive the registry in tests."""

    name: ClassVar[str] = "stub"

    def __init__(self, supported: FormatKind) -> None:
        self._supported = supported

    def supports(self, kind: FormatKind) -> bool:
        return kind == self._supported

    def extract(
        self,
        context: ExtractorContext,
        offset: int,
        length: int | None,
    ) -> Iterator[CarvedComponent]:
        yield CarvedComponent(offset=offset, size=16, name=self.name)


def test_dispatch_returns_none_when_unregistered() -> None:
    assert dispatch_for(FormatKind.UEFI_PI_VOLUME) is None


def test_register_and_dispatch_round_trip() -> None:
    stub = _StubExtractor(FormatKind.UEFI_PI_VOLUME)
    register_extractor(FormatKind.UEFI_PI_VOLUME, stub)
    assert dispatch_for(FormatKind.UEFI_PI_VOLUME) is stub


def test_register_replaces_previous_registration() -> None:
    first = _StubExtractor(FormatKind.UEFI_CAPSULE)
    second = _StubExtractor(FormatKind.UEFI_CAPSULE)
    register_extractor(FormatKind.UEFI_CAPSULE, first)
    register_extractor(FormatKind.UEFI_CAPSULE, second)
    assert dispatch_for(FormatKind.UEFI_CAPSULE) is second


def test_clear_registry_empties_everything() -> None:
    register_extractor(FormatKind.UEFI_PI_VOLUME, _StubExtractor(FormatKind.UEFI_PI_VOLUME))
    register_extractor(FormatKind.UEFI_CAPSULE, _StubExtractor(FormatKind.UEFI_CAPSULE))
    assert len(registered_extractors()) == 2
    clear_registry()
    assert registered_extractors() == {}


def test_extractor_protocol_is_runtime_checkable() -> None:
    stub = _StubExtractor(FormatKind.PCI_OPTION_ROM)
    assert isinstance(stub, Extractor)


def test_extractor_context_is_frozen(manifest_builder: ManifestBuilder) -> None:
    """Frozen so extractors can't accidentally mutate shared state."""
    ctx = ExtractorContext(
        binary_path=Path("/tmp/fw.bin"),
        manifest_builder=manifest_builder,
        max_component_size=1024,
    )
    with pytest.raises(AttributeError):
        ctx.max_component_size = 2048  # type: ignore[misc]


def test_carved_component_defaults() -> None:
    """``CarvedComponent`` accepts only the required positional fields."""
    cc = CarvedComponent(offset=0x100, size=64)
    assert cc.component_type_hint is None
    assert cc.guid is None
    assert cc.name is None
    assert cc.decompressed_payload is None


def test_carved_component_is_frozen() -> None:
    cc = CarvedComponent(offset=0, size=1)
    with pytest.raises(AttributeError):
        cc.size = 2  # type: ignore[misc]


def test_extractor_invocation_via_dispatcher(
    manifest_builder: ManifestBuilder, tmp_path: Path
) -> None:
    """Smoke-check: a registered stub yields one ``CarvedComponent`` and the
    manifest builder accepts it."""
    binary = tmp_path / "fw.bin"
    binary.write_bytes(b"x" * 1024)

    stub = _StubExtractor(FormatKind.UEFI_PI_VOLUME)
    register_extractor(FormatKind.UEFI_PI_VOLUME, stub)
    extractor = dispatch_for(FormatKind.UEFI_PI_VOLUME)
    assert extractor is not None

    ctx = ExtractorContext(
        binary_path=binary,
        manifest_builder=manifest_builder,
        max_component_size=10_000,
    )
    carves = list(extractor.extract(ctx, offset=0x100, length=None))
    assert len(carves) == 1
    assert carves[0].offset == 0x100
    assert carves[0].size == 16
