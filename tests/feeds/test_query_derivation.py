"""Tests for CVE and implant query derivation helpers (tasks 15-16).

Task 15: ``derive_cve_query(record, image) -> CVELookupQuery``
Task 16: ``derive_implant_query(component) -> ImplantRuleLookupQuery``
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from loki.feeds.errors import FeedsConfigError
from loki.feeds.models import CVELookupQuery, ImplantRuleLookupQuery
from loki.feeds.registry import derive_cve_query, derive_implant_query

# -- Lightweight duck-typed stubs for derive_cve_query ----------------------


@dataclass
class _AxisStub:
    label: str


@dataclass
class _RecordStub:
    vendor_axis: _AxisStub
    type_axis: _AxisStub


@dataclass
class _ImageStub:
    firmware_version: str
    model: str | None = None


# -- Task 15: derive_cve_query tests ---------------------------------------


class TestDeriveCveQuery:
    """Verify CVE query derivation from ClassificationRecord + FirmwareImage."""

    def test_basic_derivation(self) -> None:
        record = _RecordStub(
            vendor_axis=_AxisStub(label="INTEL"),
            type_axis=_AxisStub(label="UEFI_DRIVER"),
        )
        image = _ImageStub(firmware_version="1.2.3", model="X1")
        result = derive_cve_query(record, image)

        assert isinstance(result, CVELookupQuery)
        assert result.vendor == "intel"
        assert result.product == "uefi_driver_x1"
        assert result.version == "1.2.3"

    def test_vendor_lowercased(self) -> None:
        record = _RecordStub(
            vendor_axis=_AxisStub(label="AMI"),
            type_axis=_AxisStub(label="BIOS"),
        )
        image = _ImageStub(firmware_version="2.0", model="Z99")
        result = derive_cve_query(record, image)

        assert result.vendor == "ami"

    def test_product_without_model(self) -> None:
        record = _RecordStub(
            vendor_axis=_AxisStub(label="PHOENIX"),
            type_axis=_AxisStub(label="OPTION_ROM"),
        )
        image = _ImageStub(firmware_version="3.0.1", model=None)
        result = derive_cve_query(record, image)

        assert result.product == "option_rom"

    def test_product_with_empty_model(self) -> None:
        record = _RecordStub(
            vendor_axis=_AxisStub(label="PHOENIX"),
            type_axis=_AxisStub(label="OPTION_ROM"),
        )
        image = _ImageStub(firmware_version="3.0.1", model="")
        result = derive_cve_query(record, image)

        assert result.product == "option_rom"

    def test_missing_firmware_version_raises(self) -> None:
        record = _RecordStub(
            vendor_axis=_AxisStub(label="INTEL"),
            type_axis=_AxisStub(label="UEFI_DRIVER"),
        )
        image = _ImageStub(firmware_version="")
        with pytest.raises(FeedsConfigError, match="firmware_version"):
            derive_cve_query(record, image)

    def test_missing_vendor_axis_raises(self) -> None:
        record = object()  # no vendor_axis attribute
        image = _ImageStub(firmware_version="1.0")
        with pytest.raises(FeedsConfigError, match="vendor_axis"):
            derive_cve_query(record, image)

    def test_missing_type_axis_raises(self) -> None:
        @dataclass
        class _Partial:
            vendor_axis: _AxisStub

        record = _Partial(vendor_axis=_AxisStub(label="INTEL"))
        image = _ImageStub(firmware_version="1.0")
        with pytest.raises(FeedsConfigError, match="type_axis"):
            derive_cve_query(record, image)

    def test_version_preserved_verbatim(self) -> None:
        record = _RecordStub(
            vendor_axis=_AxisStub(label="intel"),
            type_axis=_AxisStub(label="driver"),
        )
        image = _ImageStub(firmware_version="10.2.3-beta+build.42", model="M1")
        result = derive_cve_query(record, image)

        assert result.version == "10.2.3-beta+build.42"


# -- Task 16: derive_implant_query tests -----------------------------------


@dataclass
class _ComponentStub:
    raw_hash: str
    guid: str | None = None


class TestDeriveImplantQuery:
    """Verify implant query derivation from ExtractedComponent."""

    def test_basic_derivation_with_guid(self) -> None:
        component = _ComponentStub(
            raw_hash="a" * 64,
            guid="12345678-1234-1234-1234-123456789abc",
        )
        result = derive_implant_query(component)

        assert isinstance(result, ImplantRuleLookupQuery)
        assert result.content_hash == "a" * 64
        assert result.firmware_guid == "12345678-1234-1234-1234-123456789abc"

    def test_derivation_without_guid(self) -> None:
        component = _ComponentStub(raw_hash="b" * 64, guid=None)
        result = derive_implant_query(component)

        assert result.content_hash == "b" * 64
        assert result.firmware_guid is None

    def test_missing_raw_hash_raises(self) -> None:
        component = _ComponentStub(raw_hash="")
        with pytest.raises(FeedsConfigError, match="raw_hash"):
            derive_implant_query(component)

    def test_no_raw_hash_attribute_raises(self) -> None:
        component = object()
        with pytest.raises(FeedsConfigError, match="raw_hash"):
            derive_implant_query(component)

    def test_guid_none_when_attribute_missing(self) -> None:
        @dataclass
        class _NoGuid:
            raw_hash: str

        component = _NoGuid(raw_hash="c" * 64)
        result = derive_implant_query(component)

        assert result.content_hash == "c" * 64
        assert result.firmware_guid is None
