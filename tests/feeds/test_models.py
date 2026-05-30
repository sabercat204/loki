"""Tests for loki.feeds.models — result dataclasses and version constant."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from loki.feeds import (
    FEEDS_VERSION,
    CVELookupQuery,
    CVELookupResult,
    CVEMatch,
    ImplantRuleLookupQuery,
    ImplantRuleLookupResult,
    ImplantRuleMatch,
    RefreshResult,
    RefreshStatus,
)


class TestFeedsVersion:
    """FEEDS_VERSION constant tests."""

    def test_is_string(self) -> None:
        assert isinstance(FEEDS_VERSION, str)

    def test_semver_format(self) -> None:
        parts = FEEDS_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()

    def test_current_value(self) -> None:
        assert FEEDS_VERSION == "1.0.0"


class TestRefreshStatus:
    """RefreshStatus enum tests."""

    def test_has_expected_values(self) -> None:
        assert RefreshStatus.SUCCESS == "SUCCESS"
        assert RefreshStatus.WARN_STALE == "WARN_STALE"
        assert RefreshStatus.CANCELLED == "CANCELLED"
        assert RefreshStatus.FAILED == "FAILED"

    def test_member_count(self) -> None:
        assert len(RefreshStatus) == 4

    def test_is_str_enum(self) -> None:
        assert isinstance(RefreshStatus.SUCCESS, str)


class TestRefreshResult:
    """RefreshResult frozen dataclass tests."""

    def test_construction(self) -> None:
        now = datetime.now(tz=UTC)
        result = RefreshResult(
            status=RefreshStatus.SUCCESS,
            cves_imported=100,
            bytes_fetched=2048,
            duration_seconds=1.5,
            last_refresh_at=now,
            feeds_version="1.0.0",
        )
        assert result.status == RefreshStatus.SUCCESS
        assert result.cves_imported == 100
        assert result.bytes_fetched == 2048
        assert result.duration_seconds == 1.5
        assert result.last_refresh_at == now
        assert result.feeds_version == "1.0.0"
        assert result.diagnostics == []

    def test_diagnostics_default_empty(self) -> None:
        result = RefreshResult(
            status=RefreshStatus.FAILED,
            cves_imported=0,
            bytes_fetched=0,
            duration_seconds=0.0,
            last_refresh_at=None,
            feeds_version="1.0.0",
        )
        assert result.diagnostics == []

    def test_frozen(self) -> None:
        result = RefreshResult(
            status=RefreshStatus.SUCCESS,
            cves_imported=0,
            bytes_fetched=0,
            duration_seconds=0.0,
            last_refresh_at=None,
            feeds_version="1.0.0",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.status = RefreshStatus.FAILED  # type: ignore[misc]


class TestCVEMatch:
    """CVEMatch frozen dataclass tests."""

    def test_construction(self) -> None:
        now = datetime.now(tz=UTC)
        match = CVEMatch(
            cve_id="CVE-2024-0001",
            vendor="intel",
            product="firmware",
            version="1.0.0",
            published_date=now,
            cvss_v3_score=9.8,
            cvss_v3_severity="CRITICAL",
        )
        assert match.cve_id == "CVE-2024-0001"
        assert match.cvss_v3_score == 9.8
        assert match.cvss_v3_severity == "CRITICAL"

    def test_optional_fields_default_none(self) -> None:
        now = datetime.now(tz=UTC)
        match = CVEMatch(
            cve_id="CVE-2024-0002",
            vendor="vendor",
            product="product",
            version="2.0",
            published_date=now,
        )
        assert match.cvss_v3_score is None
        assert match.cvss_v3_severity is None

    def test_frozen(self) -> None:
        now = datetime.now(tz=UTC)
        match = CVEMatch(
            cve_id="CVE-2024-0001",
            vendor="v",
            product="p",
            version="1.0",
            published_date=now,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            match.cve_id = "CVE-9999-9999"  # type: ignore[misc]


class TestCVELookupResult:
    """CVELookupResult frozen dataclass tests."""

    def test_construction_defaults(self) -> None:
        result = CVELookupResult()
        assert result.matches == []
        assert result.stale_warning is False

    def test_construction_with_matches(self) -> None:
        now = datetime.now(tz=UTC)
        match = CVEMatch(
            cve_id="CVE-2024-0001",
            vendor="v",
            product="p",
            version="1.0",
            published_date=now,
        )
        result = CVELookupResult(matches=[match], stale_warning=True)
        assert len(result.matches) == 1
        assert result.stale_warning is True

    def test_frozen(self) -> None:
        result = CVELookupResult()
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.stale_warning = True  # type: ignore[misc]


class TestCVELookupQuery:
    """CVELookupQuery frozen dataclass tests."""

    def test_construction(self) -> None:
        query = CVELookupQuery(vendor="intel", product="bios", version="1.0")
        assert query.vendor == "intel"
        assert query.product == "bios"
        assert query.version == "1.0"

    def test_frozen(self) -> None:
        query = CVELookupQuery(vendor="v", product="p", version="1.0")
        with pytest.raises(dataclasses.FrozenInstanceError):
            query.vendor = "other"  # type: ignore[misc]


class TestImplantRuleMatch:
    """ImplantRuleMatch frozen dataclass tests."""

    def test_construction(self) -> None:
        match = ImplantRuleMatch(
            rule_id="implant:blacklotus.bootmgfw",
            ioc_field="content_hash",
            threat_family="BlackLotus",
        )
        assert match.rule_id == "implant:blacklotus.bootmgfw"
        assert match.ioc_field == "content_hash"
        assert match.threat_family == "BlackLotus"

    def test_frozen(self) -> None:
        match = ImplantRuleMatch(rule_id="r", ioc_field="content_hash", threat_family="X")
        with pytest.raises(dataclasses.FrozenInstanceError):
            match.rule_id = "other"  # type: ignore[misc]


class TestImplantRuleLookupResult:
    """ImplantRuleLookupResult frozen dataclass tests."""

    def test_construction_defaults(self) -> None:
        result = ImplantRuleLookupResult()
        assert result.matches == []

    def test_construction_with_matches(self) -> None:
        match = ImplantRuleMatch(
            rule_id="implant:lojax",
            ioc_field="firmware_guid",
            threat_family="LoJax",
        )
        result = ImplantRuleLookupResult(matches=[match])
        assert len(result.matches) == 1

    def test_frozen(self) -> None:
        result = ImplantRuleLookupResult()
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.matches = []  # type: ignore[misc]


class TestImplantRuleLookupQuery:
    """ImplantRuleLookupQuery frozen dataclass tests."""

    def test_construction(self) -> None:
        query = ImplantRuleLookupQuery(
            content_hash="a" * 64,
            firmware_guid="some-guid",
        )
        assert query.content_hash == "a" * 64
        assert query.firmware_guid == "some-guid"

    def test_firmware_guid_defaults_none(self) -> None:
        query = ImplantRuleLookupQuery(content_hash="b" * 64)
        assert query.firmware_guid is None

    def test_frozen(self) -> None:
        query = ImplantRuleLookupQuery(content_hash="c" * 64)
        with pytest.raises(dataclasses.FrozenInstanceError):
            query.content_hash = "d" * 64  # type: ignore[misc]
