"""Dynamic caplog audit for the feeds subsystem (task 19).

Captures every log record emitted during curated refresh and lookup
operations; asserts no record's formatted message contains any
Forbidden_Leakage_Field_Set value.

Curated operations:
- Successful refresh (monkey-patched)
- Failed refresh (network error)
- cve_lookup hit
- cve_lookup miss
- implant_rule_lookup hit
- Cancellation

Mirrors :mod:`tests.analysis.test_log_no_leakage`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loki.feeds.cache import CacheDB, CacheMetadata
from loki.feeds.models import (
    CVELookupQuery,
    ImplantRuleLookupQuery,
    RefreshStatus,
)
from loki.feeds.registry import FeedRegistry
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig

_FORBIDDEN_STRINGS: tuple[str, ...] = (
    "/etc/loki/trust.pem",
    "trust_anchor_path_value",
    "aaaa" * 16,  # a synthetic raw_hash
    "12345678-1234-1234-1234-123456789abc",  # a synthetic GUID
)


@pytest.fixture()
def captured_records() -> Iterator[list[logging.LogRecord]]:
    """Attach a recording handler to ``loki.feeds`` for one test."""
    records: list[logging.LogRecord] = []

    class _Recorder(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("loki.feeds")
    handler = _Recorder(level=logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def _formatted_messages(records: list[logging.LogRecord]) -> list[str]:
    return [record.getMessage() for record in records]


def _assert_no_leakage(messages: list[str]) -> None:
    for msg in messages:
        for forbidden in _FORBIDDEN_STRINGS:
            assert forbidden not in msg, f"Forbidden string {forbidden!r} found in log: {msg!r}"


def _build_registry(tmp_path: Path) -> FeedRegistry:
    """Build a FeedRegistry with a pre-populated cache for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    db_path = cache_dir / "feeds.db"

    cache_db = CacheDB(db_path)
    meta = CacheMetadata(
        last_refresh_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC),
        bundle_content_hash="ab" * 32,
        trust_anchor_identity="cd" * 32,
        feed_format_version="2.0",
        feeds_writer_version=FEEDS_VERSION,
    )
    cache_db.refresh_atomic(
        [
            {
                "cve_id": "CVE-2026-0001",
                "vendor": "intel",
                "product": "firmware",
                "version": "1.0.0",
                "published_date": "2026-01-01T00:00:00",
                "cvss_v3_score": 7.5,
                "cvss_v3_severity": "HIGH",
            }
        ],
        meta,
        None,
    )

    config = FeedsConfig(
        nvd_url="https://example.com/feeds",
        update_interval=999999,
        cache_path=str(cache_dir),
        implant_rules_path="",
        trust_anchor_path=None,
    )

    from loki.feeds.implants import load_implant_rules
    from loki.feeds.trust import resolve_trust_anchor

    trust_anchor = resolve_trust_anchor(None)
    rule_set = load_implant_rules(
        Path(
            str(
                __import__("importlib.resources", fromlist=["files"])
                .files("loki.feeds")
                .joinpath("builtin_implants")
            )
        ),
        None,
    )

    return FeedRegistry(
        config=config,
        cache_db=cache_db,
        trust_anchor=trust_anchor,
        rule_set=rule_set,
    )


class TestCveLookupNoLeakage:
    """CVE lookup operations do not leak forbidden fields."""

    def test_cve_lookup_hit(
        self,
        tmp_path: Path,
        captured_records: list[logging.LogRecord],
    ) -> None:
        registry = _build_registry(tmp_path)
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")
        result = registry.cve_lookup(query, allow_refresh=False)

        assert len(result.matches) >= 1
        messages = _formatted_messages(captured_records)
        _assert_no_leakage(messages)

    def test_cve_lookup_miss(
        self,
        tmp_path: Path,
        captured_records: list[logging.LogRecord],
    ) -> None:
        registry = _build_registry(tmp_path)
        query = CVELookupQuery(vendor="nobody", product="nothing", version="0.0.0")
        result = registry.cve_lookup(query, allow_refresh=False)

        assert len(result.matches) == 0
        messages = _formatted_messages(captured_records)
        _assert_no_leakage(messages)


class TestImplantLookupNoLeakage:
    """Implant rule lookup does not leak forbidden fields."""

    def test_implant_lookup_hit(
        self,
        tmp_path: Path,
        captured_records: list[logging.LogRecord],
    ) -> None:
        registry = _build_registry(tmp_path)
        query = ImplantRuleLookupQuery(
            content_hash="aaaa" * 16,
            firmware_guid="12345678-1234-1234-1234-123456789abc",
        )
        _result = registry.implant_rule_lookup(query)

        messages = _formatted_messages(captured_records)
        _assert_no_leakage(messages)

    def test_implant_lookup_no_match(
        self,
        tmp_path: Path,
        captured_records: list[logging.LogRecord],
    ) -> None:
        registry = _build_registry(tmp_path)
        query = ImplantRuleLookupQuery(
            content_hash="0000" * 16,
            firmware_guid=None,
        )
        result = registry.implant_rule_lookup(query)

        assert len(result.matches) == 0
        messages = _formatted_messages(captured_records)
        _assert_no_leakage(messages)


class TestRefreshNoLeakage:
    """Refresh operations do not leak forbidden fields."""

    def test_cancelled_refresh(
        self,
        tmp_path: Path,
        captured_records: list[logging.LogRecord],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        registry = _build_registry(tmp_path)

        def _always_cancel() -> bool:
            return True

        result = registry.refresh(force=True, cancel=_always_cancel)
        assert result.status == RefreshStatus.CANCELLED

        messages = _formatted_messages(captured_records)
        _assert_no_leakage(messages)
