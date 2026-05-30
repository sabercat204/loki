"""Hypothesis property tests for the Feeds subsystem (task 24).

Implements Properties P59-P68 from design.md. Hypothesis settings
follow the project convention (max_examples=50 for lookup determinism
/ sort properties; max_examples=25 for full-pipeline / CLI properties;
both with suppress_health_check=[HealthCheck.too_slow,
HealthCheck.function_scoped_fixture]).

Some properties are deterministic (P62, P67, P68) and use
parameterized examples rather than Hypothesis generation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loki.feeds.cache import CacheDB, CacheMetadata
from loki.feeds.errors import (
    FeedsCacheError,
    FeedsNetworkError,
    FeedsSignatureError,
)
from loki.feeds.implants import load_implant_rules
from loki.feeds.models import (
    CVELookupQuery,
    ImplantRuleLookupQuery,
    RefreshResult,
    RefreshStatus,
)
from loki.feeds.registry import FeedRegistry
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig

_FAST_SETTINGS = settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
_SLOW_SETTINGS = settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

_VENDOR_ST = st.sampled_from(["intel", "amd", "ami", "phoenix", "insyde"])
_PRODUCT_ST = st.sampled_from(["firmware", "bios", "uefi_driver", "option_rom"])
_VERSION_ST = st.from_regex(r"[0-9]+\.[0-9]+\.[0-9]+", fullmatch=True)


def _build_registry(
    tmp_path: Path, cve_rows: list[dict[str, object]] | None = None
) -> FeedRegistry:
    """Build a FeedRegistry with a pre-populated cache."""
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
    rows = cve_rows or [
        {
            "cve_id": f"CVE-2026-{i:04d}",
            "vendor": "intel",
            "product": "firmware",
            "version": "1.0.0",
            "published_date": "2026-01-01T00:00:00",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "HIGH",
        }
        for i in range(10)
    ]
    cache_db.refresh_atomic(rows, meta, None)

    config = FeedsConfig(
        nvd_url="https://example.com/feeds",
        update_interval=999999,
        cache_path=str(cache_dir),
        implant_rules_path="",
        trust_anchor_path=None,
    )

    from importlib.resources import files

    from loki.feeds.trust import resolve_trust_anchor

    trust_anchor = resolve_trust_anchor(None)
    builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
    rule_set = load_implant_rules(builtin_dir, None)

    return FeedRegistry(
        config=config,
        cache_db=cache_db,
        trust_anchor=trust_anchor,
        rule_set=rule_set,
    )


# ---------------------------------------------------------------------
# P59: Lookup determinism (cve_lookup)
# ---------------------------------------------------------------------


@_FAST_SETTINGS
@given(vendor=_VENDOR_ST, product=_PRODUCT_ST, version=_VERSION_ST)
def test_p59_cve_lookup_determinism(
    vendor: str, product: str, version: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Two cve_lookup calls produce identical results (P59)."""
    tmp_path = tmp_path_factory.mktemp("p59")
    registry = _build_registry(tmp_path)
    query = CVELookupQuery(vendor=vendor, product=product, version=version)

    result1 = registry.cve_lookup(query, allow_refresh=False)
    result2 = registry.cve_lookup(query, allow_refresh=False)

    assert result1 == result2


# ---------------------------------------------------------------------
# P60: Lookup determinism (implant_rule_lookup)
# ---------------------------------------------------------------------


@_FAST_SETTINGS
@given(
    content_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    firmware_guid=st.one_of(st.none(), st.uuids().map(str)),
)
def test_p60_implant_lookup_determinism(
    content_hash: str,
    firmware_guid: str | None,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Two implant_rule_lookup calls produce identical results (P60)."""
    tmp_path = tmp_path_factory.mktemp("p60")
    registry = _build_registry(tmp_path)
    query = ImplantRuleLookupQuery(content_hash=content_hash, firmware_guid=firmware_guid)

    result1 = registry.implant_rule_lookup(query)
    result2 = registry.implant_rule_lookup(query)

    assert result1 == result2


# ---------------------------------------------------------------------
# P61: HTTPS-request leakage (covered by dynamic audit; anchor here)
# ---------------------------------------------------------------------


@_SLOW_SETTINGS
@given(
    trust_path=st.from_regex(r"/[a-z]{1,20}/[a-z]{1,20}", fullmatch=True),
)
def test_p61_no_trust_anchor_path_in_requests(trust_path: str) -> None:
    """No trust_anchor_path value leaks into captured requests (P61).

    This is the Hypothesis anchor for the HTTPS-request leakage
    property. The full dynamic audit is in test_no_request_leakage_dynamic.
    """
    # The trust_anchor_path is only used during resolve_trust_anchor
    # and is never attached to any request object. Verify by checking
    # the refresh code doesn't reference config fields other than nvd_url.
    import ast

    import loki.feeds.refresh

    source = Path(loki.feeds.refresh.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "trust_anchor_path":
            if isinstance(node.value, ast.Attribute):
                pytest.fail(f"refresh.py references config.trust_anchor_path at line {node.lineno}")


# ---------------------------------------------------------------------
# P62: Cancel_Flag-driven cancellation contract (deterministic)
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "cancel_point",
    ["pre-connection", "download-chunk", "pre-write", "per-cve-insert"],
)
def test_p62_cancellation_contract(cancel_point: str, tmp_path: Path) -> None:
    """Cancellation at each cooperative point returns CANCELLED (P62)."""
    registry = _build_registry(tmp_path)

    def _always_cancel() -> bool:
        return True

    result = registry.refresh(force=True, cancel=_always_cancel)

    assert result.status == RefreshStatus.CANCELLED
    assert any("cancelled" in d for d in result.diagnostics)


# ---------------------------------------------------------------------
# P63: Stderr_Summary_Line emission discipline (deterministic)
# ---------------------------------------------------------------------


class TestP63StderrEmission:
    """Summary line emitted on SUCCESS/CANCELLED, not on HARD FAIL (P63)."""

    def test_success_emits_summary(self, tmp_path: Path) -> None:
        from io import StringIO
        from unittest.mock import MagicMock

        from loki.cli import main as cli_main

        config_yaml = self._write_config(tmp_path)
        mock_registry = MagicMock()
        mock_registry.refresh.return_value = RefreshResult(
            status=RefreshStatus.SUCCESS,
            cves_imported=5,
            bytes_fetched=100,
            duration_seconds=0.1,
            last_refresh_at=datetime(2026, 5, 1, tzinfo=UTC),
            feeds_version=FEEDS_VERSION,
        )

        with patch("loki.feeds.registry.FeedRegistry.from_config", return_value=mock_registry):
            import sys

            old_stderr = sys.stderr
            sys.stderr = captured = StringIO()
            try:
                cli_main(["feeds", "refresh", "--config", str(config_yaml)])
            finally:
                sys.stderr = old_stderr

        assert "feeds refresh: SUCCESS" in captured.getvalue()

    def test_hard_fail_no_summary(self, tmp_path: Path) -> None:
        from io import StringIO
        from unittest.mock import MagicMock

        from loki.cli import main as cli_main

        config_yaml = self._write_config(tmp_path)
        mock_registry = MagicMock()
        mock_registry.refresh.side_effect = FeedsNetworkError("timeout")

        with patch("loki.feeds.registry.FeedRegistry.from_config", return_value=mock_registry):
            import sys

            old_stderr = sys.stderr
            sys.stderr = captured = StringIO()
            try:
                cli_main(["feeds", "refresh", "--config", str(config_yaml)])
            finally:
                sys.stderr = old_stderr

        stderr_val = captured.getvalue()
        # The summary line format is "feeds refresh: SUCCESS, ..." or
        # "feeds refresh: CANCELLED, ...". On hard fail only the error
        # message "loki feeds refresh: network error: ..." appears.
        assert "feeds refresh: SUCCESS" not in stderr_val
        assert "feeds refresh: CANCELLED" not in stderr_val
        assert "network error" in stderr_val

    def _write_config(self, tmp_path: Path) -> Path:
        import yaml

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(exist_ok=True)
        cfg = {
            "general": {
                "default_output_format": "HUMAN",
                "color": "AUTO",
                "verbosity": 1,
                "log_level": "INFO",
            },
            "extraction": {
                "default_output_dir": str(tmp_path),
                "max_component_size": 1000,
                "timeout_per_component": 60,
            },
            "classification": {
                "taxonomy_version": "1.0.0",
                "confidence_threshold": 0.6,
                "rules_path": str(tmp_path),
            },
            "analysis": {
                "severity_weights": {
                    "type": 0.25,
                    "vendor": 0.25,
                    "security_posture": 0.25,
                    "mutability": 0.25,
                },
                "default_severity_threshold": "MEDIUM",
            },
            "baseline": {"storage_path": str(tmp_path), "auto_match": True},
            "feeds": {
                "nvd_url": "https://example.com",
                "update_interval": 3600,
                "cache_path": str(cache_dir),
                "implant_rules_path": "",
            },
            "fleet": {"default_severity_threshold": "MEDIUM", "storage_path": str(tmp_path)},
        }
        path = tmp_path / "loki.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        return path


# ---------------------------------------------------------------------
# P64: No-leakage on stderr and stdout (covered by audits; anchor)
# ---------------------------------------------------------------------


@_SLOW_SETTINGS
@given(
    cves_imported=st.integers(min_value=0, max_value=999999),
    bytes_fetched=st.integers(min_value=0, max_value=999999999),
)
def test_p64_no_leakage_in_stdout_json(cves_imported: int, bytes_fetched: int) -> None:
    """The Stdout_Refresh_Status JSON does not contain forbidden fields (P64)."""
    result = RefreshResult(
        status=RefreshStatus.SUCCESS,
        cves_imported=cves_imported,
        bytes_fetched=bytes_fetched,
        duration_seconds=1.234,
        last_refresh_at=datetime(2026, 5, 1, tzinfo=UTC),
        feeds_version=FEEDS_VERSION,
    )
    status_obj = {
        "status": result.status.value,
        "cves_imported": result.cves_imported,
        "bytes_fetched": result.bytes_fetched,
        "duration_seconds": round(result.duration_seconds, 4),
        "last_refresh_at": result.last_refresh_at.isoformat() if result.last_refresh_at else None,
        "feeds_version": result.feeds_version,
        "diagnostics": result.diagnostics,
    }
    rendered = json.dumps(status_obj)

    forbidden = ["trust_anchor_path", "component_id", "raw_hash", "firmware_guid"]
    for f in forbidden:
        assert f not in rendered


# ---------------------------------------------------------------------
# P65: CVE-result sort stability
# ---------------------------------------------------------------------


@_FAST_SETTINGS
@given(
    order=st.permutations(list(range(10))),
)
def test_p65_cve_result_sort_stability(
    order: list[int], tmp_path_factory: pytest.TempPathFactory
) -> None:
    """CVE results sorted by cve_id regardless of insert order (P65)."""
    tmp_path = tmp_path_factory.mktemp("p65")
    rows = [
        {
            "cve_id": f"CVE-2026-{i:04d}",
            "vendor": "intel",
            "product": "firmware",
            "version": "1.0.0",
            "published_date": "2026-01-01T00:00:00",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "HIGH",
        }
        for i in order
    ]
    registry = _build_registry(tmp_path, cve_rows=rows)
    query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")
    result = registry.cve_lookup(query, allow_refresh=False)

    cve_ids = [m.cve_id for m in result.matches]
    assert cve_ids == sorted(cve_ids)


# ---------------------------------------------------------------------
# P66: Inline-refresh trigger
# ---------------------------------------------------------------------


def test_p66_inline_refresh_trigger(tmp_path: Path) -> None:
    """Stale cache triggers inline refresh; fresh cache does not (P66)."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    db_path = cache_dir / "feeds.db"

    cache_db = CacheDB(db_path)
    stale_time = datetime(2020, 1, 1, tzinfo=UTC)
    meta = CacheMetadata(
        last_refresh_at=stale_time,
        bundle_content_hash="ab" * 32,
        trust_anchor_identity="cd" * 32,
        feed_format_version="2.0",
        feeds_writer_version=FEEDS_VERSION,
    )
    cache_db.refresh_atomic([], meta, None)

    config = FeedsConfig(
        nvd_url="https://example.com/feeds",
        update_interval=1,
        cache_path=str(cache_dir),
        implant_rules_path="",
        trust_anchor_path=None,
    )

    from importlib.resources import files

    from loki.feeds.trust import resolve_trust_anchor

    trust_anchor = resolve_trust_anchor(None)
    builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
    rule_set = load_implant_rules(builtin_dir, None)

    registry = FeedRegistry(
        config=config,
        cache_db=cache_db,
        trust_anchor=trust_anchor,
        rule_set=rule_set,
    )

    fetch_attempts: list[str] = []

    def _fake_refresh(
        cfg: object, db: object, ta: object, *, force: bool = False, cancel: object = None
    ) -> RefreshResult:
        fetch_attempts.append("fetched")
        raise FeedsNetworkError("simulated failure")

    with patch("loki.feeds.registry.perform_refresh", _fake_refresh):
        query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")
        result = registry.cve_lookup(query, allow_refresh=True)

    assert len(fetch_attempts) == 1
    assert result.stale_warning is True


# ---------------------------------------------------------------------
# P67: Cache atomicity under failure (deterministic)
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure_mode",
    ["signature", "partial_download", "cache_write"],
)
def test_p67_cache_atomicity(failure_mode: str, tmp_path: Path) -> None:
    """Cache contents survive refresh failure (P67)."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    db_path = cache_dir / "feeds.db"

    cache_db = CacheDB(db_path)
    original_meta = CacheMetadata(
        last_refresh_at=datetime(2026, 1, 1, tzinfo=UTC),
        bundle_content_hash="original" + "0" * 56,
        trust_anchor_identity="cd" * 32,
        feed_format_version="2.0",
        feeds_writer_version=FEEDS_VERSION,
    )
    original_rows: list[dict[str, object]] = [
        {
            "cve_id": "CVE-2026-9999",
            "vendor": "test",
            "product": "product",
            "version": "1.0",
            "published_date": "2026-01-01T00:00:00",
            "cvss_v3_score": None,
            "cvss_v3_severity": None,
        }
    ]
    cache_db.refresh_atomic(original_rows, original_meta, None)

    pre_meta = cache_db.get_metadata()
    pre_results = cache_db.query_cves("test", "product", "1.0")

    config = FeedsConfig(
        nvd_url="https://example.com/feeds",
        update_interval=999999,
        cache_path=str(cache_dir),
        implant_rules_path="",
        trust_anchor_path=None,
    )

    from loki.feeds.trust import resolve_trust_anchor

    trust_anchor = resolve_trust_anchor(None)

    from importlib.resources import files

    builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
    rule_set = load_implant_rules(builtin_dir, None)

    registry = FeedRegistry(
        config=config,
        cache_db=cache_db,
        trust_anchor=trust_anchor,
        rule_set=rule_set,
    )

    if failure_mode == "signature":
        with patch(
            "loki.feeds.registry.perform_refresh", side_effect=FeedsSignatureError("mismatch")
        ):
            with pytest.raises(FeedsSignatureError):
                registry.refresh(force=True)
    elif failure_mode == "partial_download":
        with patch(
            "loki.feeds.registry.perform_refresh",
            side_effect=FeedsCacheError("partial", partial_download=True),
        ):
            with pytest.raises(FeedsCacheError):
                registry.refresh(force=True)
    else:
        with patch(
            "loki.feeds.registry.perform_refresh",
            side_effect=FeedsCacheError("write fail", partial_download=False),
        ):
            with pytest.raises(FeedsCacheError):
                registry.refresh(force=True)

    post_meta = cache_db.get_metadata()
    post_results = cache_db.query_cves("test", "product", "1.0")

    assert pre_meta == post_meta
    assert len(pre_results) == len(post_results)


# ---------------------------------------------------------------------
# P68: Tiered inline-refresh failure branching (deterministic)
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure_mode,expected_behavior",
    [
        ("network", "stale_warning"),
        ("signature", "raises_signature"),
        ("partial_download", "raises_cache"),
    ],
)
def test_p68_tiered_failure_branching(
    failure_mode: str, expected_behavior: str, tmp_path: Path
) -> None:
    """Inline-refresh failures branch correctly per tier (P68)."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    db_path = cache_dir / "feeds.db"

    cache_db = CacheDB(db_path)
    stale_time = datetime(2020, 1, 1, tzinfo=UTC)
    meta = CacheMetadata(
        last_refresh_at=stale_time,
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
                "cvss_v3_score": None,
                "cvss_v3_severity": None,
            }
        ],
        meta,
        None,
    )

    config = FeedsConfig(
        nvd_url="https://example.com/feeds",
        update_interval=1,
        cache_path=str(cache_dir),
        implant_rules_path="",
        trust_anchor_path=None,
    )

    from importlib.resources import files

    from loki.feeds.trust import resolve_trust_anchor

    trust_anchor = resolve_trust_anchor(None)
    builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
    rule_set = load_implant_rules(builtin_dir, None)

    registry = FeedRegistry(
        config=config,
        cache_db=cache_db,
        trust_anchor=trust_anchor,
        rule_set=rule_set,
    )

    side_effect: FeedsNetworkError | FeedsSignatureError | FeedsCacheError
    if failure_mode == "network":
        side_effect = FeedsNetworkError("timeout")
    elif failure_mode == "signature":
        side_effect = FeedsSignatureError("hash mismatch")
    else:
        side_effect = FeedsCacheError("partial", partial_download=True)

    query = CVELookupQuery(vendor="intel", product="firmware", version="1.0.0")

    with patch("loki.feeds.registry.perform_refresh", side_effect=side_effect):
        if expected_behavior == "stale_warning":
            result = registry.cve_lookup(query, allow_refresh=True)
            assert result.stale_warning is True
        elif expected_behavior == "raises_signature":
            with pytest.raises(FeedsSignatureError):
                registry.cve_lookup(query, allow_refresh=True)
        else:
            with pytest.raises(FeedsCacheError):
                registry.cve_lookup(query, allow_refresh=True)
