"""Feed registry — library entry point for the Feeds subsystem."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse

from loki.feeds.cache import CacheDB
from loki.feeds.errors import FeedsConfigError, FeedsNetworkError
from loki.feeds.implants import ImplantRuleSet, load_implant_rules, match_implant_rules
from loki.feeds.models import (
    CancellationToken,
    CVELookupQuery,
    CVELookupResult,
    ImplantRuleLookupQuery,
    ImplantRuleLookupResult,
    RefreshResult,
)
from loki.feeds.refresh import perform_refresh
from loki.feeds.trust import TrustAnchor, resolve_trust_anchor
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig

__all__ = ["FeedRegistry", "derive_cve_query", "derive_implant_query"]

logger = logging.getLogger("loki.feeds")


class FeedRegistry:
    """Library entry point for the Feeds subsystem.

    Owns the SQLite cache handle, the loaded implant rule set,
    and the resolved trust anchor.
    """

    def __init__(
        self,
        config: FeedsConfig,
        cache_db: CacheDB,
        trust_anchor: TrustAnchor,
        rule_set: ImplantRuleSet,
    ) -> None:
        self._config = config
        self._cache_db = cache_db
        self._trust_anchor = trust_anchor
        self._rule_set = rule_set

    @classmethod
    def from_config(cls, feeds_config: FeedsConfig) -> FeedRegistry:
        """Construct a FeedRegistry from a validated FeedsConfig.

        Raises FeedsConfigError on invalid configuration.
        """
        # 1. Validate nvd_url
        if not feeds_config.nvd_url:
            raise FeedsConfigError("nvd_url must be non-empty")
        parsed = urlparse(feeds_config.nvd_url)
        if parsed.scheme != "https":
            raise FeedsConfigError(f"nvd_url must use https:// scheme, got {parsed.scheme}://")

        # 2. Validate cache_path and create directory
        if not feeds_config.cache_path:
            raise FeedsConfigError("cache_path must be non-empty")
        cache_dir = Path(feeds_config.cache_path)
        cache_dir.mkdir(parents=True, exist_ok=True)

        # 3. Resolve trust anchor
        trust_anchor = resolve_trust_anchor(feeds_config.trust_anchor_path)

        # 4. Open CacheDB
        db_path = cache_dir / "feeds.db"
        cache_db = CacheDB(db_path)

        # Check writer version compatibility
        current_major = int(FEEDS_VERSION.split(".")[0])
        cache_db.check_writer_version(current_major)

        # 5. Load implant rules
        builtin_dir = Path(str(files("loki.feeds").joinpath("builtin_implants")))
        operator_dir: Path | None = None
        if feeds_config.implant_rules_path:
            operator_dir = Path(feeds_config.implant_rules_path)

        rule_set = load_implant_rules(builtin_dir, operator_dir)

        return cls(
            config=feeds_config,
            cache_db=cache_db,
            trust_anchor=trust_anchor,
            rule_set=rule_set,
        )

    def refresh(
        self,
        *,
        force: bool = False,
        cancel: CancellationToken | None = None,
    ) -> RefreshResult:
        """Perform an explicit refresh of the Cache_DB."""
        return perform_refresh(
            self._config,
            self._cache_db,
            self._trust_anchor,
            force=force,
            cancel=cancel,
        )

    def cve_lookup(
        self,
        query: CVELookupQuery,
        *,
        allow_refresh: bool = True,
    ) -> CVELookupResult:
        """Return matching CVE records from the Cache_DB."""
        # Validate query fields
        if not query.vendor.strip():
            raise FeedsConfigError("CVE lookup query vendor must be non-empty")
        if not query.product.strip():
            raise FeedsConfigError("CVE lookup query product must be non-empty")
        if not query.version.strip():
            raise FeedsConfigError("CVE lookup query version must be non-empty")

        stale_warning = False

        if allow_refresh:
            stale_warning = self._inline_refresh_if_stale()

        results = self._cache_db.query_cves(query.vendor, query.product, query.version)
        return CVELookupResult(matches=results, stale_warning=stale_warning)

    def implant_rule_lookup(
        self,
        query: ImplantRuleLookupQuery,
    ) -> ImplantRuleLookupResult:
        """Return matching implant-rule records from the loaded rule set."""
        return match_implant_rules(query, self._rule_set)

    def _inline_refresh_if_stale(self) -> bool:
        """Check cache age; trigger inline refresh if stale.

        Returns True (stale_warning) if refresh failed with network error
        but we continue with stale data.
        """
        meta = self._cache_db.get_metadata()
        if meta is not None:
            age_seconds = (datetime.now(UTC) - meta.last_refresh_at).total_seconds()
            if age_seconds < self._config.update_interval:
                return False

        # Cache is stale or empty — attempt refresh
        try:
            perform_refresh(
                self._config,
                self._cache_db,
                self._trust_anchor,
                force=True,
                cancel=None,
            )
            return False
        except FeedsNetworkError as exc:
            logger.warning("feeds: inline refresh failed: %s", exc.message)
            return True


def derive_cve_query(
    record: object,
    image: object,
) -> CVELookupQuery:
    """Derive a CVELookupQuery from a ClassificationRecord and FirmwareImage.

    Accepts duck-typed objects to avoid a hard import cycle into loki.models.
    Expects record.vendor_axis.label, record.type_axis.label, and
    image.firmware_version.
    """
    vendor_axis = getattr(record, "vendor_axis", None)
    type_axis = getattr(record, "type_axis", None)
    firmware_version = getattr(image, "firmware_version", None)

    if vendor_axis is None or not hasattr(vendor_axis, "label"):
        raise FeedsConfigError("record must have vendor_axis.label")
    if type_axis is None or not hasattr(type_axis, "label"):
        raise FeedsConfigError("record must have type_axis.label")
    if not firmware_version:
        raise FeedsConfigError("image.firmware_version must be non-empty")

    vendor = str(vendor_axis.label).lower()
    model_name = getattr(image, "model", None) or ""
    product = (
        f"{type_axis.label}_{model_name}".strip("_").lower()
        if model_name
        else str(type_axis.label).lower()
    )

    return CVELookupQuery(vendor=vendor, product=product, version=str(firmware_version))


def derive_implant_query(component: object) -> ImplantRuleLookupQuery:
    """Derive an ImplantRuleLookupQuery from an ExtractedComponent.

    Accepts a duck-typed object to avoid a hard import cycle.
    Expects component.raw_hash and optionally component.guid.
    """
    raw_hash = getattr(component, "raw_hash", None)
    if not raw_hash:
        raise FeedsConfigError("component.raw_hash must be non-empty")

    guid = getattr(component, "guid", None)
    return ImplantRuleLookupQuery(content_hash=str(raw_hash), firmware_guid=guid)
