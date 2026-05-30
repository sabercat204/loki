"""Feeds subsystem for the LOKI firmware analysis platform.

Provides vulnerability feed ingestion (NVD CVE data) and implant-rule
lookup surfaces consumed by the analysis engine. The public API is
exposed through ``FeedRegistry`` as the library entry point, with typed
result models and a five-class exception hierarchy.
"""

from loki.feeds.errors import (
    FeedsCacheError,
    FeedsConfigError,
    FeedsError,
    FeedsNetworkError,
    FeedsRefreshError,
    FeedsSignatureError,
)
from loki.feeds.models import (
    CancellationToken,
    CVELookupQuery,
    CVELookupResult,
    CVEMatch,
    ImplantRuleLookupQuery,
    ImplantRuleLookupResult,
    ImplantRuleMatch,
    RefreshResult,
    RefreshStatus,
)
from loki.feeds.registry import FeedRegistry
from loki.feeds.version import FEEDS_VERSION

__all__: list[str] = [
    "FEEDS_VERSION",
    "CVELookupQuery",
    "CVELookupResult",
    "CVEMatch",
    "CancellationToken",
    "FeedRegistry",
    "FeedsCacheError",
    "FeedsConfigError",
    "FeedsError",
    "FeedsNetworkError",
    "FeedsRefreshError",
    "FeedsSignatureError",
    "ImplantRuleLookupQuery",
    "ImplantRuleLookupResult",
    "ImplantRuleMatch",
    "RefreshResult",
    "RefreshStatus",
]
