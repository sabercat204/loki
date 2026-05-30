"""Result dataclasses for the Feeds subsystem.

Provides typed, frozen containers for CVE lookup results, implant-rule
lookup results, and refresh outcomes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

__all__: list[str] = [
    "CVELookupQuery",
    "CVELookupResult",
    "CVEMatch",
    "CancellationToken",
    "ImplantRuleLookupQuery",
    "ImplantRuleLookupResult",
    "ImplantRuleMatch",
    "RefreshResult",
    "RefreshStatus",
]

CancellationToken = Callable[[], bool]


class RefreshStatus(StrEnum):
    """Outcome status for a feed refresh operation."""

    SUCCESS = "SUCCESS"
    WARN_STALE = "WARN_STALE"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RefreshResult:
    """Outcome of a feed refresh operation."""

    status: RefreshStatus
    cves_imported: int
    bytes_fetched: int
    duration_seconds: float
    last_refresh_at: datetime | None
    feeds_version: str
    diagnostics: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CVEMatch:
    """A single CVE record matching a lookup query."""

    cve_id: str
    vendor: str
    product: str
    version: str
    published_date: datetime
    cvss_v3_score: float | None = None
    cvss_v3_severity: str | None = None


@dataclass(frozen=True)
class CVELookupResult:
    """Result container for a CVE lookup operation."""

    matches: list[CVEMatch] = field(default_factory=list)
    stale_warning: bool = False


@dataclass(frozen=True)
class CVELookupQuery:
    """Query parameters for a CVE lookup."""

    vendor: str
    product: str
    version: str


@dataclass(frozen=True)
class ImplantRuleMatch:
    """A single implant rule matching a lookup query."""

    rule_id: str
    ioc_field: str
    threat_family: str


@dataclass(frozen=True)
class ImplantRuleLookupResult:
    """Result container for an implant-rule lookup operation."""

    matches: list[ImplantRuleMatch] = field(default_factory=list)


@dataclass(frozen=True)
class ImplantRuleLookupQuery:
    """Query parameters for an implant-rule lookup."""

    content_hash: str
    firmware_guid: str | None = None
