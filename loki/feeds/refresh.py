"""Refresh logic — fetch, validate, and commit NVD feed data."""

from __future__ import annotations

import hashlib
import json
import logging
import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime
from urllib.parse import urlparse

from loki.feeds.cache import CacheDB, CacheMetadata
from loki.feeds.errors import FeedsCacheError, FeedsNetworkError
from loki.feeds.models import CancellationToken, RefreshResult, RefreshStatus
from loki.feeds.timing import Stopwatch
from loki.feeds.trust import TrustAnchor
from loki.feeds.version import FEEDS_VERSION
from loki.models.config import FeedsConfig

__all__ = ["perform_refresh"]

logger = logging.getLogger("loki.feeds")

_CHUNK_SIZE = 65536
_USER_AGENT = f"loki-feeds/{FEEDS_VERSION}"


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject cross-origin redirects."""

    def __init__(self, original_host: str) -> None:
        super().__init__()
        self._original_host = original_host

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urlparse(newurl)
        if parsed.hostname != self._original_host:
            raise FeedsNetworkError(
                f"Cross-origin redirect rejected: {self._original_host} -> {parsed.hostname}"
            )
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)  # type: ignore[arg-type]
        return new_req


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _fetch_url(
    url: str,
    ssl_context: ssl.SSLContext,
    cancel: CancellationToken | None,
) -> bytes:
    parsed = urlparse(url)
    original_host = parsed.hostname or ""

    redirect_handler = _SameHostRedirectHandler(original_host)
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
    opener = urllib.request.build_opener(redirect_handler, https_handler)

    request = urllib.request.Request(url)
    request.add_header("User-Agent", _USER_AGENT)

    try:
        response = opener.open(request)
    except urllib.error.URLError as exc:
        raise FeedsNetworkError(f"Network failure fetching {url}: {exc}") from exc

    content_length_header = response.headers.get("Content-Length")
    content_length: int | None = int(content_length_header) if content_length_header else None

    chunks: list[bytes] = []
    total_read = 0
    while True:
        if cancel is not None and cancel():
            return b""
        chunk = response.read(_CHUNK_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
        total_read += len(chunk)

    response.close()

    if content_length is not None and total_read < content_length:
        raise FeedsCacheError(
            f"Partial download: received {total_read} of {content_length} bytes",
            partial_download=True,
        )

    return b"".join(chunks)


def _parse_nvd_bundle(bundle_bytes: bytes) -> list[dict[str, object]]:
    """Parse NVD JSON 2.0 bundle into CVE row dicts."""
    try:
        data = json.loads(bundle_bytes)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FeedsCacheError(
            f"Failed to parse NVD JSON bundle: {exc}",
            partial_download=False,
        ) from exc

    vulnerabilities = data.get("vulnerabilities", [])
    rows: list[dict[str, object]] = []

    for vuln_entry in vulnerabilities:
        cve = vuln_entry.get("cve", {})
        cve_id = cve.get("id", "")
        published = cve.get("published", "")

        metrics = cve.get("metrics", {})
        cvss_v3_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        cvss_score: float | None = None
        cvss_severity: str | None = None
        if cvss_v3_data:
            primary = cvss_v3_data[0].get("cvssData", {})
            cvss_score = primary.get("baseScore")
            cvss_severity = primary.get("baseSeverity")

        configurations = cve.get("configurations", [])
        for config_node in configurations:
            for node in config_node.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 7:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5]
                        if vendor != "*" and product != "*" and version != "*":
                            rows.append(
                                {
                                    "cve_id": cve_id,
                                    "vendor": vendor,
                                    "product": product,
                                    "version": version,
                                    "published_date": published,
                                    "cvss_v3_score": cvss_score,
                                    "cvss_v3_severity": cvss_severity,
                                }
                            )

    return rows


def perform_refresh(
    config: FeedsConfig,
    cache_db: CacheDB,
    trust_anchor: TrustAnchor,
    *,
    force: bool = False,
    cancel: CancellationToken | None = None,
) -> RefreshResult:
    """Perform a feed refresh: fetch, validate, commit.

    Returns RefreshResult describing the outcome.
    Raises FeedsSignatureError, FeedsCacheError, or FeedsNetworkError on failure.
    """
    with Stopwatch() as sw:
        diagnostics: list[str] = []

        # Cooperative point: pre-connection (R9.1a)
        if cancel is not None and cancel():
            return _cancelled_result(sw, "pre-connection", diagnostics, cache_db)

        ssl_context = _build_ssl_context()

        # Fetch bundle
        bundle_url = config.nvd_url
        logger.debug("Fetching NVD bundle from %s", bundle_url)
        bundle_bytes = _fetch_url(bundle_url, ssl_context, cancel)

        # Check if cancelled during download
        if cancel is not None and cancel() and not bundle_bytes:
            return _cancelled_result(sw, "download-chunk", diagnostics, cache_db)
        if not bundle_bytes and cancel is not None:
            return _cancelled_result(sw, "download-chunk", diagnostics, cache_db)

        bytes_fetched = len(bundle_bytes)

        # Fetch verification artifact (sibling .sha256 URL)
        artifact_url = bundle_url + ".sha256"
        try:
            artifact_bytes = _fetch_url(artifact_url, ssl_context, None)
        except FeedsNetworkError as exc:
            raise FeedsNetworkError(
                f"Failed to fetch verification artifact: {exc.message}"
            ) from exc

        # Trust-anchor verification (R4.5)
        trust_anchor.verify_bundle(bundle_bytes, artifact_bytes)

        # Cooperative point: pre-write (R9.1c)
        if cancel is not None and cancel():
            return _cancelled_result(sw, "pre-write", diagnostics, cache_db)

        # Parse bundle
        cve_rows = _parse_nvd_bundle(bundle_bytes)

        # Build metadata
        now = datetime.now(UTC)
        metadata = CacheMetadata(
            last_refresh_at=now,
            bundle_content_hash=hashlib.sha256(bundle_bytes).hexdigest(),
            trust_anchor_identity=trust_anchor.identity,
            feed_format_version="2.0",
            feeds_writer_version=FEEDS_VERSION,
        )

        # Atomic commit with per-batch cancellation (R9.1d)
        cache_db.refresh_atomic(cve_rows, metadata, cancel)

        # Check if cancelled during write
        refreshed_meta = cache_db.get_metadata()
        if refreshed_meta is None or refreshed_meta.last_refresh_at != now:
            return _cancelled_result(sw, "per-cve-insert", diagnostics, cache_db)

    return RefreshResult(
        status=RefreshStatus.SUCCESS,
        cves_imported=len(cve_rows),
        bytes_fetched=bytes_fetched,
        duration_seconds=sw.duration_ms / 1000.0,
        last_refresh_at=now,
        feeds_version=FEEDS_VERSION,
        diagnostics=diagnostics,
    )


def _cancelled_result(
    sw: Stopwatch,
    stage: str,
    diagnostics: list[str],
    cache_db: CacheDB,
) -> RefreshResult:
    diagnostics.append(f"cancelled at: {stage}")
    prior_meta = cache_db.get_metadata()
    return RefreshResult(
        status=RefreshStatus.CANCELLED,
        cves_imported=0,
        bytes_fetched=0,
        duration_seconds=sw.duration_ms / 1000.0,
        last_refresh_at=prior_meta.last_refresh_at if prior_meta else None,
        feeds_version=FEEDS_VERSION,
        diagnostics=diagnostics,
    )
