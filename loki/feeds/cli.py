"""CLI surface for the Feeds subsystem (loki feeds refresh / status)."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import FrameType

__all__ = ["register_feeds_subcommand", "run_feeds_refresh", "run_feeds_status"]

_EXIT_CODES: dict[str, int] = {
    "success": 0,
    "config_error": 2,
    "signature_error": 3,
    "partial_download": 4,
    "cache_write_error": 5,
    "network_error": 6,
    "cancelled": 130,
}


def register_feeds_subcommand(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register 'feeds' subcommand group on the top-level loki dispatcher."""
    feeds_parser = sub.add_parser(
        "feeds",
        help="Manage vulnerability feed cache.",
        description="Subcommands for managing the NVD vulnerability feed cache.",
    )
    feeds_sub = feeds_parser.add_subparsers(
        dest="feeds_command",
        required=True,
        metavar="SUBCOMMAND",
    )

    refresh_parser = feeds_sub.add_parser(
        "refresh",
        help="Refresh the NVD feed cache.",
        description=(
            "Fetch the latest NVD bundle, validate against the trust anchor, "
            "and atomically replace the local cache. Emits a JSON status object "
            "to stdout and a summary line to stderr."
        ),
    )
    refresh_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to loki config YAML.",
    )
    refresh_parser.add_argument(
        "--force",
        action="store_true",
        help="Ignore cache-age check; refresh unconditionally.",
    )
    refresh_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress stdout JSON; emit only stderr summary.",
    )
    refresh_parser.set_defaults(handler=_handle_feeds_refresh)

    status_parser = feeds_sub.add_parser(
        "status",
        help="Display current cache status.",
        description="Show last refresh time, CVE count, cache size, and version info.",
    )
    status_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to loki config YAML.",
    )
    status_parser.set_defaults(handler=_handle_feeds_status)


def _handle_feeds_refresh(args: argparse.Namespace) -> int:
    return run_feeds_refresh(args)


def _handle_feeds_status(args: argparse.Namespace) -> int:
    return run_feeds_status(args)


def run_feeds_refresh(args: argparse.Namespace) -> int:
    """Execute loki feeds refresh and return the exit code."""
    from loki.feeds.errors import (
        FeedsCacheError,
        FeedsConfigError,
        FeedsNetworkError,
        FeedsSignatureError,
    )
    from loki.feeds.models import RefreshStatus
    from loki.feeds.registry import FeedRegistry
    from loki.models.config import LokiConfig

    # Load config
    config_path = getattr(args, "config", None)
    if config_path is None:
        print("loki feeds refresh: --config is required", file=sys.stderr)
        return _EXIT_CODES["config_error"]

    try:
        loki_config = LokiConfig.from_yaml(config_path)
    except Exception as exc:
        print(f"loki feeds refresh: configuration error: {exc}", file=sys.stderr)
        return _EXIT_CODES["config_error"]

    # Construct registry
    try:
        registry = FeedRegistry.from_config(loki_config.feeds)
    except FeedsConfigError as exc:
        print(f"loki feeds refresh: configuration error: {exc.message}", file=sys.stderr)
        return _EXIT_CODES["config_error"]

    # SIGINT handler
    cancel_event = threading.Event()

    def _sigint_handler(signum: int, frame: FrameType | None) -> None:
        cancel_event.set()

    prev_handler = signal.signal(signal.SIGINT, _sigint_handler)

    def _cancel_token() -> bool:
        return cancel_event.is_set()

    try:
        result = registry.refresh(
            force=getattr(args, "force", False),
            cancel=_cancel_token,
        )
    except FeedsSignatureError as exc:
        print(f"loki feeds refresh: signature error: {exc.message}", file=sys.stderr)
        return _EXIT_CODES["signature_error"]
    except FeedsCacheError as exc:
        if exc.partial_download:
            print(f"loki feeds refresh: partial download: {exc.message}", file=sys.stderr)
            return _EXIT_CODES["partial_download"]
        print(f"loki feeds refresh: cache write error: {exc.message}", file=sys.stderr)
        return _EXIT_CODES["cache_write_error"]
    except FeedsNetworkError as exc:
        print(f"loki feeds refresh: network error: {exc.message}", file=sys.stderr)
        return _EXIT_CODES["network_error"]
    finally:
        signal.signal(signal.SIGINT, prev_handler)

    # Stdout JSON
    if not getattr(args, "summary_only", False):
        status_obj = {
            "status": result.status.value,
            "cves_imported": result.cves_imported,
            "bytes_fetched": result.bytes_fetched,
            "duration_seconds": round(result.duration_seconds, 4),
            "last_refresh_at": result.last_refresh_at.isoformat()
            if result.last_refresh_at
            else None,
            "feeds_version": result.feeds_version,
            "diagnostics": result.diagnostics,
        }
        sys.stdout.write(json.dumps(status_obj, indent=2))
        sys.stdout.write("\n")

    # Stderr summary line (on SUCCESS and CANCELLED only)
    if result.status in (RefreshStatus.SUCCESS, RefreshStatus.CANCELLED):
        summary = (
            f"feeds refresh: {result.status.value}, "
            f"{result.cves_imported} CVEs, "
            f"{result.bytes_fetched} bytes, "
            f"duration={round(result.duration_seconds, 4)}s"
        )
        print(summary, file=sys.stderr)

    if result.status == RefreshStatus.CANCELLED:
        return _EXIT_CODES["cancelled"]
    return _EXIT_CODES["success"]


def run_feeds_status(args: argparse.Namespace) -> int:
    """Execute loki feeds status and return the exit code."""
    from pathlib import Path

    from loki.feeds.cache import CacheDB
    from loki.feeds.errors import FeedsConfigError
    from loki.feeds.version import FEEDS_VERSION
    from loki.models.config import LokiConfig

    config_path = getattr(args, "config", None)
    if config_path is None:
        print("loki feeds status: --config is required", file=sys.stderr)
        return _EXIT_CODES["config_error"]

    try:
        loki_config = LokiConfig.from_yaml(config_path)
    except Exception as exc:
        print(f"loki feeds status: configuration error: {exc}", file=sys.stderr)
        return _EXIT_CODES["config_error"]

    feeds_config = loki_config.feeds
    cache_dir = Path(feeds_config.cache_path)
    db_path = cache_dir / "feeds.db"

    if not db_path.exists():
        print("Cache: not initialized (no feeds.db found)")
        return 0

    try:
        cache_db = CacheDB(db_path)
    except FeedsConfigError as exc:
        print(f"loki feeds status: {exc.message}", file=sys.stderr)
        return _EXIT_CODES["config_error"]

    meta = cache_db.get_metadata()
    cache_size = db_path.stat().st_size

    cve_count_row = cache_db._conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()
    cve_count = cve_count_row[0] if cve_count_row else 0

    print(f"Feeds version:    {FEEDS_VERSION}")
    if meta:
        print(f"Last refresh:     {meta.last_refresh_at.isoformat()}")
        print(f"Writer version:   {meta.feeds_writer_version}")
        print(f"Format version:   {meta.feed_format_version}")
        print(f"Bundle hash:      {meta.bundle_content_hash[:16]}...")
    else:
        print("Last refresh:     never")
    print(f"CVE records:      {cve_count}")
    print(f"Cache size:       {cache_size} bytes")

    cache_db.close()
    return 0
