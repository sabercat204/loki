"""CLI tests for ``loki feeds refresh`` and ``loki feeds status`` (tasks 13-14).

Uses in-process invocation via ``loki.cli.main(["feeds", ...])`` with
``capsys`` capture and monkeypatched dependencies. The SIGINT
cancellation test uses subprocess for true signal delivery.

Exit-code taxonomy per HARDEN G4-A (R11.7):
  0   - success
  2   - config_error (missing --config, invalid config file)
  3   - signature_error (FeedsSignatureError)
  4   - partial_download (FeedsCacheError with partial_download=True)
  5   - cache_write_error (FeedsCacheError with partial_download=False)
  6   - network_error (FeedsNetworkError)
  130 - cancelled (SIGINT)
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import textwrap
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from loki.cli import main as cli_main
from loki.feeds.errors import (
    FeedsCacheError,
    FeedsConfigError,
    FeedsNetworkError,
    FeedsSignatureError,
)
from loki.feeds.models import RefreshResult, RefreshStatus
from loki.feeds.version import FEEDS_VERSION

# -- Fixtures ---------------------------------------------------------------


def _loki_config_dict(tmp_path: Path) -> dict[str, object]:
    """Build a minimal valid LokiConfig dict with feeds pointing at tmp_path."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(exist_ok=True)
    return {
        "general": {
            "default_output_format": "HUMAN",
            "color": "AUTO",
            "verbosity": 1,
            "log_level": "INFO",
        },
        "extraction": {
            "default_output_dir": str(tmp_path / "extract"),
            "max_component_size": 1000,
            "timeout_per_component": 60,
        },
        "classification": {
            "taxonomy_version": "1.0.0",
            "confidence_threshold": 0.6,
            "rules_path": str(tmp_path / "rules"),
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
        "baseline": {
            "storage_path": str(tmp_path / "baselines"),
            "auto_match": True,
        },
        "feeds": {
            "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "update_interval": 3600,
            "cache_path": str(cache_dir),
            "implant_rules_path": str(tmp_path / "implants"),
        },
        "fleet": {
            "default_severity_threshold": "MEDIUM",
            "storage_path": str(tmp_path / "fleet"),
        },
    }


@pytest.fixture
def config_yaml(tmp_path: Path) -> Path:
    """Write a valid loki config YAML and return its path."""
    cfg_path = tmp_path / "loki.yaml"
    cfg_path.write_text(
        yaml.safe_dump(_loki_config_dict(tmp_path)),
        encoding="utf-8",
    )
    return cfg_path


@pytest.fixture
def capture_feeds_run(
    capsys: pytest.CaptureFixture[str],
) -> Callable[[Sequence[str]], tuple[int, str, str]]:
    """Run ``loki.cli.main`` and return (exit_code, stdout, stderr)."""

    def _run(argv: Sequence[str]) -> tuple[int, str, str]:
        try:
            exit_code = int(cli_main(list(argv)))
        except SystemExit as exc:
            code = exc.code
            if code is None:
                exit_code = 0
            elif isinstance(code, int):
                exit_code = code
            else:
                exit_code = 1
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return _run


def _make_success_result() -> RefreshResult:
    """Build a synthetic RefreshResult for monkeypatching."""
    return RefreshResult(
        status=RefreshStatus.SUCCESS,
        cves_imported=42,
        bytes_fetched=1024,
        duration_seconds=1.2345,
        last_refresh_at=datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC),
        feeds_version=FEEDS_VERSION,
        diagnostics=[],
    )


def _make_cancelled_result() -> RefreshResult:
    """Build a CANCELLED RefreshResult for monkeypatching."""
    return RefreshResult(
        status=RefreshStatus.CANCELLED,
        cves_imported=0,
        bytes_fetched=0,
        duration_seconds=0.5,
        last_refresh_at=None,
        feeds_version=FEEDS_VERSION,
        diagnostics=["cancelled at: pre-connection"],
    )


# -- Task 13: loki feeds refresh tests -------------------------------------


class TestFeedsRefreshHelp:
    """R11.1: ``--help`` works without config."""

    def test_help_exits_zero(
        self,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        exit_code, stdout, _stderr = capture_feeds_run(["feeds", "refresh", "--help"])
        assert exit_code == 0
        assert "Fetch the latest NVD bundle" in stdout


class TestFeedsRefreshMissingConfig:
    """Missing --config returns exit 2."""

    def test_no_config_flag_exits_two(
        self,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        exit_code, _stdout, stderr = capture_feeds_run(["feeds", "refresh"])
        assert exit_code == 2
        assert "--config is required" in stderr

    def test_nonexistent_config_exits_two(
        self,
        tmp_path: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        exit_code, _stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(tmp_path / "nope.yaml")]
        )
        assert exit_code == 2
        assert "configuration error" in stderr


class TestFeedsRefreshSuccessPath:
    """Success path: stdout JSON parsed, stderr summary, exit 0."""

    def test_success_emits_json_and_summary(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.return_value = _make_success_result()

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 0
        obj = json.loads(stdout)
        assert obj["status"] == "SUCCESS"
        assert obj["cves_imported"] == 42
        assert obj["bytes_fetched"] == 1024
        assert obj["feeds_version"] == FEEDS_VERSION
        assert "feeds refresh: SUCCESS" in stderr
        assert "42 CVEs" in stderr

    def test_force_flag_accepted(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--force`` flag is passed through to registry.refresh."""
        mock_registry = MagicMock()
        mock_registry.refresh.return_value = _make_success_result()

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, _stdout, _stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml), "--force"]
        )

        assert exit_code == 0
        call_kwargs = mock_registry.refresh.call_args[1]
        assert call_kwargs["force"] is True


class TestFeedsRefreshSummaryOnly:
    """``--summary-only``: no stdout, stderr summary present, exit 0."""

    def test_summary_only_suppresses_stdout(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.return_value = _make_success_result()

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml), "--summary-only"]
        )

        assert exit_code == 0
        assert stdout == ""
        assert "feeds refresh: SUCCESS" in stderr


class TestFeedsRefreshErrorExitCodes:
    """Each error maps to the correct exit code per HARDEN G4-A."""

    def test_network_failure_exits_six(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.side_effect = FeedsNetworkError("connection refused")

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, _stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 6
        assert "network error" in stderr

    def test_signature_failure_exits_three(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.side_effect = FeedsSignatureError("hash mismatch")

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, _stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 3
        assert "signature error" in stderr

    def test_partial_download_exits_four(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.side_effect = FeedsCacheError(
            "incomplete data", partial_download=True
        )

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, _stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 4
        assert "partial download" in stderr

    def test_cache_write_failure_exits_five(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.side_effect = FeedsCacheError("disk full", partial_download=False)

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, _stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 5
        assert "cache write error" in stderr

    def test_config_error_from_registry_exits_two(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _fake_from_config(feeds_config: object) -> object:
            raise FeedsConfigError("bad nvd_url")

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, _stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 2
        assert "configuration error" in stderr


class TestFeedsRefreshCancelledPath:
    """Cancelled refresh returns exit 130 and emits summary."""

    def test_cancelled_exits_130(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_registry = MagicMock()
        mock_registry.refresh.return_value = _make_cancelled_result()

        def _fake_from_config(feeds_config: object) -> object:
            return mock_registry

        monkeypatch.setattr("loki.feeds.registry.FeedRegistry.from_config", _fake_from_config)

        exit_code, stdout, stderr = capture_feeds_run(
            ["feeds", "refresh", "--config", str(config_yaml)]
        )

        assert exit_code == 130
        obj = json.loads(stdout)
        assert obj["status"] == "CANCELLED"
        assert "feeds refresh: CANCELLED" in stderr


class TestFeedsRefreshSIGINT:
    """True SIGINT delivery via subprocess produces exit 130."""

    @pytest.mark.skipif(sys.platform == "win32", reason="SIGINT not reliable on Windows")
    def test_sigint_subprocess(self, config_yaml: Path) -> None:
        """Deliver SIGINT to a subprocess running feeds refresh."""
        script = textwrap.dedent(f"""\
            import sys
            import os
            import signal
            import threading

            # Monkey-patch perform_refresh to block until SIGINT
            import loki.feeds.refresh as _refresh_mod

            _original = _refresh_mod.perform_refresh

            def _blocking_refresh(config, cache_db, trust_anchor, *, force=False, cancel=None):
                # Signal parent we're ready
                sys.stderr.write("READY\\n")
                sys.stderr.flush()
                # Wait for cancel to fire
                import time
                for _ in range(100):
                    if cancel is not None and cancel():
                        from loki.feeds.models import RefreshResult, RefreshStatus
                        from loki.feeds.version import FEEDS_VERSION
                        return RefreshResult(
                            status=RefreshStatus.CANCELLED,
                            cves_imported=0,
                            bytes_fetched=0,
                            duration_seconds=0.0,
                            last_refresh_at=None,
                            feeds_version=FEEDS_VERSION,
                            diagnostics=["cancelled at: pre-connection"],
                        )
                    time.sleep(0.05)
                raise RuntimeError("cancel never fired")

            _refresh_mod.perform_refresh = _blocking_refresh

            # Also patch FeedRegistry.from_config to bypass network
            from unittest.mock import MagicMock
            import loki.feeds.registry as _reg_mod

            _original_from_config = _reg_mod.FeedRegistry.from_config

            class FakeRegistry:
                def refresh(self, *, force=False, cancel=None):
                    return _blocking_refresh(None, None, None, force=force, cancel=cancel)

            _reg_mod.FeedRegistry.from_config = classmethod(lambda cls, cfg: FakeRegistry())

            from loki.cli import main
            sys.exit(main(["feeds", "refresh", "--config", "{config_yaml}"]))
        """)

        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            # Wait for the "READY" signal
            assert proc.stderr is not None
            ready_line = proc.stderr.readline()
            assert b"READY" in ready_line

            # Deliver SIGINT
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=10)

            assert proc.returncode == 130
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()


# -- Task 14: loki feeds status tests --------------------------------------


class TestFeedsStatusHelp:
    """``loki feeds status --help`` exits 0."""

    def test_help_exits_zero(
        self,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        exit_code, stdout, _stderr = capture_feeds_run(["feeds", "status", "--help"])
        assert exit_code == 0
        assert "Show last refresh time" in stdout


class TestFeedsStatusMissingConfig:
    """Missing --config returns exit 2."""

    def test_no_config_exits_two(
        self,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        exit_code, _stdout, stderr = capture_feeds_run(["feeds", "status"])
        assert exit_code == 2
        assert "--config is required" in stderr


class TestFeedsStatusNoDatabase:
    """Status against an empty cache dir reports 'not initialized'."""

    def test_no_db_reports_not_initialized(
        self,
        config_yaml: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        exit_code, stdout, _stderr = capture_feeds_run(
            ["feeds", "status", "--config", str(config_yaml)]
        )
        assert exit_code == 0
        assert "not initialized" in stdout


class TestFeedsStatusWithDatabase:
    """Status against a populated cache reports metadata."""

    def test_reports_metadata(
        self,
        tmp_path: Path,
        capture_feeds_run: Callable[[Sequence[str]], tuple[int, str, str]],
    ) -> None:
        from loki.feeds.cache import CacheDB, CacheMetadata

        cfg_dict = _loki_config_dict(tmp_path)
        cfg_path = tmp_path / "loki.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg_dict), encoding="utf-8")

        cache_dir = Path(str(cfg_dict["feeds"]["cache_path"]))  # type: ignore[index]
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
        cache_db.close()

        exit_code, stdout, _stderr = capture_feeds_run(
            ["feeds", "status", "--config", str(cfg_path)]
        )

        assert exit_code == 0
        assert "Feeds version:" in stdout
        assert "Last refresh:" in stdout
        assert "CVE records:" in stdout
        assert "1" in stdout  # 1 CVE record
