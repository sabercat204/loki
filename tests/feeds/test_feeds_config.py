"""Tests for FeedsConfig.trust_anchor_path field extension."""

from __future__ import annotations

from pathlib import Path

import yaml

from loki.models import FeedsConfig, LokiConfig


class TestFeedsConfigTrustAnchorPath:
    """Verify trust_anchor_path field on FeedsConfig."""

    def test_defaults_to_none(self) -> None:
        cfg = FeedsConfig(
            nvd_url="https://example.com",
            update_interval=3600,
            cache_path="/tmp/cache",
            implant_rules_path="/tmp/rules",
        )
        assert cfg.trust_anchor_path is None

    def test_accepts_string_value(self) -> None:
        cfg = FeedsConfig(
            nvd_url="https://example.com",
            update_interval=3600,
            cache_path="/tmp/cache",
            implant_rules_path="/tmp/rules",
            trust_anchor_path="/etc/loki/trust.pem",
        )
        assert cfg.trust_anchor_path == "/etc/loki/trust.pem"

    def test_accepts_none_explicitly(self) -> None:
        cfg = FeedsConfig(
            nvd_url="https://example.com",
            update_interval=3600,
            cache_path="/tmp/cache",
            implant_rules_path="/tmp/rules",
            trust_anchor_path=None,
        )
        assert cfg.trust_anchor_path is None

    def test_yaml_round_trip_without_field(self, tmp_path: Path) -> None:
        """YAML config omitting trust_anchor_path loads with None default."""
        cfg_path = tmp_path / "loki.yaml"
        cfg_path.write_text(
            yaml.safe_dump(
                {
                    "general": {
                        "default_output_format": "HUMAN",
                        "color": "AUTO",
                        "verbosity": 1,
                        "log_level": "INFO",
                    },
                    "extraction": {
                        "default_output_dir": "/tmp/x",
                        "max_component_size": 1000,
                        "timeout_per_component": 60,
                    },
                    "classification": {
                        "taxonomy_version": "1.0.0",
                        "confidence_threshold": 0.6,
                        "rules_path": "/tmp/rules",
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
                        "storage_path": "/tmp/baselines",
                        "auto_match": True,
                    },
                    "feeds": {
                        "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        "update_interval": 3600,
                        "cache_path": "/tmp/cache",
                        "implant_rules_path": "/tmp/implants",
                    },
                    "fleet": {
                        "default_severity_threshold": "MEDIUM",
                        "storage_path": "/tmp/fleet",
                    },
                }
            )
        )
        cfg = LokiConfig.from_yaml(cfg_path)
        assert cfg.feeds.trust_anchor_path is None

    def test_yaml_round_trip_with_field(self, tmp_path: Path) -> None:
        """YAML config including trust_anchor_path loads correctly."""
        cfg_path = tmp_path / "loki.yaml"
        cfg_path.write_text(
            yaml.safe_dump(
                {
                    "general": {
                        "default_output_format": "HUMAN",
                        "color": "AUTO",
                        "verbosity": 1,
                        "log_level": "INFO",
                    },
                    "extraction": {
                        "default_output_dir": "/tmp/x",
                        "max_component_size": 1000,
                        "timeout_per_component": 60,
                    },
                    "classification": {
                        "taxonomy_version": "1.0.0",
                        "confidence_threshold": 0.6,
                        "rules_path": "/tmp/rules",
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
                        "storage_path": "/tmp/baselines",
                        "auto_match": True,
                    },
                    "feeds": {
                        "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        "update_interval": 3600,
                        "cache_path": "/tmp/cache",
                        "implant_rules_path": "/tmp/implants",
                        "trust_anchor_path": "/etc/loki/custom_trust.pem",
                    },
                    "fleet": {
                        "default_severity_threshold": "MEDIUM",
                        "storage_path": "/tmp/fleet",
                    },
                }
            )
        )
        cfg = LokiConfig.from_yaml(cfg_path)
        assert cfg.feeds.trust_anchor_path == "/etc/loki/custom_trust.pem"
