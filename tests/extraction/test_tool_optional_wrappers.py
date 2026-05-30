"""Tests for the optional ``UEFIExtract`` and ``chipsec`` wrappers (task 10)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from loki.extraction.tools.base import ToolStatus
from loki.extraction.tools.chipsec import ChipsecWrapper
from loki.extraction.tools.uefitool import UefitoolWrapper

# ---------------------------------------------------------------------
# UefitoolWrapper
# ---------------------------------------------------------------------


def test_uefitool_metadata() -> None:
    assert UefitoolWrapper.name == "uefitool"
    assert UefitoolWrapper.required is False


def test_uefitool_probe_missing_when_not_on_path() -> None:
    with patch("loki.extraction.tools.uefitool.shutil.which", return_value=None):
        wrapper = UefitoolWrapper()
        assert wrapper.probe() is ToolStatus.MISSING
        assert wrapper.executable is None
        assert wrapper.version is None


def test_uefitool_probe_available_with_version() -> None:
    completed = subprocess.CompletedProcess(
        args=["UEFIExtract", "--help"],
        returncode=0,
        stdout=b"UEFIExtract 1.2.3\nusage: UEFIExtract <path>\n",
        stderr=b"",
    )
    with (
        patch(
            "loki.extraction.tools.uefitool.shutil.which",
            return_value="/usr/local/bin/UEFIExtract",
        ),
        patch("loki.extraction.tools.uefitool.subprocess.run", return_value=completed),
    ):
        wrapper = UefitoolWrapper()
        assert wrapper.probe() is ToolStatus.AVAILABLE
        assert wrapper.executable == "/usr/local/bin/UEFIExtract"
        assert wrapper.version == "UEFIExtract 1.2.3"


def test_uefitool_probe_degraded_on_help_timeout() -> None:
    timeout = subprocess.TimeoutExpired(cmd=["UEFIExtract"], timeout=5.0)
    with (
        patch(
            "loki.extraction.tools.uefitool.shutil.which",
            return_value="/usr/local/bin/UEFIExtract",
        ),
        patch("loki.extraction.tools.uefitool.subprocess.run", side_effect=timeout),
    ):
        wrapper = UefitoolWrapper()
        assert wrapper.probe() is ToolStatus.DEGRADED
        # Executable was found, but version couldn't be probed.
        assert wrapper.executable == "/usr/local/bin/UEFIExtract"
        assert wrapper.version is None


def test_uefitool_probe_degraded_on_oserror() -> None:
    """``OSError`` (e.g. permission denied) also degrades rather than crashes."""
    with (
        patch(
            "loki.extraction.tools.uefitool.shutil.which",
            return_value="/opt/UEFIExtract",
        ),
        patch(
            "loki.extraction.tools.uefitool.subprocess.run",
            side_effect=OSError("permission denied"),
        ),
    ):
        wrapper = UefitoolWrapper()
        assert wrapper.probe() is ToolStatus.DEGRADED


# ---------------------------------------------------------------------
# ChipsecWrapper
# ---------------------------------------------------------------------


def test_chipsec_metadata() -> None:
    assert ChipsecWrapper.name == "chipsec"
    assert ChipsecWrapper.required is False


def test_chipsec_probe_missing_when_not_on_path() -> None:
    with patch("loki.extraction.tools.chipsec.shutil.which", return_value=None):
        wrapper = ChipsecWrapper()
        assert wrapper.probe() is ToolStatus.MISSING


def test_chipsec_probe_available_with_version() -> None:
    completed = subprocess.CompletedProcess(
        args=["chipsec_util", "--version"],
        returncode=0,
        stdout=b"CHIPSEC 1.13.6\n",
        stderr=b"",
    )
    with (
        patch(
            "loki.extraction.tools.chipsec.shutil.which",
            return_value="/usr/local/bin/chipsec_util",
        ),
        patch("loki.extraction.tools.chipsec.subprocess.run", return_value=completed),
    ):
        wrapper = ChipsecWrapper()
        assert wrapper.probe() is ToolStatus.AVAILABLE
        assert wrapper.executable == "/usr/local/bin/chipsec_util"
        assert wrapper.version == "CHIPSEC 1.13.6"


def test_chipsec_probe_degraded_on_timeout() -> None:
    timeout = subprocess.TimeoutExpired(cmd=["chipsec_util"], timeout=5.0)
    with (
        patch(
            "loki.extraction.tools.chipsec.shutil.which",
            return_value="/opt/chipsec_util",
        ),
        patch("loki.extraction.tools.chipsec.subprocess.run", side_effect=timeout),
    ):
        wrapper = ChipsecWrapper()
        assert wrapper.probe() is ToolStatus.DEGRADED


def test_optional_wrappers_implement_protocol() -> None:
    """Both optional wrappers conform to the :class:`ToolWrapper` protocol."""
    from loki.extraction.tools.base import ToolWrapper

    assert isinstance(UefitoolWrapper(), ToolWrapper)
    assert isinstance(ChipsecWrapper(), ToolWrapper)
