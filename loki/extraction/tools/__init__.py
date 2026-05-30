"""Tool wrapper boundary.

Every third-party tool used by ``loki.extraction`` (the
``uefi_firmware`` Python package, UEFITool, chipsec) is accessed
through a ``ToolWrapper`` defined in this subpackage. No other module
in ``loki.extraction`` imports ``subprocess``, ``shutil.which``,
``uefi_firmware``, or ``chipsec`` directly.

Wrapper status in v1:

- :class:`UefiFirmwareWrapper` — required. Drives the section walker
  for compressed-section decompression (R3.1, R5.8). Decompression
  helpers ``decompress_tiano`` / ``decompress_lzma`` are wired into
  :func:`loki.extraction.extractors.uefi_volume.walk_ffs_files`.
- :class:`UefitoolWrapper`, :class:`ChipsecWrapper` — optional. v1
  probes both for availability (R4.4) so
  :attr:`loki.extraction.ExtractionResult.tools_available` reflects
  reality, but no v1 extractor routes work through either binary.
  Future extractors that need ``UEFIExtract`` deeper-section
  unrolling or ``chipsec_util`` SPI/config-space decoding will
  consume these wrappers via
  :meth:`loki.extraction.tools.base.SubprocessToolWrapper.run_subprocess`.
"""

from loki.extraction.tools.chipsec import ChipsecWrapper
from loki.extraction.tools.uefi_firmware import UefiFirmwareWrapper
from loki.extraction.tools.uefitool import UefitoolWrapper

__all__ = ["ChipsecWrapper", "UefiFirmwareWrapper", "UefitoolWrapper"]
