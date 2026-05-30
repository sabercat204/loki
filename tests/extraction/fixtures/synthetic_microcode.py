"""Synthetic Intel CPU microcode update binary builder.

Produces a file containing **two** concatenated microcode update
blobs so the extractor's multi-blob walking logic gets exercised.

Layout per blob (Intel SDM Vol. 3A §9.11.1 — "Microcode Update Field
Definitions"):

  0x00  uint32  header_version    (always 1)
  0x04  uint32  update_revision   (microcode revision)
  0x08  uint32  date              (YYYYMMDD in BCD)
  0x0C  uint32  processor_signature
  0x10  uint32  checksum          (not validated by the detector)
  0x14  uint32  loader_revision   (always 1)
  0x18  uint32  processor_flags
  0x1C  uint32  data_size
  0x20  uint32  total_size
  0x24  uint32  reserved (12 bytes)
"""

from __future__ import annotations

import struct
from pathlib import Path

__all__ = ["BLOB_SIZE", "MICROCODE_HEADER_LEN", "build"]


MICROCODE_HEADER_LEN: int = 48
BLOB_SIZE: int = 2048  # total payload + header

# Realistic-looking but synthetic CPUID + revision values.
_BLOB_SPECS: tuple[tuple[int, int], ...] = (
    (0x000506E3, 0x000000F0),  # Skylake-ish CPUID + arbitrary revision
    (0x000906EA, 0x000000F1),  # Coffee Lake-ish CPUID + arbitrary revision
)


def _build_blob(*, processor_signature: int, update_revision: int) -> bytes:
    """Return one valid microcode update blob of size :data:`BLOB_SIZE`."""

    blob = bytearray(BLOB_SIZE)
    struct.pack_into("<I", blob, 0x00, 1)  # header_version
    struct.pack_into("<I", blob, 0x04, update_revision)
    struct.pack_into("<I", blob, 0x08, 0x20240115)  # date in BCD
    struct.pack_into("<I", blob, 0x0C, processor_signature)
    struct.pack_into("<I", blob, 0x10, 0xDEADBEEF)  # checksum (not checked)
    struct.pack_into("<I", blob, 0x14, 1)  # loader_revision
    struct.pack_into("<I", blob, 0x18, 0x00000003)  # processor_flags
    struct.pack_into("<I", blob, 0x1C, BLOB_SIZE - MICROCODE_HEADER_LEN)  # data_size
    struct.pack_into("<I", blob, 0x20, BLOB_SIZE)  # total_size
    # Remaining 12 bytes of header are reserved (zero by default).
    # Payload is left as zeros — the extractor only inspects the header.
    return bytes(blob)


def build(directory: Path, *, filename: str = "microcode.bin") -> Path:
    """Write a synthetic two-blob microcode update file under ``directory``.

    Args:
        directory: Caller-provided directory; created if it doesn't
            exist.
        filename: Output basename. Override only when generating
            additional fixtures within the same directory.

    Returns:
        The absolute path to the freshly written binary.
    """

    directory.mkdir(parents=True, exist_ok=True)
    out = directory / filename
    payload = b"".join(
        _build_blob(processor_signature=cpuid, update_revision=rev) for cpuid, rev in _BLOB_SPECS
    )
    out.write_bytes(payload)
    return out
