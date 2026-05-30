"""Chunked SHA-256 hashing and slice helpers.

The pipeline must keep peak resident memory bounded even on
multi-hundred-megabyte inputs (R8.1, R8.2, R8.3). Every hash and
every component-byte read goes through these helpers so the rest of
the subsystem can stay agnostic about chunk sizes.

Two entry points:

- :class:`StreamingHasher` — used once per extraction run to compute
  ``FirmwareImage.file_hash``, the file size, and the leading 64 KiB
  ``peek`` window the format detector inspects (R2.1).
- :func:`streaming_sha256_slice` — used by ``ManifestBuilder`` when
  computing each ``ExtractedComponent.raw_hash`` so the carved bytes
  never need to be held in memory all at once.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

__all__ = [
    "StreamingHasher",
    "streaming_sha256_slice",
]

#: Bytes read per ``read()`` call. Sized for streaming I/O — keeping
#: peak memory close to a single chunk on multi-hundred-MB inputs
#: (R8.2).
CHUNK_SIZE: int = 1 << 20  # 1 MiB

#: Number of leading bytes returned by ``StreamingHasher.hash_file()``
#: as the format-detector ``peek`` window. Sized to fit the IFD,
#: capsule, FV, option-ROM, and microcode headers we look for in
#: ``loki.extraction.detection`` without re-reading the file (R2.1).
PEEK_SIZE: int = 1 << 16  # 64 KiB


class StreamingHasher:
    """Compute SHA-256 over a file in 1 MiB chunks.

    The same single read pass produces the leading ``peek_bytes``
    window, so format detection can run against the same bytes without
    a second open.
    """

    CHUNK_SIZE: int = CHUNK_SIZE
    PEEK_SIZE: int = PEEK_SIZE

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def hash_file(self) -> tuple[str, int, bytes]:
        """Return ``(file_hash_hex, file_size, peek_bytes)``.

        ``file_hash_hex`` is 64 lowercase hex characters (R1.7).
        ``file_size`` is the exact byte count read.
        ``peek_bytes`` is the first :data:`PEEK_SIZE` bytes (or the
        entire file if it's smaller than that).
        """

        digest = hashlib.sha256()
        peek = bytearray()
        size = 0
        with self._path.open("rb") as fh:
            while True:
                chunk = fh.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                if len(peek) < self.PEEK_SIZE:
                    needed = self.PEEK_SIZE - len(peek)
                    peek.extend(chunk[:needed])
        return digest.hexdigest(), size, bytes(peek)


def streaming_sha256_slice(path: Path, offset: int, size: int) -> str:
    """Return the lowercase SHA-256 hex digest of a byte slice.

    Implements the streaming-slice contract from R3.8 / R8.3. Reads
    only the requested ``[offset, offset + size)`` window in 1 MiB
    chunks; never loads the full file into memory.

    Args:
        path: Filesystem path to the source firmware binary.
        offset: Absolute byte offset to start hashing from.
            Must be ``>= 0``.
        size: Number of bytes to hash. Must be ``> 0``.

    Returns:
        64-character lowercase hex SHA-256 digest of the slice.

    Raises:
        ValueError: ``offset < 0`` or ``size <= 0``.
        OSError: I/O failure while reading.
        EOFError: The file ends before ``offset + size`` bytes have
            been read.
    """

    if offset < 0:
        raise ValueError(f"offset must be >= 0, got {offset}")
    if size <= 0:
        raise ValueError(f"size must be > 0, got {size}")

    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as fh:
        fh.seek(offset)
        while remaining > 0:
            to_read = min(CHUNK_SIZE, remaining)
            chunk = fh.read(to_read)
            if not chunk:
                raise EOFError(
                    f"reached end of {path} after {size - remaining} of "
                    f"{size} bytes (offset={offset})"
                )
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()
