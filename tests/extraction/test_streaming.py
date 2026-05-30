"""Tests for the streaming hash and slice helpers (task 5).

Covers full-file hash, slice hash, peek-window sizing, and the
chunked-memory invariant from R8.2 / R8.3.
"""

from __future__ import annotations

import hashlib
import tracemalloc
from pathlib import Path

import pytest

from loki.extraction.streaming import (
    CHUNK_SIZE,
    PEEK_SIZE,
    StreamingHasher,
    streaming_sha256_slice,
)


def _write_blob(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    return path


def test_streaming_hasher_matches_hashlib_on_small_file(tmp_path: Path) -> None:
    """Full-file hash matches ``hashlib.sha256(file.read_bytes())``."""
    payload = b"hello loki" * 1024
    f = _write_blob(tmp_path / "small.rom", payload)

    file_hash, size, peek = StreamingHasher(f).hash_file()

    assert file_hash == hashlib.sha256(payload).hexdigest()
    assert size == len(payload)
    assert peek == payload  # smaller than PEEK_SIZE → peek is the entire file


def test_streaming_hasher_peek_caps_at_peek_size(tmp_path: Path) -> None:
    """``peek_bytes`` is at most ``PEEK_SIZE`` even on larger files."""
    payload = b"\x42" * (PEEK_SIZE + 4096)
    f = _write_blob(tmp_path / "big.rom", payload)

    _, size, peek = StreamingHasher(f).hash_file()

    assert size == len(payload)
    assert len(peek) == PEEK_SIZE
    assert peek == payload[:PEEK_SIZE]


def test_streaming_hasher_handles_multi_chunk_file(tmp_path: Path) -> None:
    """File spanning multiple ``CHUNK_SIZE`` reads still hashes correctly."""
    # 4 MiB + a stub so we don't land exactly on a chunk boundary.
    payload = (b"abc" * (CHUNK_SIZE // 3) * 4) + b"tail"
    f = _write_blob(tmp_path / "multi.rom", payload)

    file_hash, size, peek = StreamingHasher(f).hash_file()

    assert file_hash == hashlib.sha256(payload).hexdigest()
    assert size == len(payload)
    assert peek == payload[:PEEK_SIZE]


def test_streaming_hasher_keeps_peak_memory_bounded(tmp_path: Path) -> None:
    """Hashing a 4 MiB file allocates < 4 MiB of new resident memory.

    R8.2 says the hash must read in 1 MiB chunks rather than slurping
    the whole file. ``tracemalloc`` snapshots the diff so a regression
    that re-introduces ``f.read()`` on the full file fails this test.
    """

    payload = b"\x00" * (4 * CHUNK_SIZE)
    f = _write_blob(tmp_path / "memcheck.rom", payload)

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    StreamingHasher(f).hash_file()
    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    diff = snapshot_after.compare_to(snapshot_before, "filename")
    new_bytes = sum(stat.size_diff for stat in diff if stat.size_diff > 0)

    assert new_bytes < 4 * CHUNK_SIZE, (
        f"hash_file allocated {new_bytes} bytes; expected < {4 * CHUNK_SIZE}"
    )


# ---------------------------------------------------------------------
# streaming_sha256_slice
# ---------------------------------------------------------------------


def test_streaming_slice_matches_hashlib(tmp_path: Path) -> None:
    """Slice hash matches ``hashlib.sha256(file.read_bytes()[off:off+sz])``."""
    payload = bytes(range(256)) * 1024  # 256 KiB
    f = _write_blob(tmp_path / "slice.rom", payload)

    offset = 100
    size = 4096
    expected = hashlib.sha256(payload[offset : offset + size]).hexdigest()

    actual = streaming_sha256_slice(f, offset, size)

    assert actual == expected


def test_streaming_slice_at_zero_offset(tmp_path: Path) -> None:
    payload = b"loki" * 1024
    f = _write_blob(tmp_path / "zero.rom", payload)

    expected = hashlib.sha256(payload[:128]).hexdigest()
    assert streaming_sha256_slice(f, 0, 128) == expected


def test_streaming_slice_rejects_negative_offset(tmp_path: Path) -> None:
    f = _write_blob(tmp_path / "neg.rom", b"x")
    with pytest.raises(ValueError, match=r"offset must be >= 0"):
        streaming_sha256_slice(f, -1, 1)


def test_streaming_slice_rejects_zero_size(tmp_path: Path) -> None:
    f = _write_blob(tmp_path / "zero-size.rom", b"x")
    with pytest.raises(ValueError, match=r"size must be > 0"):
        streaming_sha256_slice(f, 0, 0)


def test_streaming_slice_raises_eof_when_truncated(tmp_path: Path) -> None:
    """Reading past EOF surfaces a typed ``EOFError`` rather than silent truncation."""
    f = _write_blob(tmp_path / "truncated.rom", b"abc")
    with pytest.raises(EOFError):
        streaming_sha256_slice(f, 1, 100)
