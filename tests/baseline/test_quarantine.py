"""Tests for the QuarantineSet container (task 5)."""

from __future__ import annotations

from pathlib import Path

from loki.baseline.quarantine import QuarantineEntry, QuarantineSet


def _entry(name: str, reason: str = "test", raw: bytes | None = b"raw") -> QuarantineEntry:
    return QuarantineEntry(path=Path(f"/tmp/{name}"), reason=reason, raw=raw)


def test_empty_set_has_zero_length() -> None:
    qs = QuarantineSet()
    assert len(qs) == 0
    assert list(qs) == []
    assert bool(qs) is False


def test_add_appends_in_insertion_order() -> None:
    qs = QuarantineSet()
    qs.add(_entry("a.yaml"))
    qs.add(_entry("b.yaml"))
    qs.add(_entry("c.yaml"))
    paths = [e.path.name for e in qs]
    assert paths == ["a.yaml", "b.yaml", "c.yaml"]


def test_len_matches_count_of_entries() -> None:
    qs = QuarantineSet()
    for i in range(5):
        qs.add(_entry(f"{i}.yaml"))
    assert len(qs) == 5


def test_bool_is_true_when_non_empty() -> None:
    qs = QuarantineSet()
    assert bool(qs) is False
    qs.add(_entry("x.yaml"))
    assert bool(qs) is True


def test_entry_preserves_raw_bytes_verbatim() -> None:
    raw = b"\x00\xff\x42malformed: yaml: ::"
    entry = _entry("x.yaml", raw=raw)
    qs = QuarantineSet()
    qs.add(entry)
    [stored] = list(qs)
    assert stored.raw == raw


def test_entry_accepts_none_raw() -> None:
    """When the file couldn't be read at all, ``raw`` is ``None``."""
    entry = _entry("x.yaml", raw=None)
    assert entry.raw is None


def test_entry_is_frozen() -> None:
    """Entries are immutable so callers can't tamper with quarantine state."""
    import pytest as _pytest

    entry = _entry("x.yaml")
    with _pytest.raises((AttributeError, Exception)):
        entry.reason = "mutated"  # type: ignore[misc]


def test_repr_includes_count() -> None:
    qs = QuarantineSet()
    assert repr(qs) == "QuarantineSet(0 entries)"
    qs.add(_entry("x.yaml"))
    assert repr(qs) == "QuarantineSet(1 entries)"
