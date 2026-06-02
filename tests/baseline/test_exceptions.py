"""Tests for the baseline-persistence exception hierarchy (task 2)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from loki.baseline.errors import (
    BaselineAlreadyExistsError,
    BaselineConcurrentModificationError,
    BaselineNotFoundError,
    BaselineSerializationError,
    BaselineStorageUnwritableError,
    BaselineStoreError,
)


def test_inheritance_chain() -> None:
    """Every public exception inherits from ``BaselineStoreError``."""
    assert issubclass(BaselineConcurrentModificationError, BaselineStoreError)
    assert issubclass(BaselineAlreadyExistsError, BaselineStoreError)
    assert issubclass(BaselineSerializationError, BaselineStoreError)
    assert issubclass(BaselineStorageUnwritableError, BaselineStoreError)
    assert issubclass(BaselineNotFoundError, BaselineStoreError)
    assert issubclass(BaselineStoreError, Exception)


def test_concurrent_modification_carries_snapshots() -> None:
    path = Path("/tmp/x.yaml")
    err = BaselineConcurrentModificationError(
        path,
        recorded=(123_456_789, 4096),
        observed=(123_999_999, 4097),
    )
    assert err.path == path
    assert err.recorded == (123_456_789, 4096)
    assert err.observed == (123_999_999, 4097)
    text = str(err)
    # ``str(Path)`` uses native path separators; assert the platform-native
    # rendering rather than a hard-coded POSIX literal so the test passes
    # on Windows, macOS, and Linux alike.
    assert str(path) in text
    assert "(123456789, 4096)" in text
    assert "(123999999, 4097)" in text


def test_concurrent_modification_accepts_str_path() -> None:
    err = BaselineConcurrentModificationError(
        "/tmp/x.yaml",
        recorded=(0, 0),
        observed=(1, 1),
    )
    assert isinstance(err.path, Path)


def test_already_exists_carries_path() -> None:
    err = BaselineAlreadyExistsError("/tmp/x.yaml")
    assert err.path == Path("/tmp/x.yaml")
    assert str(Path("/tmp/x.yaml")) in str(err)


def test_serialization_error_carries_message_and_cause() -> None:
    underlying = ValueError("oops")
    err = BaselineSerializationError("validation failed", cause=underlying)
    assert err.message == "validation failed"
    assert err.__cause__ is underlying
    assert str(err) == "validation failed"


def test_serialization_error_cause_is_optional() -> None:
    err = BaselineSerializationError("size limit exceeded")
    assert err.__cause__ is None


def test_storage_unwritable_carries_path_and_errno() -> None:
    err = BaselineStorageUnwritableError("/tmp/baselines", errno=13)
    assert err.path == Path("/tmp/baselines")
    assert err.errno == 13
    text = str(err)
    assert str(Path("/tmp/baselines")) in text
    assert "errno=13" in text


def test_not_found_carries_baseline_id() -> None:
    bid = uuid.uuid4()
    err = BaselineNotFoundError(bid)
    assert err.baseline_id == bid
    assert err.path is None
    assert str(bid) in str(err)


def test_not_found_optionally_carries_path() -> None:
    bid = uuid.uuid4()
    err = BaselineNotFoundError(bid, path="/tmp/baselines/intel-x1-1.0.yaml")
    assert err.baseline_id == bid
    assert err.path == Path("/tmp/baselines/intel-x1-1.0.yaml")
    text = str(err)
    assert str(bid) in text
    assert str(Path("/tmp/baselines/intel-x1-1.0.yaml")) in text


def test_exceptions_can_be_raised_and_caught() -> None:
    """Smoke check that every class is raise-and-catch friendly."""
    with pytest.raises(BaselineStoreError):
        raise BaselineAlreadyExistsError("/tmp/x.yaml")
    with pytest.raises(BaselineStoreError):
        raise BaselineConcurrentModificationError("/tmp/x.yaml", (0, 0), (1, 1))
    with pytest.raises(BaselineStoreError):
        raise BaselineSerializationError("nope")
    with pytest.raises(BaselineStoreError):
        raise BaselineStorageUnwritableError("/tmp/x", errno=13)
    with pytest.raises(BaselineStoreError):
        raise BaselineNotFoundError(uuid.uuid4())
