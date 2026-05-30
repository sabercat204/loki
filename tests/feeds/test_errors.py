"""Tests for loki.feeds.errors — typed exception hierarchy."""

from __future__ import annotations

import pytest

from loki.feeds import (
    FeedsCacheError,
    FeedsConfigError,
    FeedsError,
    FeedsNetworkError,
    FeedsRefreshError,
    FeedsSignatureError,
)


class TestFeedsError:
    """Root exception tests."""

    def test_construction(self) -> None:
        err = FeedsError("something went wrong")
        assert err.message == "something went wrong"
        assert str(err) == "something went wrong"

    def test_is_exception(self) -> None:
        assert issubclass(FeedsError, Exception)

    def test_raise_and_catch(self) -> None:
        with pytest.raises(FeedsError):
            raise FeedsError("test")


class TestFeedsConfigError:
    """Config error subclass tests."""

    def test_is_subclass_of_feeds_error(self) -> None:
        assert issubclass(FeedsConfigError, FeedsError)

    def test_construction(self) -> None:
        err = FeedsConfigError("bad config")
        assert err.message == "bad config"

    def test_catch_as_feeds_error(self) -> None:
        with pytest.raises(FeedsError):
            raise FeedsConfigError("invalid url")


class TestFeedsSignatureError:
    """Signature error subclass tests."""

    def test_is_subclass_of_feeds_error(self) -> None:
        assert issubclass(FeedsSignatureError, FeedsError)

    def test_construction(self) -> None:
        err = FeedsSignatureError("hash mismatch")
        assert err.message == "hash mismatch"

    def test_catch_as_feeds_error(self) -> None:
        with pytest.raises(FeedsError):
            raise FeedsSignatureError("invalid signature")


class TestFeedsNetworkError:
    """Network error subclass tests."""

    def test_is_subclass_of_feeds_error(self) -> None:
        assert issubclass(FeedsNetworkError, FeedsError)

    def test_construction(self) -> None:
        err = FeedsNetworkError("connection refused")
        assert err.message == "connection refused"

    def test_catch_as_feeds_error(self) -> None:
        with pytest.raises(FeedsError):
            raise FeedsNetworkError("timeout")


class TestFeedsCacheError:
    """Cache error subclass tests."""

    def test_is_subclass_of_feeds_error(self) -> None:
        assert issubclass(FeedsCacheError, FeedsError)

    def test_construction_default(self) -> None:
        err = FeedsCacheError("write failure")
        assert err.message == "write failure"
        assert err.partial_download is False

    def test_construction_partial_download(self) -> None:
        err = FeedsCacheError("incomplete bundle", partial_download=True)
        assert err.message == "incomplete bundle"
        assert err.partial_download is True

    def test_catch_as_feeds_error(self) -> None:
        with pytest.raises(FeedsError):
            raise FeedsCacheError("cache failure")

    def test_partial_download_attribute(self) -> None:
        err_partial = FeedsCacheError("partial", partial_download=True)
        err_write = FeedsCacheError("write", partial_download=False)
        assert err_partial.partial_download is True
        assert err_write.partial_download is False


class TestFeedsRefreshError:
    """Refresh error subclass tests."""

    def test_is_subclass_of_feeds_error(self) -> None:
        assert issubclass(FeedsRefreshError, FeedsError)

    def test_construction(self) -> None:
        err = FeedsRefreshError("general failure")
        assert err.message == "general failure"

    def test_catch_as_feeds_error(self) -> None:
        with pytest.raises(FeedsError):
            raise FeedsRefreshError("refresh failed")


class TestHierarchyRelationships:
    """Cross-cutting subclass relationship tests."""

    def test_all_subclasses_derive_from_feeds_error(self) -> None:
        subclasses = [
            FeedsConfigError,
            FeedsSignatureError,
            FeedsNetworkError,
            FeedsCacheError,
            FeedsRefreshError,
        ]
        for cls in subclasses:
            assert issubclass(cls, FeedsError)
            assert issubclass(cls, Exception)

    def test_subclasses_are_distinct(self) -> None:
        subclasses = [
            FeedsConfigError,
            FeedsSignatureError,
            FeedsNetworkError,
            FeedsCacheError,
            FeedsRefreshError,
        ]
        for i, cls_a in enumerate(subclasses):
            for cls_b in subclasses[i + 1 :]:
                assert not issubclass(cls_a, cls_b)
                assert not issubclass(cls_b, cls_a)
