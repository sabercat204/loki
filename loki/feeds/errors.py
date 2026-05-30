"""Typed exception hierarchy for the Feeds subsystem."""

__all__: list[str] = [
    "FeedsCacheError",
    "FeedsConfigError",
    "FeedsError",
    "FeedsNetworkError",
    "FeedsRefreshError",
    "FeedsSignatureError",
]


class FeedsError(Exception):
    """Root exception for the Feeds subsystem."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class FeedsConfigError(FeedsError):
    """Invalid configuration (exit code 2)."""


class FeedsSignatureError(FeedsError):
    """Trust-anchor validation failure (exit code 3). Security event."""


class FeedsNetworkError(FeedsError):
    """Network/server failure (exit code 6 on explicit refresh)."""


class FeedsCacheError(FeedsError):
    """Partial download or cache write failure (exit code 4 or 5)."""

    def __init__(self, message: str, *, partial_download: bool = False) -> None:
        self.partial_download = partial_download
        super().__init__(message)


class FeedsRefreshError(FeedsError):
    """General refresh failure not covered by the above."""
