"""Typed exception hierarchy for the Fleet analysis subsystem."""

from __future__ import annotations

__all__: list[str] = ["FleetConfigError", "FleetError", "FleetInputError"]


class FleetError(Exception):
    """Root exception for the Fleet analysis subsystem."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class FleetConfigError(FleetError):
    """Configuration or fleet-membership error (empty fleet, missing config)."""


class FleetInputError(FleetError):
    """Invalid input report (bad JSON, Pydantic validation failure, missing file)."""
