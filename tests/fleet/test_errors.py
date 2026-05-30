"""Tests for the Fleet analysis exception hierarchy (task 2)."""

from __future__ import annotations

from loki.fleet import FleetConfigError, FleetError, FleetInputError
from loki.fleet.version import FLEET_VERSION


class TestFleetErrorHierarchy:
    """All exceptions are constructible and inherit from FleetError."""

    def test_fleet_error_constructible(self) -> None:
        exc = FleetError("something failed")
        assert exc.message == "something failed"
        assert str(exc) == "something failed"

    def test_fleet_config_error_is_fleet_error(self) -> None:
        exc = FleetConfigError("empty fleet")
        assert isinstance(exc, FleetError)
        assert exc.message == "empty fleet"

    def test_fleet_input_error_is_fleet_error(self) -> None:
        exc = FleetInputError("bad JSON")
        assert isinstance(exc, FleetError)
        assert exc.message == "bad JSON"

    def test_all_are_exceptions(self) -> None:
        for cls in (FleetError, FleetConfigError, FleetInputError):
            assert issubclass(cls, Exception)


class TestFleetVersion:
    """FLEET_VERSION is a valid semver string."""

    def test_version_format(self) -> None:
        import re

        assert re.match(r"^\d+\.\d+\.\d+$", FLEET_VERSION)

    def test_version_value(self) -> None:
        assert FLEET_VERSION == "1.0.0"
