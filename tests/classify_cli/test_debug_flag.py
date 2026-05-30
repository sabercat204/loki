"""Tests for ``_install_debug_logger`` covering R7.1-R7.8.

Pins the lifecycle behavior of the ``loki.classification`` logger
under ``--debug``: level promotion to ``DEBUG`` (R7.2), the no-
double-attach rule (R7.3), the ``propagate = False`` discipline
(R7.4 / D3 default), the no-op behavior when ``--debug`` is not
set (R7.5), the no-modification rule for sibling loggers (R7.6),
and the routing-through-attached-handler check that motivates
the R7.7 no-leakage paired audit (deferred to task 19's dynamic
audit).

Each test isolates global logger state via fixture teardown so
the tests can run in any order without cross-pollution. The
``loki.classification`` logger is shared with the rest of the
test suite, so tests carefully restore its state after each run.
"""

from __future__ import annotations

import logging
from collections.abc import Generator

import pytest

from loki.classify_helpers import _install_debug_logger


@pytest.fixture
def isolated_classification_logger() -> Generator[logging.Logger, None, None]:
    """Snapshot then restore the ``loki.classification`` logger.

    Captures ``level``, ``propagate``, and ``handlers`` at
    fixture-entry time, yields the logger, and on teardown sets
    every captured value back. This protects the shared global
    state from any test that fails partway through restoration.
    """
    logger = logging.getLogger("loki.classification")
    previous_level = logger.level
    previous_propagate = logger.propagate
    previous_handlers = list(logger.handlers)
    try:
        yield logger
    finally:
        # Strip everything we may have left behind.
        for handler in list(logger.handlers):
            if handler not in previous_handlers:
                logger.removeHandler(handler)
                handler.close()
        # Reattach any handlers we accidentally removed.
        for handler in previous_handlers:
            if handler not in logger.handlers:
                logger.addHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate


class TestDebugDisabled:
    """Behavior when ``enabled=False`` (R7.5)."""

    def test_disabled_is_no_op(self, isolated_classification_logger: logging.Logger) -> None:
        """When ``enabled=False``, no logger state is modified."""
        logger = isolated_classification_logger
        before_level = logger.level
        before_propagate = logger.propagate
        before_handlers = list(logger.handlers)

        restore = _install_debug_logger(enabled=False)

        assert logger.level == before_level
        assert logger.propagate == before_propagate
        assert logger.handlers == before_handlers

        # Restore is also a no-op.
        restore()
        assert logger.level == before_level
        assert logger.propagate == before_propagate
        assert logger.handlers == before_handlers


class TestDebugEnabledNoPriorHandler:
    """Behavior when ``enabled=True`` and no handler is attached."""

    def test_enabled_attaches_stderr_handler(
        self, isolated_classification_logger: logging.Logger
    ) -> None:
        """A stderr StreamHandler is attached when none exists (R7.3)."""
        logger = isolated_classification_logger
        # Ensure we start clean for this test's purposes.
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        assert logger.handlers == []

        restore = _install_debug_logger(enabled=True)
        try:
            assert len(logger.handlers) == 1
            attached = logger.handlers[0]
            assert isinstance(attached, logging.StreamHandler)
        finally:
            restore()

    def test_enabled_sets_level_and_propagate(
        self, isolated_classification_logger: logging.Logger
    ) -> None:
        """Logger level becomes DEBUG and propagate becomes False (R7.2, R7.4)."""
        logger = isolated_classification_logger

        restore = _install_debug_logger(enabled=True)
        try:
            assert logger.level == logging.DEBUG
            assert logger.propagate is False
        finally:
            restore()

    def test_restore_detaches_handler_and_resets_state(
        self, isolated_classification_logger: logging.Logger
    ) -> None:
        """The restore callable returns the logger to its prior state."""
        logger = isolated_classification_logger
        # Strip handlers so the installer attaches a fresh one.
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

        before_level = logger.level
        before_propagate = logger.propagate

        restore = _install_debug_logger(enabled=True)
        # Sanity: the installer attached one handler.
        assert len(logger.handlers) == 1

        restore()

        # After restore: handler removed, level and propagate
        # back to their previous values.
        assert logger.handlers == []
        assert logger.level == before_level
        assert logger.propagate == before_propagate

    def test_debug_record_routes_through_attached_handler(
        self,
        isolated_classification_logger: logging.Logger,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A logger.debug call routes through the attached stderr handler.

        This pins the routing contract for R7.7: when the logger
        emits a DEBUG record while ``--debug`` is enabled, the
        record reaches stderr through the handler this installer
        attached. The full no-leakage audit (forbidden values do
        not appear in the captured stderr) is deferred to task
        19's dynamic test in ``test_no_leakage.py``.
        """
        logger = isolated_classification_logger
        # Strip any preexisting handlers so we know the routing
        # path is the one we attached.
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

        restore = _install_debug_logger(enabled=True)
        try:
            logger.debug("routing-test")
            captured = capsys.readouterr()
            assert "routing-test" in captured.err
            # The minimal formatter prefixes the logger name and
            # level; verify the prefix is present.
            assert "loki.classification" in captured.err
            assert "DEBUG" in captured.err
        finally:
            restore()


class TestDebugEnabledWithPriorHandler:
    """Behavior when ``enabled=True`` and a handler is already attached (R7.3)."""

    def test_does_not_double_attach(self, isolated_classification_logger: logging.Logger) -> None:
        """An already-attached handler is left alone; no second handler."""
        logger = isolated_classification_logger
        # Set up a synthetic prior handler.
        prior = logging.StreamHandler()
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        logger.addHandler(prior)
        try:
            assert len(logger.handlers) == 1

            restore = _install_debug_logger(enabled=True)
            try:
                # Still exactly one handler — the prior one.
                assert len(logger.handlers) == 1
                assert logger.handlers[0] is prior
            finally:
                restore()

            # Restore preserves the prior handler.
            assert len(logger.handlers) == 1
            assert logger.handlers[0] is prior
        finally:
            logger.removeHandler(prior)
            prior.close()


class TestDebugDoesNotTouchSiblingLoggers:
    """R7.6: sibling loggers are NOT modified by ``--debug``."""

    def test_loki_baseline_unchanged(self, isolated_classification_logger: logging.Logger) -> None:
        """``loki.baseline`` is untouched by ``_install_debug_logger``."""
        baseline_logger = logging.getLogger("loki.baseline")
        before_level = baseline_logger.level
        before_propagate = baseline_logger.propagate
        before_handlers = list(baseline_logger.handlers)

        restore = _install_debug_logger(enabled=True)
        try:
            assert baseline_logger.level == before_level
            assert baseline_logger.propagate == before_propagate
            assert baseline_logger.handlers == before_handlers
        finally:
            restore()

    def test_loki_extraction_unchanged(
        self, isolated_classification_logger: logging.Logger
    ) -> None:
        """``loki.extraction`` is untouched by ``_install_debug_logger``."""
        extraction_logger = logging.getLogger("loki.extraction")
        before_level = extraction_logger.level
        before_propagate = extraction_logger.propagate
        before_handlers = list(extraction_logger.handlers)

        restore = _install_debug_logger(enabled=True)
        try:
            assert extraction_logger.level == before_level
            assert extraction_logger.propagate == before_propagate
            assert extraction_logger.handlers == before_handlers
        finally:
            restore()

    def test_loki_analysis_unchanged(self, isolated_classification_logger: logging.Logger) -> None:
        """``loki.analysis`` is untouched by ``_install_debug_logger``."""
        analysis_logger = logging.getLogger("loki.analysis")
        before_level = analysis_logger.level
        before_propagate = analysis_logger.propagate
        before_handlers = list(analysis_logger.handlers)

        restore = _install_debug_logger(enabled=True)
        try:
            assert analysis_logger.level == before_level
            assert analysis_logger.propagate == before_propagate
            assert analysis_logger.handlers == before_handlers
        finally:
            restore()
