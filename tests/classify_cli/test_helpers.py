"""Unit tests for module-internal helpers in ``loki.classify_helpers``.

This file collects the small example-based tests for the private
helpers that do not need their own dedicated module (the SIGINT
handler installer, the ``_CancelFlag`` dataclass). Helpers that
have richer per-flag behavior get their own dedicated test module
(see ``test_input_paths.py`` for ``_load_manifest``,
``test_debug_flag.py`` for ``_install_debug_logger``,
``test_progress.py`` for ``_build_progress_callback``,
``test_stdout_shape.py`` for ``_serialize_result``,
``test_stderr_summary.py`` for ``_format_summary_line``).

Per the design D6 default, the helpers are module-private; tests
import them via ``from loki.classify_helpers import ...`` rather
than via a public package re-export.
"""

from __future__ import annotations

from loki.classify_helpers import _CancelFlag


class TestCancelFlag:
    """Behavior tests for the ``_CancelFlag`` dataclass (R6.1, D2)."""

    def test_default_constructor_is_false(self) -> None:
        """An empty constructor yields a flag whose ``value`` is False."""
        flag = _CancelFlag()
        assert flag.value is False

    def test_explicit_false_constructor(self) -> None:
        """Passing ``value=False`` matches the default behavior."""
        flag = _CancelFlag(value=False)
        assert flag.value is False

    def test_value_field_is_mutable(self) -> None:
        """The ``value`` field can be flipped post-construction.

        This is the contract the SIGINT handler relies on: the
        installed signal handler flips ``flag.value = True`` on
        receipt of SIGINT, and the cancel callback reads the new
        value at the next cooperative-cancellation poll.
        """
        flag = _CancelFlag()
        flag.value = True
        assert flag.value is True

    def test_two_equal_valued_instances_compare_equal(self) -> None:
        """Dataclass-generated ``__eq__`` compares structurally.

        Two ``_CancelFlag`` instances with the same ``value`` are
        equal under the auto-generated equality method.
        """
        a = _CancelFlag(value=False)
        b = _CancelFlag(value=False)
        assert a == b

        c = _CancelFlag(value=True)
        d = _CancelFlag(value=True)
        assert c == d

    def test_unequal_values_compare_unequal(self) -> None:
        """Instances with different ``value`` fields are not equal."""
        a = _CancelFlag(value=False)
        b = _CancelFlag(value=True)
        assert a != b


class TestInstallSigintHandler:
    """Behavior tests for ``_install_sigint_handler`` (R6.1, R6.5).

    The signal handler itself is excluded from coverage with
    ``# pragma: no cover - signal`` because pytest's
    signal-injection patterns are environment-dependent. The
    deterministic in-process P55 cancellation contract test in
    ``test_cancellation.py`` (task 12) exercises the same
    flag-flip mechanism via the cancel callback directly.

    These tests verify the handler-installation lifecycle: the
    previous SIGINT disposition is captured and is restored when
    the returned restore callable is invoked.
    """

    def test_install_returns_cancel_flag_initially_false(self) -> None:
        """The returned ``_CancelFlag`` starts in the False state."""
        import signal

        from loki.classify_helpers import _install_sigint_handler

        cancel_flag, restore = _install_sigint_handler()
        try:
            assert isinstance(cancel_flag, _CancelFlag)
            assert cancel_flag.value is False
        finally:
            restore()
            # Final cleanup: leave the parent test process in
            # the Python default disposition.
            signal.signal(signal.SIGINT, signal.SIG_DFL)

    def test_install_then_restore_round_trips_previous_handler(self) -> None:
        """Installing then restoring preserves the previous handler.

        Synthesizes a stand-in previous handler, installs it, then
        calls ``_install_sigint_handler`` (which captures it as the
        previous handler), then calls the returned restore callable
        and asserts ``signal.getsignal(SIGINT) is _prev``.
        """
        import signal

        from loki.classify_helpers import _install_sigint_handler

        def _prev(signum: int, frame: object) -> None:  # pragma: no cover - signal
            pass

        # Install our synthetic previous handler.
        original = signal.signal(signal.SIGINT, _prev)
        try:
            # Now run the installer; it should capture _prev.
            cancel_flag, restore = _install_sigint_handler()
            try:
                # The installer's own handler is in place now;
                # signal.getsignal would return that wrapper, not
                # our _prev. We rely on the restore step to put
                # _prev back.
                assert cancel_flag.value is False
            finally:
                restore()
            # After restore, _prev should be reinstated.
            assert signal.getsignal(signal.SIGINT) is _prev
        finally:
            # Final cleanup: restore the truly-original handler.
            signal.signal(signal.SIGINT, original)

    def test_double_install_each_restore_independently(self) -> None:
        """Two nested installs each restore to the correct previous handler.

        R6.5's no-op double-Ctrl-C contract is structurally
        guaranteed by re-flipping a True flag to True; this test
        is the lifecycle counterpart, verifying that each
        ``_install_sigint_handler`` call captures the handler it
        replaces (which may itself be one of our installer's
        handlers).
        """
        import signal

        from loki.classify_helpers import _install_sigint_handler

        original = signal.getsignal(signal.SIGINT)
        try:
            outer_flag, outer_restore = _install_sigint_handler()
            inner_flag, inner_restore = _install_sigint_handler()
            try:
                assert outer_flag is not inner_flag
                assert outer_flag.value is False
                assert inner_flag.value is False
            finally:
                inner_restore()
                outer_restore()
            # After both restores, the original handler is back.
            assert signal.getsignal(signal.SIGINT) == original
        finally:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
