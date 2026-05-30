"""Per-format extractor strategies.

The :func:`register` helper wires every concrete extractor into the
dispatch registry. The public :func:`loki.extraction.extract_firmware`
entry point calls this once per run; tests that need a clean slate
call :func:`loki.extraction.extractors.base.clear_registry` first
and then ``register()``.
"""

from __future__ import annotations

from loki.extraction.extractors.capsule import register as _register_capsule
from loki.extraction.extractors.ifd import register as _register_ifd
from loki.extraction.extractors.microcode import register as _register_microcode
from loki.extraction.extractors.option_rom import register as _register_option_rom
from loki.extraction.extractors.uefi_volume import register as _register_uefi_volume

__all__ = ["register"]


def register() -> None:
    """Register every concrete extractor with the dispatch registry.

    Idempotent — re-running it replaces existing registrations with
    fresh instances, which is what tests want when toggling between
    real and stub extractors.
    """

    _register_uefi_volume()
    _register_ifd()
    _register_capsule()
    _register_option_rom()
    _register_microcode()
