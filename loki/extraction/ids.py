"""Deterministic component-id and error-id derivation.

The two helpers in this module are the *single source of truth* for
the determinism contract (Properties 19 and 20 of
``specs/extraction-pipeline/design.md``). Anything that touches
the payload string format risks producing different UUIDs for the same
content, so the format is locked here and tested via Hypothesis in
``tests/extraction/test_ids.py``.

Payload formats:

- Successful component:  ``f"{file_hash}:0x{offset:x}:{raw_hash}"``
- Per-component error:   ``f"{file_hash}:0x{offset:x}:err:{error_kind}"``

Both hashes are 64-character lowercase hex strings (already
normalised by ``loki.extraction.streaming``). The offset is rendered
with ``f"0x{n:x}"`` so a value of ``5`` and ``0x5`` produce the same
UUID.
"""

from __future__ import annotations

import re
import uuid

from loki.models import LOKI_NAMESPACE

__all__ = [
    "derive_component_id",
    "derive_error_component_id",
]


_LOWER_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VALID_ERROR_KIND = re.compile(r"^[A-Z0-9_]+$")


def _validate_hash(name: str, value: str) -> str:
    if not _LOWER_HEX64.match(value):
        msg = f"{name} must be exactly 64 lowercase hexadecimal characters, got {value!r}"
        raise ValueError(msg)
    return value


def _validate_offset(value: int) -> int:
    if value < 0:
        raise ValueError(f"offset must be >= 0, got {value}")
    return value


def derive_component_id(
    *,
    source_image_hash: str,
    offset: int,
    raw_hash: str,
) -> uuid.UUID:
    """Return a stable :class:`uuid.UUID` for a successfully carved component.

    Implements R7.2. Two extractions of the same firmware binary yield
    the same ``component_id`` for the same component.

    Args:
        source_image_hash: ``FirmwareImage.file_hash`` — 64 lowercase
            hex characters.
        offset: absolute byte offset of the component in the source
            image. Rendered as ``0x{offset:x}`` in the payload, so the
            integer value is what matters, not its string form.
        raw_hash: ``ExtractedComponent.raw_hash`` — 64 lowercase hex
            characters of the component's bytes as they appear in the
            source image.

    Returns:
        ``uuid.uuid5(LOKI_NAMESPACE, payload)`` where ``payload`` is
        ``f"{source_image_hash}:0x{offset:x}:{raw_hash}"``.

    Raises:
        ValueError: any input fails its format check.
    """

    _validate_hash("source_image_hash", source_image_hash)
    _validate_hash("raw_hash", raw_hash)
    _validate_offset(offset)
    payload = f"{source_image_hash}:0x{offset:x}:{raw_hash}"
    return uuid.uuid5(LOKI_NAMESPACE, payload)


def derive_error_component_id(
    *,
    source_image_hash: str,
    offset: int,
    error_kind: str,
) -> uuid.UUID:
    """Return a stable :class:`uuid.UUID` for a per-component extraction error.

    Implements R7.3. Used by ``ManifestBuilder.record_error`` when the
    component itself wasn't carved, so ``raw_hash`` is unavailable.
    Different ``error_kind`` values at the same offset produce
    distinct UUIDs so two failures don't collide.

    Args:
        source_image_hash: ``FirmwareImage.file_hash`` — 64 lowercase
            hex characters.
        offset: absolute byte offset of the would-be component.
        error_kind: short uppercase identifier for the failure
            category (e.g. ``"FFS_HEADER_CRC"``,
            ``"DECOMPRESSION_FAILED"``). Restricted to
            ``[A-Z0-9_]+``.

    Returns:
        ``uuid.uuid5(LOKI_NAMESPACE, payload)`` where ``payload`` is
        ``f"{source_image_hash}:0x{offset:x}:err:{error_kind}"``.

    Raises:
        ValueError: any input fails its format check.
    """

    _validate_hash("source_image_hash", source_image_hash)
    _validate_offset(offset)
    if not error_kind or not _VALID_ERROR_KIND.match(error_kind):
        raise ValueError(f"error_kind must match [A-Z0-9_]+ and be non-empty, got {error_kind!r}")
    payload = f"{source_image_hash}:0x{offset:x}:err:{error_kind}"
    return uuid.uuid5(LOKI_NAMESPACE, payload)
