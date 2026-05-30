"""Code-signing signature presence detection.

Detects PE32 Authenticode signatures and UEFI
``EFI_FIRMWARE_IMAGE_AUTHENTICATION`` wrappers in a component's
raw bytes. Returns a ``(present: bool, error_message: str | None)``
tuple. v1 only detects presence; signer parsing and verification
are out of scope (R5.2-R5.4, R5.7).

Reads at most 1 MiB per component (R11.2) and never consults a
trust root, network resource, or external certificate store.
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path

from loki.models import ExtractedComponent

__all__ = ["detect_signature"]

# R11.2: bound the per-component read at 1 MiB.
_MAX_READ_BYTES: int = 1 << 20

# Minimum bytes needed for any recognizer to even attempt parsing.
# DOS header is 64 bytes; PE optional header offset must fit in the
# DOS header's e_lfanew field (offset 0x3C). UEFI auth wrappers
# are smaller. 64 bytes covers both lower bounds.
_MIN_USEFUL_BYTES: int = 64

# UEFI EFI_CERT_TYPE_PKCS7_GUID per the UEFI 2.x spec.
# In raw byte form (uuid.UUID.bytes_le, which is LE for the
# first three components and BE for the trailing eight bytes,
# matching the wire format used in firmware images).
_EFI_CERT_TYPE_PKCS7_GUID: bytes = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le

# Component_type_hint prefixes that gate the UEFI auth wrapper
# recognizer per R5.5. The extraction pipeline emits hints like
# ``UEFI_CAPSULE_BODY``, ``FFS_FILE_TYPE_0x...``, plus inner-carve
# variants. The recognizer fires only when the hint suggests a
# UEFI capsule / firmware container, since the auth wrapper
# byte format is meaningful only in that context.
_UEFI_HINT_PREFIXES: tuple[str, ...] = ("UEFI_", "FFS_")


def detect_signature(component: ExtractedComponent) -> tuple[bool, str | None]:
    """Detect signature presence in ``component``'s raw bytes.

    Returns ``(present, error_message)``:

    - ``present`` is ``True`` when the component's bytes carry a
      recognized code-signing structure (PE32 Authenticode
      security-directory entry or UEFI
      ``EFI_FIRMWARE_IMAGE_AUTHENTICATION`` wrapper). False
      otherwise.
    - ``error_message`` is ``None`` on success and a non-empty
      string when the component's bytes were unreadable
      (``raw_path`` is ``None`` or the file is missing /
      unreadable / shorter than the minimum recognizer prefix).
      Per R5.6, callers translate a non-``None`` ``error_message``
      into a ``ClassificationError`` while still emitting the
      ``ClassificationRecord``.

    Recognizer dispatch: try PE32 first, then UEFI; the first
    ``True`` wins. Both recognizers are pure functions over
    bounded byte ranges.

    The recognizers do not parse certificates, do not consult
    any trust root, and do not attempt verification (R5.2-R5.4,
    R5.7). ``SignatureInfo.signer`` and
    ``SignatureInfo.cert_expiry`` are populated as ``None`` by
    the pipeline, not the recognizer.
    """

    if component.raw_path is None:
        return (False, "signature detection failed: raw_path missing")

    raw_path = Path(component.raw_path)

    try:
        with raw_path.open("rb") as fh:
            data = fh.read(_MAX_READ_BYTES)
    except FileNotFoundError as exc:
        return (
            False,
            f"signature detection failed: file unreadable: errno={exc.errno}",
        )
    except (PermissionError, OSError) as exc:
        return (
            False,
            f"signature detection failed: file unreadable: errno={exc.errno}",
        )

    if len(data) < _MIN_USEFUL_BYTES:
        # Too short for any recognizer to make a determination.
        # This is not a read failure (we read what was there);
        # the bytes simply don't carry a signature, so return
        # False with no error message.
        return (False, None)

    # Try PE32 Authenticode first.
    if _detect_pe32_authenticode(data):
        return (True, None)

    # Then try UEFI auth wrapper, gated on component_type_hint
    # per R5.5.
    if _is_uefi_firmware_hint(component.component_type_hint) and _detect_uefi_auth_wrapper(data):
        return (True, None)

    return (False, None)


def _detect_pe32_authenticode(data: bytes) -> bool:
    """Detect a non-zero PE32 security data-directory entry.

    Implements the PE32 Authenticode recognizer per R5.5:

    1. Verify the DOS header signature (``MZ``).
    2. Read ``e_lfanew`` at DOS offset ``0x3C`` to find the PE
       header.
    3. Verify the PE signature (``PE\\x00\\x00``).
    4. Read the optional-header magic to distinguish PE32
       (``0x10B``) from PE32+ (``0x20B``); the magic chooses
       the offset of the data-directories array.
    5. Read the Security data-directory entry (index 4) and
       check that ``VirtualAddress > 0 and Size > 0``.

    Returns ``True`` when a non-empty Security entry is present,
    ``False`` for any malformed or zero entry. Truncation
    anywhere along the parse returns ``False`` rather than
    raising; the recognizer is robust against short / damaged
    inputs.
    """

    # 1. DOS signature.
    if data[:2] != b"MZ":
        return False

    # 2. e_lfanew at 0x3C (4-byte little-endian).
    if len(data) < 0x40:
        return False
    e_lfanew_bytes = data[0x3C:0x40]
    e_lfanew = struct.unpack("<I", e_lfanew_bytes)[0]
    if e_lfanew >= len(data):
        return False

    # 3. PE signature.
    pe_sig_end = e_lfanew + 4
    if pe_sig_end > len(data):
        return False
    if data[e_lfanew:pe_sig_end] != b"PE\x00\x00":
        return False

    # 4. COFF + optional-header magic.
    # COFF header is 20 bytes; the optional-header starts after.
    optional_header_start = e_lfanew + 4 + 20
    magic_end = optional_header_start + 2
    if magic_end > len(data):
        return False
    magic = struct.unpack("<H", data[optional_header_start:magic_end])[0]
    if magic == 0x10B:
        # PE32: data directories start at optional_header_start + 96.
        data_dirs_start = optional_header_start + 96
    elif magic == 0x20B:
        # PE32+: data directories start at optional_header_start + 112.
        data_dirs_start = optional_header_start + 112
    else:
        return False

    # 5. Security data directory is index 4 (0-based).
    # Each data directory entry is 8 bytes: VirtualAddress (4) + Size (4).
    security_entry_offset = data_dirs_start + (4 * 8)
    security_entry_end = security_entry_offset + 8
    if security_entry_end > len(data):
        return False
    virtual_address: int
    size: int
    virtual_address, size = struct.unpack("<II", data[security_entry_offset:security_entry_end])
    return virtual_address > 0 and size > 0


def _detect_uefi_auth_wrapper(data: bytes) -> bool:
    """Detect a UEFI ``EFI_FIRMWARE_IMAGE_AUTHENTICATION`` wrapper.

    Per the UEFI 2.x spec, the wrapper begins with an EFI_TIME
    structure followed by a ``WIN_CERTIFICATE_UEFI_GUID`` whose
    ``CertType`` is ``EFI_CERT_TYPE_PKCS7_GUID``. The exact
    preamble size varies between implementations (16-byte vs
    24-byte EFI_TIME after vendor padding), so this recognizer
    searches for the GUID byte sequence within a small window
    at the start of the data.

    The PKCS7 GUID is unique enough that a substring match
    within the first ~80 bytes is a reliable signal. Returns
    ``True`` on match, ``False`` otherwise.
    """

    # Search the first 80 bytes (covers any reasonable EFI_TIME +
    # WIN_CERTIFICATE preamble size). The GUID itself is 16
    # bytes; cap the search window at min(80, len(data) - 16).
    search_end = min(80, len(data) - 16)
    if search_end <= 0:
        return False
    return bool(_EFI_CERT_TYPE_PKCS7_GUID in data[: search_end + 16])


def _is_uefi_firmware_hint(hint: str | None) -> bool:
    """Return True when ``hint`` looks like a UEFI capsule / firmware container.

    R5.5 carves out the UEFI auth wrapper recognizer for UEFI
    capsule / firmware components. The extraction pipeline emits
    type hints prefixed with ``UEFI_`` (e.g. ``UEFI_CAPSULE_BODY``)
    or ``FFS_`` (e.g. ``FFS_FILE_TYPE_0x07``). Other prefixes
    (PCI option ROM, microcode, IFD region) get the PE32 path
    only.
    """
    if hint is None:
        return False
    return hint.startswith(_UEFI_HINT_PREFIXES)
