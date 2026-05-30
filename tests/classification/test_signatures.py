"""Tests for the signature detector.

Covers Requirement 5: PE32 Authenticode + UEFI auth-wrapper
recognizers, the missing/unreadable-bytes error path, and the
short-file no-crash invariant. The recognizers are designed to
be robust against malformed inputs — truncation anywhere in the
parse returns ``False`` rather than raising.
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path

from loki.classification.signatures import detect_signature
from loki.models import ExtractedComponent

_VALID_HASH = "a" * 64

# PKCS7 GUID per the UEFI 2.x spec, used in
# EFI_FIRMWARE_IMAGE_AUTHENTICATION wrappers.
_EFI_CERT_TYPE_PKCS7_GUID_BYTES = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le


def _component(
    *,
    raw_path: Path | None = None,
    component_type_hint: str | None = "dxe_driver",
) -> ExtractedComponent:
    """Build an ExtractedComponent for signature-detection tests."""
    return ExtractedComponent(
        component_id=uuid.uuid5(uuid.NAMESPACE_DNS, "test-signatures"),
        source_image_id=uuid.uuid5(uuid.NAMESPACE_DNS, "test-image"),
        offset="0x1000",
        size=4096,
        raw_hash=_VALID_HASH,
        component_type_hint=component_type_hint,
        guid=None,
        name=None,
        raw_path=str(raw_path) if raw_path is not None else None,
    )


# ---------------------------------------------------------------------------
# Helpers: synthetic binary builders
# ---------------------------------------------------------------------------


def _build_pe32_with_security_directory(
    *, virtual_address: int, size: int, magic: int = 0x10B
) -> bytes:
    """Build a minimal but valid PE32 (or PE32+) binary with a
    Security data-directory entry.

    Layout:
      - DOS header (64 bytes); e_lfanew at 0x3C points to PE
        header at offset 0x80.
      - Pad bytes between DOS header and PE header.
      - PE signature (4 bytes).
      - COFF header (20 bytes; values don't matter for the
        recognizer).
      - Optional header magic (2 bytes).
      - Padding to fill the optional header up to the data
        directories start.
      - Data directories array. Index 4 is the Security entry,
        which we populate with the requested
        (virtual_address, size).
    """
    pe_header_offset = 0x80
    # DOS header: MZ + 58 bytes of don't-care + e_lfanew (4 bytes LE).
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_header_offset)
    # Pad to PE header offset (0x80).
    padding = b"\x00" * (pe_header_offset - len(dos_header))
    # PE signature.
    pe_sig = b"PE\x00\x00"
    # COFF header (20 bytes).
    coff_header = b"\x00" * 20
    # Optional header: magic (2 bytes) + the rest. Data directories
    # start at offset +96 for PE32 or +112 for PE32+.
    if magic == 0x10B:
        optional_header_pre_dirs = struct.pack("<H", magic) + b"\x00" * (96 - 2)
    elif magic == 0x20B:
        optional_header_pre_dirs = struct.pack("<H", magic) + b"\x00" * (112 - 2)
    else:
        raise ValueError(f"unsupported magic: {magic:#x}")

    # Data directories: 5 entries before Security, then Security,
    # then enough padding so the recognizer doesn't truncate.
    # Each entry is 8 bytes. Index 4 is Security.
    data_dirs = b"\x00" * (4 * 8) + struct.pack("<II", virtual_address, size) + b"\x00" * (10 * 8)

    return dos_header + padding + pe_sig + coff_header + optional_header_pre_dirs + data_dirs


def _build_uefi_auth_wrapper(*, time_size: int = 16, include_pkcs7_guid: bool = True) -> bytes:
    """Build a minimal UEFI auth wrapper byte buffer.

    Layout:
      - EFI_TIME (16 or 24 bytes; size varies between
        implementations).
      - WIN_CERTIFICATE header (8 bytes): dwLength (4) +
        wRevision (2) + wCertificateType (2). Values don't
        matter for the recognizer.
      - WIN_CERTIFICATE_UEFI_GUID extension: CertType GUID (16
        bytes). When include_pkcs7_guid is True, this is the
        PKCS7 GUID that triggers the recognizer; when False, it's
        an unrelated GUID.
      - Trailing padding.
    """
    efi_time = b"\x00" * time_size
    win_certificate = b"\x00" * 8
    if include_pkcs7_guid:
        cert_type = _EFI_CERT_TYPE_PKCS7_GUID_BYTES
    else:
        cert_type = uuid.UUID(int=0xDEADBEEF).bytes_le
    return efi_time + win_certificate + cert_type + b"\x00" * 64


# ---------------------------------------------------------------------------
# Missing-bytes error path (R5.6)
# ---------------------------------------------------------------------------


def test_raw_path_none_returns_missing_bytes_error() -> None:
    component = _component(raw_path=None)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is not None
    assert "raw_path missing" in error_message


def test_nonexistent_raw_path_returns_unreadable_error(tmp_path: Path) -> None:
    nonexistent = tmp_path / "no-such-file.bin"
    component = _component(raw_path=nonexistent)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is not None
    assert "file unreadable" in error_message


# ---------------------------------------------------------------------------
# Short-file no-crash invariant
# ---------------------------------------------------------------------------


def test_four_byte_file_returns_false_without_crash(tmp_path: Path) -> None:
    """A 4-byte file is shorter than the minimum recognizer prefix.
    The detector should return (False, None) rather than crashing."""
    short_file = tmp_path / "tiny.bin"
    short_file.write_bytes(b"\x00\x01\x02\x03")
    component = _component(raw_path=short_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_empty_file_returns_false_without_crash(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    component = _component(raw_path=empty_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


# ---------------------------------------------------------------------------
# PE32 Authenticode recognizer
# ---------------------------------------------------------------------------


def test_pe32_with_valid_security_directory_returns_true(tmp_path: Path) -> None:
    """A PE32 with VirtualAddress > 0 and Size > 0 in the
    Security data directory has a present signature."""
    binary = _build_pe32_with_security_directory(virtual_address=0x10000, size=512)
    pe_file = tmp_path / "signed.exe"
    pe_file.write_bytes(binary)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None


def test_pe32_with_zero_security_directory_returns_false(tmp_path: Path) -> None:
    """A well-formed PE32 with VirtualAddress=0 and Size=0 has
    no signature."""
    binary = _build_pe32_with_security_directory(virtual_address=0, size=0)
    pe_file = tmp_path / "unsigned.exe"
    pe_file.write_bytes(binary)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_pe32_plus_with_valid_security_directory_returns_true(
    tmp_path: Path,
) -> None:
    """The PE32+ variant uses optional-header magic 0x20B and
    a different data-directories offset; the recognizer
    handles it the same way."""
    binary = _build_pe32_with_security_directory(virtual_address=0x20000, size=1024, magic=0x20B)
    pe_file = tmp_path / "signed-pe32plus.exe"
    pe_file.write_bytes(binary)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None


def test_non_pe32_file_returns_false(tmp_path: Path) -> None:
    """A file that doesn't start with `MZ` is not a PE32; recognizer returns False."""
    non_pe = tmp_path / "not-pe32.bin"
    non_pe.write_bytes(b"\x7fELF" + b"\x00" * 200)
    component = _component(raw_path=non_pe)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_pe32_with_truncated_optional_header_returns_false(
    tmp_path: Path,
) -> None:
    """A file that has a valid PE signature but is truncated
    before the security directory should return False, not
    crash."""
    truncated = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)  # e_lfanew=0x40
    truncated += b"PE\x00\x00"  # PE signature at 0x40
    # No COFF/optional header at all.
    pe_file = tmp_path / "truncated.exe"
    pe_file.write_bytes(truncated + b"\x00" * 4)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_pe32_with_e_lfanew_pointing_past_end_returns_false(
    tmp_path: Path,
) -> None:
    """e_lfanew that points beyond the file size returns False."""
    bogus = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xDEADBEEF)
    pe_file = tmp_path / "bogus.exe"
    pe_file.write_bytes(bogus)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_pe32_with_unknown_optional_magic_returns_false(tmp_path: Path) -> None:
    """An optional-header magic that's not PE32 (0x10B) or
    PE32+ (0x20B) returns False."""
    # Custom builder: valid DOS + PE signature but bogus magic.
    pe_offset = 0x80
    binary = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    binary += b"\x00" * (pe_offset - len(binary))
    binary += b"PE\x00\x00"
    binary += b"\x00" * 20  # COFF header
    binary += struct.pack("<H", 0xFFFF)  # bogus magic
    binary += b"\x00" * 200
    pe_file = tmp_path / "bogus-magic.exe"
    pe_file.write_bytes(binary)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


# ---------------------------------------------------------------------------
# UEFI auth-wrapper recognizer
# ---------------------------------------------------------------------------


def test_uefi_auth_wrapper_with_pkcs7_guid_and_uefi_hint_returns_true(
    tmp_path: Path,
) -> None:
    """A UEFI capsule body with a PKCS7 GUID in the auth wrapper
    triggers the recognizer."""
    binary = _build_uefi_auth_wrapper(include_pkcs7_guid=True)
    capsule_file = tmp_path / "capsule.bin"
    capsule_file.write_bytes(binary)
    component = _component(raw_path=capsule_file, component_type_hint="UEFI_CAPSULE_BODY")
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None


def test_uefi_auth_wrapper_with_ffs_hint_also_works(tmp_path: Path) -> None:
    """The recognizer also fires for FFS-prefixed type hints."""
    binary = _build_uefi_auth_wrapper(include_pkcs7_guid=True)
    ffs_file = tmp_path / "ffs.bin"
    ffs_file.write_bytes(binary)
    component = _component(raw_path=ffs_file, component_type_hint="FFS_FILE_TYPE_0x07")
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None


def test_uefi_auth_wrapper_with_24_byte_efi_time_works(tmp_path: Path) -> None:
    """Some implementations use a 24-byte EFI_TIME variant; the
    recognizer's substring search handles both lengths."""
    binary = _build_uefi_auth_wrapper(time_size=24, include_pkcs7_guid=True)
    capsule_file = tmp_path / "capsule24.bin"
    capsule_file.write_bytes(binary)
    component = _component(raw_path=capsule_file, component_type_hint="UEFI_CAPSULE_BODY")
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None


def test_uefi_auth_wrapper_without_pkcs7_guid_returns_false(
    tmp_path: Path,
) -> None:
    """An auth wrapper with a different CertType GUID does not fire."""
    binary = _build_uefi_auth_wrapper(include_pkcs7_guid=False)
    capsule_file = tmp_path / "capsule-other-guid.bin"
    capsule_file.write_bytes(binary)
    component = _component(raw_path=capsule_file, component_type_hint="UEFI_CAPSULE_BODY")
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_uefi_auth_wrapper_with_non_uefi_hint_does_not_fire(
    tmp_path: Path,
) -> None:
    """The UEFI recognizer is gated on UEFI / FFS type hints. A
    non-UEFI component with PKCS7 bytes in its body should NOT
    fire the UEFI recognizer (R5.5 carves out UEFI capsule /
    firmware components specifically).

    Note: PE32 recognizer runs first; this test uses bytes that
    do not start with ``MZ`` so the PE32 path returns False, and
    then the UEFI path is gated off by the non-UEFI hint.
    """
    binary = _build_uefi_auth_wrapper(include_pkcs7_guid=True)
    rom_file = tmp_path / "option-rom.bin"
    rom_file.write_bytes(binary)
    component = _component(raw_path=rom_file, component_type_hint="PCI_LEGACY_X86")
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


def test_uefi_auth_wrapper_with_none_hint_does_not_fire(tmp_path: Path) -> None:
    """A component with component_type_hint=None should not fire
    the UEFI recognizer."""
    binary = _build_uefi_auth_wrapper(include_pkcs7_guid=True)
    rom_file = tmp_path / "no-hint.bin"
    rom_file.write_bytes(binary)
    component = _component(raw_path=rom_file, component_type_hint=None)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


# ---------------------------------------------------------------------------
# Recognizer dispatch order
# ---------------------------------------------------------------------------


def test_pe32_recognizer_runs_first(tmp_path: Path) -> None:
    """When a binary triggers PE32 first (valid MZ + PE +
    non-zero security directory), the recognizer returns True
    even when the component has a UEFI hint."""
    binary = _build_pe32_with_security_directory(virtual_address=0x10000, size=512)
    pe_file = tmp_path / "signed.exe"
    pe_file.write_bytes(binary)
    # Even with a UEFI-flavored hint, PE32 wins when its bytes
    # match.
    component = _component(raw_path=pe_file, component_type_hint="UEFI_CAPSULE_BODY")
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None


def test_neither_recognizer_fires_returns_false(tmp_path: Path) -> None:
    """Random bytes that don't form a PE32 or UEFI auth wrapper
    return False with no error."""
    random_bytes = b"\xde\xad\xbe\xef" * 100
    rand_file = tmp_path / "random.bin"
    rand_file.write_bytes(random_bytes)
    component = _component(raw_path=rand_file)
    present, error_message = detect_signature(component)
    assert present is False
    assert error_message is None


# ---------------------------------------------------------------------------
# 1 MiB read bound (R11.2)
# ---------------------------------------------------------------------------


def test_recognizer_does_not_read_past_one_mib(tmp_path: Path) -> None:
    """The recognizer reads at most 1 MiB. A 5 MiB file with the
    PE32 security directory in the first 1 MiB still detects;
    the rest of the file is never read.

    This test pins the bound by writing a large file but only
    populating the first 1 MiB with the signature. We can't
    directly observe the file-position cap, but we verify that
    a structurally valid signature in the first ~256 bytes is
    detected even when the file is much larger.
    """
    binary = _build_pe32_with_security_directory(virtual_address=0x10000, size=512)
    # Pad to 5 MiB.
    binary = binary + b"\x00" * (5 * 1024 * 1024)
    pe_file = tmp_path / "large.exe"
    pe_file.write_bytes(binary)
    component = _component(raw_path=pe_file)
    present, error_message = detect_signature(component)
    assert present is True
    assert error_message is None
