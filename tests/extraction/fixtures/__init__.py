"""Synthetic firmware-binary fixtures for the extraction test suite.

Each builder is a pure function that writes a tiny but format-valid
binary into a caller-provided directory and returns the path. The
binaries are small (sub-kilobyte to a few KiB) so they fit comfortably
in version control and run instantly.

Builders:

- :func:`synthetic_uefi_volume.build` — a single-FFS UEFI PI volume
- :func:`synthetic_option_rom.build` — a two-image PCI option ROM
- :func:`synthetic_microcode.build` — a two-blob Intel microcode update
"""
