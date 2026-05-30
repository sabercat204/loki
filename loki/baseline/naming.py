"""Filename slugification + collision handling for Baseline_Files.

The naming contract (R1.2, R1.3): each Baseline_File's name is

    {slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml

where ``slug()`` lowercases its input, replaces every character
outside ``[a-z0-9._-]`` with ``_``, collapses runs of ``_``, and
strips leading / trailing ``_``. When two records would produce the
same canonical filename, the second gets a
``-{first 8 hex chars of baseline_id}`` suffix before the ``.yaml``
extension so the first record keeps the canonical form.

This module is pure — no I/O, no dependencies on the rest of the
persistence subsystem.
"""

from __future__ import annotations

import re
import uuid

from loki.models import BaselineRecord

__all__ = [
    "filename_for",
    "slug",
    "unique_filename_for",
]


_INVALID_RUN = re.compile(r"[^a-z0-9._-]+")
_UNDERSCORE_RUN = re.compile(r"_+")


def slug(value: str) -> str:
    """Return a filesystem-safe slug for ``value``.

    Lowercases the input, replaces every character outside
    ``[a-z0-9._-]`` with ``_``, collapses runs of ``_``, and strips
    leading / trailing ``_`` so ``"v1.42"`` -> ``"v1.42"`` and
    ``"/etc/passwd"`` -> ``"etc_passwd"`` (not ``"_etc_passwd_"``).

    Idempotent: ``slug(slug(value)) == slug(value)`` (R1.2,
    Property 28).
    """

    lowered = value.lower()
    replaced = _INVALID_RUN.sub("_", lowered)
    collapsed = _UNDERSCORE_RUN.sub("_", replaced)
    return collapsed.strip("_")


def filename_for(record: BaselineRecord) -> str:
    """Return the canonical Baseline_Filename for ``record`` (R1.2).

    Form: ``{slug(vendor)}-{slug(model)}-{slug(firmware_version)}.yaml``.
    Collision resolution is deliberately *not* handled here —
    :func:`unique_filename_for` is the entry point that takes the
    set of already-taken filenames into account.
    """

    return f"{slug(record.vendor)}-{slug(record.model)}-{slug(record.firmware_version)}.yaml"


def unique_filename_for(record: BaselineRecord, taken: set[str]) -> str:
    """Return a Baseline_Filename guaranteed not to collide with ``taken``.

    R1.3, Property 29. If the canonical filename is already in
    ``taken``, append ``-{first 8 hex chars of baseline_id}`` before
    the ``.yaml`` extension.

    Args:
        record: The :class:`BaselineRecord` whose filename to compute.
        taken: Set of filenames already in use under the
            Storage_Directory. The caller is responsible for keeping
            this set up to date.

    Returns:
        A filename that is not a member of ``taken`` and that matches
        ``[a-z0-9._-]+\\.yaml``.

    Raises:
        ValueError: if the colliding filename + the disambiguating
            suffix would *still* clash with ``taken``. In practice
            the suffix is the first 8 hex chars of ``baseline_id``,
            so this only happens if two records share the same
            ``baseline_id`` prefix *and* the same canonical filename
            — collision space ~ 1 in 4 billion.
    """

    canonical = filename_for(record)
    if canonical not in taken:
        return canonical
    suffix = _baseline_id_suffix(record.baseline_id)
    candidate = canonical.removesuffix(".yaml") + f"-{suffix}.yaml"
    if candidate in taken:
        msg = (
            f"both {canonical!r} and {candidate!r} are already taken; "
            f"baseline_id collision in the leading 8 hex chars"
        )
        raise ValueError(msg)
    return candidate


def _baseline_id_suffix(baseline_id: uuid.UUID) -> str:
    """Return the first 8 hex chars of ``baseline_id``'s ``hex`` form."""

    return baseline_id.hex[:8]
