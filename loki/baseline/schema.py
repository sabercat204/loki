"""On-disk Schema_Version constants for Baseline_File envelopes.

The Schema_Version is the file-format version of a Baseline_File,
distinct from the per-baseline semantic version carried by
``BaselineRecord.baseline_version``. This module is the single
source of truth that ``BaselineStore``, the CLI subcommands, and
the test suite all import.

v1 of the persistence subsystem supports exactly one Schema_Version
(R4.2). Loading a Baseline_File whose envelope ``schema_version``
isn't in :data:`SUPPORTED_SCHEMA_VERSIONS` quarantines the file
rather than auto-upgrading (R4.4, R4.5). A future
``baseline-schema-migration`` spec will define an explicit migration
tool.
"""

from __future__ import annotations

import re

__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "is_supported_schema_version",
]


_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


#: Current Schema_Version written into every saved Baseline_File.
#:
#: Bumped only when the on-disk envelope shape evolves in a way
#: existing tooling can't read (e.g. a renamed envelope key, a
#: required new top-level field). Adding fields *inside* the
#: ``baseline`` payload that the model layer marks optional doesn't
#: count and doesn't require a bump.
SCHEMA_VERSION: str = "1.0.0"


#: The set of Schema_Version strings that :meth:`BaselineStore.load`
#: will accept without quarantining (R4.2). v1 supports exactly one.
SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({SCHEMA_VERSION})


def is_supported_schema_version(value: object) -> bool:
    """Return ``True`` when ``value`` is a recognised Schema_Version string.

    Used by :meth:`BaselineStore.load` to decide whether to deserialize
    or quarantine. Rejects non-strings to defend against corrupted
    envelopes.
    """

    return isinstance(value, str) and value in SUPPORTED_SCHEMA_VERSIONS


def _validate_schema_version_format(value: str) -> None:
    """Raise ``ValueError`` if ``value`` is not in semver shape.

    Internal helper: every Schema_Version *must* match ``^\\d+\\.\\d+\\.\\d+$``.
    """

    if not _SEMVER_RE.match(value):
        raise ValueError(f"Schema_Version must match ^\\d+\\.\\d+\\.\\d+$, got {value!r}")


# Module-level invariant check: ensures the constant always parses.
_validate_schema_version_format(SCHEMA_VERSION)
