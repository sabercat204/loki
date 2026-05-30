"""YAML envelope schema + (de)serialization for Baseline_Files.

A Baseline_File is a YAML document with four top-level keys:

- ``schema_version`` — string in ``^\\d+\\.\\d+\\.\\d+$`` form.
- ``written_at`` — UTC ISO-8601 timestamp.
- ``written_by_extractor_version`` — free-form string from the
  process that wrote the file.
- ``baseline`` — the serialized :class:`BaselineRecord` payload as
  produced by ``record.model_dump(mode="json")``.

The four keys are sorted alphabetically by ``yaml.safe_dump``'s
``sort_keys=True`` flag, which gives byte-deterministic output for
the same input plus the same ``written_at`` timestamp (R3.7,
Property 25).

When PyYAML's libyaml-backed C variants (``CSafeLoader`` /
``CSafeDumper``) are available they are used in preference to the
pure-Python implementations. Output is byte-identical
(``CSafeDumper`` honours the same ``sort_keys`` /
``default_flow_style`` / ``allow_unicode`` options) and parsed
dicts compare equal under ``==``. The C variants are ~7x faster on
the deserialize side, which is what makes the R9.1 load budget
achievable in practice.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from loki.models import BaselineRecord

__all__ = [
    "Envelope",
    "EnvelopeMalformedError",
    "deserialize",
    "serialize",
]


_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"schema_version", "written_at", "written_by_extractor_version", "baseline"}
)

#: Loader / dumper classes resolved at module import. Falls back to
#: the pure-Python implementations when libyaml isn't available
#: (e.g. minimal pip install without the wheel's libyaml binary).
#: Both pairs produce semantically equivalent output:
#:
#: - ``CSafeLoader`` and ``SafeLoader`` parse the same YAML grammar
#:   and produce dicts that compare equal under ``==``.
#: - ``CSafeDumper`` and ``SafeDumper`` honour the same
#:   ``sort_keys`` / ``default_flow_style`` / ``allow_unicode``
#:   options and emit byte-identical output for our envelope shape.
_SafeLoader: type[yaml.SafeLoader] = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_SafeDumper: type[yaml.SafeDumper] = getattr(yaml, "CSafeDumper", yaml.SafeDumper)


class EnvelopeMalformedError(Exception):
    """The envelope is missing required keys, or types are wrong.

    Distinct from :class:`loki.baseline.errors.BaselineSerializationError`
    so the bulk-load path can convert these to quarantine entries
    while the single-file load path can re-raise as a typed pipeline
    error.
    """

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        self.message = message
        self.path = path
        super().__init__(message)


@dataclass(frozen=True)
class Envelope:
    """Parsed Baseline_File envelope (R3.4)."""

    schema_version: str
    written_at: datetime
    written_by_extractor_version: str
    baseline: dict[str, object]


def serialize(
    record: BaselineRecord,
    *,
    schema_version: str,
    written_at: datetime,
    written_by_extractor_version: str,
) -> bytes:
    """Build the envelope and emit deterministic UTF-8 YAML bytes (R3.4-R3.7).

    Args:
        record: Pydantic-validated :class:`BaselineRecord` to wrap.
        schema_version: The Schema_Version string the writer is
            tagging this file with. Caller passes
            :data:`loki.baseline.schema.SCHEMA_VERSION`; tests can
            pass an alternate value to verify quarantine behaviour.
        written_at: UTC timestamp embedded in the envelope.
        written_by_extractor_version: Free-form version string from
            the writing process.

    Returns:
        UTF-8 bytes ending in a trailing newline (R1.7).
    """

    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "written_at": _format_datetime(written_at),
        "written_by_extractor_version": written_by_extractor_version,
        "baseline": record.model_dump(mode="json"),
    }
    text = yaml.dump(
        payload,
        Dumper=_SafeDumper,
        sort_keys=True,
        default_flow_style=False,
        allow_unicode=True,
    )
    if not text.endswith("\n"):
        text += "\n"
    return text.encode("utf-8")


def deserialize(payload: bytes, *, path: Path) -> Envelope:
    """Parse + validate the envelope shape (R8.2-R8.3).

    Raises:
        EnvelopeMalformedError: Anything wrong with the envelope —
            unparseable YAML, non-dict top-level, missing required
            key, non-string ``schema_version``,
            ``written_by_extractor_version`` not a string, or
            ``written_at`` not a parseable timestamp. The bulk-load
            path catches this and creates a quarantine entry; the
            single-file load path re-raises as
            :class:`loki.baseline.errors.BaselineSerializationError`.
    """

    try:
        loaded = yaml.load(payload, Loader=_SafeLoader)
    except yaml.YAMLError as exc:
        raise EnvelopeMalformedError(
            f"malformed yaml: {exc}",
            path=path,
        ) from exc

    if not isinstance(loaded, dict):
        raise EnvelopeMalformedError(
            f"top-level YAML must be a mapping, got {type(loaded).__name__}",
            path=path,
        )

    missing = _REQUIRED_KEYS - loaded.keys()
    if missing:
        # Pick a deterministic single-key message for stable test
        # output; the reason string in QuarantineEntry only quotes
        # one key per R8.3.
        first_missing = sorted(missing)[0]
        raise EnvelopeMalformedError(
            f"missing required envelope key: {first_missing}",
            path=path,
        )

    schema_version = loaded["schema_version"]
    if not isinstance(schema_version, str):
        raise EnvelopeMalformedError(
            f"envelope key 'schema_version' must be a string, got {type(schema_version).__name__}",
            path=path,
        )

    written_at_raw = loaded["written_at"]
    written_at = _parse_datetime(written_at_raw, path=path)

    written_by = loaded["written_by_extractor_version"]
    if not isinstance(written_by, str):
        raise EnvelopeMalformedError(
            f"envelope key 'written_by_extractor_version' must be a string, "
            f"got {type(written_by).__name__}",
            path=path,
        )

    baseline = loaded["baseline"]
    if not isinstance(baseline, dict):
        raise EnvelopeMalformedError(
            f"envelope key 'baseline' must be a mapping, got {type(baseline).__name__}",
            path=path,
        )

    return Envelope(
        schema_version=schema_version,
        written_at=written_at,
        written_by_extractor_version=written_by,
        baseline=dict(baseline),
    )


def _format_datetime(value: datetime) -> str:
    """Render ``value`` as an ISO-8601 string with UTC ``Z`` suffix."""
    if value.tzinfo is None:
        raise ValueError("written_at must be timezone-aware")
    return value.isoformat()


def _parse_datetime(value: object, *, path: Path) -> datetime:
    """Return ``value`` as a :class:`datetime` or raise EnvelopeMalformedError."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            raise EnvelopeMalformedError(
                f"envelope key 'written_at' is not a parseable ISO-8601 timestamp: {value!r}",
                path=path,
            ) from exc
    raise EnvelopeMalformedError(
        f"envelope key 'written_at' must be a datetime or ISO-8601 string, "
        f"got {type(value).__name__}",
        path=path,
    )
