"""Test-only helpers for the ``loki classify`` CLI suite (task 14+).

This module name has a single leading underscore so pytest does
not collect it as a test module. It hosts post-processing
helpers shared across the CLI test suite.

Determinism note: ``ClassificationRecord.timestamp`` is set by
the library to the run-start time per upstream R8.1, so two
runs on the same input produce JSON that differs in exactly
that field. Tests that assert byte-equal stdout strip the
field via ``strip_record_timestamps`` before comparing.
"""

from __future__ import annotations

import json
from typing import Any


def strip_record_timestamps(stdout_text: str) -> dict[str, Any]:
    """Parse stdout JSON and replace per-record ``timestamp`` with a sentinel.

    Returns a ``dict`` suitable for equality comparison: walks
    ``parsed["records"][*]["timestamp"]`` and rewrites each value
    to the literal ``"<TS>"`` so two runs of the same input
    compare equal modulo the run-start timestamp the library
    injects per upstream R8.1.

    The same normalization is applied to ``parsed["errors"][*]
    ["timestamp"]`` so the partial-cancellation marker (which
    carries its own ``datetime.now(tz=UTC)`` per the library)
    does not introduce per-run drift either.

    The function does not mutate ``stdout_text``; it returns a
    fresh ``dict`` per call.
    """
    payload: dict[str, Any] = json.loads(stdout_text)
    for record in payload.get("records", []):
        if "timestamp" in record:
            record["timestamp"] = "<TS>"
    for error in payload.get("errors", []):
        if "timestamp" in error:
            error["timestamp"] = "<TS>"
    return payload
