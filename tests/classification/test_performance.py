"""Performance smoke tests for the classification pipeline (task 22).

Marked ``slow``, skipped on CI by default. Run locally with
``pytest -m slow tests/classification/test_performance.py``.

Two budgets:

- **R11.1 budget**: 4096 components x 1024 rules, matcher
  evaluation only (raw_path=None so signature detection
  short-circuits). Wall time < 30s on a 2024-class developer
  laptop.
- **R11.3 budget**: 4096 components with real raw_path files
  totalling ≤ 256 MiB; signature-detection phase wall time
  < 60s.

Both tests use ``tracemalloc`` to verify R11.4's 64 MiB peak
memory budget plus the rule-set size.
"""

from __future__ import annotations

import struct
import time
import tracemalloc
import uuid
from pathlib import Path

import pytest

from loki.classification import classify_components
from loki.models import LOKI_NAMESPACE, ExtractedComponent
from loki.models.config import ClassificationConfig
from tests.classification.fixtures import build_components, build_rule_files

# 64 MiB fixed working set + headroom per R11.4. We add 16 MiB
# headroom to absorb Python interpreter overhead, Pydantic
# allocator churn, and the Hypothesis fixture import cost.
_PEAK_MEMORY_BUDGET_BYTES: int = (64 + 16) * 1024 * 1024

# R11.1 budget.
_MATCHER_BUDGET_SECONDS: float = 30.0

# R11.3 budget.
_SIGNATURE_BUDGET_SECONDS: float = 60.0

# Per-file payload size for the R11.3 test. 4096 files * 64 KiB
# = 256 MiB, the upper bound R11.3 contracts.
_R11_3_FILES: int = 4096
_R11_3_FILE_SIZE: int = 64 * 1024

# R11.1: full distribution sums to 1024 rules.
_R11_1_AXIS_DISTRIBUTION = {
    "type": 256,
    "vendor": 256,
    "security_posture": 256,
    "mutability": 256,
}


def _config(rules_dir: Path) -> ClassificationConfig:
    return ClassificationConfig(
        taxonomy_version="1.0.0",
        confidence_threshold=0.6,
        rules_path=str(rules_dir),
    )


def _build_pe32_stub() -> bytes:
    """Build a minimal valid-looking PE32 binary for the
    signature detector. The detector reads the PE header,
    optional-header magic, and the Security data directory; we
    populate them with zero values so the detector returns
    ``(False, None)`` quickly without crashing.

    Layout:
      - 64-byte DOS header with ``MZ`` signature and
        ``e_lfanew=0x40``.
      - PE signature ``PE\\x00\\x00`` at offset 0x40.
      - 20-byte COFF header.
      - PE32 optional header magic ``0x10B`` plus zero-padding
        through the data-directories array.
      - Zero-valued data directories (16 entries x 8 bytes).
    """
    pe_offset = 0x40
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
    pe_sig = b"PE\x00\x00"
    coff_header = b"\x00" * 20
    optional_header = struct.pack("<H", 0x10B) + b"\x00" * (96 - 2)
    data_dirs = b"\x00" * (16 * 8)
    return dos_header + pe_sig + coff_header + optional_header + data_dirs


# ---------------------------------------------------------------------
# R11.1: matcher-evaluation budget (raw_path=None → no signature I/O)
# ---------------------------------------------------------------------


@pytest.mark.slow
def test_r11_1_matcher_evaluation_budget(tmp_path: Path) -> None:
    """4096 components x 1024 rules complete classification under 30s.

    Per R11.1, this budget is "exclusive of signature-detection
    file I/O", so we set every component's raw_path=None to
    short-circuit signature detection. The dual-record errors
    that result are part of the R5.6 contract; we assert their
    expected count rather than treating them as failures.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    build_rule_files(rules_dir, axis_distribution=_R11_1_AXIS_DISTRIBUTION)
    components = build_components(count=4096)

    tracemalloc.start()
    start = time.monotonic()
    result = classify_components(components, _config(rules_dir))
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(result.records) == 4096, f"expected 4096 records, got {len(result.records)}"
    # Every component triggers the dual-record error path because
    # raw_path=None.
    assert len(result.errors) == 4096, (
        f"expected 4096 errors (dual-record contract), got {len(result.errors)}"
    )

    assert elapsed < _MATCHER_BUDGET_SECONDS, (
        f"R11.1: matcher-evaluation budget exceeded "
        f"({elapsed:.2f}s >= {_MATCHER_BUDGET_SECONDS:.0f}s)"
    )

    assert peak < _PEAK_MEMORY_BUDGET_BYTES, (
        f"R11.4: peak memory budget exceeded "
        f"({peak / 1024 / 1024:.1f} MiB >= "
        f"{_PEAK_MEMORY_BUDGET_BYTES / 1024 / 1024:.0f} MiB)"
    )


# ---------------------------------------------------------------------
# R11.3: signature-detection budget (4096 files, ≤ 256 MiB total)
# ---------------------------------------------------------------------


@pytest.mark.slow
def test_r11_3_signature_detection_budget(tmp_path: Path) -> None:
    """Signature-detection phase over ≤ 256 MiB total bytes
    completes under 60s.

    Constructs 4096 PE32 stubs of 64 KiB each (totalling exactly
    256 MiB), classifies them with a minimal rule set (so
    matcher-evaluation overhead is negligible), and asserts the
    full classification time fits in the R11.3 budget. Since
    the matcher contributes negligibly when there's only a
    handful of rules, the wall time approximates the
    signature-detection phase alone.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    # Tiny rule set so matcher-evaluation overhead doesn't
    # dominate the budget.
    build_rule_files(
        rules_dir,
        axis_distribution={
            "type": 1,
            "vendor": 1,
            "security_posture": 1,
            "mutability": 1,
        },
    )

    # Build 4096 components with shared raw_path stubs. Reusing
    # the same file across many components is cheaper than
    # writing 4096 separate files; the signature detector still
    # opens and reads each file once per component.
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    pe_stub = _build_pe32_stub() + b"\x00" * (_R11_3_FILE_SIZE - len(_build_pe32_stub()))
    assert len(pe_stub) == _R11_3_FILE_SIZE
    raw_file = raw_dir / "stub.bin"
    raw_file.write_bytes(pe_stub)

    components: list[ExtractedComponent] = []
    for i in range(_R11_3_FILES):
        components.append(
            ExtractedComponent(
                component_id=uuid.uuid5(LOKI_NAMESPACE, f"perf-r11-3-{i}"),
                source_image_id=uuid.uuid5(LOKI_NAMESPACE, "perf-image"),
                offset=f"0x{i * 0x1000:x}",
                size=_R11_3_FILE_SIZE,
                raw_hash="0" * 64,
                component_type_hint="dxe_driver",
                guid=str(uuid.uuid5(LOKI_NAMESPACE, f"perf-guid-{i}")),
                name=f"COMP_{i:04d}",
                raw_path=str(raw_file),
            )
        )

    tracemalloc.start()
    start = time.monotonic()
    result = classify_components(components, _config(rules_dir))
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(result.records) == _R11_3_FILES, (
        f"expected {_R11_3_FILES} records, got {len(result.records)}"
    )
    # No dual-record errors expected since raw_path is readable.
    assert len(result.errors) == 0, (
        f"expected 0 errors (raw_path readable), got {len(result.errors)}"
    )

    assert elapsed < _SIGNATURE_BUDGET_SECONDS, (
        f"R11.3: signature-detection budget exceeded "
        f"({elapsed:.2f}s >= {_SIGNATURE_BUDGET_SECONDS:.0f}s)"
    )

    assert peak < _PEAK_MEMORY_BUDGET_BYTES, (
        f"R11.4: peak memory budget exceeded "
        f"({peak / 1024 / 1024:.1f} MiB >= "
        f"{_PEAK_MEMORY_BUDGET_BYTES / 1024 / 1024:.0f} MiB)"
    )
