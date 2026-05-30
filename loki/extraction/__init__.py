"""loki.extraction - firmware extraction pipeline.

Public entry point::

    from loki.extraction import extract_firmware
    result = extract_firmware(path, config)

Scope: turn a firmware binary on disk into a validated
``ExtractionManifest``. Classification, baseline comparison, and
analysis are explicitly out of scope and have their own subsystems.
"""

from loki.extraction.api import (
    EXTRACTOR_VERSION,
    CancellationToken,
    ExtractionResult,
    PipelineConfig,
    ProgressCallback,
    ProgressEvent,
    extract_firmware,
)
from loki.extraction.errors import (
    ExtractionPipelineError,
    InvalidInputError,
    ManifestConstructionError,
    ToolFailedError,
    ToolTimedOutError,
    ToolWrapperError,
)

__all__ = [
    "EXTRACTOR_VERSION",
    "CancellationToken",
    "ExtractionPipelineError",
    "ExtractionResult",
    "InvalidInputError",
    "ManifestConstructionError",
    "PipelineConfig",
    "ProgressCallback",
    "ProgressEvent",
    "ToolFailedError",
    "ToolTimedOutError",
    "ToolWrapperError",
    "extract_firmware",
]
