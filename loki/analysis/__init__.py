"""Analysis engine subsystem for the LOKI platform.

Produces ``FindingRecord`` and ``DeviationScore`` instances by comparing
``ClassificationRecord`` sets against ``BaselineRegistry`` entries. Single
public entry point ``analyze_image`` exposed once Wave 6 lands; this is
the v0.1.0 scaffold (Wave 1 of the implementation plan).

See ``.kiro/specs/analysis-engine/{requirements,design,tasks}.md`` for the
full contract.
"""

from loki.analysis.api import (
    AnalysisCancellationToken,
    AnalysisProgressCallback,
    AnalysisProgressEvent,
    analyze_image,
)
from loki.analysis.errors import (
    AnalysisConfigError,
    AnalysisError,
    AnalysisInputError,
    AnalysisReportConstructionError,
    BaselineNotFoundError,
)
from loki.analysis.version import ANALYSIS_VERSION

__all__ = [
    "ANALYSIS_VERSION",
    "AnalysisCancellationToken",
    "AnalysisConfigError",
    "AnalysisError",
    "AnalysisInputError",
    "AnalysisProgressCallback",
    "AnalysisProgressEvent",
    "AnalysisReportConstructionError",
    "BaselineNotFoundError",
    "analyze_image",
]
