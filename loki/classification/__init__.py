"""Classification pipeline for the LOKI firmware analysis platform.

Turns ``ExtractedComponent`` records produced by the extraction
pipeline into validated ``ClassificationRecord`` instances along
the four taxonomic axes (type, vendor, security posture,
mutability). Public entry point is ``classify_components``.

The subsystem is synchronous, single-threaded, and deterministic:
same input + same Rule_Set produces the same records modulo the
run-start ``timestamp`` field. Determinism is enforced by an
AST-based no-side-channels audit and by Hypothesis property
tests.
"""

from loki.classification.api import (
    CancellationToken,
    ClassificationResult,
    ProgressCallback,
    ProgressEvent,
    classify_components,
)
from loki.classification.errors import (
    ClassificationConfigError,
    ClassificationError,
    ClassificationPipelineError,
    ClassificationRuleError,
)
from loki.classification.rules import Effect, Matcher, Rule, RuleSet
from loki.classification.version import CLASSIFICATION_VERSION

__all__ = [
    "CLASSIFICATION_VERSION",
    "CancellationToken",
    "ClassificationConfigError",
    "ClassificationError",
    "ClassificationPipelineError",
    "ClassificationResult",
    "ClassificationRuleError",
    "Effect",
    "Matcher",
    "ProgressCallback",
    "ProgressEvent",
    "Rule",
    "RuleSet",
    "classify_components",
]
