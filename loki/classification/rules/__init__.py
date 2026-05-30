"""Rule-set schema, loader, and matcher for classification rules.

Re-exports the public surface (``Effect``, ``Matcher``, ``Rule``,
``RuleSet``) from ``loki.classification.rules.schema``, plus the
``load_rule_set`` entry point and the ``matches`` evaluator.
Curators that build CLI / GUI tooling can import these without
reaching into private modules.
"""

from loki.classification.rules.loader import load_rule_set
from loki.classification.rules.matcher import matches
from loki.classification.rules.schema import (
    Effect,
    GuidPredicate,
    Matcher,
    NamePredicate,
    RawHashPredicate,
    Rule,
    RuleSet,
    SizePredicate,
    TypeHintPredicate,
)

__all__ = [
    "Effect",
    "GuidPredicate",
    "Matcher",
    "NamePredicate",
    "RawHashPredicate",
    "Rule",
    "RuleSet",
    "SizePredicate",
    "TypeHintPredicate",
    "load_rule_set",
    "matches",
]
