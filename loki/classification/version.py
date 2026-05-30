"""Classification pipeline semantic version.

Defines ``CLASSIFICATION_VERSION`` per Requirement 1.5
(``^\\d+\\.\\d+\\.\\d+$`` form). Bumped on a minor version when
any rule-evaluation behavior changes.

Bumping is currently a manual discipline; future work could
enforce semantic-version bumps via a property test that
compares record outputs across versions and fails when the
``classification_version`` did not move.
"""

CLASSIFICATION_VERSION: str = "1.0.0"

__all__: list[str] = ["CLASSIFICATION_VERSION"]
