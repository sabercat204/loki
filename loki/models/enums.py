"""StrEnum types used across the LOKI data model layer.

All enums inherit from ``StrEnum`` (Python 3.11+) so they serialize to plain
strings in JSON and YAML without custom encoders.
"""

from enum import StrEnum

__all__ = [
    "ClassificationMethod",
    "ColorMode",
    "ComponentTypeLabel",
    "DeltaType",
    "LogLevel",
    "MatchStrategy",
    "MutabilityChange",
    "MutabilityLabel",
    "OutputFormat",
    "PostureRating",
    "SecurityDirection",
    "SecurityPostureLabel",
    "SeverityLevel",
    "SignatureDelta",
    "VendorLabel",
]


class ComponentTypeLabel(StrEnum):
    """Domain-specific labels for firmware component types."""

    UEFI_DRIVER = "UEFI_DRIVER"
    BOOTLOADER = "BOOTLOADER"
    OS_KERNEL = "OS_KERNEL"
    RUNTIME_SERVICE = "RUNTIME_SERVICE"
    SMM_MODULE = "SMM_MODULE"
    PEI_MODULE = "PEI_MODULE"
    DXE_DRIVER = "DXE_DRIVER"
    OPTION_ROM = "OPTION_ROM"
    MICROCODE = "MICROCODE"
    ACPI_TABLE = "ACPI_TABLE"
    EMBEDDED_CONTROLLER = "EMBEDDED_CONTROLLER"
    CONFIGURATION_DATA = "CONFIGURATION_DATA"
    UNKNOWN = "UNKNOWN"


class VendorLabel(StrEnum):
    """Vendor identifiers for firmware component attribution."""

    INTEL = "INTEL"
    AMD = "AMD"
    ARM = "ARM"
    QUALCOMM = "QUALCOMM"
    BROADCOM = "BROADCOM"
    NVIDIA = "NVIDIA"
    MICROSOFT = "MICROSOFT"
    APPLE = "APPLE"
    SAMSUNG = "SAMSUNG"
    PHOENIX = "PHOENIX"
    AMI = "AMI"
    INSYDE = "INSYDE"
    UNKNOWN = "UNKNOWN"


class SecurityPostureLabel(StrEnum):
    """Security posture classification for a firmware component."""

    SECURE = "SECURE"
    VULNERABLE = "VULNERABLE"
    UNKNOWN = "UNKNOWN"


class MutabilityLabel(StrEnum):
    """Mutability classification for a firmware component."""

    READONLY = "READONLY"
    MUTABLE = "MUTABLE"
    UNKNOWN = "UNKNOWN"


class ClassificationMethod(StrEnum):
    """Method used to classify a firmware component axis."""

    SIGNATURE = "SIGNATURE"
    RULE = "RULE"
    HEURISTIC = "HEURISTIC"


class DeltaType(StrEnum):
    """Type of change detected between baseline and target firmware."""

    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
    RECLASSIFIED = "RECLASSIFIED"
    UNCHANGED = "UNCHANGED"


class SeverityLevel(StrEnum):
    """Severity level for analysis findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PostureRating(StrEnum):
    """Overall security posture rating for a firmware image or fleet."""

    COMPROMISED = "COMPROMISED"
    AT_RISK = "AT_RISK"
    DEGRADED = "DEGRADED"
    BASELINE = "BASELINE"
    HARDENED = "HARDENED"


class SecurityDirection(StrEnum):
    """Direction of security change between baseline and target."""

    DEGRADED = "DEGRADED"
    UNCHANGED = "UNCHANGED"
    IMPROVED = "IMPROVED"


class SignatureDelta(StrEnum):
    """Change in code-signing signature status between baseline and target."""

    LOST = "LOST"
    GAINED = "GAINED"
    CHANGED = "CHANGED"
    NONE = "NONE"


class MutabilityChange(StrEnum):
    """Change in mutability status between baseline and target."""

    BECAME_MUTABLE = "BECAME_MUTABLE"
    BECAME_READONLY = "BECAME_READONLY"
    NONE = "NONE"


class OutputFormat(StrEnum):
    """Output format for CLI and report generation."""

    HUMAN = "HUMAN"
    JSON = "JSON"
    YAML = "YAML"


class ColorMode(StrEnum):
    """Color mode for CLI output."""

    AUTO = "AUTO"
    ALWAYS = "ALWAYS"
    NEVER = "NEVER"


class LogLevel(StrEnum):
    """Log verbosity level."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class MatchStrategy(StrEnum):
    """Match strategy for resolving the Matched_Baseline (analysis-engine R2.1).

    The analysis engine selects the Matched_Baseline using one of three
    strategies carried on ``AnalysisConfig.match_strategy``:

    - ``EXPLICIT``: use ``AnalysisConfig.baseline_id`` only; raises
      ``BaselineNotFoundError`` if the lookup misses.
    - ``AUTO``: auto-match by ``(target.vendor, target.model,
      target.firmware_version)`` only; raises ``BaselineNotFoundError`` if
      the lookup misses.
    - ``EXPLICIT_OR_AUTO``: try the explicit lookup first when
      ``baseline_id`` is set, otherwise fall back to auto-match. A
      mid-flight explicit miss does NOT silently fall back to auto-match
      (analysis-engine R2.5).
    """

    EXPLICIT = "EXPLICIT"
    AUTO = "AUTO"
    EXPLICIT_OR_AUTO = "EXPLICIT_OR_AUTO"
