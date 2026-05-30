"""loki.baseline — GLEIPNIR persistence layer.

Move :class:`~loki.models.BaselineRecord` and
:class:`~loki.models.BaselineRegistry` instances between memory and a
YAML directory layout on disk. The model layer (``loki.models``) owns
the data contract; this subsystem owns the storage, retrieval, and
lifecycle contract.

Concurrency contract (R5.6):

- Single-host, multi-process safe for **non-overlapping** baselines.
- Overlapping concurrent writes raise
  :class:`BaselineConcurrentModificationError` rather than silently
  merging. There are no lock files in v1; safety is provided by
  ``Atomic_Write`` plus an mtime/size check.
"""

from loki.baseline.errors import (
    BaselineAlreadyExistsError,
    BaselineConcurrentModificationError,
    BaselineNotFoundError,
    BaselineSerializationError,
    BaselineStorageUnwritableError,
    BaselineStoreError,
)
from loki.baseline.quarantine import QuarantineEntry, QuarantineSet
from loki.baseline.schema import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS
from loki.baseline.store import (
    BaselineStore,
    CancellationToken,
    LoadProgressCallback,
    LoadProgressEvent,
    LoadResult,
)

__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "BaselineAlreadyExistsError",
    "BaselineConcurrentModificationError",
    "BaselineNotFoundError",
    "BaselineSerializationError",
    "BaselineStorageUnwritableError",
    "BaselineStore",
    "BaselineStoreError",
    "CancellationToken",
    "LoadProgressCallback",
    "LoadProgressEvent",
    "LoadResult",
    "QuarantineEntry",
    "QuarantineSet",
]
