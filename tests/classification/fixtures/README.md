
# Classification fixtures

Deterministic test fixtures for the classification pipeline.

## Files

- `synthetic_components.py` — `build_components(*, count, source_image_id, include_inner)`
  returns a deterministic `list[ExtractedComponent]`. Component
  IDs derive from `uuid5(LOKI_NAMESPACE, ...)` seeds so the output
  is byte-identical across runs and hosts.
- `synthetic_rules.py` — `build_rule_files(rules_dir, axis_distribution)`
  writes deterministic YAML rule files into `rules_dir` and
  returns the expected `RuleSet`. Used by the loader / classifier
  / pipeline tests as their primary rule input.
- `golden/canonical_rules_v1.yaml` — committed canonical rule
  file consumed by `tests/classification/test_golden.py`.
  References the synthetic-component fixture's GUIDs by their
  exact `uuid5` derivation.
- `golden/canonical_classifications_v1.json` — committed
  expected output for `classify_components(build_components(count=4),
  config)` against `canonical_rules_v1.yaml`. Records are
  rendered via `model_dump(mode="json")` with the `timestamp`
  field stripped.

## Regenerating the golden snapshot

The golden snapshot is intentionally version-suffixed so any
intentional change creates a new file rather than overwriting
history. When the rule schema, the classifier, the signature
detector, or the pipeline changes in a way that affects record
contents:

1. Bump the suffix on both fixture files (e.g. `_v2.yaml` /
   `_v2.json`).
2. Update `tests/classification/test_golden.py` to point at the
   new files.
3. Generate the new JSON snapshot:

   ```bash
   .venv/bin/python -c "
   import json, shutil, tempfile
   from pathlib import Path
   from loki.classification import classify_components
   from loki.models.config import ClassificationConfig
   from tests.classification.fixtures import build_components

   with tempfile.TemporaryDirectory() as tmp:
       tmp_path = Path(tmp)
       rules_dir = tmp_path / 'rules'
       rules_dir.mkdir()
       shutil.copy(
           'tests/classification/fixtures/golden/canonical_rules_v2.yaml',
           rules_dir / 'canonical.yaml',
       )
       components = build_components(count=4)
       config = ClassificationConfig(
           taxonomy_version='1.0.0',
           confidence_threshold=0.6,
           rules_path=str(rules_dir),
       )
       result = classify_components(components, config)
       dumps = []
       for record in result.records:
           d = record.model_dump(mode='json')
           d.pop('timestamp', None)
           dumps.append(d)
       print(json.dumps(dumps, indent=2, sort_keys=True))
   " > tests/classification/fixtures/golden/canonical_classifications_v2.json
   ```

4. Commit both new files and the updated test.

Do **not** overwrite `_v1` files in place. Keeping prior versions
makes it possible to bisect regressions across schema changes.

## Why these specific GUIDs

The canonical rules use the exact GUIDs produced by
`build_components(count=4)` so the rules fire in known ways:

- Component 0's GUID matches `golden.type.000` (UEFI_DRIVER)
- Component 1's GUID matches `golden.vendor.000` (INTEL)
- Component 2's GUID matches `golden.security.000` (SECURE)
- Component 3's GUID matches `golden.mutability.000` (READONLY)

If `synthetic_components.py`'s `_FIXTURE_NAMESPACE` ever changes,
the GUIDs will shift and the canonical YAML must be regenerated:

```bash
.venv/bin/python -c "
import uuid
from loki.models import LOKI_NAMESPACE
ns = uuid.uuid5(LOKI_NAMESPACE, 'tests.classification.fixtures')
for i in range(4):
    print(i, uuid.uuid5(ns, f'comp-guid-{i}'))
"
```
