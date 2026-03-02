# navi-sanitize Integration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the 287-line hand-rolled sanitization pipeline with navi-sanitize, deleting ~218 lines of superseded code while preserving all 44 sanitize-related tests.

**Architecture:** Add navi-sanitize as a dependency. Rewrite `sanitize.py` to thin domain wrappers (~40 lines) that call `navi_sanitize.clean()`, `walk()`, `jinja2_escaper`, and `path_escaper`. Update test logger captures from `navi_bootstrap.sanitize` to `navi_sanitize`. CLI callers unchanged.

**Tech Stack:** navi-sanitize>=0.1.0 (stdlib-only, zero transitive deps)

---

### Task 1: Add navi-sanitize dependency

**Files:**
- Modify: `pyproject.toml:23-28`

**Step 1: Add dependency**

In `pyproject.toml`, add `navi-sanitize>=0.1.0` to the `dependencies` list:

```toml
dependencies = [
    "click>=8.1.0",
    "jinja2>=3.1.0",
    "jsonschema>=4.20.0",
    "navi-sanitize>=0.1.0",
    "pyyaml>=6.0",
]
```

**Step 2: Sync**

Run: `uv sync`
Expected: Resolves and installs navi-sanitize 0.1.0

**Step 3: Verify import**

Run: `uv run python -c "from navi_sanitize import clean, walk, jinja2_escaper, path_escaper; print('OK')"`
Expected: `OK`

**Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "feat: add navi-sanitize dependency"
```

---

### Task 2: Rewrite sanitize.py

**Files:**
- Modify: `src/navi_bootstrap/sanitize.py` (full rewrite, 287 → ~45 lines)

**Step 1: Run existing tests to confirm green baseline**

Run: `uv run pytest tests/adversarial/ tests/test_dest_sanitize.py -v`
Expected: 44 passed

**Step 2: Rewrite sanitize.py**

Replace the entire file with:

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Project Navi

"""Input sanitization for hostile spec and manifest values.

Thin domain wrappers around navi-sanitize. Encodes which fields get
which escaper — all pipeline logic lives in navi-sanitize.
"""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any

from navi_sanitize import clean, jinja2_escaper, path_escaper, walk

logger = logging.getLogger("navi_bootstrap.sanitize")


def _apply_path_escaper(obj: dict[str, Any], key: str) -> None:
    """Apply path_escaper to a specific key in a dict, if present and str."""
    if key in obj and isinstance(obj[key], str):
        obj[key] = path_escaper(obj[key])


def sanitize_spec(spec_data: dict[str, Any]) -> dict[str, Any]:
    """Sanitize a loaded spec dict. Returns cleaned copy.

    All string values get the full navi-sanitize pipeline (null bytes,
    invisibles, NFKC, homoglyphs, re-NFKC) plus Jinja2 delimiter escaping.
    Path fields additionally get traversal stripping.
    """
    spec: dict[str, Any] = walk(spec_data, escaper=jinja2_escaper)

    # Path fields: additional traversal stripping
    _apply_path_escaper(spec, "name")
    if isinstance(spec.get("structure"), dict):
        for key in ("src_dir", "test_dir", "docs_dir"):
            _apply_path_escaper(spec["structure"], key)

    # Module names are path-like
    if isinstance(spec.get("modules"), list):
        for mod in spec["modules"]:
            if isinstance(mod, dict):
                _apply_path_escaper(mod, "name")

    return spec


def sanitize_manifest(manifest_data: dict[str, Any]) -> dict[str, Any]:
    """Sanitize a loaded manifest dict. Returns cleaned copy.

    String fields (name, description, version) get full pipeline + Jinja2
    escaping. Template dest paths get full pipeline + path escaping only
    (no Jinja2 escaping — dest values are legitimate Jinja2 templates).
    """
    manifest = deepcopy(manifest_data)

    # String fields: full pipeline + jinja2 escaping
    for key in ("name", "description", "version"):
        if key in manifest and isinstance(manifest[key], str):
            manifest[key] = clean(manifest[key], escaper=jinja2_escaper)

    # Dest paths: full pipeline + path escaping (no jinja2 escaping)
    if isinstance(manifest.get("templates"), list):
        for entry in manifest["templates"]:
            if isinstance(entry, dict) and isinstance(entry.get("dest"), str):
                entry["dest"] = clean(entry["dest"], escaper=path_escaper)

    return manifest
```

**Step 3: Run the sanitize tests (expect failures — logger name mismatch)**

Run: `uv run pytest tests/adversarial/ tests/test_dest_sanitize.py -v 2>&1 | head -60`
Expected: Some tests fail because they capture on `navi_bootstrap.sanitize` logger but warnings now come from `navi_sanitize`

---

### Task 3: Update test logger captures

**Files:**
- Modify: `tests/adversarial/test_unicode_hostile.py` — change all `logger="navi_bootstrap.sanitize"` to `logger="navi_sanitize"`
- Modify: `tests/adversarial/test_template_injection.py` — same change
- Modify: `tests/adversarial/test_path_traversal.py` — same change
- Modify: `tests/adversarial/test_full_pipeline.py` — same change

**Step 1: Update logger name in test_unicode_hostile.py**

Replace all occurrences of `logger="navi_bootstrap.sanitize"` with `logger="navi_sanitize"` (8 occurrences).

**Step 2: Update logger name in test_template_injection.py**

Replace all occurrences of `logger="navi_bootstrap.sanitize"` with `logger="navi_sanitize"` (9 occurrences).

**Step 3: Update logger name in test_path_traversal.py**

Replace all occurrences of `logger="navi_bootstrap.sanitize"` with `logger="navi_sanitize"` (8 occurrences).

**Step 4: Update logger name in test_full_pipeline.py**

Replace all occurrences of `logger="navi_bootstrap.sanitize"` with `logger="navi_sanitize"` (4 occurrences).

**Step 5: Run sanitize tests — all should pass**

Run: `uv run pytest tests/adversarial/ tests/test_dest_sanitize.py -v`
Expected: 44 passed

**Step 6: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: 325 passed

**Step 7: Commit**

```bash
git add src/navi_bootstrap/sanitize.py tests/adversarial/
git commit -m "feat: replace sanitize pipeline with navi-sanitize

Delete 218 lines of hand-rolled sanitization code (homoglyph map,
zero-width chars, NFKC, jinja2 escaping, path traversal, recursive
walker). Replace with navi-sanitize library which provides:
- 51 homoglyph pairs (was 42)
- 411+ invisible char coverage (was 6 zero-width)
- 6-stage pipeline with re-NFKC for idempotency (was 5)
- Pluggable escaper pattern

sanitize_spec() and sanitize_manifest() remain as thin domain
wrappers encoding which-fields-get-which-escaper."
```

---

### Task 4: Run quality checks

**Step 1: Lint**

Run: `uv run ruff check src/navi_bootstrap/sanitize.py tests/adversarial/`
Expected: Clean

**Step 2: Format**

Run: `uv run ruff format --check src/navi_bootstrap/sanitize.py tests/adversarial/`
Expected: Clean

**Step 3: Type check**

Run: `uv run mypy src/navi_bootstrap/sanitize.py`
Expected: Clean (navi-sanitize ships py.typed)

**Step 4: Full test suite one more time**

Run: `uv run pytest tests/ -v`
Expected: 325 passed

**Step 5: Fix any issues found, amend or new commit as appropriate**

---

### Task 5: Verify navi-sanitize coverage improvements

Quick manual verification that the new pipeline catches things the old one missed.

**Step 1: Verify Tag block smuggling is now caught**

Run:
```bash
uv run python -c "
from navi_bootstrap.sanitize import sanitize_spec
spec = {'name': 'test\U000E0001hidden\U000E007F', 'language': 'python'}
result = sanitize_spec(spec)
print(repr(result['name']))
assert '\U000E0001' not in result['name'], 'Tag block not stripped!'
print('PASS: Tag block chars stripped')
"
```
Expected: `PASS: Tag block chars stripped`

**Step 2: Verify bidi override is now caught**

Run:
```bash
uv run python -c "
from navi_bootstrap.sanitize import sanitize_spec
spec = {'name': 'test\u202Ehidden\u202C', 'language': 'python'}
result = sanitize_spec(spec)
print(repr(result['name']))
assert '\u202E' not in result['name'], 'Bidi override not stripped!'
print('PASS: Bidi override stripped')
"
```
Expected: `PASS: Bidi override stripped`

**Step 3: Verify idempotency**

Run:
```bash
uv run python -c "
from navi_bootstrap.sanitize import sanitize_spec
spec = {'name': 'n\u0430vi', 'language': 'python', 'description': '\u0430\u03bf test'}
r1 = sanitize_spec(spec)
r2 = sanitize_spec(r1)
assert r1 == r2, f'Not idempotent: {r1} != {r2}'
print('PASS: Pipeline is idempotent')
"
```
Expected: `PASS: Pipeline is idempotent`
