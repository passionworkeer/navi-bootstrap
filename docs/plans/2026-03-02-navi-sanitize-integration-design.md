# Design: Wire navi-sanitize into navi-bootstrap

**Date:** 2026-03-02
**Author:** Alpha
**Status:** Approved

## Goal

Replace the 288-line hand-rolled sanitization pipeline in `sanitize.py` with
`navi-sanitize`, the production-grade standalone library extracted from this
very codebase. Delete all superseded code, wire navi-sanitize everywhere
untrusted text enters the system.

## What gets deleted (~218 lines)

All internal implementation in `sanitize.py`:

- `HOMOGLYPH_MAP` — 42-pair lookup table (navi-sanitize has 51)
- `ZERO_WIDTH_CHARS` + `_ZERO_WIDTH_RE` — 6 chars (navi-sanitize covers 411+
  including Tag block U+E0001–E007F and bidi overrides/isolates)
- `_JINJA2_DELIMITERS` — regex for Jinja2 delimiter detection
- `_strip_null_bytes()` — superseded by `clean()` stage 1
- `_strip_zero_width()` — superseded by `clean()` stage 2
- `_normalize_fullwidth()` — superseded by `clean()` stage 3
- `_replace_homoglyphs()` — superseded by `clean()` stage 4
- `_escape_jinja2()` — superseded by `jinja2_escaper`
- `_sanitize_path()` — superseded by `path_escaper`
- `_sanitize_string()` — 5-stage orchestrator, superseded by `clean()` (6-stage)
- `_walk_and_sanitize()` — recursive walker, superseded by `walk()`
- Old imports: `re`, `unicodedata`

## What stays (rewritten, ~40 lines)

Two thin domain wrappers that encode which-fields-get-which-escaper:

### `sanitize_spec(spec_data) -> dict`

```python
from navi_sanitize import clean, walk, jinja2_escaper, path_escaper

def sanitize_spec(spec_data):
    # 1. Deep-copy + full pipeline + jinja2 escaping on all strings
    spec = walk(spec_data, escaper=jinja2_escaper)

    # 2. Path fields get additional traversal stripping
    _sanitize_path_field(spec, "name")
    if "structure" in spec and isinstance(spec["structure"], dict):
        for key in ("src_dir", "test_dir", "docs_dir"):
            _sanitize_path_field(spec["structure"], key)

    # 3. Module names
    if "modules" in spec and isinstance(spec["modules"], list):
        for mod in spec["modules"]:
            if isinstance(mod, dict):
                _sanitize_path_field(mod, "name")

    return spec
```

### `sanitize_manifest(manifest_data) -> dict`

```python
def sanitize_manifest(manifest_data):
    manifest = deepcopy(manifest_data)

    # String fields: full pipeline + jinja2 escaping
    for key in ("name", "description", "version"):
        if key in manifest and isinstance(manifest[key], str):
            manifest[key] = clean(manifest[key], escaper=jinja2_escaper)

    # Dest paths: full pipeline + path escaping only (no jinja escape —
    # dest values are legitimate Jinja2 templates for looped rendering)
    if "templates" in manifest and isinstance(manifest["templates"], list):
        for entry in manifest["templates"]:
            if isinstance(entry, dict) and "dest" in entry:
                if isinstance(entry["dest"], str):
                    entry["dest"] = clean(entry["dest"], escaper=path_escaper)

    return manifest
```

## What improves (for free)

| Dimension | Before | After |
|-----------|--------|-------|
| Homoglyph pairs | 42 | 51 (adds Armenian, Cherokee) |
| Invisible char coverage | 6 zero-width | 411+ (zero-width + Tag block + bidi) |
| Pipeline stages | 5 | 6 (adds re-NFKC for idempotency) |
| Idempotency | Not guaranteed | `clean(clean(x)) == clean(x)` |
| LOC in sanitize.py | 288 | ~40 |

## Dependency change

`pyproject.toml`:
```toml
dependencies = [
    "click>=8.1.0",
    "jinja2>=3.1.0",
    "navi-sanitize>=0.1.0",   # NEW
    "pyyaml>=6.0",
    "jsonschema>=4.20.0",
]
```

## CLI changes

None. `cli.py` keeps importing `from navi_bootstrap.sanitize import sanitize_manifest, sanitize_spec`.

## Test changes

Tests capture warnings via `caplog.at_level(logging.WARNING, logger="navi_bootstrap.sanitize")`.
After this change, pipeline warnings (null bytes, invisibles, homoglyphs, fullwidth) come from
the `navi_sanitize` logger. Update all test logger captures to `navi_sanitize`.

Test conftest fixtures (hostile payloads) are test data, not implementation — they stay unchanged.

## Untrusted text entry points (all covered)

1. **Spec loading** — `load_spec()` reads JSON from user file → `sanitize_spec()` in CLI
2. **Manifest loading** — `load_manifest()` reads YAML from pack → `sanitize_manifest()` in CLI
3. **init command** — `inspect_project()` reads pyproject.toml metadata → `sanitize_spec()` in CLI
4. **Dest path rendering** — `_render_dest_path()` uses SandboxedEnvironment (separate defense)
5. **Template rendering** — Jinja2 with StrictUndefined (separate defense, sanitized inputs)
6. **Hooks** — shell commands gated by `--trust` flag (separate defense, not sanitization)

All text sanitization flows through `sanitize_spec()` or `sanitize_manifest()` in `cli.py`.
No additional wiring needed — the existing call sites are correct.
