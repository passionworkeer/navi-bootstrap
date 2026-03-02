# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Project Navi

"""Input sanitization for hostile spec and manifest values.

Thin domain wrappers around navi-sanitize. Encodes which fields get
which escaper — all pipeline logic lives in navi-sanitize.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from navi_sanitize import clean, jinja2_escaper, path_escaper, walk


def _clean_path_and_jinja(value: str) -> str:
    """Clean a path field: pipeline + path escaping, then jinja2 escaping.

    path_escaper replaces backslashes with forward slashes, so it must run
    before jinja2_escaper (which introduces backslash sequences like ``\\{``).
    """
    return jinja2_escaper(clean(value, escaper=path_escaper))


def _apply_path_jinja(obj: dict[str, Any], key: str) -> None:
    """Apply path+jinja2 cleaning to a specific key in a dict, if present and str."""
    if key in obj and isinstance(obj[key], str):
        obj[key] = _clean_path_and_jinja(obj[key])


def sanitize_spec(spec_data: dict[str, Any]) -> dict[str, Any]:
    """Sanitize a loaded spec dict. Returns cleaned copy.

    All string values get the full navi-sanitize pipeline (null bytes,
    invisibles, NFKC, homoglyphs, re-NFKC) plus Jinja2 delimiter escaping.
    Path fields additionally get traversal stripping.
    """
    spec: dict[str, Any] = walk(spec_data, escaper=jinja2_escaper)

    # Path fields need path escaping applied BEFORE jinja2 escaping.
    # Re-process these from raw spec_data so path_escaper sees the original
    # values before jinja2_escaper adds backslash sequences.
    raw = deepcopy(spec_data)

    _apply_path_jinja(raw, "name")
    if "name" in raw:
        spec["name"] = raw["name"]

    if isinstance(raw.get("structure"), dict) and isinstance(spec.get("structure"), dict):
        for key in ("src_dir", "test_dir", "docs_dir"):
            _apply_path_jinja(raw["structure"], key)
            if key in raw["structure"]:
                spec["structure"][key] = raw["structure"][key]

    # Module names are path-like
    if isinstance(raw.get("modules"), list) and isinstance(spec.get("modules"), list):
        for i, raw_mod in enumerate(raw["modules"]):
            if isinstance(raw_mod, dict) and i < len(spec["modules"]):
                _apply_path_jinja(raw_mod, "name")
                if "name" in raw_mod and isinstance(spec["modules"][i], dict):
                    spec["modules"][i]["name"] = raw_mod["name"]

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
