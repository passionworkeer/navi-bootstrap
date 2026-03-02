# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Project Navi

"""Manifest loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml


def _find_schema(filename: str) -> Path:
    """Find schema file — works in both installed wheel and editable install."""
    # Installed wheel: navi_bootstrap/schema/
    pkg_path = Path(__file__).parent / "schema" / filename
    if pkg_path.exists():
        return pkg_path
    # Editable install: repo_root/schema/
    dev_path = Path(__file__).parent.parent.parent / "schema" / filename
    if dev_path.exists():
        return dev_path
    msg = f"Schema not found: {filename}"
    raise FileNotFoundError(msg)


class ManifestError(Exception):
    """Raised when a manifest is invalid or cannot be loaded."""


def _load_schema() -> dict[str, Any]:
    """Load the YAML schema for manifest validation."""
    return cast(dict[str, Any], yaml.safe_load(_find_schema("manifest-schema.yaml").read_text()))


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Validate a manifest dict against the schema. Raises ManifestError on failure."""
    schema = _load_schema()
    try:
        jsonschema.validate(instance=manifest, schema=schema)
    except jsonschema.ValidationError as e:
        raise ManifestError(f"Manifest validation failed: {e.message}") from e


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate a manifest from a YAML file. Returns the manifest dict."""
    if not path.exists():
        raise ManifestError(f"Manifest file not found: {path}")
    try:
        manifest = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ManifestError(f"Failed to parse manifest YAML: {e}") from e
    if not isinstance(manifest, dict):
        raise ManifestError("Manifest must be a YAML mapping")
    validate_manifest(manifest)
    return manifest
