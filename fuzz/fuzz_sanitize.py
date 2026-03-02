# SPDX-License-Identifier: MIT
"""Fuzz harness for navi-bootstrap sanitization.

Targets: sanitize_spec() and sanitize_manifest() — the two
untrusted-input entry points.

Invariants checked:
  - sanitize_spec() never raises on valid structure
  - sanitize_spec() always returns dict
  - sanitize_spec() output contains no null bytes
  - sanitize_manifest() never raises on valid structure
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from navi_bootstrap.sanitize import sanitize_manifest, sanitize_spec


def _make_spec(fdp: atheris.FuzzedDataProvider) -> dict:
    """Build a minimal valid spec from fuzzed data."""
    return {
        "name": fdp.ConsumeUnicode(50),
        "language": "python",
        "description": fdp.ConsumeUnicode(100),
        "structure": {
            "src_dir": fdp.ConsumeUnicode(30),
            "test_dir": fdp.ConsumeUnicode(30),
        },
        "modules": [
            {"name": fdp.ConsumeUnicode(30), "description": fdp.ConsumeUnicode(50)}
            for _ in range(fdp.ConsumeIntInRange(0, 3))
        ],
    }


def _make_manifest(fdp: atheris.FuzzedDataProvider) -> dict:
    """Build a minimal valid manifest from fuzzed data."""
    return {
        "name": fdp.ConsumeUnicode(30),
        "version": "0.1.0",
        "description": fdp.ConsumeUnicode(100),
        "templates": [
            {"src": "file.j2", "dest": fdp.ConsumeUnicode(50)}
            for _ in range(fdp.ConsumeIntInRange(0, 3))
        ],
    }


def fuzz_spec(data: bytes) -> None:
    """Fuzz sanitize_spec with constructed spec dicts."""
    fdp = atheris.FuzzedDataProvider(data)
    spec = _make_spec(fdp)

    result = sanitize_spec(spec)

    # Invariant: always returns dict
    assert isinstance(result, dict)

    # Invariant: no null bytes in any string value
    for v in _extract_strings(result):
        assert "\x00" not in v


def fuzz_manifest(data: bytes) -> None:
    """Fuzz sanitize_manifest with constructed manifest dicts."""
    fdp = atheris.FuzzedDataProvider(data)
    manifest = _make_manifest(fdp)

    result = sanitize_manifest(manifest)

    # Invariant: always returns dict
    assert isinstance(result, dict)

    # Invariant: no null bytes
    for v in _extract_strings(result):
        assert "\x00" not in v


def _extract_strings(obj: object) -> list[str]:
    """Recursively extract all string values from a nested structure."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_extract_strings(item))
    return strings


def main() -> None:
    atheris.Setup(sys.argv, fuzz_spec)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
