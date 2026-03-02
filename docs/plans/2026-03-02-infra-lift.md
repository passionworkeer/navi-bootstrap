# Infra Lift Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bring navi-bootstrap's CI/CD, security, governance, and developer experience to parity with navi-sanitize and grippy-code-review.

**Architecture:** Port known-good configs from sibling repos, adapting paths and project names. All tasks are independent — no ordering constraints. Parallel subagent dispatch is safe.

**Tech Stack:** GitHub Actions, Semgrep, Atheris, pip-audit, Codecov, git-cliff, mypy strict

---

### Task 1: Add Semgrep SAST workflow

**Files:**
- Create: `.github/workflows/semgrep.yml`

**Step 1: Create the workflow**

```yaml
name: Semgrep SAST

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  semgrep:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    container:
      image: semgrep/semgrep:1.152.0
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Run Semgrep
        run: semgrep scan --config p/python --config p/owasp-top-ten --sarif -o semgrep.sarif .
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@28deaeda66b76a05916b6923827895f2b60cf3df # v3.28.16
        if: always()
        with:
          sarif_file: semgrep.sarif
```

Note: Use the same checkout SHA that navi-bootstrap already uses in its other workflows. Use the codeql-action SHA from the existing `codeql.yml`.

**Step 2: Verify syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/semgrep.yml')); print('valid')"`
Expected: `valid`

**Step 3: Commit**

```bash
git add .github/workflows/semgrep.yml
git commit -m "ci: add Semgrep SAST workflow

Python + OWASP Top Ten rulesets with SARIF upload to GitHub
Security tab. Ported from navi-sanitize."
```

---

### Task 2: Add Atheris fuzz harness + workflow

**Files:**
- Create: `fuzz/fuzz_sanitize.py`
- Create: `.github/workflows/fuzz.yml`

**Step 1: Create the fuzz harness**

```python
# SPDX-License-Identifier: MIT
"""Fuzz harness for navi-bootstrap sanitization.

Targets: sanitize_spec() and sanitize_manifest() — the two
untrusted-input entry points.

Invariants checked:
  - sanitize_spec() never raises on valid structure
  - sanitize_spec() always returns dict
  - sanitize_spec() output contains no null bytes
  - sanitize_spec() is idempotent (second pass is no-op)
  - sanitize_manifest() never raises on valid structure
  - sanitize_manifest() is idempotent
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

    # Invariant: idempotent
    assert sanitize_spec(result) == result


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

    # Invariant: idempotent
    assert sanitize_manifest(result) == result


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
```

**Step 2: Create the workflow**

```yaml
name: Fuzz

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 3" # Wednesday 03:00 UTC

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        target: [fuzz_sanitize]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: astral-sh/setup-uv@0c5e2b8115b80b4c7c5ddf6ffdd634974642d182 # v5.4.2
        with:
          enable-cache: true
      - name: Install dependencies
        run: |
          uv sync --frozen
          uv pip install atheris
      - name: Run fuzzer
        env:
          FUZZ_TARGET: ${{ matrix.target }}
        run: |
          uv run python "fuzz/${FUZZ_TARGET}.py" -atheris_runs=100000 -max_len=4096
      - name: Upload crash artifacts
        if: failure()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: fuzz-crash-${{ matrix.target }}
          path: |
            crash-*
            oom-*
            timeout-*
```

Note: Use the checkout and setup-uv SHAs that match what navi-bootstrap already uses or the latest pinned versions. Check the existing workflows for the right SHAs.

**Step 3: Verify syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/fuzz.yml')); print('valid')"`
Expected: `valid`

**Step 4: Commit**

```bash
git add fuzz/fuzz_sanitize.py .github/workflows/fuzz.yml
git commit -m "ci: add Atheris fuzz testing for sanitization

Fuzz harness targets sanitize_spec() and sanitize_manifest() with
constructed dicts from fuzzed Unicode. Invariants: never raises,
always returns dict, no null bytes in output, idempotent.
100K runs per invocation, weekly + on every PR.
Ported from navi-sanitize."
```

---

### Task 3: Add pip-audit + Codecov + coverage threshold to tests.yml

**Files:**
- Modify: `.github/workflows/tests.yml`

**Step 1: Add security job with pip-audit**

Add a new `security` job after the existing `lint` job:

```yaml
  security:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - name: Harden runner
        uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e # v2.10.4
        with:
          egress-policy: audit
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Set up Python
        uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0
        with:
          python-version: "3.12"
      - name: Install uv
        run: pip install uv
      - name: Install dependencies
        run: uv sync
      - name: pip-audit
        run: uvx pip-audit==2.9.0
```

**Step 2: Update test job to upload coverage**

In the `test` job, replace the test run step:

```yaml
      - name: Run tests with coverage
        run: |
          uv run pytest tests/ -v --cov=src/navi_bootstrap --cov-report=xml:coverage.xml --cov-report=term-missing --cov-fail-under=80
      - name: Upload coverage to Codecov
        if: matrix.python-version == '3.12'
        uses: codecov/codecov-action@18283e04ce6e62d37312384ff67af1b5c587a882 # v5.4.3
        with:
          files: coverage.xml
          fail_ci_if_error: false
```

Note: Use the latest SHA-pinned codecov-action. Check https://github.com/codecov/codecov-action/releases for the current version and pin the SHA.

**Step 3: Verify syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/tests.yml')); print('valid')"`
Expected: `valid`

**Step 4: Verify coverage threshold locally**

Run: `uv run pytest tests/ -v --cov=src/navi_bootstrap --cov-report=term-missing --cov-fail-under=80`
Expected: PASS (coverage should be well above 80%)

**Step 5: Commit**

```bash
git add .github/workflows/tests.yml
git commit -m "ci: add pip-audit, Codecov upload, 80% coverage floor

- New security job with pip-audit dependency vulnerability scan
- Coverage XML export + Codecov upload (Python 3.12 only)
- --cov-fail-under=80 enforces minimum coverage threshold"
```

---

### Task 4: Upgrade mypy to strict mode

**Files:**
- Modify: `pyproject.toml` (mypy section)
- Modify: `.github/workflows/tests.yml` (mypy invocation)

**Step 1: Update pyproject.toml mypy config**

Replace the `[tool.mypy]` section with:

```toml
[tool.mypy]
python_version = "3.12"
strict = true
```

This replaces the individual flags (warn_unused_configs, disallow_untyped_defs, etc.) with the `strict` umbrella which enables all of them plus more.

**Step 2: Update CI mypy invocation**

In `.github/workflows/tests.yml`, in the lint job, change:

```yaml
      - name: Type check
        run: uv run mypy src/navi_bootstrap/ --ignore-missing-imports
```

to:

```yaml
      - name: Type check
        run: uv run mypy src/navi_bootstrap/
```

Remove `--ignore-missing-imports` — strict mode should not paper over missing stubs.

**Step 3: Verify locally**

Run: `uv run mypy src/navi_bootstrap/`
Expected: If there are errors, fix them. Common issues: missing type stubs for dependencies (add to dev deps if needed).

**Step 4: Commit**

```bash
git add pyproject.toml .github/workflows/tests.yml
git commit -m "chore: upgrade mypy to strict mode

Matches navi-sanitize and grippy-code-review. Removes
--ignore-missing-imports escape hatch."
```

---

### Task 5: Add governance docs

**Files:**
- Create: `CODE_OF_CONDUCT.md`
- Create: `SECURITY.md`
- Create: `GOVERNANCE.md`

**Step 1: Create CODE_OF_CONDUCT.md**

```markdown
# Code of Conduct

## Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a positive experience for everyone, regardless of background or identity.

## Our Standards

**Encouraged behavior:**

- Being respectful and constructive
- Giving and accepting feedback gracefully
- Focusing on what is best for the community
- Showing empathy toward other community members

**Unacceptable behavior:**

- Personal attacks, insults, or derogatory comments
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

## Enforcement

Instances of unacceptable behavior may be reported to the project maintainer at security@projectnavi.ai. All reports will be reviewed and investigated promptly and fairly.

The project maintainer has the right and responsibility to remove, edit, or reject contributions that are not aligned with this Code of Conduct, and to temporarily or permanently restrict any contributor for behavior they deem inappropriate.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org/), version 2.1.
```

**Step 2: Create SECURITY.md**

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest) | Yes |

## Reporting a Vulnerability

**Do not open a public issue.** Instead, email the maintainer directly:

- **Email:** security@projectnavi.ai
- **Subject prefix:** `[navi-bootstrap] SECURITY:`

Include:

- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The impact as you understand it

## Response Timeline

- **Acknowledge:** within 48 hours
- **Fix or disclose:** within 90 days

If the vulnerability is accepted, a fix will be released and credited in the changelog (unless you prefer to remain anonymous). If declined, you'll receive an explanation.

## Scope

This policy covers the navi-bootstrap engine, CLI, and bundled template packs. User-supplied specs and custom packs are out of scope.
```

**Step 3: Create GOVERNANCE.md**

```markdown
# Governance

## Project Lead

navi-bootstrap is maintained by [Nelson Spence](https://github.com/ndspence) at [Project Navi LLC](https://github.com/Project-Navi).

## Decision Making

This project follows a benevolent dictator model. The project lead makes final decisions on:

- Feature scope and API design
- Template pack standards
- Release timing and versioning
- Security response

## Contributions

All contributions are welcome via pull requests. The project lead reviews and merges PRs. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Releases

Releases follow [semantic versioning](https://semver.org/). The project lead decides when to cut releases.

## Security

Security vulnerabilities are handled per [SECURITY.md](SECURITY.md). The project lead coordinates fixes and disclosure.

## Changes to Governance

This governance model may evolve as the project grows. Changes will be documented in this file.
```

**Step 4: Commit**

```bash
git add CODE_OF_CONDUCT.md SECURITY.md GOVERNANCE.md
git commit -m "docs: add governance docs (CoC, Security, Governance)

Contributor Covenant v2.1, vulnerability reporting policy (48h ack,
90d fix), benevolent dictator governance model. Consistent with
navi-sanitize and grippy-code-review."
```

---

### Task 6: Update README badges

**Files:**
- Modify: `README.md` (badge section, lines 1-6)

**Step 1: Replace the badge block**

Replace the existing badge lines (lines 3-6) with:

```markdown
[![Tests](https://github.com/Project-Navi/navi-bootstrap/actions/workflows/tests.yml/badge.svg)](https://github.com/Project-Navi/navi-bootstrap/actions/workflows/tests.yml)
[![CodeQL](https://github.com/Project-Navi/navi-bootstrap/actions/workflows/codeql.yml/badge.svg)](https://github.com/Project-Navi/navi-bootstrap/actions/workflows/codeql.yml)
[![Fuzz](https://github.com/Project-Navi/navi-bootstrap/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Project-Navi/navi-bootstrap/actions/workflows/fuzz.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Project-Navi/navi-bootstrap/badge)](https://scorecard.dev/viewer/?uri=github.com/Project-Navi/navi-bootstrap)
[![PyPI](https://img.shields.io/pypi/v/navi-bootstrap)](https://pypi.org/project/navi-bootstrap/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
```

That's 8 badges: Tests, CodeQL, Fuzz, Scorecard, PyPI, License, Python, Ruff.

Codecov badge can be added later once the Codecov integration is live and has uploaded at least one report.

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add Fuzz, Scorecard, PyPI, Ruff badges to README

8 badges total (was 4). Codecov badge deferred until first
upload lands."
```

---

### Task 7: Final verification

**Step 1: Run full quality checks**

```bash
uv run ruff check src/navi_bootstrap/ tests/
uv run ruff format --check src/navi_bootstrap/ tests/
uv run mypy src/navi_bootstrap/
uv run pytest tests/ -v --cov=src/navi_bootstrap --cov-report=term-missing --cov-fail-under=80
```

Expected: All pass.

**Step 2: Validate all workflow YAML**

```bash
for f in .github/workflows/*.yml; do python -c "import yaml; yaml.safe_load(open('$f')); print(f'OK: $f')"; done
```

Expected: All OK.

**Step 3: Verify git log**

```bash
git log --oneline -10
```

Expected: 6 new commits (semgrep, fuzz, tests.yml, mypy, governance, badges).
