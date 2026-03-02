# Design: Full infra lift for navi-bootstrap

**Date:** 2026-03-02
**Author:** Alpha
**Status:** Approved

## Goal

Bring navi-bootstrap's CI/CD, security tooling, governance, and developer
experience up to parity with its sibling repos (navi-sanitize, grippy-code-review).
Port known-good configs — no invention needed.

## Gap summary

| Item | Source repo | Notes |
|------|------------|-------|
| Semgrep SAST | navi-sanitize | Python + OWASP Top Ten |
| Fuzzing (Atheris) | navi-sanitize | Adapt harness for sanitize_spec/manifest |
| pip-audit in CI | navi-sanitize | Add to tests.yml |
| Codecov + badge | navi-sanitize | Coverage upload + README badge |
| Coverage threshold | grippy (80%) | Enforce in CI |
| Governance (3 docs) | navi-sanitize | CoC, SECURITY.md, GOVERNANCE.md |
| README badges | navi-sanitize | Scorecard, Coverage, Ruff, PyPI |
| mypy strict | navi-sanitize | Upgrade from partial to full strict |

## What stays unchanged

- SBOM generation (already ahead of siblings)
- SLSA L3 attestations (already ahead)
- detect-secrets pre-commit (already ahead)
- Dependabot config (already present)
- CodeQL workflow (already present)
- Scorecard workflow (already present)
- Release workflow (already present)

## Parallel execution

All items are independent — no code dependencies between them.
Perfect for parallel subagent dispatch.
