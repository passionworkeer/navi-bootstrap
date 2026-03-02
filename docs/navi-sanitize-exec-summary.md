# navi-sanitize

**Input sanitization pipeline for untrusted text. Deterministic. No ML. No false positives.**

---

## The Problem

Every application that accepts text from users or external systems is vulnerable to Unicode-based attacks. Homoglyph substitution (Cyrillic "а" posing as Latin "a"), zero-width character insertion, fullwidth encoding, and null byte injection bypass validation, poison templates, fool humans, and break LLM prompts.

The industry response has been detection: guardrails that classify whether input *looks like* an attack. This approach fails. Research published in 2025 showed that emoji smuggling achieves 100% evasion against every major guardrail, bidirectional text bypasses 79-90%, and basic homoglyph substitution evades 44-76%. The detection arms race cannot be won because attackers only need one bypass.

This is the same mistake the industry made with SQL injection for a decade — trying to detect malicious queries instead of making them structurally impossible.

## The Solution

navi-sanitize takes a different approach: clean the input, every time, unconditionally. No classification. No model. No confidence scores. Untrusted bytes go in, clean bytes come out. The attacker cannot opt out.

The pipeline runs five ordered stages:

1. **Null byte removal** — eliminates string terminators that truncate downstream processing
2. **Zero-width stripping** — removes 6 invisible Unicode characters used to evade detection and split tokens
3. **NFKC normalization** — collapses fullwidth ASCII and compatibility forms to standard codepoints
4. **Homoglyph replacement** — maps 42 Cyrillic/Greek lookalikes to their Latin equivalents
5. **Pluggable escaper** — caller-supplied function that escapes for the target context (Jinja2, filesystem paths, LLM prompts, or anything else)

Stages 1-4 are universal. They apply regardless of where the text is going. Stage 5 is where the caller tells the pipeline what the output is for. An escaper is a function from string to string — three lines of code to write a new one.

The pipeline never errors. It always produces output. When it changes something, it emits a warning with what it did. This is sanitize-and-warn, not sanitize-and-reject — production systems stay up, security teams get observability.

## Differentiators

**Deterministic, not probabilistic.** No ML model, no confidence thresholds, no false positives. Given the same input, the output is always the same. This makes it auditable, testable, and safe for regulated environments.

**Composable, not monolithic.** The pipeline ships with built-in escapers for Jinja2 templates and filesystem paths. Users bring their own for LLM prompts, SQL, HTML, or any other context. The universal stages don't change — only the final escaper varies.

**Data-layer defense, not application-layer.** Like parameterized queries for SQL injection, navi-sanitize removes the vulnerability class at the input boundary. Downstream code doesn't need to know about Unicode attacks because it never sees hostile codepoints.

**Battle-tested.** The pipeline ships with 37 adversarial tests covering Cyrillic/Greek homoglyphs, zero-width evasion of template delimiters, null byte truncation, fullwidth bypasses, SSTI payloads, and mixed-vector attacks. The test suite was built attack-first: every test encodes a real technique.

## API Surface

Three functions:

- `clean(text, escaper=None)` — sanitize a single string
- `walk(data, escaper=None)` — recursively sanitize every string in a dict/list/nested structure
- Escapers: `jinja2_escaper`, `path_escaper`, or bring your own `Callable[[str], str]`

## Market

Any system that processes untrusted text and feeds it into templates, prompts, filenames, or structured output. The immediate verticals:

- **LLM application developers** — prompt injection via Unicode is OWASP #1 for LLM applications in 2025. Current mitigations (guardrails, classifiers) have documented bypass rates above 44%.
- **Template rendering systems** — any Jinja2, Mustache, or string interpolation pipeline that touches user input.
- **Platform engineering teams** — CI/CD generators, IaC templating, config management across repositories.
- **Security teams** — input normalization layer that sits in front of existing validation, making downstream rules effective against encoded bypasses.

## Status

Working code. 37 adversarial tests passing. Pipeline proven in a production-grade Jinja2 rendering engine (navi-bootstrap) that serves as the reference integration. Needs extraction into standalone package, public API finalization, and PyPI release.

Zero dependencies for the core pipeline. Python 3.12+.
