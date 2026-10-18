# Changelog

All notable changes to this project are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-18

### Added

- `scan(text, options)` reports prompt-injection signals with severity, category, position and a plain-English reason, plus an overall risk and score.
- 31 pattern rules across instruction overrides, role hijacks, fake chat delimiters, prompt leaking, secrecy, exfiltration, tool abuse and text that addresses an AI directly.
- Normalization that defeats zero-width characters, lookalike letters, fullwidth and math letters.
- Hidden-text detection: Unicode tag characters (decoded and scanned), bidi controls, zero-width characters inside words, HTML comments, invisible HTML elements and Markdown comments.
- Base64 payloads are decoded and scanned.
- `sanitize()`, `wrapUntrusted()`, `isSuspicious()` and `normalize()`.
- `injection-scan` CLI with `--threshold`, `--disable`, `--json`, `--sanitize` and `--quiet`.

[0.1.0]: https://github.com/acus9345/injection-scan/releases/tag/v0.1.0
