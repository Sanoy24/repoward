# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- MCP server over stdio with a `ping` tool.
- Default-deny YAML policy with strict loading and `repoward validate-policy`.
- Single guarded pipeline for every tool attempt.
- Hash-chained audit log with HMAC mode, `repoward audit verify` and `repoward audit checkpoint`.
- Per-principal, per-tool rate limits.
- Read tools for issues, code search, files, CI status and job logs.
- Framing, invisible-character removal and redaction for text from GitHub users.
