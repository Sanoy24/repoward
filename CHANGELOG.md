# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - Unreleased

### Added

- `repoward init`, which creates a safe starter policy and prints a client config.
- MCP server over stdio with a `ping` tool.
- Default-deny YAML policy with strict loading and `repoward validate-policy`.
- Single guarded pipeline for every tool attempt.
- Hash-chained audit log with HMAC mode, `repoward audit verify` and `repoward audit checkpoint`.
- Per-principal, per-tool rate limits.
- Read tools for issues, code search, files, CI status and job logs.
- Framing, invisible-character removal and redaction for text from GitHub users.
- Write tools for branches, commits, draft pull requests and comments.
- Approval store, `repoward approvals` commands, and dangerous tools for merging pull requests and
  deleting branches.
- Flow guard: writes are decided by what the agent has read, using repository visibility and author
  association from GitHub, with `repoward flow` commands for people.
- Policy rules for the branch prefix, draft-only pull requests and commit limits, and a scan that
  refuses to send recognizable credentials.

### Security

- `github_get_file` could return a denied file through a symlink at an allowed path, because
  GitHub's contents API follows such links and reports them as files. It now walks the Git tree
  and refuses anything but a regular file. Never in a release.
