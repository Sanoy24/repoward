# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Audit log rotation: set `audit.rotate_mb` to start a new file at that size. Archives keep one
  unbroken chain, and `audit verify` and `policy replay` read them together. Off by default.

## [0.4.0] - 2026-11-09

### Added

- HTTP mode: `repoward serve --http` serves several users from one server, each logging in with a JWT
  from your identity provider. It cannot run without login, and flow guard labels, rate limits and
  approvals are per user.
- Policy replay applies edits to `identity_map`, using the groups now recorded in HTTP audit records.

### Changed

- The README explains what repoward can enforce in each deployment, how a call flows through it, and
  how to set it up in OpenCode.
- `uvicorn` is now a direct dependency, for HTTP mode.

## [0.3.0] - 2026-11-06

### Added

- `repoward policy replay` reports which recorded decisions a policy would change, and says `unknown`
  where the log does not hold what a decision depends on. It never contacts GitHub.
- Pull request receipts: an optional commit status summarizing the agent's run, with no arguments
  or content. Off by default.
- Audit decision records now include `flow_trusted`, the flow guard's trusted associations at that
  moment, or null when the guard was off.

## [0.2.0] - 2026-11-06

### Added

- GitHub App mode: each call uses a short-lived token limited to one repository and that tool's
  permissions, and tokens wider than requested are refused.
- A real pull request review can approve a merge, tied to the exact commit. Off by default.

## [0.1.1] - 2026-11-06

### Fixed

- `repoward serve` no longer creates `~/.repoward` when every path is given explicitly.
- The README now says to run `repoward init` first, and what to do if a client cannot connect.
- Releases are no longer marked as pre-releases, so they show on the repository page.

## [0.1.0] - 2026-11-06

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
