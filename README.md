# repoward

A GitHub MCP server that stops AI agents acting on what an attacker's issue told them to do.

> **Status: pre-alpha.** Read and write tools work. Approvals and flow guard are not built yet, so
> the attack described below is not stopped yet. Do not rely on this project for security.

## The problem

An agent with GitHub access can read a malicious public issue, read a private repository, and post
the contents in a public pull request. Each call looks allowed on its own, so per-tool permissions
do not stop the sequence.

## What works today

- **Policy:** default-deny YAML with roles, repository allowlists and path denylists. See
  [policy.example.yaml](policy.example.yaml).
- **Single guarded path:** every tool attempt, including unknown tools and invalid arguments, passes
  through one pipeline and is logged.
- **Audit log:** a hash-chained record of every decision, with optional HMAC and checkpoints.
- **Rate limits:** per principal and per tool.
- **Read tools:** `github_list_issues`, `github_get_issue`, `github_search_code`, `github_get_file`,
  `ci_get_status` and `ci_get_job_logs`.
- **Write tools:** `github_create_branch`, `github_commit_files`, `github_create_pull_request` and
  `github_comment`. Writes only reach branches with the configured prefix (`agent/` by default),
  pull requests are draft only by default, commit sizes are limited, nothing is forced or retried,
  and text holding a recognizable credential is refused.
- **Untrusted content handling:** text from GitHub users comes back wrapped in a tag with a random
  id per response, after invisible characters, hidden HTML comments and images are removed and
  secrets are redacted. This is a mitigation, not a guarantee: a model can still be fooled, which
  is why the rules above are enforced outside the model.

## Planned

- **Flow guard:** tracks what the agent has read, using facts from GitHub, then blocks
  private-to-public writes and requires approval for writes after untrusted input.
- **Approvals:** risky actions wait for a human, tied to the exact commit.
- **Least-privilege tokens:** short-lived GitHub App tokens scoped to each call.

## Who it is for

Agents whose only route to GitHub is this server, such as CI bots and hosted agents. An agent with
shell access can run `git` or read local credentials directly, so this server is not a security
boundary for it.

## Try it

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Sanoy24/repoward.git
cd repoward
uv sync
cp policy.example.yaml policy.yaml  # then edit repos.allow
uv run repoward validate-policy policy.yaml
GITHUB_TOKEN=... uv run repoward serve --policy policy.yaml --audit audit.jsonl
```

The server speaks MCP over stdio. Check the log with:

```bash
uv run repoward audit verify audit.jsonl
```

## GitHub token

Use a [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new)
limited to the repositories you allow, with short expiry. Choose **Only select repositories** so
that repository permissions appear. The read tools need these, all read-only:

| Permission | Used for |
| --- | --- |
| Metadata | Required by GitHub |
| Contents | `github_get_file` |
| Issues | `github_list_issues`, `github_get_issue` |
| Pull requests | Pull requests in those same tools |
| Actions | `ci_get_status`, `ci_get_job_logs` |
| Commit statuses | `ci_get_status` |

To use the write tools, also give it read and write access to Contents, Issues and Pull requests.
Leave the Workflows permission off: GitHub then refuses workflow file changes even if your policy
allows the path.

`Contents: write` lets a token push to any branch and merge, and GitHub cannot limit it to `agent/`
branches. That limit lives in this server, so also protect your default branch with a ruleset that
requires pull requests and has no bypass for the token's owner. If the token leaks or the server is
misconfigured, that ruleset still holds.

Limits to know about:

- `ci_get_status` does not show third-party checks reported only through the Checks API, which
  GitHub documents as unavailable to fine-grained tokens.
- `github_search_code` covers the default branch and files under 384 KB. New repositories can
  return nothing until GitHub indexes them.
- `github_get_file` refuses symlinks, submodules, binary files and files over 1 MB. It walks the
  Git tree, so each read makes one request per folder in the path.
- `ci_get_job_logs` fails closed if GitHub moves log storage to a host it does not recognize.

## What the audit log proves

The log is tamper-evident, not tamper-proof.

| Attack | Plain chain | With an HMAC key the attacker cannot read | With off-host checkpoints |
| --- | --- | --- | --- |
| Edit one record | Detected | Detected | Detected |
| Edit a record and recompute all later hashes | **Not detected** | Detected | Detected back to the last checkpoint |
| Delete the newest records | **Not detected** | **Not detected** | Detected back to the last checkpoint |

Set `REPOWARD_AUDIT_HMAC_KEY` to use HMAC, and store the output of `repoward audit checkpoint`
somewhere the server cannot write. A crash during a write leaves an incomplete last line, and new
writes are then refused until an operator repairs the log. Secret redaction is best effort.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). This is an independent project, not affiliated with or endorsed by GitHub.
