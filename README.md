# repoward

<!-- mcp-name: io.github.Sanoy24/repoward -->

A GitHub MCP server that stops AI agents acting on what an attacker's issue told them to do.

> **Status: alpha.** It has not had an independent security review. Read
> [the threat model](https://github.com/Sanoy24/repoward/blob/main/docs/THREAT_MODEL.md), especially the part about where it runs.

## The problem

An agent with GitHub access can read a malicious public issue, read a private repository, and post
the contents in a public pull request. Each call looks allowed on its own, so per-tool permissions
do not stop the sequence. This is the
[attack Invariant Labs published](https://invariantlabs.ai/blog/mcp-github-vulnerability) against
agents using GitHub's MCP server, and repoward's test suite replays it against real repositories.

## Flow guard

Before every write, repoward checks what this agent has already read, using facts from GitHub:

| If the agent has read | Then |
| --- | --- |
| Anything from a private repository | Writes to public repositories are denied |
| An issue, pull request or comment from an author outside `OWNER`, `MEMBER` and `COLLABORATOR`, or a job log | Each write needs human approval |

This does not depend on the model noticing an attack or on scanning text, so rewording or
encoding the data does not get around it. The state survives restarts, and no tool can clear it.
A person can:

```bash
uvx repoward flow status
uvx repoward flow reset
```

What it does not do:

- It only sees this server's tools. A shell, a browser or another MCP server is still a way out, so
  it protects agents whose GitHub access and outbound routes are limited to this server.
- Data can stay in an agent's context after the window (60 minutes by default) ends. Restart a
  long-running agent to clear its context.
- Reading one private repository and writing to another private repository is allowed, unless you
  set `single_repo: true`.
- Repository files and code search results do not count as untrusted input, because they were
  merged by someone with write access.
- `author_association` is a coarse signal, and a compromised trusted account counts as trusted.
- Maintainers of public repositories will see more approval requests. That is the cost of the
  default, and `trusted_associations` is configurable.

## What works today

- **Policy:** default-deny YAML with roles, repository allowlists and path denylists. See
  [policy.example.yaml](https://github.com/Sanoy24/repoward/blob/main/policy.example.yaml).
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
- **Dangerous tools:** `github_merge_pull_request` and `github_delete_branch` need human approval.
  An approval covers one exact call at one exact commit, works once and expires. Merging is off
  until a policy turns it on.
- **Untrusted content handling:** text from GitHub users comes back wrapped in a tag with a random
  id per response, after invisible characters, hidden HTML comments and images are removed and
  secrets are redacted. This is a mitigation, not a guarantee: a model can still be fooled, which
  is why the rules above are enforced outside the model.

## Planned

- **Least-privilege tokens:** short-lived GitHub App tokens scoped to each call.

## Who it is for

Agents whose only route to GitHub is this server, such as CI bots and hosted agents. An agent with
shell access can run `git` or read local credentials directly, so this server is not a security
boundary for it.

## Install

Requires [uv](https://docs.astral.sh/uv/). Create a starter policy, which also prints a client
config to paste:

```bash
uvx repoward init --repo your-org/your-repo
```

The starter policy gives the server read-only tools. Add `--role contributor` for write tools. Files
live in `~/.repoward`, or wherever `REPOWARD_HOME` points. An existing policy is never overwritten.

Then add it to your MCP client, and use a token set up as described in [GitHub token](#github-token).
Avoid committing a config that holds a real token.

<details open>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add --env GITHUB_TOKEN=<your-token> --transport stdio repoward -- uvx repoward serve
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

In `claude_desktop_config.json`, under Settings > Developer > Edit Config:

```json
{
  "mcpServers": {
    "repoward": {
      "command": "uvx",
      "args": ["repoward", "serve"],
      "env": { "GITHUB_TOKEN": "<your-token>" }
    }
  }
}
```

</details>

<details>
<summary><b>Cursor</b></summary>

In `~/.cursor/mcp.json`, reading the token from your environment:

```json
{
  "mcpServers": {
    "repoward": {
      "command": "uvx",
      "args": ["repoward", "serve"],
      "env": { "GITHUB_TOKEN": "${env:GITHUB_TOKEN}" }
    }
  }
}
```

</details>

<details>
<summary><b>VS Code</b></summary>

In `.vscode/mcp.json` or your user profile's `mcp.json`, which prompts for the token once:

```json
{
  "inputs": [
    { "type": "promptString", "id": "github-token", "description": "GitHub token", "password": true }
  ],
  "servers": {
    "repoward": {
      "type": "stdio",
      "command": "uvx",
      "args": ["repoward", "serve"],
      "env": { "GITHUB_TOKEN": "${input:github-token}" }
    }
  }
}
```

</details>

<details>
<summary><b>Codex</b></summary>

In `~/.codex/config.toml`, forwarding the token from your environment:

```toml
[mcp_servers.repoward]
command = "uvx"
args = ["repoward", "serve"]
env_vars = ["GITHUB_TOKEN"]
```

</details>

<details>
<summary><b>Gemini CLI</b></summary>

In `~/.gemini/settings.json`, reading the token from your environment:

```json
{
  "mcpServers": {
    "repoward": {
      "command": "uvx",
      "args": ["repoward", "serve"],
      "env": { "GITHUB_TOKEN": "$GITHUB_TOKEN" }
    }
  }
}
```

</details>

Any other client that can launch a stdio MCP server runs the same command: `uvx repoward serve`.

Useful commands:

```bash
uvx repoward validate-policy
uvx repoward audit verify
```

## Approving risky actions

A call that needs approval does not run. It returns an `approval_id`, and a person decides from a
terminal:

```bash
uvx repoward approvals list
uvx repoward approvals show <id>
uvx repoward approvals approve <id>
```

The agent then repeats the same call. Pushing new commits changes the commit the call names, so
the old approval no longer applies, and GitHub refuses a merge whose head has moved.

If the agent runs as the same OS user as this server and has a shell, it could run these commands
or edit the database itself. Run the server and its files under a separate user or in a container
for approvals to mean anything.

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
  return nothing until GitHub indexes them, and its handling of real results has so far only been
  tested against simulated responses.
- `github_get_file` refuses symlinks, submodules, binary files and files over 1 MB. It walks the
  Git tree, so each read makes one request per folder in the path.
- `ci_get_job_logs` fails closed if GitHub moves log storage to a host it does not recognize.
- `github_merge_pull_request` does not support merge queues or stacked pull requests.
- `github_delete_branch` checks the commit and then deletes, because GitHub has no conditional
  delete, so a small window remains between the two.

## What the audit log proves

The log is tamper-evident, not tamper-proof.

| Attack | Plain chain | With an HMAC key the attacker cannot read | With off-host checkpoints |
| --- | --- | --- | --- |
| Edit one record | Detected | Detected | Detected |
| Edit a record and recompute all later hashes | **Not detected** | Detected | Detected back to the last checkpoint |
| Delete the newest records | **Not detected** | **Not detected** | Detected back to the last checkpoint |

Set `REPOWARD_AUDIT_HMAC_KEY` to use HMAC, and store the output of `repoward audit checkpoint`
somewhere the server cannot write. Comment bodies, titles, commit messages and file contents are
logged as a length and hash rather than as text. A crash during a write leaves an incomplete last line, and new
writes are then refused until an operator repairs the log. Secret redaction is best effort.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/Sanoy24/repoward/blob/main/CONTRIBUTING.md). Please report vulnerabilities as described in
[SECURITY.md](https://github.com/Sanoy24/repoward/blob/main/SECURITY.md).

## License

[MIT](https://github.com/Sanoy24/repoward/blob/main/LICENSE). This is an independent project, not affiliated with or endorsed by GitHub.
