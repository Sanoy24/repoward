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

## Features

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
- **GitHub App tokens (optional):** each call gets a short-lived token limited to one repository and
  only the permissions that tool needs, and GitHub enforces those limits itself.
- **Pull request review as approval (optional):** a merge can be approved by a real GitHub review
  of the exact commit.
- **Pull request receipts (optional):** a commit status summarizing how the agent's run has gone.
- **Policy replay:** see which past decisions a policy edit would change before you deploy it.
- **Untrusted content handling:** text from GitHub users comes back wrapped in a tag with a random
  id per response, after invisible characters, hidden HTML comments and images are removed and
  secrets are redacted. This is a mitigation, not a guarantee: a model can still be fooled, which
  is why the rules above are enforced outside the model.

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

Run this first, because the server will not start without a policy. Then add it to your MCP client,
and use a token set up as described in [GitHub token](#github-token).
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

<details>
<summary><b>OpenCode</b></summary>

In `opencode.json` in your project, or `~/.config/opencode/opencode.json`, reading the token from your
environment:

```json
{
  "mcp": {
    "repoward": {
      "type": "local",
      "command": ["uvx", "repoward", "serve"],
      "environment": { "GITHUB_TOKEN": "{env:GITHUB_TOKEN}" }
    }
  }
}
```

</details>

Any other client that can launch a stdio MCP server runs the same command: `uvx repoward serve`.

If your client reports that the server failed to connect, run `uvx repoward serve` in a terminal
to see why. The usual cause is that `repoward init` has not been run yet, so there is no policy.

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

### Approving with a pull request review

A merge can also be approved by a normal GitHub review, so the approver needs their own GitHub
identity and not just access to this machine. Turn it on in your policy:

```yaml
approvals:
  github_review: { enabled: true, min_permission: write }
```

A review counts only if it approves the exact commit being merged, comes from a user other than the
pull request's author and this server's own identity, and that user has the required access. Any
reviewer's outstanding request for changes blocks it. Each check is made again at merge time.

This needs the server to act as a GitHub App or a separate bot account. With your own token, your
own reviews are refused. If an agent can reach the reviewer's GitHub credentials, such as a logged-in
`gh` on the same machine, this protection is lost.

### Limits of approvals

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

### Using a GitHub App instead

A [GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)
gives each tool call its own short-lived token, limited to one repository and that tool's
permissions. The App also has its own identity, which review approvals need.

Register an App with webhooks off and only the permissions you need, then install it on the
repositories in your policy, and generate a private key:

| Permission | Level | Used for |
| --- | --- | --- |
| Contents | Read, or write for write tools | Files, search, branches, commits, merges |
| Issues | Read, or write for comments | Issues and comments |
| Pull requests | Read, or write for write tools | Pull requests, reviews and comments |
| Actions | Read | CI status and job logs |
| Commit statuses | Read, or write for receipts | CI status and receipts |

Then set this in your policy, and point `GITHUB_APP_PRIVATE_KEY_FILE` at the key in the server's
environment:

```yaml
github_auth:
  mode: app
  client_id: Iv1.your-client-id
  installation_id: 12345678
```

The private key is a long-lived secret that can issue new tokens. Keep it away from the agent. A
`contents: write` token can still push to any branch of that repository, so the ruleset advice above
still applies.

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

## Pull request receipts

Reviewers of an agent's pull request can see how its run has gone. Turn this on in your policy:

```yaml
receipts:
  enabled: true
```

After each commit or pull request the agent makes, repoward posts a commit status named
`repoward/receipt`:

```text
policy 4c16a8364c1a; audit seq 12-40; 2 denied; 1 escalated; flow labels: yes
```

That is the policy's hash, the audit records since this server started, how many calls were denied
or needed approval, and whether anything restricts the agent's writes. `flow labels` can also say
`no`, `unknown`, or `off` if the flow guard is off.

- It needs `Commit statuses: write`. A GitHub App uses a separate token holding only that permission
  for each receipt. A personal token needs the permission on the token itself, so every tool's calls
  carry it.
- A receipt is audited before it is posted. If posting fails, the agent's commit or pull request still
  succeeds, and the failure is logged.
- **A receipt does not prove a change came through repoward.** Anyone with that permission can post
  the same status, so don't make it a required check.
- **Anyone who can see the repository can read it.** On a public repository, that includes how many
  calls were refused and whether flow labels are set, which can hint that the agent read private
  content.

## Trying a policy change

Replay a policy against your audit log to see what it would have done differently:

```bash
repoward policy replay --policy new-policy.yaml
```

```text
3 decisions: 1 unchanged, 1 changed, 1 unknown

Changed:
  seq 2  github_comment  org/app: allow -> approval_required  (flow.untrusted_author)

Unknown (the log does not hold what this decision depends on):
  seq 5  github_commit_files  org/app: allow -> unknown  (it depends on file sizes or text the log does not hold)
```

It never contacts GitHub and changes nothing, and it refuses a log that fails verification. Add
`--key-env` to name the variable holding your HMAC key if the log uses one.

The log leaves out content, so some answers are not knowable. A decision can depend on a file's exact
size, on whether hidden text held a credential, or on flow guard facts that were not recorded, such as
the visibility of a repository the log never read. Replay reports those as `unknown` and does not
guess.

Replay assumes the agent would have made the same calls. A real agent that was refused would have
done something else, so treat the report as a guide to the policy's effect and not as a prediction.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/Sanoy24/repoward/blob/main/CONTRIBUTING.md). Please report vulnerabilities as described in
[SECURITY.md](https://github.com/Sanoy24/repoward/blob/main/SECURITY.md).

## License

[MIT](https://github.com/Sanoy24/repoward/blob/main/LICENSE). This is an independent project, not affiliated with or endorsed by GitHub.
