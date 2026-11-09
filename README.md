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
- **HTTP mode (optional):** serve several users from one server, each logging in with a JWT from your
  identity provider.
- **Policy replay:** see which past decisions a policy edit would change before you deploy it.
- **Untrusted content handling:** text from GitHub users comes back wrapped in a tag with a random
  id per response, after invisible characters, hidden HTML comments and images are removed and
  secrets are redacted. This is a mitigation, not a guarantee: a model can still be fooled, which
  is why the rules above are enforced outside the model.

## How it works

Every tool call takes the same path, including calls to unknown tools and calls with invalid
arguments, so each attempt is logged. Tool code is only ever run from this one place.

```text
MCP client
    |  stdio, or HTTP with a JWT checked on every request
    v
repoward
    1. Find the tool and validate its arguments    fail: refused and logged
    2. Check the policy                            default deny
    3. Check the flow guard                        for writes
    4. Check the rate limit
    5. Check for human approval                    if policy or the flow guard asks for it
    6. Log the decision                            if this fails, a write does not happen
    7. Run the tool
    8. Clean, redact, limit and label the output
    9. Log the outcome
    |
    v
GitHub API
```

## Who it is for

Agents whose only route to GitHub is this server, such as CI bots and hosted agents. What repoward
can enforce depends on where it runs relative to the agent:

| Deployment | The agent can reach | What holds |
| --- | --- | --- |
| The agent has only MCP tools, with no shell or file access | MCP tools | Policy, flow guard, approvals and audit |
| Same OS user, and the agent has a shell (a typical local coding agent) | Everything the user can reach | **Not a security boundary.** The agent could use `git` or read the token directly, edit the policy, approve its own requests or rewrite the log |
| The server runs under its own OS user, in a container, or on another host over HTTP | Only the MCP server | Policy, flow guard, approvals and audit, as long as the agent cannot read or write the token, policy, databases, audit log or HMAC key |

With a shell on the same OS user, repoward only helps an agent that is misled and not trying to get
around it. [Running repoward as its own user](https://github.com/Sanoy24/repoward/blob/main/docs/SEPARATE_USER.md)
sets up the separated case on Linux, and is tested automatically. GitHub-side controls, such as a ruleset protecting your default branch, are the backstop
in every case.

By default it runs over stdio as one identity. To serve several people from one server, see
[Serving over HTTP](#serving-over-http).

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

### Keeping the token out of config files

Instead of putting the token in your MCP client's config, you can store it in your operating
system's keychain, such as Windows Credential Manager or the macOS Keychain:

```bash
uvx --from 'repoward[keyring]' repoward token set
```

It asks for the token at a hidden prompt. Then leave `GITHUB_TOKEN` out of the client config, and
launch the server with the same extra: `uvx --from 'repoward[keyring]' repoward serve`.
`GITHUB_TOKEN` still takes precedence when it is set, and `repoward token status` and
`repoward token delete` check and remove the stored token.

This stops the token being copied or committed along with a config file. It does not hide it from
an agent running a shell as you, which can read your keychain too. On a Linux server with no desktop
keychain, use the environment file from
[Running repoward as its own user](https://github.com/Sanoy24/repoward/blob/main/docs/SEPARATE_USER.md).

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

## Serving over HTTP

`repoward serve --http` serves several users from one server. It acts as an OAuth resource server:
your identity provider issues the tokens, and repoward checks one on every request. There is no way
to run HTTP mode without login. Add this to your policy:

```yaml
http_auth:
  issuer: "https://idp.example.com/"
  audience: "https://mcp.example.com/mcp"
  jwks_uri: "https://idp.example.com/.well-known/jwks.json"
  algorithms: [RS256]
  resource_server_url: "https://mcp.example.com/mcp"
  allowed_hosts: ["mcp.example.com"]

identity_map:
  claim: groups
  mapping:
    mcp-readers: reader
    mcp-devs: contributor
```

```bash
repoward serve --http --host 127.0.0.1 --port 8000
```

- **Roles:** each caller needs exactly one role. A token whose groups map to no role, or to more than
  one, is refused, and roles are never combined. The role comes from the current token on each call,
  so a changed group applies as soon as a new token is used.
- **Per user:** flow guard labels, rate limits and approvals all belong to the caller, who is
  identified by the token's `iss` and `sub`.
- **Audit log:** records each caller and their groups, so group names end up in the log. Requests with
  a bad token are refused before any of this and only logged to stderr, so anonymous traffic cannot
  grow the audit log.
- **Signing keys:** come only from `jwks_uri`, and only asymmetric algorithms are accepted.
- **Network:** it listens on `127.0.0.1` by default and refuses other addresses without
  `allowed_hosts`. It has no TLS of its own, so put it behind a reverse proxy that handles HTTPS and
  passes the `Host` header through.

Limits:

- **One GitHub identity:** callers' tokens are never sent to GitHub, so all users share the server's
  GitHub credential, and GitHub's own logs show only that. This server's audit log is the only record
  of who did what.
- **One process:** rate limits and legacy sessions live in memory, so run a single instance.
- **Approvals:** the command line approvals still run on the server's host, so whoever approves needs
  access there. Review approval works as usual.
- **Tested with:** Keycloak 26.8, as well as locally signed tokens against real GitHub repositories,
  in both MCP protocol versions. Other identity providers have not been tried, so test yours first.

With Keycloak, give the client an audience mapper that adds your `resource_server_url` to access
tokens, and a group membership mapper with the claim name `groups` and full group path turned off.
Without the first, every token is refused for the wrong audience.

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
- **On its own, a receipt does not prove a change came through repoward.** Anyone with that
  permission can post a status with the same name. See below for making it count.
- **Anyone who can see the repository can read it.** On a public repository, that includes how many
  calls were refused and whether flow labels are set, which can hint that the agent read private
  content.

### Requiring a receipt

In GitHub App mode, a branch ruleset can require `repoward/receipt` **from your App
specifically**. GitHub then ignores the same status posted by anyone else. In a live test, a
receipt posted by a person left the pull request blocked, even though GitHub's combined status
showed success, and the App's receipt unblocked it.

To set it up, add a **Require status checks to pass** rule with the check `repoward/receipt`, and
choose your App as its source. Through the API, that is
`{"context": "repoward/receipt", "integration_id": <your App's ID>}`.

What that proves, and what it does not:

- The newest commit was made by repoward, or by someone else holding your App's private key. A
  commit pushed some other way has no receipt from the App, so it blocks the merge until repoward
  commits again.
- It does not judge the change. A receipt is always posted as success, whatever it counts.
- It applies to every pull request into that branch, including people's own. Target only the
  branches agents merge into, or let maintainers bypass the rule.
- With a personal token, the receipt is posted as you, so requiring it proves nothing. This only
  works in App mode.

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

### Rotating the log

The log grows forever unless you set a size limit in your policy:

```yaml
audit:
  rotate_mb: 50
```

When the file reaches that size, it is renamed to an archive such as
`audit.000000000001-000000004200.jsonl`, named by the records it holds, and a new file continues the
same chain. `repoward audit verify` and `repoward policy replay` read the archives and the current
file together, so editing, renaming or removing an archive in the middle is detected.

You can delete or move the oldest archives to save space. Verification then warns that the log no
longer reaches its start, and any checkpoint pointing into a removed archive fails, so prune old
anchors at the same time. Keep the archives you remove somewhere safe if you may need them.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/Sanoy24/repoward/blob/main/CONTRIBUTING.md). Please report vulnerabilities as described in
[SECURITY.md](https://github.com/Sanoy24/repoward/blob/main/SECURITY.md).

## License

[MIT](https://github.com/Sanoy24/repoward/blob/main/LICENSE). This is an independent project, not affiliated with or endorsed by GitHub.
