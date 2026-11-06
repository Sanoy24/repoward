# repoward

A GitHub MCP server that stops AI agents acting on what an attacker's issue told them to do.

> **Status: pre-alpha.** The governance core works, but there are no GitHub tools yet. Do not rely
> on this project for security.

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

## Planned

- **GitHub tools:** issues, files, code search, CI status, branches, commits and draft pull requests.
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
cp policy.example.yaml policy.yaml
uv run repoward validate-policy policy.yaml
uv run repoward serve --policy policy.yaml --audit audit.jsonl
```

The server speaks MCP over stdio and has one tool so far, `ping`. Check the log with:

```bash
uv run repoward audit verify audit.jsonl
```

## What the audit log proves

The log is tamper-evident, not tamper-proof.

| Attack | Plain chain | With an HMAC key the attacker cannot read | With off-host checkpoints |
| --- | --- | --- | --- |
| Edit one record | Detected | Detected | Detected |
| Edit a record and recompute all later hashes | **Not detected** | Detected | Detected |
| Delete the newest records | **Not detected** | **Not detected** | Detected back to the last checkpoint |

Set `REPOWARD_AUDIT_HMAC_KEY` to use HMAC, and store the output of `repoward audit checkpoint`
somewhere the server cannot write. A crash during a write leaves an incomplete last line, and new
writes are then refused until an operator repairs the log. Secret redaction is best effort.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). This is an independent project, not affiliated with or endorsed by GitHub.
