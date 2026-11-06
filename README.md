# repoward

A GitHub MCP server that stops AI agents acting on what an attacker's issue told them to do.

> **Status: pre-alpha.** Only the server skeleton exists today. The features below are planned and
> do not work yet. Do not rely on this project for security.

## The problem

An agent with GitHub access can read a malicious public issue, read a private repository, and post
the contents in a public pull request. Each call looks allowed on its own, so per-tool permissions
do not stop the sequence.

## Planned

- **Flow guard:** tracks what the agent has read, using facts from GitHub, then blocks
  private-to-public writes and requires approval for writes after untrusted input.
- **Policy:** default-deny YAML with roles, repository allowlists and path denylists.
- **Approvals:** risky actions wait for a human, tied to the exact commit.
- **Audit log:** a tamper-evident record of every decision.
- **Least-privilege tokens:** short-lived GitHub App tokens scoped to each call.

## Who it is for

Agents whose only route to GitHub is this server, such as CI bots and hosted agents. An agent with
shell access can run `git` or read local credentials directly, so this server is not a security
boundary for it.

## Try the skeleton

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Sanoy24/repoward.git
cd repoward
uv sync
uv run repoward serve
```

The server speaks MCP over stdio and has one placeholder tool, `ping`.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). This is an independent project, not affiliated with or endorsed by GitHub.
