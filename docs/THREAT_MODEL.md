# Threat model

What repoward defends against, what it does not, and what that depends on.

## Where it runs decides what it protects

| Deployment | The agent can reach | What holds |
| --- | --- | --- |
| **The agent has only MCP tools**, with no shell or file access | MCP tools | Policy, flow guard, approvals and audit |
| **Same OS user, and the agent has a shell** (a typical local coding agent) | Everything the user can reach | **Not a security boundary.** The agent could use `git` or `gh` directly, read the token, edit the policy, approve its own requests or rewrite the log. repoward only helps with a cooperative or misled agent |
| **Separated**: server under its own OS user or in a container, or the agent on another host | Only the MCP interface | Policy, flow guard, approvals and audit. The token, policy, databases and log must not be readable or writable by the agent |

Flow guard also needs the agent's other outbound routes closed. It cannot see a browser, a shell or
another MCP server.

## Threats

| Threat | Mitigation | What remains |
| --- | --- | --- |
| Toxic flow: a public issue steers the agent to read a private repository and publish it | Flow guard denies writes to public repositories after a private read, using repository visibility from GitHub | Routes outside this server; private-to-private writes unless `single_repo` is on; data remembered after the window |
| Prompt injection through GitHub text | Writes after untrusted input need approval. Text is framed with a random id per response, and invisible characters, hidden HTML comments and images are removed. Rules are enforced outside the model | A model can still be fooled, and framing is not a guarantee. Misuse within the role at the same visibility is possible. Repository files and search results do not count as untrusted input |
| Reading a denied file through a symlink | The file tool walks the Git tree, checks real modes and fetches blobs by SHA. It does not use the contents API, which follows such links | None known |
| Search widening beyond the allowed repository | Qualifiers and operators are refused, and every result is filtered by repository and path | None known |
| Over-broad permissions | Default deny, roles, limits, branch prefix, draft-only pull requests, and a separate switch for dangerous tools. In GitHub App mode, GitHub itself enforces each tool's permissions, and a token wider than requested is refused | `Contents: write` lets the token itself push to any branch and merge. Protect your default branch with a ruleset that has no bypass for the token's owner |
| Workflow tampering | `.github/**` is denied by the starter policy, and the token needs no Workflows permission, so GitHub refuses too | Other code that a workflow runs, such as scripts it calls |
| Agent approves its own action or edits policy | Approval happens outside MCP, on the command line or through a GitHub review by a separate identity, and no tool can approve or reset | Command-line approval is unprotected if the agent has a shell as the same OS user. Review approval is lost if the agent can reach the reviewer's GitHub credentials |
| Replayed or swapped approvals | Atomic single use, expiry, match on user, tool, repository and exact arguments. Merges name a commit, and GitHub refuses if the head moved | A short window between check and delete for branch deletion |
| Fake approval screen | Terminal escapes and invisible characters are removed, and GitHub text is labelled untrusted | The approver must still read carefully |
| Token theft | Environment variable only, never logged, redacted from output, least-privilege permissions. GitHub App mode uses short-lived tokens limited to one repository and one tool's permissions | A stolen personal token works until it expires, so use short expiry. A stolen App private key can issue new tokens |
| Credential exfiltration through write tools | Recognizable credentials in comments, pull requests and commits are refused | Encoded or unrecognized secrets |
| Secrets in output and logs | Pattern redaction before truncation. Audit records keep a length and hash of content | Redaction is best effort |
| Tampered audit log | Hash chain, optional HMAC, off-host checkpoints | See the table in the README. A plain chain can be recomputed, and newest records can be deleted unless checkpointed. Forward-secure logging is not provided |
| Log and label loss | Writes fail closed if they cannot be audited, and content is withheld if it cannot be tracked | Reads proceed with an alert if only the audit write fails. A torn final record blocks writes until repaired by hand |
| SSRF | No tool accepts a URL, the API host is fixed, and redirects are not followed, except job logs to one recognized storage host and without the token | Log storage moving to another host fails closed |
| Supply chain | Lockfile, actions pinned to commits, publishing without a long-lived token | A compromised upstream release |

## Not covered

- Compromise of the machine running the server, or of GitHub.
- A compromised trusted account: `author_association` reflects the account, not its intent.
- Teams and remote use: there is no HTTP mode or per-user login yet, and all calls share one GitHub
  identity. This server's audit log is then the only per-user record, and today there is one user.
- Review approval trusts GitHub's `commit_id` and permission answers at the moment of the check.
- Independent review. Flow guard's untrusted-author rule is tested using real `author_association`
  values from GitHub, with a policy that marks the author's association as untrusted.
