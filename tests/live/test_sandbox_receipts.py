"""A receipt on a real pull request, posted with a GitHub App token. Skipped by default.

Needs REPOWARD_LIVE_REPO, REPOWARD_LIVE_APP_CLIENT_ID, REPOWARD_LIVE_APP_INSTALLATION_ID and
GITHUB_APP_PRIVATE_KEY_FILE. The App needs Commit statuses: write. The branch and pull request are
removed afterwards.
"""

import os
import re
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.adapters.github_auth import AppTokens, load_private_key
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.receipts import CONTEXT, ReceiptLedger
from repoward.scope import CallScope
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

REPO = os.environ.get("REPOWARD_LIVE_REPO", "")
CLIENT_ID = os.environ.get("REPOWARD_LIVE_APP_CLIENT_ID", "")
INSTALLATION = os.environ.get("REPOWARD_LIVE_APP_INSTALLATION_ID", "")
AGENT = Principal("live-receipts", "contributor")


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


async def test_a_real_pull_request_shows_its_receipt(tmp_path: Path) -> None:
    if not (REPO and CLIENT_ID and INSTALLATION):
        pytest.skip("GitHub App settings are required")
    compiled = parse_policy(
        f"""\
version: 1
default: deny
github_auth:
  mode: app
  client_id: {CLIENT_ID}
  installation_id: {INSTALLATION}
repos:
  allow: ["{REPO}"]
receipts:
  enabled: true
flow_guard:
  enabled: false
roles:
  contributor:
    tools: [github_create_branch, github_commit_files, github_create_pull_request]
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: contributor
""".encode()
    )
    tokens = AppTokens(CLIENT_ID, int(INSTALLATION), load_private_key())
    github = GitHubClient(tokens)
    audit = tmp_path / "audit.jsonl"
    pipeline = Pipeline(
        compiled,
        build_registry(compiled, github),
        AuditLog(audit),
        receipts=ReceiptLedger(github.post_commit_status, compiled.sha256),
    )

    async def call(tool: str, **args: Any) -> CallToolResult:
        return await pipeline.call(AGENT, tool, {"repo": REPO, **args})

    branch = f"agent/receipt-{uuid.uuid4().hex[:10]}"
    token = await tokens.token(
        CallScope(REPO, {"contents": "write", "pull_requests": "write", "statuses": "read"}),
        github._http,
    )
    client = httpx.Client(
        base_url=f"https://api.github.com/repos/{REPO}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=30,
    )
    number: int | None = None
    try:
        assert not (await call("github_create_branch", branch=branch, base="main")).is_error
        commit = await call(
            "github_commit_files",
            branch=branch,
            message="test: receipt",
            files=[{"path": f"live/{branch.split('/')[1]}.txt", "content": "receipt"}],
        )
        assert not commit.is_error, text(commit)
        pull = await call(
            "github_create_pull_request",
            title="Live test: receipt",
            head=branch,
            base="main",
            body="Removed by the test.",
        )
        assert not pull.is_error, text(pull)
        match = re.search(r"pull request #(\d+)", text(pull))
        assert match
        number = int(match[1])

        head = client.get(f"/pulls/{number}").json()["head"]["sha"]
        status = client.get(f"/commits/{head}/status").json()
        receipts = [item for item in status["statuses"] if item["context"] == CONTEXT]
        assert len(receipts) == 1
        assert receipts[0]["state"] == "success"
        assert receipts[0]["description"].startswith(f"policy {compiled.sha256[:12]}; audit seq 1-")
        assert "flow labels: off" in receipts[0]["description"]
        assert verify_log(audit).ok
    finally:
        if number is not None:
            client.patch(f"/pulls/{number}", json={"state": "closed"})
        client.delete(f"/git/refs/heads/{branch}")
        client.close()
        await github.aclose()
