"""GitHub App tokens and review approvals against real repositories. Skipped by default.

Needs REPOWARD_LIVE_REPO, REPOWARD_LIVE_APP_CLIENT_ID, REPOWARD_LIVE_APP_INSTALLATION_ID and
GITHUB_APP_PRIVATE_KEY_FILE. The App opens the pull request, so a person can review it. The review
test also needs REPOWARD_LIVE_REVIEW=1 and a logged-in gh CLI, whose user approves as the human.
A person should run that test themselves, because it approves a pull request in their name.
"""

import os
import re
import shutil
import subprocess
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.adapters.github_auth import AppTokens, load_private_key
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.scope import CallScope
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

REPO = os.environ.get("REPOWARD_LIVE_REPO", "")
PRIVATE = os.environ.get("REPOWARD_LIVE_PRIVATE_REPO", "")
CLIENT_ID = os.environ.get("REPOWARD_LIVE_APP_CLIENT_ID", "")
INSTALLATION = os.environ.get("REPOWARD_LIVE_APP_INSTALLATION_ID", "")
AGENT = Principal("live-app", "maintainer")


class Stack:
    def __init__(self, tmp_path: Path) -> None:
        policy = parse_policy(
            f"""\
version: 1
default: deny
github_auth:
  mode: app
  client_id: {CLIENT_ID}
  installation_id: {INSTALLATION}
repos:
  allow: ["{REPO}"]
pull_requests:
  allow_non_draft: true
dangerous_tools:
  github_merge_pull_request: {{ enabled: true }}
approvals:
  github_review: {{ enabled: true, min_permission: write }}
flow_guard:
  enabled: false
roles:
  maintainer:
    tools: [github_list_issues, github_get_issue, github_get_file, ci_get_status,
            github_create_branch, github_commit_files, github_create_pull_request,
            github_comment, github_merge_pull_request]
    require_approval: [github_merge_pull_request]
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: maintainer
""".encode()
        )
        self.tokens = AppTokens(CLIENT_ID, int(INSTALLATION), load_private_key())
        self.github = GitHubClient(self.tokens)
        self.store = ApprovalStore(tmp_path / "approvals.db")
        self.audit = tmp_path / "audit.jsonl"
        self.pipeline = Pipeline(
            policy, build_registry(policy, self.github), AuditLog(self.audit), approvals=self.store
        )

    async def call(self, tool: str, **args: Any) -> CallToolResult:
        return await self.pipeline.call(AGENT, tool, {"repo": REPO, **args})

    async def raw_token(self, permissions: dict[str, str]) -> str:
        return await self.tokens.token(CallScope(REPO, permissions), self.github._http)


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    if not (REPO and CLIENT_ID and INSTALLATION):
        pytest.skip("GitHub App settings are required")
    built = Stack(tmp_path)
    yield built
    await built.github.aclose()


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def api(token: str) -> httpx.Client:
    return httpx.Client(
        base_url=f"https://api.github.com/repos/{REPO}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        timeout=30,
    )


async def test_read_tools_work_with_narrow_tokens(stack: Stack) -> None:
    issues = await stack.call("github_list_issues")
    assert not issues.is_error, text(issues)
    file = await stack.call("github_get_file", path="src/app.py")
    assert not file.is_error, text(file)
    assert "def add" in text(file)
    status = await stack.call("ci_get_status", ref="main")
    assert not status.is_error, text(status)
    assert verify_log(stack.audit).ok


async def test_a_read_token_really_cannot_write(stack: Stack) -> None:
    """GitHub itself enforces this, whatever this server's code does."""
    token = await stack.raw_token({"contents": "read"})
    with api(token) as client:
        assert client.get("/contents/README.md").status_code == 200
        denied = client.delete("/git/refs/heads/repoward-no-such-branch-xyz")
        assert denied.status_code == 403
        # An empty comment cannot be created, so this only tests the permission check.
        assert client.post("/issues/2/comments", json={}).status_code == 403


async def test_a_token_is_limited_to_one_repository(stack: Stack) -> None:
    if not PRIVATE:
        pytest.skip("REPOWARD_LIVE_PRIVATE_REPO is required")
    token = await stack.raw_token({"contents": "read"})
    response = httpx.get(
        f"https://api.github.com/repos/{PRIVATE}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    assert response.status_code == 404


async def test_identity_is_the_apps_bot(stack: Stack) -> None:
    assert (await stack.github.identity()).endswith("[bot]")


async def test_a_human_review_approves_the_exact_commit(stack: Stack) -> None:
    if os.environ.get("REPOWARD_LIVE_REVIEW") != "1":
        pytest.skip("REPOWARD_LIVE_REVIEW=1 is required")
    gh = shutil.which("gh")
    assert gh
    # gh prefers token variables over its login, and the reviewer must be the logged-in person.
    human_env = {k: v for k, v in os.environ.items() if k not in {"GITHUB_TOKEN", "GH_TOKEN"}}
    branch = f"agent/live-{uuid.uuid4().hex[:10]}"
    number: int | None = None
    token = await stack.raw_token({"contents": "write", "pull_requests": "write"})
    client = api(token)
    try:
        assert not (await stack.call("github_create_branch", branch=branch, base="main")).is_error

        async def commit(name: str) -> str:
            done = await stack.call(
                "github_commit_files",
                branch=branch,
                message=f"test: {name}",
                files=[{"path": f"live/{branch.split('/')[1]}-{name}.txt", "content": name}],
            )
            assert not done.is_error, text(done)
            sha: str = client.get(f"/git/ref/heads/{branch}").json()["object"]["sha"]
            return sha

        first_sha = await commit("first")
        pull = await stack.call(
            "github_create_pull_request",
            title="Live test: review approval",
            head=branch,
            base="main",
            body="Opened by the App, reviewed by a person, merged by repoward.",
            draft=False,
        )
        assert not pull.is_error, text(pull)
        match = re.search(r"pull request #(\d+)", text(pull))
        assert match
        number = int(match[1])
        assert client.get(f"/pulls/{number}").json()["user"]["login"].endswith("[bot]")

        waiting = await stack.call("github_merge_pull_request", number=number, head_sha=first_sha)
        assert waiting.structured_content is not None
        assert waiting.structured_content["status"] == "approval_required"

        subprocess.run(  # noqa: S603
            [gh, "pr", "review", str(number), "--approve", "-R", REPO, "-b", "Live test approval."],
            check=True,
            env=human_env,
        )

        # A push after the review must void it, whatever GitHub's own settings do.
        second_sha = await commit("pushed-after-review")
        stale = await stack.call("github_merge_pull_request", number=number, head_sha=second_sha)
        assert stale.structured_content is not None
        assert stale.structured_content["status"] == "approval_required"
        assert client.get(f"/pulls/{number}").json()["merged"] is False

        subprocess.run(  # noqa: S603
            [gh, "pr", "review", str(number), "--approve", "-R", REPO, "-b", "Approved again."],
            check=True,
            env=human_env,
        )
        merged = await stack.call("github_merge_pull_request", number=number, head_sha=second_sha)
        assert not merged.is_error, text(merged)
        assert client.get(f"/pulls/{number}").json()["merged"] is True
        assert verify_log(stack.audit).ok
    finally:
        if number is not None:
            client.patch(f"/pulls/{number}", json={"state": "closed"})
        client.delete(f"/git/refs/heads/{branch}")
        client.close()
