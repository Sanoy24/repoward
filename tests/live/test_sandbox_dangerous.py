"""Approvals and dangerous tools against a real sandbox. Skipped by default.

This merges real commits into the sandbox's default branch, so point it only at a sandbox.
Needs GITHUB_WRITE_TOKEN and REPOWARD_LIVE_REPO. Run with: uv run pytest -m live
"""

import os
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

TOKEN = os.environ.get("GITHUB_WRITE_TOKEN", "")
REPO = os.environ.get("REPOWARD_LIVE_REPO", "")
AGENT = Principal("live-test", "maintainer")


class Sandbox:
    def __init__(self) -> None:
        self.http = httpx.Client(
            base_url=f"https://api.github.com/repos/{REPO}",
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
            },
            timeout=30,
        )
        self.branch = f"agent/live-{uuid.uuid4().hex[:10]}"
        self.pull_number: int | None = None

    def head(self) -> str:
        sha: str = self.http.get(f"/git/ref/heads/{self.branch}").json()["object"]["sha"]
        return sha

    def cleanup(self) -> None:
        if self.pull_number is not None:
            self.http.patch(f"/pulls/{self.pull_number}", json={"state": "closed"})
        self.http.delete(f"/git/refs/heads/{self.branch}")
        self.http.close()


@pytest.fixture
def sandbox() -> Iterator[Sandbox]:
    if not TOKEN or not REPO:
        pytest.skip("GITHUB_WRITE_TOKEN and REPOWARD_LIVE_REPO are required")
    box = Sandbox()
    yield box
    box.cleanup()


class Stack:
    def __init__(self, pipeline: Pipeline, store: ApprovalStore, audit: Path) -> None:
        self.pipeline = pipeline
        self.store = store
        self.audit = audit

    async def call(self, tool: str, **args: Any) -> CallToolResult:
        return await self.pipeline.call(AGENT, tool, {"repo": REPO, **args})


@pytest.fixture
async def stack(sandbox: Sandbox, tmp_path: Path) -> AsyncIterator[Stack]:
    policy = parse_policy(
        f"""\
version: 1
default: deny
repos:
  allow: ["{REPO}"]
pull_requests:
  allow_non_draft: true
dangerous_tools:
  github_merge_pull_request: {{ enabled: true }}
  github_delete_branch: {{ enabled: true }}
roles:
  maintainer:
    tools: [github_create_branch, github_commit_files, github_create_pull_request,
            github_merge_pull_request, github_delete_branch]
    require_approval: [github_merge_pull_request, github_delete_branch]
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: maintainer
""".encode()
    )
    github = GitHubClient(TOKEN)
    store = ApprovalStore(tmp_path / "approvals.db")
    audit = tmp_path / "audit.jsonl"
    pipeline = Pipeline(policy, build_registry(policy, github), AuditLog(audit), approvals=store)
    yield Stack(pipeline, store, audit)
    await github.aclose()


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


async def commit(stack: Stack, sandbox: Sandbox, name: str) -> None:
    result = await stack.call(
        "github_commit_files",
        branch=sandbox.branch,
        message=f"test: {name}",
        files=[{"path": f"live/{sandbox.branch.split('/')[1]}-{name}.txt", "content": name}],
    )
    assert not result.is_error, text(result)


async def open_pull(stack: Stack, sandbox: Sandbox) -> None:
    created = await stack.call("github_create_branch", branch=sandbox.branch, base="main")
    assert not created.is_error, text(created)
    await commit(stack, sandbox, "first")
    pull = await stack.call(
        "github_create_pull_request",
        title="Live test merge",
        head=sandbox.branch,
        base="main",
        body="Created by the live test suite.",
        draft=False,
    )
    assert not pull.is_error, text(pull)
    match = re.search(r"pull request #(\d+)", text(pull))
    assert match
    sandbox.pull_number = int(match[1])


async def test_merge_needs_approval_and_a_push_voids_it(stack: Stack, sandbox: Sandbox) -> None:
    await open_pull(stack, sandbox)
    assert sandbox.pull_number is not None
    approved_sha = sandbox.head()
    main_before = sandbox.http.get("/git/ref/heads/main").json()["object"]["sha"]

    first = await stack.call(
        "github_merge_pull_request", number=sandbox.pull_number, head_sha=approved_sha
    )
    assert first.structured_content is not None
    assert first.structured_content["status"] == "approval_required"
    approval_id = first.structured_content["approval_id"]
    request = stack.store.get(approval_id)
    assert request is not None
    assert "Live test merge" in request.context
    assert sandbox.http.get("/git/ref/heads/main").json()["object"]["sha"] == main_before

    assert stack.store.decide(approval_id, True, "live-test-human")
    await commit(stack, sandbox, "pushed-after-approval")
    moved = await stack.call(
        "github_merge_pull_request", number=sandbox.pull_number, head_sha=approved_sha
    )
    assert moved.is_error, text(moved)
    assert sandbox.http.get("/git/ref/heads/main").json()["object"]["sha"] == main_before
    assert sandbox.http.get(f"/pulls/{sandbox.pull_number}").json()["merged"] is False

    new_head = sandbox.head()
    second = await stack.call(
        "github_merge_pull_request", number=sandbox.pull_number, head_sha=new_head
    )
    assert second.structured_content is not None
    assert stack.store.decide(second.structured_content["approval_id"], True, "live-test-human")
    merged = await stack.call(
        "github_merge_pull_request", number=sandbox.pull_number, head_sha=new_head
    )
    assert not merged.is_error, text(merged)
    assert sandbox.http.get(f"/pulls/{sandbox.pull_number}").json()["merged"] is True

    replay = await stack.call(
        "github_merge_pull_request", number=sandbox.pull_number, head_sha=new_head
    )
    assert replay.structured_content is not None
    assert replay.structured_content["status"] == "approval_required"
    assert verify_log(stack.audit).ok


async def test_delete_branch_needs_approval(stack: Stack, sandbox: Sandbox) -> None:
    created = await stack.call("github_create_branch", branch=sandbox.branch, base="main")
    assert not created.is_error
    head = sandbox.head()

    first = await stack.call("github_delete_branch", branch=sandbox.branch, expected_sha=head)
    assert first.structured_content is not None
    assert sandbox.http.get(f"/git/ref/heads/{sandbox.branch}").status_code == 200

    stack.store.decide(first.structured_content["approval_id"], True, "live-test-human")
    deleted = await stack.call("github_delete_branch", branch=sandbox.branch, expected_sha=head)
    assert not deleted.is_error, text(deleted)
    assert sandbox.http.get(f"/git/ref/heads/{sandbox.branch}").status_code == 404
