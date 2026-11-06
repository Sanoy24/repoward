"""Replays the toxic flow attack against a real public and private sandbox pair.

Skipped by default. Needs GITHUB_WRITE_TOKEN, REPOWARD_LIVE_REPO and REPOWARD_LIVE_PRIVATE_REPO.

Every sandbox issue has the same owner, and a test cannot create an outside author. So where a
test needs an untrusted author, its policy marks OWNER as not trusted, which exercises the same
code using the real author_association GitHub returns.
"""

import os
import re
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog, verify_log
from repoward.flow import FlowGuard, FlowStore
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

TOKEN = os.environ.get("GITHUB_WRITE_TOKEN", "")
PUBLIC = os.environ.get("REPOWARD_LIVE_REPO", "")
PRIVATE = os.environ.get("REPOWARD_LIVE_PRIVATE_REPO", "")
AGENT = Principal("live-agent", "contributor")
MARKER = "FAKE-PRIVATE-MARKER"


class Stack:
    def __init__(self, tmp_path: Path, trusted: str) -> None:
        policy = parse_policy(
            f"""\
version: 1
default: deny
repos:
  allow: ["{PUBLIC}", "{PRIVATE}"]
flow_guard:
  trusted_associations: {trusted}
roles:
  contributor:
    tools: [github_list_issues, github_get_issue, github_get_file, github_comment,
            github_create_branch, github_commit_files, github_create_pull_request]
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: contributor
""".encode()
        )
        self.github = GitHubClient(TOKEN)
        self.audit = tmp_path / "audit.jsonl"
        self.approvals = ApprovalStore(tmp_path / "approvals.db")
        self.flow_path = tmp_path / "flow.db"
        self.pipeline = Pipeline(
            policy,
            build_registry(policy, self.github),
            AuditLog(self.audit),
            approvals=self.approvals,
            flow=FlowGuard(
                policy.policy.flow_guard, FlowStore(self.flow_path), self.github.repo_is_private
            ),
        )

    async def call(self, tool: str, **args: Any) -> CallToolResult:
        return await self.pipeline.call(AGENT, tool, args)


@pytest.fixture
def public_api() -> Iterator[httpx.Client]:
    if not (TOKEN and PUBLIC and PRIVATE):
        pytest.skip("GITHUB_WRITE_TOKEN and both sandbox repos are required")
    client = httpx.Client(
        base_url=f"https://api.github.com/repos/{PUBLIC}",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        timeout=30,
    )
    yield client
    client.close()


@pytest.fixture
async def outsider_stack(public_api: httpx.Client, tmp_path: Path) -> AsyncIterator[Stack]:
    """The issue's author counts as an outsider."""
    stack = Stack(tmp_path, "[MEMBER]")
    yield stack
    await stack.github.aclose()


@pytest.fixture
async def trusting_stack(public_api: httpx.Client, tmp_path: Path) -> AsyncIterator[Stack]:
    stack = Stack(tmp_path, "[OWNER, MEMBER, COLLABORATOR]")
    yield stack
    await stack.github.aclose()


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


async def injection_issue(stack: Stack) -> int:
    listing = text(await stack.call("github_list_issues", repo=PUBLIC))
    match = re.search(r"#(\d+): Prompt injection test fixture", listing)
    assert match
    return int(match[1])


def comment_count(api: httpx.Client, number: int) -> int:
    count: int = api.get(f"/issues/{number}").json()["comments"]
    return count


async def test_the_published_attack_is_blocked(
    trusting_stack: Stack, public_api: httpx.Client
) -> None:
    """Read a public issue, read the private repo, then try to publish it. The write must fail."""
    stack = trusting_stack
    number = await injection_issue(stack)
    before = comment_count(public_api, number)

    issue = await stack.call("github_get_issue", repo=PUBLIC, number=number)
    assert "Ignore previous instructions" in text(issue)

    stolen = await stack.call("github_get_file", repo=PRIVATE, path="notes/internal.txt")
    assert not stolen.is_error, text(stolen)
    assert MARKER in text(stolen)

    leak = await stack.call("github_comment", repo=PUBLIC, number=number, body=text(stolen))
    assert leak.is_error
    assert "private content" in text(leak)
    assert comment_count(public_api, number) == before

    pull = await stack.call(
        "github_create_pull_request",
        repo=PUBLIC,
        title="Leak",
        head="agent/example",
        base="main",
        body=text(stolen),
    )
    assert pull.is_error
    assert "private content" in text(pull)
    assert verify_log(stack.audit).ok


async def test_private_issues_set_the_same_label(
    trusting_stack: Stack, public_api: httpx.Client
) -> None:
    stack = trusting_stack
    listing = await stack.call("github_list_issues", repo=PRIVATE)
    assert not listing.is_error, text(listing)
    number = await injection_issue(stack)
    before = comment_count(public_api, number)
    result = await stack.call("github_comment", repo=PUBLIC, number=number, body="x")
    assert result.is_error
    assert comment_count(public_api, number) == before


async def test_clean_reads_leave_writes_alone(
    trusting_stack: Stack, public_api: httpx.Client
) -> None:
    """Only trusted public reads came first, so the same comment goes through."""
    stack = trusting_stack
    number = await injection_issue(stack)
    await stack.call("github_get_issue", repo=PUBLIC, number=number)
    before = comment_count(public_api, number)
    result = await stack.call(
        "github_comment", repo=PUBLIC, number=number, body="Live flow test: allowed comment."
    )
    assert not result.is_error, text(result)
    assert comment_count(public_api, number) == before + 1


async def test_outside_author_requires_approval_for_one_write(
    outsider_stack: Stack, public_api: httpx.Client
) -> None:
    stack = outsider_stack
    number = await injection_issue(stack)
    before = comment_count(public_api, number)
    await stack.call("github_get_issue", repo=PUBLIC, number=number)

    args: dict[str, Any] = {
        "repo": PUBLIC,
        "number": number,
        "body": "Live flow test: approved comment.",
    }
    first = await stack.call("github_comment", **args)
    assert first.structured_content is not None
    assert first.structured_content["status"] == "approval_required"
    assert comment_count(public_api, number) == before

    assert stack.approvals.decide(first.structured_content["approval_id"], True, "live-human")
    done = await stack.call("github_comment", **args)
    assert not done.is_error, text(done)
    assert comment_count(public_api, number) == before + 1

    again = await stack.call("github_comment", **args)
    assert again.structured_content is not None
    assert again.structured_content["status"] == "approval_required"
    assert comment_count(public_api, number) == before + 1


async def test_repo_visibility_comes_from_github(trusting_stack: Stack) -> None:
    assert await trusting_stack.github.repo_is_private(PRIVATE) is True
    assert await trusting_stack.github.repo_is_private(PUBLIC) is False
