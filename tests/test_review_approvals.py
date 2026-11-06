"""A real pull request review as the approval for a merge."""

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = pytest.mark.anyio

API = "https://api.github.com"
REPO = "org/sandbox"
BASE = f"{API}/repos/{REPO}"
HEAD = "a" * 40
OLD = "b" * 40
MERGED = "c" * 40
AGENT = Principal("agent", "maintainer")
ARGS = {"repo": REPO, "number": 5, "head_sha": HEAD}
BOT = "repoward-bot"
AUTHOR = "pr-author"
HUMAN = "alice"


def policy_text(review: str = "{ enabled: true, min_permission: write }") -> str:
    return f"""\
version: 1
default: deny
repos:
  allow: ["org/sandbox"]
dangerous_tools:
  github_merge_pull_request: {{ enabled: true }}
approvals:
  github_review: {review}
flow_guard:
  enabled: false
roles:
  maintainer:
    tools: [github_merge_pull_request]
    require_approval: [github_merge_pull_request]
rate_limits:
  default: {{ per_minute: 1000 }}
stdio:
  role: maintainer
"""


class Stack:
    def __init__(self, tmp_path: Path, review: str | None = None) -> None:
        text_policy = policy_text() if review is None else policy_text(review)
        policy = parse_policy(text_policy.encode())
        self.github = GitHubClient("fake-token")
        self.audit_path = tmp_path / "audit.jsonl"
        self.store = ApprovalStore(tmp_path / "approvals.db")
        self.pipeline = Pipeline(
            policy,
            build_registry(policy, self.github),
            AuditLog(self.audit_path),
            approvals=self.store,
        )

    def last_decision(self) -> dict[str, Any]:
        rows = [json.loads(line) for line in self.audit_path.read_bytes().splitlines()]
        decisions = [row for row in rows if row["event"] == "tool_call_decision"]
        result: dict[str, Any] = decisions[-1]
        return result


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    built = Stack(tmp_path)
    yield built
    await built.github.aclose()


def review(
    login: str = HUMAN,
    state: str = "APPROVED",
    commit: str = HEAD,
    kind: str = "User",
    review_id: int = 1,
) -> dict[str, Any]:
    return {
        "id": review_id,
        "state": state,
        "commit_id": commit,
        "user": {"login": login, "type": kind},
    }


class GitHub:
    def __init__(self, router: respx.MockRouter) -> None:
        self.router = router
        self.merge = router.put(f"{BASE}/pulls/5/merge").respond(
            json={"merged": True, "sha": MERGED}
        )
        self.user = router.get(f"{API}/user").respond(json={"login": BOT})
        self.pull(HEAD)
        self.permission(HUMAN, "write")

    def pull(self, head: str = HEAD, state: str = "open", author: str = AUTHOR) -> None:
        self.router.get(f"{BASE}/pulls/5").respond(
            json={
                "state": state,
                "title": "t",
                "user": {"login": author},
                "head": {"sha": head, "ref": "agent/x"},
                "base": {"ref": "main"},
            }
        )

    def reviews(self, *items: dict[str, Any]) -> None:
        self.router.get(f"{BASE}/pulls/5/reviews").respond(json=list(items))

    def permission(self, login: str, level: str) -> None:
        self.router.get(f"{BASE}/collaborators/{login}/permission").respond(
            json={"permission": level}
        )


@pytest.fixture
def github() -> Iterator[GitHub]:
    with respx.mock(assert_all_called=False) as router:
        yield GitHub(router)


async def merge(stack: Stack) -> CallToolResult:
    return await stack.pipeline.call(AGENT, "github_merge_pull_request", ARGS)


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def was_refused(result: CallToolResult, github: GitHub) -> bool:
    return (
        result.structured_content is not None
        and result.structured_content.get("status") == "approval_required"
        and not github.merge.called
    )


async def test_a_qualifying_review_approves_the_merge(stack: Stack, github: GitHub) -> None:
    github.reviews(review(review_id=42))
    result = await merge(stack)
    assert not result.is_error
    assert MERGED in text(result)
    assert json.loads(github.merge.calls.last.request.content)["sha"] == HEAD
    decision = stack.last_decision()
    assert decision["rule_id"] == "approvals.github_review"
    assert decision["approved_by"] == HUMAN
    assert decision["review_id"] == 42
    assert stack.store.list() == []
    assert verify_log(stack.audit_path).ok


async def test_no_review_falls_back_to_the_cli_flow(stack: Stack, github: GitHub) -> None:
    github.reviews()
    first = await merge(stack)
    assert was_refused(first, github)
    assert first.structured_content is not None
    stack.store.decide(first.structured_content["approval_id"], True, "human")
    assert not (await merge(stack)).is_error
    assert stack.last_decision()["rule_id"] == "approvals.consumed"


@pytest.mark.parametrize(
    "reviews",
    [
        pytest.param([review(commit=OLD)], id="approved-an-older-commit"),
        pytest.param([review(login=AUTHOR)], id="the-author-approved"),
        pytest.param([review(login=BOT)], id="this-server-approved"),
        pytest.param([review(login=BOT.upper())], id="this-server-in-another-case"),
        pytest.param([review(kind="Bot")], id="a-bot-approved"),
        pytest.param([review(state="COMMENTED")], id="only-a-comment"),
        pytest.param([review(state="PENDING")], id="not-submitted"),
        pytest.param(
            [review(), review(state="DISMISSED", review_id=2)],
            id="the-approval-was-dismissed",
        ),
        pytest.param(
            [review(), review(state="CHANGES_REQUESTED", review_id=2)],
            id="the-same-person-changed-their-mind",
        ),
        pytest.param(
            [review(), review(login="bob", state="CHANGES_REQUESTED", review_id=2)],
            id="someone-else-requested-changes",
        ),
        pytest.param([{"id": 1, "state": "APPROVED", "commit_id": HEAD}], id="no-user"),
    ],
)
async def test_reviews_that_do_not_qualify(
    stack: Stack, github: GitHub, reviews: list[dict[str, Any]]
) -> None:
    github.reviews(*reviews)
    assert was_refused(await merge(stack), github)


async def test_a_later_comment_does_not_cancel_an_approval(stack: Stack, github: GitHub) -> None:
    github.reviews(review(), review(state="COMMENTED", review_id=2, commit=OLD))
    assert not (await merge(stack)).is_error


async def test_requested_changes_can_be_superseded_by_the_same_person(
    stack: Stack, github: GitHub
) -> None:
    github.reviews(review(state="CHANGES_REQUESTED"), review(review_id=2))
    assert not (await merge(stack)).is_error


@pytest.mark.parametrize("level", ["read", "none", "triage", "unknown"])
async def test_a_reviewer_without_write_access_does_not_count(
    stack: Stack, github: GitHub, level: str
) -> None:
    github.reviews(review())
    github.permission(HUMAN, level)
    assert was_refused(await merge(stack), github)


async def test_policy_can_require_admin(tmp_path: Path, github: GitHub) -> None:
    built = Stack(tmp_path, "{ enabled: true, min_permission: admin }")
    github.reviews(review())
    assert was_refused(await merge(built), github)
    github.permission(HUMAN, "admin")
    assert not (await merge(built)).is_error
    await built.github.aclose()


async def test_a_pushed_commit_voids_the_review(stack: Stack, github: GitHub) -> None:
    github.pull(head=OLD)
    github.reviews(review())
    assert was_refused(await merge(stack), github)


@pytest.mark.parametrize("state", ["closed"])
async def test_a_closed_pull_request_does_not_qualify(
    stack: Stack, github: GitHub, state: str
) -> None:
    github.pull(state=state)
    github.reviews(review())
    assert was_refused(await merge(stack), github)


async def test_it_is_off_by_default(tmp_path: Path, github: GitHub) -> None:
    built = Stack(tmp_path, "{ enabled: false }")
    github.reviews(review())
    assert was_refused(await merge(built), github)
    assert not github.user.called
    await built.github.aclose()


@pytest.mark.parametrize("failing", ["reviews", "identity", "permission"])
async def test_a_failed_check_means_no_approval(stack: Stack, github: GitHub, failing: str) -> None:
    github.reviews(review())
    if failing == "reviews":
        github.router.get(f"{BASE}/pulls/5/reviews").respond(500)
    elif failing == "identity":
        github.user.respond(500)
    else:
        github.router.get(f"{BASE}/collaborators/{HUMAN}/permission").respond(404)
    assert was_refused(await merge(stack), github)


async def test_too_many_reviews_means_no_approval(stack: Stack, github: GitHub) -> None:
    github.router.get(f"{BASE}/pulls/5/reviews").respond(
        json=[review(login="bob", state="COMMENTED")] * 100
    )
    assert was_refused(await merge(stack), github)


async def test_github_still_refuses_if_the_head_moved_at_the_last_moment(
    stack: Stack, github: GitHub
) -> None:
    github.reviews(review())
    github.merge.respond(409, json={"message": "head moved"})
    result = await merge(stack)
    assert result.is_error
    assert "conflict" in text(result)


async def test_delete_branch_has_no_review_route(stack: Stack, github: GitHub) -> None:
    registry_tool = stack.pipeline._registry.get("github_delete_branch")
    assert registry_tool is not None
    assert registry_tool.review_approval is None
