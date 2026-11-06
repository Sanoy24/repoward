"""The approval store, the pipeline's use of it, and the operator CLI."""

import json
import sqlite3
import threading
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore, ApprovalStoreError, TooManyPendingError
from repoward.audit import AuditLog, verify_log
from repoward.cli import main
from repoward.pipeline import Pipeline
from repoward.policy.loader import CompiledPolicy, PolicyError, parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

API = "https://api.github.com"
REPO = "org/sandbox"
BASE = f"{API}/repos/{REPO}"
SHA = "a" * 40
OTHER_SHA = "b" * 40
MERGED_SHA = "c" * 40
MAINTAINER = Principal("carol", "maintainer")

POLICY = """\
version: 1
default: deny
repos:
  allow: ["org/sandbox"]
dangerous_tools:
  github_merge_pull_request: { enabled: true }
  github_delete_branch: { enabled: true }
approvals:
  ttl_minutes: 15
roles:
  maintainer:
    tools: [github_merge_pull_request, github_delete_branch]
    require_approval: [github_merge_pull_request, github_delete_branch]
  limited:
    tools: [github_merge_pull_request]
    require_approval: [github_merge_pull_request]
rate_limits:
  default: { per_minute: 1000 }
stdio:
  role: maintainer
"""


class Clock:
    now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "approvals.db"


@pytest.fixture
def store(db: Path, clock: Clock) -> ApprovalStore:
    return ApprovalStore(db, ttl_seconds=900.0, max_pending_per_principal=3, clock=clock)


def request(store: ApprovalStore, args_hash: str = "h1", principal: str = "p") -> str:
    return store.request(principal, "tool", "org/repo", args_hash, "{}", "ctx").id


# Store


def test_ids_are_long_and_random(store: ApprovalStore) -> None:
    first, second = request(store, "a"), request(store, "b")
    assert first != second
    assert len(first) == 32


def test_identical_pending_request_returns_the_same_id(store: ApprovalStore) -> None:
    assert request(store) == request(store)
    assert len(store.list()) == 1


def test_unapproved_requests_cannot_be_consumed(store: ApprovalStore) -> None:
    request(store)
    assert store.consume("p", "tool", "org/repo", "h1") is None


def test_approval_is_single_use(store: ApprovalStore) -> None:
    approval_id = request(store)
    assert store.decide(approval_id, True, "human")
    assert store.consume("p", "tool", "org/repo", "h1") == approval_id
    assert store.consume("p", "tool", "org/repo", "h1") is None
    approval = store.get(approval_id)
    assert approval is not None
    assert approval.status == "consumed"
    assert approval.decided_by == "human"
    assert approval.consumed_at is not None


@pytest.mark.parametrize(
    ("principal", "tool", "repo", "args_hash"),
    [
        ("other", "tool", "org/repo", "h1"),
        ("p", "other", "org/repo", "h1"),
        ("p", "tool", "org/other", "h1"),
        ("p", "tool", None, "h1"),
        ("p", "tool", "org/repo", "other"),
    ],
)
def test_approval_only_matches_the_exact_call(
    store: ApprovalStore, principal: str, tool: str, repo: str | None, args_hash: str
) -> None:
    store.decide(request(store), True, "human")
    assert store.consume(principal, tool, repo, args_hash) is None
    assert store.consume("p", "tool", "org/repo", "h1") is not None


def test_denied_requests_cannot_be_consumed_or_redecided(store: ApprovalStore) -> None:
    approval_id = request(store)
    assert store.decide(approval_id, False, "human")
    assert store.consume("p", "tool", "org/repo", "h1") is None
    assert not store.decide(approval_id, True, "human")


def test_decisions_are_final(store: ApprovalStore) -> None:
    approval_id = request(store)
    assert store.decide(approval_id, True, "first")
    assert not store.decide(approval_id, False, "second")
    approval = store.get(approval_id)
    assert approval is not None
    assert approval.decided_by == "first"


def test_pending_requests_expire(store: ApprovalStore, clock: Clock) -> None:
    approval_id = request(store)
    clock.now += 900.0
    assert not store.decide(approval_id, True, "human")
    approval = store.get(approval_id)
    assert approval is not None
    assert approval.status == "expired"


def test_approvals_expire(store: ApprovalStore, clock: Clock) -> None:
    store.decide(request(store), True, "human")
    clock.now += 900.0
    assert store.consume("p", "tool", "org/repo", "h1") is None


def test_approving_starts_a_fresh_window(store: ApprovalStore, clock: Clock) -> None:
    approval_id = request(store)
    clock.now += 800.0
    store.decide(approval_id, True, "human")
    clock.now += 800.0
    assert store.consume("p", "tool", "org/repo", "h1") == approval_id


def test_pending_requests_are_capped_per_principal(store: ApprovalStore, clock: Clock) -> None:
    for name in "abc":
        request(store, name)
    with pytest.raises(TooManyPendingError):
        request(store, "d")
    request(store, "d", principal="someone-else")
    clock.now += 900.0
    request(store, "d")


def test_concurrent_consumers_get_exactly_one_success(db: Path) -> None:
    store = ApprovalStore(db)
    store.decide(request(store), True, "human")
    results: list[str | None] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        results.append(ApprovalStore(db).consume("p", "tool", "org/repo", "h1"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len([result for result in results if result]) == 1


def test_sql_metacharacters_are_just_data(store: ApprovalStore) -> None:
    hostile = "x'; DROP TABLE approvals; --"
    approval_id = store.request(hostile, hostile, hostile, hostile, hostile, hostile).id
    approval = store.get(approval_id)
    assert approval is not None
    assert approval.tool == hostile
    assert store.get(hostile) is None


def test_unusable_database_raises(tmp_path: Path) -> None:
    with pytest.raises(ApprovalStoreError):
        ApprovalStore(tmp_path)


def test_corrupt_status_is_refused_by_the_schema(store: ApprovalStore, db: Path) -> None:
    approval_id = request(store)
    connection = sqlite3.connect(db)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE approvals SET status = 'bogus' WHERE id = ?", (approval_id,))
    connection.close()


# Through the pipeline


class Stack:
    def __init__(self, tmp_path: Path, policy: CompiledPolicy, github: GitHubClient) -> None:
        self.audit_path = tmp_path / "audit.jsonl"
        self.store = ApprovalStore(tmp_path / "approvals.db")
        self.pipeline = Pipeline(
            policy,
            build_registry(policy, github),
            AuditLog(self.audit_path),
            approvals=self.store,
        )

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_path.read_bytes().splitlines()]


@pytest.fixture
def dangerous_policy() -> CompiledPolicy:
    return parse_policy(POLICY.encode())


@pytest.fixture
async def stack(dangerous_policy: CompiledPolicy, tmp_path: Path) -> AsyncIterator[Stack]:
    github = GitHubClient("fake-token")
    yield Stack(tmp_path, dangerous_policy, github)
    await github.aclose()


@pytest.fixture
def github() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def merge_args(**overrides: Any) -> dict[str, Any]:
    return {"repo": REPO, "number": 5, "head_sha": SHA, **overrides}


def mock_pull(github: respx.MockRouter, head: str = SHA) -> None:
    github.get(f"{BASE}/pulls/5").respond(
        json={
            "title": "A pull request",
            "state": "open",
            "draft": False,
            "mergeable": True,
            "changed_files": 2,
            "additions": 3,
            "deletions": 1,
            "author_association": "MEMBER",
            "head": {"sha": head, "ref": "agent/x"},
            "base": {"ref": "main"},
        }
    )


@pytest.mark.anyio
async def test_merge_needs_approval_and_then_runs_exactly_once(
    stack: Stack, github: respx.MockRouter
) -> None:
    mock_pull(github)
    merge = github.put(f"{BASE}/pulls/5/merge").respond(
        json={"merged": True, "sha": MERGED_SHA, "message": "ok"}
    )

    first = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert not first.is_error
    assert first.structured_content is not None
    assert first.structured_content["status"] == "approval_required"
    approval_id = first.structured_content["approval_id"]
    assert not merge.called

    again = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert again.structured_content is not None
    assert again.structured_content["approval_id"] == approval_id
    assert not merge.called

    assert stack.store.decide(approval_id, True, "human")
    done = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert not done.is_error
    assert MERGED_SHA in text(done)
    assert merge.call_count == 1
    assert json.loads(merge.calls.last.request.content) == {"sha": SHA, "merge_method": "squash"}

    replay = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert replay.structured_content is not None
    assert replay.structured_content["status"] == "approval_required"
    assert merge.call_count == 1


@pytest.mark.anyio
async def test_a_different_commit_is_not_covered_by_the_approval(
    stack: Stack, github: respx.MockRouter
) -> None:
    mock_pull(github)
    merge = github.put(f"{BASE}/pulls/5/merge").respond(json={"merged": True, "sha": MERGED_SHA})
    first = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert first.structured_content is not None
    stack.store.decide(first.structured_content["approval_id"], True, "human")

    other = await stack.pipeline.call(
        MAINTAINER, "github_merge_pull_request", merge_args(head_sha=OTHER_SHA)
    )
    assert other.structured_content is not None
    assert other.structured_content["status"] == "approval_required"
    assert not merge.called


@pytest.mark.anyio
async def test_github_refusal_after_a_push_still_spends_the_approval(
    stack: Stack, github: respx.MockRouter
) -> None:
    mock_pull(github)
    merge = github.put(f"{BASE}/pulls/5/merge").respond(409, json={"message": "head moved"})
    first = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert first.structured_content is not None
    stack.store.decide(first.structured_content["approval_id"], True, "human")

    result = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert result.is_error
    assert "conflict" in text(result)
    assert merge.call_count == 1
    retry = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert retry.structured_content is not None
    assert retry.structured_content["status"] == "approval_required"
    assert merge.call_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"head_sha": "main"},
        {"head_sha": "A" * 40},
        {"merge_method": "fast-forward"},
        {"bypass_rules": True},
    ],
)
async def test_bad_merge_arguments_are_refused(
    stack: Stack, github: respx.MockRouter, overrides: dict[str, Any]
) -> None:
    result = await stack.pipeline.call(
        MAINTAINER, "github_merge_pull_request", merge_args(**overrides)
    )
    assert result.is_error
    assert stack.store.list() == []
    assert not github.calls


@pytest.mark.anyio
async def test_merge_is_disabled_unless_switched_on(tmp_path: Path) -> None:
    policy = parse_policy(
        POLICY.replace("github_merge_pull_request: { enabled: true }", "").encode()
    )
    client = GitHubClient("fake-token")
    stack = Stack(tmp_path, policy, client)
    with respx.mock(assert_all_called=False) as router:
        result = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
        assert not router.calls
    assert result.is_error
    assert "disabled" in text(result)
    assert stack.store.list() == []
    await client.aclose()


@pytest.mark.anyio
async def test_no_store_means_nothing_runs(
    dangerous_policy: CompiledPolicy, tmp_path: Path, github: respx.MockRouter
) -> None:
    client = GitHubClient("fake-token")
    pipeline = Pipeline(
        dangerous_policy, build_registry(dangerous_policy, client), AuditLog(tmp_path / "a.jsonl")
    )
    result = await pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert result.is_error
    assert not github.calls
    await client.aclose()


@pytest.mark.anyio
async def test_a_broken_store_means_nothing_runs(
    stack: Stack, github: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_: object) -> None:
        raise ApprovalStoreError("store down")

    monkeypatch.setattr(stack.store, "consume", fail)
    result = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert result.is_error
    assert stack.records()[-1]["rule_id"] == "approvals.unavailable"
    assert not github.calls


@pytest.mark.anyio
async def test_context_failure_does_not_block_the_request(
    stack: Stack, github: respx.MockRouter
) -> None:
    github.get(f"{BASE}/pulls/5").respond(500)
    result = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert result.structured_content is not None
    assert "Could not fetch details" in stack.store.list()[0].context


@pytest.mark.anyio
async def test_context_warns_when_the_head_has_moved(
    stack: Stack, github: respx.MockRouter
) -> None:
    mock_pull(github, head=OTHER_SHA)
    await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert "WARNING" in stack.store.list()[0].context


@pytest.mark.anyio
async def test_the_agent_is_not_shown_github_text_in_the_approval_result(
    stack: Stack, github: respx.MockRouter
) -> None:
    mock_pull(github)
    result = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert "A pull request" not in text(result)


@pytest.mark.anyio
async def test_the_whole_flow_is_audited(stack: Stack, github: respx.MockRouter) -> None:
    mock_pull(github)
    github.put(f"{BASE}/pulls/5/merge").respond(json={"merged": True, "sha": MERGED_SHA})
    first = await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    assert first.structured_content is not None
    approval_id = first.structured_content["approval_id"]
    stack.store.decide(approval_id, True, "human")
    await stack.pipeline.call(MAINTAINER, "github_merge_pull_request", merge_args())
    request_record, decision, outcome = stack.records()
    assert request_record["decision"] == "approval_required"
    assert request_record["approval_id"] == approval_id
    assert decision["decision"] == "allow"
    assert decision["rule_id"] == "approvals.consumed"
    assert decision["approval_id"] == approval_id
    assert outcome["result_status"] == "ok"
    assert verify_log(stack.audit_path).ok


# Delete branch


def delete_args(**overrides: Any) -> dict[str, Any]:
    return {"repo": REPO, "branch": "agent/x", "expected_sha": SHA, **overrides}


async def approve_delete(stack: Stack, **overrides: Any) -> None:
    first = await stack.pipeline.call(MAINTAINER, "github_delete_branch", delete_args(**overrides))
    assert first.structured_content is not None
    stack.store.decide(first.structured_content["approval_id"], True, "human")


@pytest.mark.anyio
async def test_delete_branch_after_approval(stack: Stack, github: respx.MockRouter) -> None:
    github.get(BASE).respond(json={"default_branch": "main"})
    github.get(f"{BASE}/git/ref/heads/agent/x").respond(json={"object": {"sha": SHA}})
    delete = github.delete(f"{BASE}/git/refs/heads/agent/x").respond(204)
    await approve_delete(stack)
    assert not delete.called
    result = await stack.pipeline.call(MAINTAINER, "github_delete_branch", delete_args())
    assert not result.is_error, text(result)
    assert delete.call_count == 1


@pytest.mark.anyio
async def test_delete_refuses_a_branch_that_moved(stack: Stack, github: respx.MockRouter) -> None:
    github.get(BASE).respond(json={"default_branch": "main"})
    github.get(f"{BASE}/git/ref/heads/agent/x").respond(json={"object": {"sha": OTHER_SHA}})
    delete = github.delete(f"{BASE}/git/refs/heads/agent/x").respond(204)
    await approve_delete(stack)
    result = await stack.pipeline.call(MAINTAINER, "github_delete_branch", delete_args())
    assert result.is_error
    assert "moved" in text(result)
    assert not delete.called


@pytest.mark.anyio
async def test_delete_never_touches_the_default_branch(
    stack: Stack, github: respx.MockRouter
) -> None:
    github.get(BASE).respond(json={"default_branch": "agent/x"})
    github.get(f"{BASE}/git/ref/heads/agent/x").respond(json={"object": {"sha": SHA}})
    delete = github.delete(f"{BASE}/git/refs/heads/agent/x").respond(204)
    await approve_delete(stack)
    result = await stack.pipeline.call(MAINTAINER, "github_delete_branch", delete_args())
    assert result.is_error
    assert "default branch" in text(result)
    assert not delete.called


@pytest.mark.anyio
@pytest.mark.parametrize("branch", ["main", "feature/x"])
async def test_delete_is_limited_to_the_prefix(
    stack: Stack, github: respx.MockRouter, branch: str
) -> None:
    result = await stack.pipeline.call(
        MAINTAINER, "github_delete_branch", delete_args(branch=branch)
    )
    assert result.is_error
    assert stack.store.list() == []
    assert not github.calls


# CLI


def seed(db: Path, context: str = "Title: hello") -> str:
    store = ApprovalStore(db)
    return store.request("agent", "github_merge_pull_request", REPO, "h", '{"n": 1}', context).id


def test_cli_list_and_show(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    approval_id = seed(db)
    assert main(["approvals", "--db", str(db), "list"]) == 0
    assert approval_id in capsys.readouterr().out
    assert main(["approvals", "--db", str(db), "show", approval_id]) == 0
    out = capsys.readouterr().out
    assert out.index("Tool:") < out.index("Arguments:") < out.index("From GitHub (untrusted")
    assert "Title: hello" in out


def test_cli_empty_list_and_missing_id(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["approvals", "--db", str(db), "list"]) == 0
    assert "No requests" in capsys.readouterr().out
    assert main(["approvals", "--db", str(db), "show", "nope"]) == 1


def test_cli_approve_is_audited_and_final(
    db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit = tmp_path / "audit.jsonl"
    approval_id = seed(db)
    base = ["approvals", "--db", str(db)]
    assert main([*base, "approve", approval_id, "--audit", str(audit)]) == 0
    assert "approved" in capsys.readouterr().out
    record = json.loads(audit.read_bytes().splitlines()[0])
    assert record["event"] == "approval_decision"
    assert record["decision"] == "approved"
    assert record["approval_id"] == approval_id
    assert record["decided_by"]
    assert main([*base, "deny", approval_id, "--audit", str(audit)]) == 1
    assert verify_log(audit).records == 1
    assert main([*base, "list"]) == 0
    assert "No requests" in capsys.readouterr().out
    assert main([*base, "list", "--all"]) == 0
    assert approval_id in capsys.readouterr().out


def test_cli_deny(db: Path, tmp_path: Path) -> None:
    approval_id = seed(db)
    audit = str(tmp_path / "audit.jsonl")
    assert main(["approvals", "--db", str(db), "deny", approval_id, "--audit", audit]) == 0
    assert ApprovalStore(db).consume("agent", "github_merge_pull_request", REPO, "h") is None


def test_no_audit_means_no_decision(db: Path, tmp_path: Path) -> None:
    approval_id = seed(db)
    code = main(["approvals", "--db", str(db), "approve", approval_id, "--audit", str(tmp_path)])
    assert code == 1
    approval = ApprovalStore(db).get(approval_id)
    assert approval is not None
    assert approval.status == "pending"


def test_terminal_escapes_cannot_spoof_the_approver(
    db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    escape = chr(27)
    hostile = (
        f"Title: fine{escape}[2K{escape}[1A{escape}]0;owned{chr(7)}"
        f"{chr(0x202E)}10${chr(0x200B)}\nsecond"
    )
    approval_id = seed(db, hostile)
    assert main(["approvals", "--db", str(db), "show", approval_id]) == 0
    out = capsys.readouterr().out
    assert escape not in out
    assert chr(0x202E) not in out
    assert chr(0x200B) not in out
    assert "  | second" in out


def test_cli_reports_an_unusable_database(tmp_path: Path) -> None:
    assert main(["approvals", "--db", str(tmp_path), "list"]) == 1


# Policy


@pytest.mark.parametrize("value", ["0", "1441"])
def test_invalid_ttl_is_refused(value: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(POLICY.replace("ttl_minutes: 15", f"ttl_minutes: {value}").encode())
