"""Pull request receipts: informational, built from numbers only, and never able to fail a call."""

import json
import re
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.types import TextContent

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog, AuditWriteError, verify_log
from repoward.catalog import RECEIPT_PERMISSIONS
from repoward.flow import FlowGuard, FlowStore, FlowStoreError
from repoward.pipeline import Pipeline
from repoward.policy.loader import PolicyError, parse_policy
from repoward.policy.replay import replay_log
from repoward.principal import Principal
from repoward.receipts import CONTEXT, MAX_DESCRIPTION_CHARS, ReceiptLedger
from repoward.registry import ToolError
from repoward.scope import current_scope
from repoward.server import build_registry

pytestmark = pytest.mark.anyio

API = "https://api.github.com"
REPO = "org/sandbox"
BASE = f"{API}/repos/{REPO}"
PARENT = "1" * 40
TREE = "2" * 40
COMMIT = "3" * 40
HEAD = "4" * 40
AGENT = Principal("local:me", "contributor")
COMMIT_ARGS = {
    "repo": REPO,
    "branch": "agent/x",
    "message": "MESSAGE-TEXT",
    "files": [{"path": "CHOSEN-PATH.txt", "content": "FILE-CONTENT"}],
}
PR_ARGS = {
    "repo": REPO,
    "title": "TITLE-TEXT",
    "head": "agent/x",
    "base": "main",
    "body": "BODY-TEXT",
}


def compiled_policy(receipts: bool = True, flow: bool = False) -> Any:
    return parse_policy(
        f"""\
version: 1
default: deny
repos:
  allow: ["{REPO}"]
receipts:
  enabled: {str(receipts).lower()}
flow_guard:
  enabled: {str(flow).lower()}
roles:
  contributor:
    tools: [github_get_file, github_commit_files, github_create_pull_request, github_comment]
    require_approval: [github_comment]
rate_limits:
  default: {{ per_minute: 1000 }}
stdio:
  role: contributor
""".encode()
    )


class Stack:
    def __init__(self, tmp_path: Path, flow: bool = False) -> None:
        self.policy = compiled_policy(flow=flow)
        self.github = GitHubClient("fake-token")
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = AuditLog(self.audit_path)
        self.ledger = ReceiptLedger(self.github.post_commit_status, self.policy.sha256)
        self.flow = (
            FlowGuard(
                self.policy.policy.flow_guard,
                FlowStore(tmp_path / "flow.db"),
                self.github.repo_is_private,
            )
            if flow
            else None
        )
        self.approvals = ApprovalStore(tmp_path / "approvals.db")
        self.pipeline = Pipeline(
            self.policy,
            build_registry(self.policy, self.github),
            self.audit,
            approvals=self.approvals,
            flow=self.flow,
            receipts=self.ledger,
        )

    def events(self, name: str) -> list[dict[str, Any]]:
        rows = [json.loads(line) for line in self.audit_path.read_bytes().splitlines()]
        return [row for row in rows if row["event"] == name]

    async def commit(self) -> Any:
        return await self.pipeline.call(AGENT, "github_commit_files", COMMIT_ARGS)


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    built = Stack(tmp_path)
    yield built
    await built.github.aclose()


class GitHub:
    def __init__(self, router: respx.MockRouter) -> None:
        router.get(f"{BASE}/git/ref/heads/agent/x").respond(json={"object": {"sha": PARENT}})
        router.get(f"{BASE}/git/commits/{PARENT}").respond(json={"tree": {"sha": TREE}})
        router.post(f"{BASE}/git/trees").respond(json={"sha": TREE})
        self.create_commit = router.post(f"{BASE}/git/commits").respond(json={"sha": COMMIT})
        router.patch(f"{BASE}/git/refs/heads/agent/x").respond(json={})
        self.pulls = router.post(f"{BASE}/pulls").respond(
            json={"number": 7, "draft": True, "head": {"sha": HEAD}}
        )
        self.commit_status = router.post(f"{BASE}/statuses/{COMMIT}").respond(201, json={})
        self.head_status = router.post(f"{BASE}/statuses/{HEAD}").respond(201, json={})
        router.get(f"{BASE}").respond(json={"private": False})


@pytest.fixture
def github() -> Iterator[GitHub]:
    with respx.mock(assert_all_called=False) as router:
        yield GitHub(router)


def body_of(route: respx.Route) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(route.calls.last.request.content)
    return result


async def test_a_commit_posts_a_receipt_on_the_new_commit(stack: Stack, github: GitHub) -> None:
    result = await stack.commit()
    assert not result.is_error
    sent = body_of(github.commit_status)
    assert sent["state"] == "success"
    assert sent["context"] == CONTEXT == "repoward/receipt"
    assert sent["description"] == (
        f"policy {stack.policy.sha256[:12]}; audit seq 1-2; 0 denied; 0 escalated; flow labels: off"
    )


async def test_a_pull_request_posts_a_receipt_on_its_head(stack: Stack, github: GitHub) -> None:
    assert not (await stack.pipeline.call(AGENT, "github_create_pull_request", PR_ARGS)).is_error
    assert body_of(github.head_status)["context"] == CONTEXT


async def test_a_receipt_holds_no_arguments_or_content(stack: Stack, github: GitHub) -> None:
    await stack.commit()
    await stack.pipeline.call(AGENT, "github_create_pull_request", PR_ARGS)
    for route in (github.commit_status, github.head_status):
        sent = route.calls.last.request.content.decode()
        for text in ("MESSAGE", "CHOSEN-PATH", "FILE-CONTENT", "TITLE", "BODY", "agent/x"):
            assert text not in sent
    description = body_of(github.commit_status)["description"]
    assert re.fullmatch(
        r"policy [0-9a-f]{12}; audit seq \d+-\d+; \d+ denied; \d+ escalated; flow labels: \w+",
        description,
    )


async def test_refused_calls_are_counted(stack: Stack, github: GitHub) -> None:
    await stack.pipeline.call(AGENT, "no_such_tool", {})
    await stack.pipeline.call(AGENT, "github_get_file", {"repo": "other/repo", "path": "a"})
    await stack.pipeline.call(AGENT, "github_comment", {"repo": REPO, "number": 1, "body": "x"})
    await stack.commit()
    description = body_of(github.commit_status)["description"]
    assert "audit seq 1-5" in description
    assert "2 denied; 1 escalated" in description


async def test_the_receipt_is_audited_before_it_is_posted(stack: Stack, github: GitHub) -> None:
    await stack.commit()
    receipt = stack.events("receipt")[0]
    assert receipt["sha"] == COMMIT
    assert receipt["repo"] == REPO
    assert receipt["description"] == body_of(github.commit_status)["description"]
    assert stack.events("receipt_outcome")[0]["result_status"] == "ok"
    assert verify_log(stack.audit_path).ok


async def test_posting_uses_a_scope_of_only_the_receipt_permission(tmp_path: Path) -> None:
    seen: list[Any] = []

    async def post(repo: str, sha: str, context: str, description: str) -> None:
        seen.append(current_scope())

    ledger = ReceiptLedger(post, "a" * 64)
    with respx.mock(assert_all_called=False) as router:
        GitHub(router)
        built = Stack(tmp_path)
        pipeline = Pipeline(
            built.policy,
            build_registry(built.policy, built.github),
            built.audit,
            receipts=ledger,
        )
        await pipeline.call(AGENT, "github_commit_files", COMMIT_ARGS)
        await built.github.aclose()
    assert seen[0].repo == REPO
    assert dict(seen[0].permissions) == RECEIPT_PERMISSIONS == {"statuses": "write"}


@pytest.mark.parametrize("code", [403, 404, 422, 500])
async def test_a_failed_post_does_not_fail_the_commit(
    stack: Stack, github: GitHub, code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    github.commit_status.respond(code, json={"message": "no"})
    result = await stack.commit()
    assert not result.is_error
    assert stack.events("tool_call_outcome")[0]["result_status"] == "ok"
    outcome = stack.events("receipt_outcome")[0]
    assert outcome["result_status"] == "error"
    assert outcome["error"]
    assert "receipt was not posted" in capsys.readouterr().err
    assert verify_log(stack.audit_path).ok


async def test_an_unexpected_failure_does_not_fail_the_commit(tmp_path: Path) -> None:
    async def post(repo: str, sha: str, context: str, description: str) -> None:
        raise RuntimeError("secret detail")

    with respx.mock(assert_all_called=False) as router:
        GitHub(router)
        built = Stack(tmp_path)
        pipeline = Pipeline(
            built.policy,
            build_registry(built.policy, built.github),
            built.audit,
            receipts=ReceiptLedger(post, "a" * 64),
        )
        assert not (await pipeline.call(AGENT, "github_commit_files", COMMIT_ARGS)).is_error
        await built.github.aclose()
    assert built.events("receipt_outcome")[0]["error"] == "RuntimeError"


async def test_nothing_is_posted_if_the_receipt_cannot_be_audited(
    stack: Stack, github: GitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = stack.audit.append

    def failing(fields: dict[str, Any]) -> dict[str, Any]:
        if fields["event"] == "receipt":
            raise AuditWriteError("disk full")
        return original(fields)

    monkeypatch.setattr(stack.audit, "append", failing)
    assert not (await stack.commit()).is_error
    assert not github.commit_status.called


async def test_a_lost_receipt_outcome_stops_further_changes(
    stack: Stack, github: GitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = stack.audit.append

    def failing(fields: dict[str, Any]) -> dict[str, Any]:
        if fields["event"] == "receipt_outcome":
            raise AuditWriteError("disk full")
        return original(fields)

    monkeypatch.setattr(stack.audit, "append", failing)
    assert not (await stack.commit()).is_error
    assert github.commit_status.called
    monkeypatch.setattr(stack.audit, "append", original)
    again = await stack.commit()
    assert again.is_error
    assert github.commit_status.call_count == 1


async def test_a_failed_tool_posts_nothing(stack: Stack, github: GitHub) -> None:
    github.create_commit.respond(500, json={"message": "no"})
    assert (await stack.commit()).is_error
    assert not github.commit_status.called
    assert not stack.events("receipt")


async def test_a_refused_call_posts_nothing(stack: Stack, github: GitHub) -> None:
    args = {**COMMIT_ARGS, "branch": "main"}
    assert (await stack.pipeline.call(AGENT, "github_commit_files", args)).is_error
    assert not stack.events("receipt")


async def test_other_tools_post_nothing(stack: Stack, github: GitHub) -> None:
    await stack.pipeline.call(AGENT, "github_comment", {"repo": REPO, "number": 1, "body": "x"})
    assert not stack.events("receipt")


async def test_a_pull_request_response_without_a_head_means_no_receipt(
    stack: Stack, github: GitHub
) -> None:
    github.pulls.respond(json={"number": 7, "draft": True, "head": {"sha": "not-a-sha"}})
    result = await stack.pipeline.call(AGENT, "github_create_pull_request", PR_ARGS)
    assert not result.is_error
    assert not github.head_status.called


async def test_receipts_are_off_without_a_ledger(tmp_path: Path, github: GitHub) -> None:
    built = Stack(tmp_path)
    pipeline = Pipeline(
        compiled_policy(receipts=False),
        build_registry(compiled_policy(receipts=False), built.github),
        built.audit,
    )
    assert not (await pipeline.call(AGENT, "github_commit_files", COMMIT_ARGS)).is_error
    assert not github.commit_status.called
    await built.github.aclose()


async def test_the_agent_is_not_told_about_receipts(stack: Stack, github: GitHub) -> None:
    result = await stack.commit()
    text = "\n".join(block.text for block in result.content if isinstance(block, TextContent))
    assert "receipt" not in text.casefold()


async def test_flow_labels_are_reported(tmp_path: Path, github: GitHub) -> None:
    built = Stack(tmp_path, flow=True)
    await built.commit()
    assert body_of(github.commit_status)["description"].endswith("flow labels: no")
    assert built.flow is not None
    built.flow._store.add(AGENT.id, "untrusted_input", "github-issue:org/x#1", 60.0)
    # With that label a write needs approval, so it posts nothing until a person approves it.
    waiting = await built.pipeline.call(AGENT, "github_create_pull_request", PR_ARGS)
    assert waiting.structured_content is not None
    assert not github.head_status.called
    built.approvals.decide(waiting.structured_content["approval_id"], True, "human")
    assert not (await built.pipeline.call(AGENT, "github_create_pull_request", PR_ARGS)).is_error
    description = body_of(github.head_status)["description"]
    assert description.endswith("1 escalated; flow labels: yes")
    await built.github.aclose()


async def test_a_touched_repo_alone_is_not_a_label(tmp_path: Path, github: GitHub) -> None:
    built = Stack(tmp_path, flow=True)
    assert built.flow is not None
    built.flow._store.add(AGENT.id, "touched_repo", REPO, 60.0)
    await built.commit()
    assert body_of(github.commit_status)["description"].endswith("flow labels: no")
    await built.github.aclose()


async def test_unavailable_flow_state_is_reported_as_unknown(
    tmp_path: Path, github: GitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    built = Stack(tmp_path, flow=True)
    assert built.flow is not None

    async def broken(principal: str) -> bool:
        raise FlowStoreError("store is down")

    monkeypatch.setattr(built.flow, "has_labels", broken)
    assert not (await built.commit()).is_error
    assert body_of(github.commit_status)["description"].endswith("flow labels: unknown")
    await built.github.aclose()


async def test_replay_ignores_receipt_records(stack: Stack, github: GitHub) -> None:
    await stack.commit()
    assert stack.events("receipt")
    report = replay_log(stack.audit_path, stack.policy)
    assert report.decisions == 1
    assert report.unchanged == 1


async def test_the_description_fits_githubs_limit() -> None:
    async def post(repo: str, sha: str, context: str, description: str) -> None:
        raise ToolError("unused")

    ledger = ReceiptLedger(post, "a" * 64)
    huge = 10**60
    ledger.observe({"seq": huge, "event": "tool_call_decision", "principal": "p"})
    ledger.observe({"seq": huge + 1, "event": "tool_call_outcome"})
    description = ledger.description("p", "yes")
    assert description is not None
    assert len(description) <= MAX_DESCRIPTION_CHARS


async def test_a_principal_with_no_records_has_no_receipt() -> None:
    async def post(repo: str, sha: str, context: str, description: str) -> None:
        raise ToolError("unused")

    assert ReceiptLedger(post, "a" * 64).description("nobody", "no") is None


@pytest.mark.parametrize("setting", ["{ enabled: 'yes' }", "{ unknown: true }", "true"])
async def test_the_policy_section_is_strict(setting: str) -> None:
    text = f"""\
version: 1
default: deny
receipts: {setting}
roles: {{}}
rate_limits:
  default: {{ per_minute: 1 }}
"""
    with pytest.raises(PolicyError):
        parse_policy(text.encode())


async def test_receipts_are_off_by_default() -> None:
    text = """\
version: 1
default: deny
roles:
  reader:
    tools: []
rate_limits:
  default: { per_minute: 1 }
"""
    assert parse_policy(text.encode()).policy.receipts.enabled is False
