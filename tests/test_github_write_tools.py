"""The write tools through the real pipeline, against a mocked GitHub."""

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import CompiledPolicy, PolicyError, parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = pytest.mark.anyio

API = "https://api.github.com"
REPO = "org/sandbox"
BASE = f"{API}/repos/{REPO}"
HEAD = "a" * 40
TREE = "b" * 40
NEW_TREE = "c" * 40
NEW_COMMIT = "d" * 40
SECRET = "ghp_" + "s" * 36
WRITER = Principal("bob", "contributor")
READER = Principal("alice", "reader")

POLICY = """\
version: 1
default: deny
repos:
  allow: ["org/sandbox"]
paths:
  deny: [".github/**", "**/.env*", "**/secrets/**"]
roles:
  reader:
    tools: [github_get_file]
  contributor:
    inherits: reader
    tools: [github_create_branch, github_commit_files, github_create_pull_request, github_comment]
    commit_limits: { max_files: 2, max_bytes: 100 }
rate_limits:
  default: { per_minute: 1000 }
"""


@pytest.fixture
def write_policy() -> CompiledPolicy:
    return parse_policy(POLICY.encode())


@pytest.fixture
async def pipeline(write_policy: CompiledPolicy, tmp_path: Path) -> AsyncIterator[Pipeline]:
    github = GitHubClient("fake-token")
    yield Pipeline(
        write_policy, build_registry(write_policy, github), AuditLog(tmp_path / "audit.jsonl")
    )
    await github.aclose()


@pytest.fixture
def github() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def sent(route: respx.Route) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(route.calls.last.request.content)
    return body


def writes(github: respx.MockRouter) -> list[str]:
    return [call.request.method for call in github.calls if call.request.method != "GET"]


def mock_commit_flow(github: respx.MockRouter, branch: str = "agent/x") -> dict[str, respx.Route]:
    return {
        "ref": github.get(f"{BASE}/git/ref/heads/{branch}").respond(json={"object": {"sha": HEAD}}),
        "parent": github.get(f"{BASE}/git/commits/{HEAD}").respond(json={"tree": {"sha": TREE}}),
        "tree": github.post(f"{BASE}/git/trees").respond(201, json={"sha": NEW_TREE}),
        "commit": github.post(f"{BASE}/git/commits").respond(201, json={"sha": NEW_COMMIT}),
        "update": github.patch(f"{BASE}/git/refs/heads/{branch}").respond(json={}),
    }


# Branches


async def test_create_branch_from_a_named_ref(pipeline: Pipeline, github: respx.MockRouter) -> None:
    github.get(f"{BASE}/commits/main").respond(json={"sha": HEAD})
    create = github.post(f"{BASE}/git/refs").respond(201, json={})
    result = await pipeline.call(
        WRITER, "github_create_branch", {"repo": REPO, "branch": "agent/x", "base": "main"}
    )
    assert not result.is_error
    assert sent(create) == {"ref": "refs/heads/agent/x", "sha": HEAD}


async def test_create_branch_from_a_sha_needs_no_lookup(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    create = github.post(f"{BASE}/git/refs").respond(201, json={})
    await pipeline.call(
        WRITER, "github_create_branch", {"repo": REPO, "branch": "agent/x", "base": HEAD}
    )
    assert sent(create)["sha"] == HEAD
    assert len(github.calls) == 1


@pytest.mark.parametrize("branch", ["main", "feature/x", "agents/x", "Agent/x", "xagent/y"])
async def test_branches_outside_the_prefix_never_reach_github(
    pipeline: Pipeline, github: respx.MockRouter, branch: str
) -> None:
    result = await pipeline.call(
        WRITER, "github_create_branch", {"repo": REPO, "branch": branch, "base": "main"}
    )
    assert result.is_error
    assert "agent/" in text(result)
    assert not github.calls


# Commits


async def test_commit_is_one_atomic_fast_forward(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    routes = mock_commit_flow(github)
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        {
            "repo": REPO,
            "branch": "agent/x",
            "message": "fix: a thing",
            "files": [{"path": "src/a.py", "content": "print(1)"}],
            "deletions": ["src/old.py"],
        },
    )
    assert not result.is_error
    assert NEW_COMMIT in text(result)
    tree = sent(routes["tree"])
    assert tree["base_tree"] == TREE
    assert tree["tree"] == [
        {"path": "src/a.py", "mode": "100644", "type": "blob", "content": "print(1)"},
        {"path": "src/old.py", "mode": "100644", "type": "blob", "sha": None},
    ]
    assert sent(routes["commit"]) == {
        "message": "fix: a thing",
        "tree": NEW_TREE,
        "parents": [HEAD],
    }
    assert sent(routes["update"]) == {"sha": NEW_COMMIT, "force": False}


def commit_args(**overrides: Any) -> dict[str, Any]:
    return {
        "repo": REPO,
        "branch": "agent/x",
        "message": "msg",
        "files": [{"path": "src/a.py", "content": "x"}],
        **overrides,
    }


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"branch": "main"}, "branches.write_prefix"),
        ({"repo": "org/other"}, "repos.allow"),
        ({"files": [{"path": ".github/workflows/x.yml", "content": "x"}]}, "paths.deny"),
        ({"files": [{"path": ".GITHUB/WORKFLOWS/x.yml", "content": "x"}]}, "paths.deny"),
        ({"files": [{"path": "a/.env", "content": "x"}]}, "paths.deny"),
        ({"files": [], "deletions": ["secrets/key.txt"]}, "paths.deny"),
        (
            {"files": [{"path": f"f{n}", "content": "x"} for n in range(3)]},
            "roles.commit_limits",
        ),
        (
            {
                "files": [{"path": "a", "content": "x"}, {"path": "b", "content": "x"}],
                "deletions": ["c"],
            },
            "roles.commit_limits",
        ),
        ({"files": [{"path": "a", "content": "x" * 101}]}, "roles.commit_limits"),
        ({"files": [{"path": "a", "content": SECRET}]}, "secrets.outbound"),
        ({"message": f"fix {SECRET}"}, "secrets.outbound"),
        ({"files": []}, "input.invalid"),
        (
            {"files": [{"path": "a", "content": "x"}, {"path": "A", "content": "y"}]},
            "input.invalid",
        ),
        ({"files": [{"path": "a", "content": "x"}], "deletions": ["a"]}, "input.invalid"),
        ({"files": [{"path": "../a", "content": "x"}]}, "input.invalid"),
        ({"files": [{"path": "a", "content": "x", "mode": "120000"}]}, "input.invalid"),
        ({"message": "   "}, "input.invalid"),
        ({"message": "bad\x00message"}, "input.invalid"),
        ({"force": True}, "input.invalid"),
    ],
)
async def test_bad_commits_never_reach_github(
    pipeline: Pipeline,
    github: respx.MockRouter,
    tmp_path: Path,
    overrides: dict[str, Any],
    rule: str,
) -> None:
    result = await pipeline.call(WRITER, "github_commit_files", commit_args(**overrides))
    assert result.is_error
    assert not github.calls
    record = json.loads((tmp_path / "audit.jsonl").read_bytes().splitlines()[-1])
    assert record["rule_id"] == rule


async def test_multibyte_content_counts_as_bytes(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        commit_args(files=[{"path": "a", "content": chr(0x20AC) * 40}]),
    )
    assert "100 bytes" in text(result)
    assert not github.calls


async def test_moved_branch_fails_without_forcing(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    routes = mock_commit_flow(github)
    routes["update"].respond(422, json={"message": "not a fast forward"})
    result = await pipeline.call(WRITER, "github_commit_files", commit_args())
    assert result.is_error
    assert routes["update"].call_count == 1
    assert sent(routes["update"])["force"] is False


async def test_write_failures_are_not_retried(pipeline: Pipeline, github: respx.MockRouter) -> None:
    routes = mock_commit_flow(github)
    routes["tree"].respond(500)
    result = await pipeline.call(WRITER, "github_commit_files", commit_args())
    assert result.is_error
    assert routes["tree"].call_count == 1
    assert not routes["commit"].called


# Pull requests


def pull_args(**overrides: Any) -> dict[str, Any]:
    return {"repo": REPO, "title": "A title", "head": "agent/x", "base": "main", **overrides}


async def test_pull_requests_are_draft_by_default(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    route = github.post(f"{BASE}/pulls").respond(201, json={"number": 9, "draft": True})
    result = await pipeline.call(WRITER, "github_create_pull_request", pull_args())
    assert not result.is_error
    assert sent(route)["draft"] is True
    assert "draft pull request #9" in text(result)


async def test_non_draft_is_refused_by_default(
    pipeline: Pipeline, github: respx.MockRouter, tmp_path: Path
) -> None:
    result = await pipeline.call(WRITER, "github_create_pull_request", pull_args(draft=False))
    assert result.is_error
    assert not github.calls
    record = json.loads((tmp_path / "audit.jsonl").read_bytes().splitlines()[-1])
    assert record["rule_id"] == "pull_requests.allow_non_draft"


async def test_non_draft_can_be_enabled_by_policy(tmp_path: Path) -> None:
    policy = parse_policy(
        (POLICY + "pull_requests:\n  allow_non_draft: true\n").encode(),
    )
    client = GitHubClient("fake-token")
    pipeline = Pipeline(policy, build_registry(policy, client), AuditLog(tmp_path / "a.jsonl"))
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{BASE}/pulls").respond(201, json={"number": 3, "draft": False})
        result = await pipeline.call(WRITER, "github_create_pull_request", pull_args(draft=False))
    assert not result.is_error
    assert sent(route)["draft"] is False
    await client.aclose()


async def test_rejected_draft_is_never_retried_as_non_draft(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    route = github.post(f"{BASE}/pulls").respond(422, json={"message": "Draft not supported"})
    result = await pipeline.call(WRITER, "github_create_pull_request", pull_args())
    assert result.is_error
    assert route.call_count == 1


async def test_a_pull_request_that_is_not_a_draft_is_flagged(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    github.post(f"{BASE}/pulls").respond(201, json={"number": 9, "draft": False})
    result = await pipeline.call(WRITER, "github_create_pull_request", pull_args())
    assert result.is_error
    assert "not a draft" in text(result)


@pytest.mark.parametrize(
    "overrides",
    [
        {"head": "main"},
        {"head": "other:agent/x"},
        {"head_repo": "evil/repo"},
        {"issue": 5},
        {"title": ""},
        {"title": "x" * 257},
        {"body": f"see {SECRET}"},
        {"title": f"see {SECRET}"},
    ],
)
async def test_bad_pull_requests_never_reach_github(
    pipeline: Pipeline, github: respx.MockRouter, overrides: dict[str, Any]
) -> None:
    result = await pipeline.call(WRITER, "github_create_pull_request", pull_args(**overrides))
    assert result.is_error
    assert not github.calls


# Comments


async def test_comment_is_posted(pipeline: Pipeline, github: respx.MockRouter) -> None:
    route = github.post(f"{BASE}/issues/4/comments").respond(201, json={"id": 77})
    result = await pipeline.call(
        WRITER, "github_comment", {"repo": REPO, "number": 4, "body": "Looks good"}
    )
    assert not result.is_error
    assert sent(route) == {"body": "Looks good"}
    assert "comment 77" in text(result)


@pytest.mark.parametrize(
    "secret",
    [
        SECRET,
        "github_pat_" + "a" * 30,
        "AKIA" + "B" * 16,
        "eyJabcde.eyJabcde.signature",
        "-----BEGIN PRIVATE KEY-----\nabc",
    ],
)
async def test_comments_holding_credentials_are_blocked(
    pipeline: Pipeline, github: respx.MockRouter, secret: str
) -> None:
    result = await pipeline.call(
        WRITER, "github_comment", {"repo": REPO, "number": 4, "body": f"leak {secret}"}
    )
    assert result.is_error
    assert "credential" in text(result)
    assert secret not in text(result)
    assert not github.calls


async def test_ordinary_code_mentioning_keys_is_not_blocked(
    pipeline: Pipeline, github: respx.MockRouter
) -> None:
    routes = mock_commit_flow(github)
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        commit_args(files=[{"path": "a.py", "content": 'API_KEY = os.environ["KEY"]'}]),
    )
    assert not result.is_error
    assert routes["update"].called


async def test_a_blocked_secret_never_reaches_the_audit_log(
    pipeline: Pipeline, github: respx.MockRouter, tmp_path: Path
) -> None:
    await pipeline.call(WRITER, "github_comment", {"repo": REPO, "number": 4, "body": SECRET})
    assert SECRET not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


# Roles and audit


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("github_create_branch", {"repo": REPO, "branch": "agent/x", "base": "main"}),
        ("github_commit_files", commit_args()),
        ("github_create_pull_request", pull_args()),
        ("github_comment", {"repo": REPO, "number": 1, "body": "x"}),
    ],
)
async def test_readers_cannot_write(
    pipeline: Pipeline, github: respx.MockRouter, tool: str, args: dict[str, Any]
) -> None:
    result = await pipeline.call(READER, tool, args)
    assert result.is_error
    assert "ask a maintainer" in text(result)
    assert not github.calls


async def test_issue_to_draft_pr_is_fully_audited(
    pipeline: Pipeline, github: respx.MockRouter, tmp_path: Path
) -> None:
    github.get(f"{BASE}/commits/main").respond(json={"sha": HEAD})
    github.post(f"{BASE}/git/refs").respond(201, json={})
    mock_commit_flow(github)
    github.post(f"{BASE}/pulls").respond(201, json={"number": 9, "draft": True})
    github.post(f"{BASE}/issues/9/comments").respond(201, json={"id": 1})
    steps = [
        ("github_create_branch", {"repo": REPO, "branch": "agent/x", "base": "main"}),
        ("github_commit_files", commit_args()),
        ("github_create_pull_request", pull_args()),
        ("github_comment", {"repo": REPO, "number": 9, "body": "Ready"}),
    ]
    for tool, args in steps:
        assert not (await pipeline.call(WRITER, tool, args)).is_error
    path = tmp_path / "audit.jsonl"
    report = verify_log(path)
    assert report.ok
    assert report.records == 8
    decisions = [
        json.loads(line)["tool"]
        for line in path.read_bytes().splitlines()
        if json.loads(line)["event"] == "tool_call_decision"
    ]
    assert decisions == [tool for tool, _ in steps]


# Policy schema


def test_commit_limits_inherit_and_can_be_overridden() -> None:
    text_policy = POLICY + ("branches:\n  write_prefix: bot/\n")
    compiled = parse_policy(
        text_policy.replace(
            "  contributor:\n",
            "  lead:\n    inherits: contributor\n"
            "  big:\n    inherits: contributor\n"
            "    commit_limits: { max_files: 50 }\n"
            "  contributor:\n",
        ).encode()
    )
    assert compiled.roles["lead"].commit_limits.max_files == 2
    assert compiled.roles["big"].commit_limits.max_files == 50
    assert compiled.roles["reader"].commit_limits.max_files == 20
    assert compiled.policy.branches.write_prefix == "bot/"


@pytest.mark.parametrize("prefix", ["", "agent", "/agent/", "a/b/", "../", "agent/ "])
def test_invalid_write_prefixes_are_refused(prefix: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy((POLICY + f'branches:\n  write_prefix: "{prefix}"\n').encode())


@pytest.mark.parametrize("limits", ["{ max_files: 0 }", "{ max_bytes: 0 }", "{ nope: 1 }"])
def test_invalid_limits_are_refused(limits: str) -> None:
    text_policy = POLICY.replace(
        "commit_limits: { max_files: 2, max_bytes: 100 }", f"commit_limits: {limits}"
    )
    with pytest.raises(PolicyError):
        parse_policy(text_policy.encode())
