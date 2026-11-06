"""Write tools against a real sandbox repository. Skipped by default.

Needs GITHUB_WRITE_TOKEN (no Workflows permission) and REPOWARD_LIVE_REPO. Run with:
uv run pytest -m live

Every test works on a uniquely named agent/ branch, which is removed afterwards.
"""

import base64
import os
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

TOKEN = os.environ.get("GITHUB_WRITE_TOKEN", "")
REPO = os.environ.get("REPOWARD_LIVE_REPO", "")
WRITER = Principal("live-test", "contributor")
TOOLS = """[github_list_issues, github_get_issue, github_get_file, github_create_branch,
            github_commit_files, github_create_pull_request, github_comment]"""


def policy_text(deny: str) -> bytes:
    return f"""\
version: 1
default: deny
repos:
  allow: ["{REPO}"]
paths:
  deny: {deny}
roles:
  contributor:
    tools: {TOOLS}
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: contributor
""".encode()


class Sandbox:
    """Direct API access for test setup and cleanup, separate from the code under test."""

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


@pytest.fixture
async def pipeline(sandbox: Sandbox, tmp_path: Path) -> AsyncIterator[Pipeline]:
    policy = parse_policy(policy_text('[".github/**", "**/.env*", "**/secrets/**"]'))
    github = GitHubClient(TOKEN)
    yield Pipeline(policy, build_registry(policy, github), AuditLog(tmp_path / "audit.jsonl"))
    await github.aclose()


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


async def make_branch(pipeline: Pipeline, sandbox: Sandbox) -> None:
    result = await pipeline.call(
        WRITER,
        "github_create_branch",
        {"repo": REPO, "branch": sandbox.branch, "base": "main"},
    )
    assert not result.is_error, text(result)


async def test_issue_to_draft_pull_request(
    pipeline: Pipeline, sandbox: Sandbox, tmp_path: Path
) -> None:
    issue = await pipeline.call(WRITER, "github_get_issue", {"repo": REPO, "number": 3})
    assert not issue.is_error
    await make_branch(pipeline, sandbox)

    commit = await pipeline.call(
        WRITER,
        "github_commit_files",
        {
            "repo": REPO,
            "branch": sandbox.branch,
            "message": "feat: add subtract",
            "files": [
                {"path": "src/subtract.py", "content": "def subtract(a, b):\n    return a - b\n"},
                {"path": "src/notes.txt", "content": "live test\n"},
            ],
        },
    )
    assert not commit.is_error, text(commit)
    assert "Committed 2 changes" in text(commit)
    tree = sandbox.http.get(f"/git/trees/{sandbox.branch}", params={"recursive": "1"}).json()
    paths = {entry["path"]: entry["mode"] for entry in tree["tree"]}
    assert paths["src/subtract.py"] == "100644"
    assert "README.md" in paths

    pull = await pipeline.call(
        WRITER,
        "github_create_pull_request",
        {
            "repo": REPO,
            "title": "Live test: add subtract",
            "head": sandbox.branch,
            "base": "main",
            "body": "Created by the live test suite. Closes automatically.",
        },
    )
    assert not pull.is_error, text(pull)
    match = re.search(r"draft pull request #(\d+)", text(pull))
    assert match
    sandbox.pull_number = int(match[1])
    assert sandbox.http.get(f"/pulls/{sandbox.pull_number}").json()["draft"] is True

    comment = await pipeline.call(
        WRITER,
        "github_comment",
        {"repo": REPO, "number": sandbox.pull_number, "body": "Live test comment."},
    )
    assert not comment.is_error, text(comment)

    report = verify_log(tmp_path / "audit.jsonl")
    assert report.ok
    assert report.records == 10


async def test_deleting_a_file_on_a_real_branch(pipeline: Pipeline, sandbox: Sandbox) -> None:
    await make_branch(pipeline, sandbox)
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        {
            "repo": REPO,
            "branch": sandbox.branch,
            "message": "chore: drop",
            "deletions": ["README.md"],
        },
    )
    assert not result.is_error, text(result)
    assert (
        sandbox.http.get("/contents/README.md", params={"ref": sandbox.branch}).status_code == 404
    )
    assert sandbox.http.get("/contents/README.md", params={"ref": "main"}).status_code == 200


async def test_default_branch_is_protected_by_policy(pipeline: Pipeline, sandbox: Sandbox) -> None:
    before = sandbox.http.get("/git/ref/heads/main").json()["object"]["sha"]
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        {
            "repo": REPO,
            "branch": "main",
            "message": "should not land",
            "files": [{"path": "x.txt", "content": "x"}],
        },
    )
    assert result.is_error
    assert sandbox.http.get("/git/ref/heads/main").json()["object"]["sha"] == before


async def test_github_refuses_workflow_changes_without_the_permission(
    sandbox: Sandbox, tmp_path: Path
) -> None:
    """The second layer: with the policy path opened, GitHub itself must still say no."""
    policy = parse_policy(policy_text("[]"))
    github = GitHubClient(TOKEN)
    pipeline = Pipeline(policy, build_registry(policy, github), AuditLog(tmp_path / "a.jsonl"))
    await make_branch(pipeline, sandbox)
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        {
            "repo": REPO,
            "branch": sandbox.branch,
            "message": "ci: should be refused",
            "files": [{"path": ".github/workflows/evil.yml", "content": "name: evil\n"}],
        },
    )
    await github.aclose()
    assert result.is_error, "GitHub accepted a workflow change"
    tree = sandbox.http.get(f"/git/trees/{sandbox.branch}", params={"recursive": "1"}).json()
    assert ".github/workflows/evil.yml" not in {entry["path"] for entry in tree["tree"]}


async def test_symlinks_to_denied_paths_are_refused(pipeline: Pipeline, sandbox: Sandbox) -> None:
    """A real regression test: GitHub's contents API does return the denied text here."""
    await make_branch(pipeline, sandbox)
    head = sandbox.http.get(f"/git/ref/heads/{sandbox.branch}").json()["object"]["sha"]
    base_tree = sandbox.http.get(f"/git/commits/{head}").json()["tree"]["sha"]

    def link(path: str, target: bytes) -> dict[str, str]:
        content = base64.b64encode(target).decode()
        created = sandbox.http.post("/git/blobs", json={"content": content, "encoding": "base64"})
        return {"path": path, "mode": "120000", "type": "blob", "sha": created.json()["sha"]}

    tree = sandbox.http.post(
        "/git/trees",
        json={
            "base_tree": base_tree,
            "tree": [
                link("docs/link.txt", b"../secrets/placeholder.txt"),
                link("alias", b"secrets"),
            ],
        },
    ).json()
    commit = sandbox.http.post(
        "/git/commits", json={"message": "test: add links", "tree": tree["sha"], "parents": [head]}
    ).json()
    updated = sandbox.http.patch(f"/git/refs/heads/{sandbox.branch}", json={"sha": commit["sha"]})
    assert updated.status_code == 200

    direct = sandbox.http.get("/contents/docs/link.txt", params={"ref": sandbox.branch}).json()
    leaked = "Placeholder" in base64.b64decode(direct.get("content") or "").decode()
    print("contents API type:", direct.get("type"), "| returned denied text:", leaked)

    for path in ("docs/link.txt", "alias/placeholder.txt"):
        result = await pipeline.call(
            WRITER, "github_get_file", {"repo": REPO, "path": path, "ref": sandbox.branch}
        )
        assert result.is_error, path
        assert "not a regular file" in text(result)
        assert "Placeholder in a denied path" not in text(result)

    regular = await pipeline.call(
        WRITER, "github_get_file", {"repo": REPO, "path": "src/app.py", "ref": sandbox.branch}
    )
    assert not regular.is_error, text(regular)
    by_sha = await pipeline.call(
        WRITER, "github_get_file", {"repo": REPO, "path": "src/app.py", "ref": head}
    )
    assert not by_sha.is_error, text(by_sha)


async def test_force_is_not_available(pipeline: Pipeline, sandbox: Sandbox) -> None:
    result = await pipeline.call(
        WRITER,
        "github_commit_files",
        {
            "repo": REPO,
            "branch": sandbox.branch,
            "message": "x",
            "files": [{"path": "a", "content": "x"}],
            "force": True,
        },
    )
    assert result.is_error


async def test_comment_holding_a_credential_never_posts(
    pipeline: Pipeline, sandbox: Sandbox
) -> None:
    before = sandbox.http.get("/issues/3").json()["comments"]
    fake = "ghp_" + "f" * 36
    result = await pipeline.call(
        WRITER, "github_comment", {"repo": REPO, "number": 3, "body": f"leak {fake}"}
    )
    assert result.is_error
    assert sandbox.http.get("/issues/3").json()["comments"] == before
