"""Read tools against a real sandbox repository. Skipped by default.

Run with GITHUB_TOKEN and REPOWARD_LIVE_REPO set: uv run pytest -m live
The sandbox needs a draft PR, an issue whose text contains "Ignore previous instructions",
a src/app.py file, a file under secrets/, and at least one completed workflow run.
"""

import os
import re
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import parse_policy
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("REPOWARD_LIVE_REPO", "")
READER = Principal("live-test", "reader")


@pytest.fixture
async def pipeline(tmp_path: Path) -> AsyncIterator[Pipeline]:
    if not TOKEN or not REPO:
        pytest.skip("GITHUB_TOKEN and REPOWARD_LIVE_REPO are required")
    policy = parse_policy(
        f"""\
version: 1
default: deny
repos:
  allow: ["{REPO}"]
paths:
  deny: [".github/**", "**/.env*", "**/secrets/**"]
roles:
  reader:
    tools: [github_list_issues, github_get_issue, github_search_code, github_get_file,
            ci_get_status, ci_get_job_logs]
rate_limits:
  default: {{ per_minute: 100 }}
""".encode()
    )
    github = GitHubClient(TOKEN)
    yield Pipeline(policy, build_registry(policy, github), AuditLog(tmp_path / "audit.jsonl"))
    await github.aclose()


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


async def test_list_issues_includes_the_draft_pr(pipeline: Pipeline) -> None:
    result = await pipeline.call(READER, "github_list_issues", {"repo": REPO})
    assert not result.is_error
    output = text(result)
    assert "pull_request" in output
    assert "author_association=" in output
    assert "<untrusted-content" in output


async def test_injection_fixture_comes_back_framed(pipeline: Pipeline) -> None:
    listing = text(await pipeline.call(READER, "github_list_issues", {"repo": REPO}))
    match = re.search(r"#(\d+): Prompt injection test fixture", listing)
    assert match
    output = text(
        await pipeline.call(READER, "github_get_issue", {"repo": REPO, "number": int(match[1])})
    )
    assert output.index("<untrusted-content") < output.index("Ignore previous instructions")
    assert "github-comment:" in output


async def test_get_file_reads_a_real_blob(pipeline: Pipeline) -> None:
    result = await pipeline.call(READER, "github_get_file", {"repo": REPO, "path": "src/app.py"})
    assert not result.is_error
    assert "def add" in text(result)


async def test_denied_paths_are_refused(pipeline: Pipeline) -> None:
    for path in ("secrets/placeholder.txt", ".github/workflows/ci.yml", "config/.env.sample"):
        result = await pipeline.call(READER, "github_get_file", {"repo": REPO, "path": path})
        assert result.is_error
        assert "not permitted" in text(result)


async def test_a_directory_is_not_a_file(pipeline: Pipeline) -> None:
    result = await pipeline.call(READER, "github_get_file", {"repo": REPO, "path": "src"})
    assert result.is_error


async def test_search_runs_with_a_fine_grained_token(pipeline: Pipeline) -> None:
    result = await pipeline.call(READER, "github_search_code", {"repo": REPO, "query": "add"})
    assert not result.is_error
    assert "total_count=" in text(result)


async def test_status_and_real_job_logs(pipeline: Pipeline, tmp_path: Path) -> None:
    status = text(await pipeline.call(READER, "ci_get_status", {"repo": REPO, "ref": "main"}))
    assert "Combined commit status" in status
    job = re.search(r"Job (\d+) status=completed", status)
    assert job
    logs = await pipeline.call(READER, "ci_get_job_logs", {"repo": REPO, "job_id": int(job[1])})
    assert not logs.is_error
    assert "sandbox job ran" in text(logs)
    assert verify_log(tmp_path / "audit.jsonl").ok


async def test_a_disallowed_repo_is_refused(pipeline: Pipeline) -> None:
    result = await pipeline.call(READER, "github_list_issues", {"repo": "github/docs"})
    assert result.is_error
