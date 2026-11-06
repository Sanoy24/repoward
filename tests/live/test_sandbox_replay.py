"""Policy replay on a log written from real GitHub answers. Skipped by default.

Needs GITHUB_TOKEN, REPOWARD_LIVE_REPO and REPOWARD_LIVE_PRIVATE_REPO. Nothing is written to GitHub:
the only write attempted is the one the flow guard is expected to refuse.
"""

import os
from pathlib import Path

import pytest

from repoward.adapters.github import GitHubClient
from repoward.audit import AuditLog
from repoward.flow import FlowGuard, FlowStore
from repoward.pipeline import Pipeline
from repoward.policy.loader import CompiledPolicy, parse_policy
from repoward.policy.replay import replay_log
from repoward.principal import Principal
from repoward.server import build_registry

pytestmark = [pytest.mark.live, pytest.mark.anyio]

REPO = os.environ.get("REPOWARD_LIVE_REPO", "")
PRIVATE = os.environ.get("REPOWARD_LIVE_PRIVATE_REPO", "")
AGENT = Principal("live-replay", "contributor")


def policy(flow: str = "{ enabled: true }", repos: str | None = None) -> CompiledPolicy:
    allowed = repos if repos is not None else f'"{REPO}", "{PRIVATE}"'
    return parse_policy(
        f"""\
version: 1
default: deny
repos:
  allow: [{allowed}]
flow_guard: {flow}
roles:
  contributor:
    tools: [github_get_file, github_comment]
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: contributor
""".encode()
    )


async def test_replay_reports_changes_for_an_edited_policy(tmp_path: Path) -> None:
    if not (REPO and PRIVATE and os.environ.get("GITHUB_TOKEN")):
        pytest.skip("GITHUB_TOKEN and both sandbox repositories are required")
    compiled = policy()
    audit = tmp_path / "audit.jsonl"
    client = GitHubClient(os.environ["GITHUB_TOKEN"])
    pipeline = Pipeline(
        compiled,
        build_registry(compiled, client),
        AuditLog(audit),
        flow=FlowGuard(
            compiled.policy.flow_guard, FlowStore(tmp_path / "flow.db"), client.repo_is_private
        ),
    )
    try:
        public_read = await pipeline.call(
            AGENT, "github_get_file", {"repo": REPO, "path": "README.md"}
        )
        assert not public_read.is_error
        private_read = await pipeline.call(
            AGENT, "github_get_file", {"repo": PRIVATE, "path": "README.md"}
        )
        assert not private_read.is_error
        blocked = await pipeline.call(
            AGENT, "github_comment", {"repo": REPO, "number": 2, "body": "must not be posted"}
        )
        assert blocked.is_error
    finally:
        await client.aclose()

    same = replay_log(audit, compiled)
    assert same.decisions == 3
    assert same.unchanged == 3

    guard_off = replay_log(audit, policy("{ enabled: false }"))
    assert [(row.tool, row.recorded, row.replayed) for row in guard_off.changed] == [
        ("github_comment", "deny", "allow")
    ]

    softer = replay_log(audit, policy("{ enabled: true, on_private_to_public: require_approval }"))
    assert [row.replayed for row in softer.changed] == ["approval_required"]

    no_private = replay_log(audit, policy(repos=f'"{REPO}"'))
    assert [(row.tool, row.replayed) for row in no_private.changed] == [
        ("github_get_file", "deny"),
        ("github_comment", "allow"),
    ]
