"""Every role x tool x repo x path combination, against an independent statement of the rules."""

import itertools

import pytest

from repoward.catalog import TOOL_CATALOG
from repoward.policy.engine import Effect, Target, decide
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal

READER = {"ping", "github_get_file"}
CONTRIBUTOR = READER | {"github_commit_files"}
MAINTAINER = CONTRIBUTOR | {"github_delete_branch", "github_merge_pull_request"}
GRANTS = {"reader": READER, "contributor": CONTRIBUTOR, "maintainer": MAINTAINER, "ghost": set()}

REPOS = {"Org/Sandbox": True, "org/sandbox": True, "ORG/SANDBOX": True, "org/other": False}
PATHS = {
    "src/app.py": True,
    "README.md": True,
    ".env": False,
    "deep/dir/.env.local": False,
    ".github/workflows/ci.yml": False,
    ".GitHub/Workflows/CI.yml": False,
    "app/secrets/key.txt": False,
    "github/notes.md": True,
}


def expected(role: str, tool: str, repo_ok: bool, path_ok: bool) -> tuple[Effect, str]:
    if role == "ghost":
        return Effect.DENY, "role.unknown"
    if tool not in GRANTS[role]:
        return Effect.DENY, "default.deny"
    if tool == "github_merge_pull_request":
        return Effect.DENY, "dangerous_tools.github_merge_pull_request.disabled"
    if not repo_ok:
        return Effect.DENY, "repos.allow"
    if not path_ok:
        return Effect.DENY, "paths.deny"
    if tool == "github_delete_branch":
        return Effect.APPROVAL_REQUIRED, "roles.maintainer.require_approval"
    return Effect.ALLOW, f"roles.{role}.tools"


MATRIX = list(itertools.product(GRANTS, TOOL_CATALOG, REPOS.items(), PATHS.items()))


@pytest.mark.parametrize(("role", "tool", "repo", "path"), MATRIX)
def test_policy_matrix(
    policy: CompiledPolicy,
    role: str,
    tool: str,
    repo: tuple[str, bool],
    path: tuple[str, bool],
) -> None:
    decision = decide(
        policy,
        Principal("p", role),
        tool,
        TOOL_CATALOG[tool],
        Target(repo=repo[0], paths=[path[0]]),
    )
    assert (decision.effect, decision.rule_id) == expected(role, tool, repo[1], path[1])


def test_one_denied_path_among_many_denies_the_call(policy: CompiledPolicy) -> None:
    decision = decide(
        policy,
        Principal("p", "contributor"),
        "github_commit_files",
        TOOL_CATALOG["github_commit_files"],
        Target(repo="org/sandbox", paths=["src/a.py", ".env", "src/b.py"]),
    )
    assert decision.rule_id == "paths.deny"


def test_target_free_tool_is_allowed_by_role_alone(policy: CompiledPolicy) -> None:
    decision = decide(policy, Principal("p", "reader"), "ping", TOOL_CATALOG["ping"], Target())
    assert decision.effect is Effect.ALLOW


def test_a_dangerous_tool_missing_from_the_switch_list_is_disabled(
    policy: CompiledPolicy,
) -> None:
    switches = dict(policy.policy.dangerous_tools)
    del switches["github_delete_branch"]
    stripped = policy.policy.model_copy(update={"dangerous_tools": switches})
    compiled = CompiledPolicy(
        stripped,
        policy.sha256,
        policy.roles,
        policy.allowed_repos,
        policy.denied_paths,
        policy.rate_limits,
    )
    decision = decide(
        compiled,
        Principal("p", "maintainer"),
        "github_delete_branch",
        TOOL_CATALOG["github_delete_branch"],
        Target(repo="org/sandbox"),
    )
    assert decision.rule_id == "dangerous_tools.github_delete_branch.disabled"


@pytest.mark.parametrize(
    ("role", "tool", "repo", "path"),
    [
        ("reader", "github_commit_files", "org/sandbox", "a"),
        ("reader", "github_get_file", "org/other", "a"),
        ("reader", "github_get_file", "org/sandbox", ".env"),
        ("ghost", "ping", None, None),
    ],
)
def test_deny_messages_do_not_leak_policy_details(
    policy: CompiledPolicy, role: str, tool: str, repo: str | None, path: str | None
) -> None:
    decision = decide(
        policy,
        Principal("p", role),
        tool,
        TOOL_CATALOG[tool],
        Target(repo=repo, paths=[path] if path else []),
    )
    assert decision.message
    for leak in ("Org/Sandbox", "secrets", "**", decision.rule_id):
        assert leak not in decision.message
