"""Policy replay: reports what a policy would change, and says unknown rather than guessing."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import respx

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog
from repoward.cli import main
from repoward.flow import FlowGuard, FlowStore
from repoward.pipeline import Pipeline
from repoward.policy.loader import CompiledPolicy, parse_policy
from repoward.policy.replay import UNKNOWN, ReplayError, ReplayReport, replay_log
from repoward.principal import Principal
from repoward.server import build_registry

REPO = "org/app"
OTHER = "org/other"
PRIVATE_REPO = "org/secret"
SHA = "a" * 40
ME = "local:me"
TRUSTED = ["COLLABORATOR", "MEMBER", "OWNER"]
ALL_TOOLS = (
    "[ping, github_list_issues, github_get_issue, github_get_file, github_create_branch, "
    "github_commit_files, github_create_pull_request, github_comment]"
)
MERGE_TOOLS = ALL_TOOLS[:-1] + ", github_merge_pull_request]"
MERGE_ON = "dangerous_tools:\n  github_merge_pull_request: { enabled: true }"


def policy(
    tools: str = ALL_TOOLS,
    repos: str = f'"{REPO}", "{OTHER}", "{PRIVATE_REPO}"',
    extra: str = "",
    role: str = "",
    per_minute: int = 1000,
    flow: str = "{ enabled: false }",
    stdio_role: str = "maintainer",
) -> CompiledPolicy:
    return parse_policy(
        f"""\
version: 1
default: deny
repos:
  allow: [{repos}]
flow_guard: {flow}
{extra}
roles:
  maintainer:
    tools: {tools}
    {role}
  reader:
    tools: [github_list_issues]
rate_limits:
  default: {{ per_minute: {per_minute} }}
stdio:
  role: {stdio_role}
""".encode()
    )


def fingerprint(characters: int) -> str:
    return f"[{characters} characters, sha256 {'b' * 64}]"


def commit_args(*paths: str, characters: int = 5, branch: str = "agent/x") -> dict[str, Any]:
    return {
        "repo": REPO,
        "branch": branch,
        "message": fingerprint(4),
        "files": [{"path": path, "content": fingerprint(characters)} for path in paths],
        "deletions": [],
    }


COMMENT = {"repo": REPO, "number": 1, "body": fingerprint(4)}
FILE = {"repo": REPO, "path": "a.py"}


class Log:
    """Write records with chosen times, as the server would."""

    def __init__(self, path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.path = path
        self.audit = AuditLog(path)
        self.now = datetime(2026, 11, 6, 12, tzinfo=UTC)
        self.count = 0
        monkeypatch.setattr(
            "repoward.audit._utc_now", lambda: self.now.isoformat().replace("+00:00", "Z")
        )

    def tick(self, **amount: float) -> None:
        self.now += timedelta(**amount)

    def call(
        self,
        tool: str,
        args: dict[str, Any],
        decision: str = "allow",
        rule: str = "roles.maintainer.tools",
        outcome: str | None = "ok",
        labels: tuple[tuple[str, str], ...] = (),
        trusted: list[str] | None = None,
        instance: str = "one",
    ) -> None:
        self.count += 1
        request = f"request-{self.count}"
        self.audit.append(
            {
                "event": "tool_call_decision",
                "request_id": request,
                "instance_id": instance,
                "session_id": None,
                "principal": ME,
                "role": "maintainer",
                "tool": tool,
                "policy_hash": "c" * 64,
                "flow_trusted": trusted,
                "args_redacted": args,
                "args_hash": "d" * 64,
                "decision": decision,
                "rule_id": rule,
            }
        )
        for kind, source in labels:
            self.audit.append(
                {
                    "event": "flow_label",
                    "request_id": request,
                    "principal": ME,
                    "kind": kind,
                    "source": source,
                }
            )
        if decision == "allow" and outcome is not None:
            self.audit.append(
                {
                    "event": "tool_call_outcome",
                    "request_id": request,
                    "result_status": outcome,
                    "duration_ms": 1,
                    "error": None,
                }
            )

    def read_private(self, trusted: list[str] | None = TRUSTED) -> None:
        self.call(
            "github_get_file",
            {"repo": PRIVATE_REPO, "path": "a.py"},
            labels=(("private_read", PRIVATE_REPO),),
            trusted=trusted,
        )

    def read_public(self, repo: str = REPO, trusted: list[str] | None = TRUSTED) -> None:
        self.call("github_get_file", {"repo": repo, "path": "a.py"}, trusted=trusted)

    def read_issue(
        self,
        source: str = f"github-issue:{REPO}#1",
        trusted: list[str] | None = TRUSTED,
        untrusted: bool = True,
    ) -> None:
        self.call(
            "github_get_issue",
            {"repo": REPO, "number": 1},
            labels=(("untrusted_input", source),) if untrusted else (),
            trusted=trusted,
        )

    def comment(self, rule: str = "roles.maintainer.tools", decision: str = "allow") -> None:
        self.call("github_comment", COMMENT, decision, rule, trusted=TRUSTED)


@pytest.fixture
def log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Log:
    return Log(tmp_path / "audit.jsonl", monkeypatch)


def replay(log: Log, compiled: CompiledPolicy) -> ReplayReport:
    return replay_log(log.path, compiled)


def only_change(report: ReplayReport) -> tuple[str, str, str]:
    assert not report.unknown, report.unknown
    assert len(report.changed) == 1, report.changed
    row = report.changed[0]
    return row.recorded, row.replayed, row.reason


# Static policy.


def test_the_same_policy_changes_nothing(log: Log) -> None:
    log.call("github_get_file", FILE)
    log.comment()
    report = replay(log, policy())
    assert report.decisions == 2
    assert report.unchanged == 2
    assert not report.changed
    assert not report.unknown


@pytest.mark.parametrize(
    ("compiled", "rule"),
    [
        pytest.param(policy(tools="[ping]"), "default.deny", id="tool-removed-from-role"),
        pytest.param(policy(repos=f'"{OTHER}"'), "repos.allow", id="repository-removed"),
        pytest.param(policy(stdio_role="reader"), "default.deny", id="server-role-changed"),
        pytest.param(policy(extra='paths:\n  deny: ["*.py"]'), "paths.deny", id="path-now-denied"),
    ],
)
def test_tightening_is_reported(log: Log, compiled: CompiledPolicy, rule: str) -> None:
    log.call("github_get_file", FILE)
    assert only_change(replay(log, compiled)) == ("allow", "deny", rule)


def test_loosening_is_reported(log: Log) -> None:
    log.call("github_get_file", FILE, "deny", "repos.allow")
    assert only_change(replay(log, policy())) == ("deny", "allow", "roles.maintainer.tools")


def test_a_new_approval_requirement_is_reported(log: Log) -> None:
    log.comment()
    role = "require_approval: [github_comment]"
    assert only_change(replay(log, policy(role=role))) == (
        "allow",
        "approval_required",
        "roles.maintainer.require_approval",
    )


def test_the_branch_prefix_is_checked_from_recorded_arguments(log: Log) -> None:
    log.call("github_commit_files", commit_args("a.py"))
    changed = policy(extra="branches:\n  write_prefix: bot/")
    assert only_change(replay(log, changed))[2] == "branches.write_prefix"


def test_non_draft_pull_requests_are_checked(log: Log) -> None:
    log.call(
        "github_create_pull_request",
        {
            "repo": REPO,
            "title": fingerprint(3),
            "head": "agent/x",
            "base": "main",
            "body": fingerprint(3),
            "draft": False,
        },
        "deny",
        "pull_requests.allow_non_draft",
    )
    assert not replay(log, policy()).changed
    # The credential check was never reached, so its answer is not in the log.
    allowed = policy(extra="pull_requests:\n  allow_non_draft: true")
    report = replay(log, allowed)
    assert report.unknown[0].replayed == UNKNOWN


def test_turning_off_a_dangerous_tool_is_reported(log: Log) -> None:
    args = {"repo": REPO, "number": 1, "head_sha": SHA, "merge_method": "squash"}
    log.call("github_merge_pull_request", args, rule="approvals.consumed")
    changed = policy(tools=MERGE_TOOLS, role=NEEDS_APPROVAL)
    assert only_change(replay(log, changed))[2] == (
        "dangerous_tools.github_merge_pull_request.disabled"
    )


# What the log hides.


def limits(max_files: int = 20, max_bytes: int = 200_000) -> str:
    return f"commit_limits: {{ max_files: {max_files}, max_bytes: {max_bytes} }}"


def test_file_count_limits_are_exact(log: Log) -> None:
    log.call("github_commit_files", commit_args("a.py", "b.py", "c.py"))
    assert only_change(replay(log, policy(role=limits(max_files=2))))[2] == "roles.commit_limits"


@pytest.mark.parametrize(
    ("max_bytes", "expected"),
    [
        pytest.param(99, "deny", id="smaller-than-the-character-count"),
        pytest.param(100, UNKNOWN, id="fits-only-if-it-is-ascii"),
        pytest.param(399, UNKNOWN, id="just-under-the-most-it-could-be"),
        pytest.param(400, "allow", id="fits-whatever-the-characters-are"),
    ],
)
def test_byte_limits_use_what_the_character_count_proves(
    log: Log, max_bytes: int, expected: str
) -> None:
    log.call("github_commit_files", commit_args("a.py", characters=100))
    report = replay(log, policy(role=limits(max_bytes=max_bytes)))
    if expected == "allow":
        assert report.unchanged == 1
    elif expected == UNKNOWN:
        assert report.unknown[0].replayed == UNKNOWN
    else:
        assert report.changed[0].replayed == "deny"


def test_a_call_blocked_for_a_credential_stays_blocked(log: Log) -> None:
    log.comment("secrets.outbound", "deny")
    assert replay(log, policy()).unchanged == 1


def test_a_call_past_the_credential_check_had_no_credential(log: Log) -> None:
    log.comment("flow.untrusted_author", "approval_required")
    assert only_change(replay(log, policy())) == (
        "approval_required",
        "allow",
        "roles.maintainer.tools",
    )


def test_a_call_denied_before_the_credential_check_is_unknown(log: Log) -> None:
    log.comment("repos.allow", "deny")
    assert replay(log, policy()).unknown[0].replayed == UNKNOWN


def test_a_redacted_path_is_unknown_not_guessed(log: Log) -> None:
    log.call("github_get_file", {"repo": REPO, "path": "[REDACTED].py"})
    report = replay(log, policy(extra='paths:\n  deny: ["*.py"]'))
    assert report.unknown[0].replayed == UNKNOWN


def test_a_list_the_log_may_have_cut_is_unknown(log: Log) -> None:
    paths = [f"f{number}.py" for number in range(50)]
    log.call("github_commit_files", commit_args(*paths))
    assert replay(log, policy()).unknown[0].replayed == UNKNOWN


@pytest.mark.parametrize("rule", ["tool.unknown", "input.invalid"])
def test_refusals_made_before_policy_never_change(log: Log, rule: str) -> None:
    log.call("github_comment", {"nonsense": True}, "deny", rule)
    report = replay(log, policy(tools="[ping]"))
    assert report.unchanged == 1


@pytest.mark.parametrize(
    "rule",
    ["audit.degraded", "approvals.unavailable", "approvals.too_many_pending", "flow.unavailable"],
)
def test_operational_refusals_are_unknown(log: Log, rule: str) -> None:
    log.comment(rule, "deny")
    assert replay(log, policy()).unknown[0].replayed == UNKNOWN


def test_operational_refusal_that_policy_would_also_deny_is_unchanged(log: Log) -> None:
    log.comment("audit.degraded", "deny")
    assert replay(log, policy(tools="[ping]")).unchanged == 1


def test_a_tool_that_no_longer_exists_is_unknown(log: Log) -> None:
    log.call("github_removed_tool", FILE)
    assert replay(log, policy()).unknown[0].replayed == UNKNOWN


# Approvals.


def test_removing_an_approval_requirement_is_reported(log: Log) -> None:
    log.comment("approvals.consumed")
    assert only_change(replay(log, policy())) == (
        "approval_required",
        "allow",
        "roles.maintainer.tools",
    )


def test_a_cli_approval_keeps_counting(log: Log) -> None:
    log.comment("approvals.consumed")
    role = "require_approval: [github_comment]"
    assert replay(log, policy(role=role)).unchanged == 1


REVIEWED = {"repo": REPO, "number": 1, "head_sha": SHA, "merge_method": "squash"}
NEEDS_APPROVAL = "require_approval: [github_merge_pull_request]"


def merge_policy(review: str = "") -> CompiledPolicy:
    extra = MERGE_ON + (f"\napprovals:\n  github_review: {review}" if review else "")
    return policy(tools=MERGE_TOOLS, extra=extra, role=NEEDS_APPROVAL)


def test_a_review_approval_keeps_counting_with_the_same_setting(log: Log) -> None:
    log.call("github_merge_pull_request", REVIEWED, rule="approvals.github_review")
    assert replay(log, merge_policy("{ enabled: true }")).unchanged == 1


def test_turning_off_review_approval_is_reported(log: Log) -> None:
    log.call("github_merge_pull_request", REVIEWED, rule="approvals.github_review")
    recorded, replayed, _ = only_change(replay(log, merge_policy()))
    assert "review" in recorded
    assert replayed == "approval_required"


def test_requiring_admin_review_is_unknown(log: Log) -> None:
    log.call("github_merge_pull_request", REVIEWED, rule="approvals.github_review")
    report = replay(log, merge_policy("{ enabled: true, min_permission: admin }"))
    assert report.unknown[0].replayed == UNKNOWN


# Flow state, rebuilt from the log.

GUARD = "{ enabled: true }"


def public_write(log: Log) -> None:
    log.read_public()
    log.comment()


def test_private_then_public_is_denied_when_the_guard_is_on(log: Log) -> None:
    log.read_private()
    public_write(log)
    assert only_change(replay(log, policy(flow=GUARD))) == (
        "allow",
        "deny",
        "flow.private_to_public",
    )


def test_writing_to_the_private_repository_is_still_allowed(log: Log) -> None:
    log.read_private()
    log.call("github_comment", {**COMMENT, "repo": PRIVATE_REPO}, trusted=TRUSTED)
    assert replay(log, policy(flow=GUARD)).unchanged == 3 - 1


def test_softening_the_private_rule_is_reported(log: Log) -> None:
    log.read_private()
    public_write(log)
    log.call("github_comment", COMMENT, "deny", "flow.private_to_public", trusted=TRUSTED)
    soft = policy(flow="{ enabled: true, on_private_to_public: require_approval }")
    report = replay(log, soft)
    assert [row.replayed for row in report.changed] == ["approval_required", "approval_required"]


def test_a_target_of_unknown_visibility_is_unknown(log: Log) -> None:
    log.read_private()
    log.comment()
    assert replay(log, policy(flow=GUARD)).unknown[0].tool == "github_comment"


def test_a_recorded_refusal_shows_the_target_was_public(log: Log) -> None:
    log.read_private()
    log.call("github_comment", COMMENT, "deny", "flow.private_to_public", trusted=TRUSTED)
    report = replay(log, policy(flow=GUARD))
    assert not report.unknown
    assert report.unchanged == 2


def test_turning_the_guard_off_is_reported(log: Log) -> None:
    log.read_private()
    log.call("github_comment", COMMENT, "deny", "flow.private_to_public", trusted=TRUSTED)
    assert only_change(replay(log, policy())) == ("deny", "allow", "roles.maintainer.tools")


def test_a_label_expires_with_the_new_window(log: Log) -> None:
    log.read_private()
    log.read_public()
    log.tick(minutes=30)
    log.comment()
    assert not replay(log, policy(flow="{ enabled: true, window_minutes: 10 }")).changed
    assert replay(log, policy(flow="{ enabled: true, window_minutes: 45 }")).changed


def test_rereading_a_private_repository_extends_the_label(log: Log) -> None:
    log.read_private()
    log.read_public()
    log.tick(minutes=25)
    log.call("github_get_file", {"repo": PRIVATE_REPO, "path": "a.py"}, trusted=TRUSTED)
    log.tick(minutes=25)
    log.comment()
    assert replay(log, policy(flow="{ enabled: true, window_minutes: 30 }")).changed


def test_a_reset_clears_the_labels(log: Log) -> None:
    log.read_private()
    log.read_public()
    log.audit.append({"event": "flow_reset", "principal": ME, "decided_by": "human"})
    log.comment()
    assert not replay(log, policy(flow=GUARD)).changed


def test_a_read_the_new_policy_denies_sets_no_label(log: Log) -> None:
    log.read_private()
    public_write(log)
    report = replay(log, policy(flow=GUARD, repos=f'"{REPO}", "{OTHER}"'))
    assert [row.tool for row in report.changed] == ["github_get_file"]
    assert not report.unknown


def test_a_failed_read_sets_no_label(log: Log) -> None:
    log.call("github_get_file", {"repo": OTHER, "path": "a.py"}, outcome="error", trusted=TRUSTED)
    public_write(log)
    assert not replay(log, policy(flow=GUARD)).changed


def test_a_read_newly_allowed_might_have_set_a_label(log: Log) -> None:
    log.call("github_get_file", {"repo": OTHER, "path": "a.py"}, "deny", "repos.allow")
    public_write(log)
    report = replay(log, policy(flow=GUARD))
    assert [row.tool for row in report.unknown] == ["github_comment"]


def test_a_read_with_no_recorded_outcome_might_have_set_a_label(log: Log) -> None:
    log.call("github_get_file", {"repo": OTHER, "path": "a.py"}, outcome=None, trusted=TRUSTED)
    public_write(log)
    assert [row.tool for row in replay(log, policy(flow=GUARD)).unknown] == ["github_comment"]


def test_enabling_the_guard_on_a_log_without_labels_is_unknown(log: Log) -> None:
    log.call("github_get_file", FILE, trusted=None)
    log.comment()
    report = replay(log, policy(flow=GUARD))
    assert [row.tool for row in report.unknown] == ["github_comment"]


def test_enabling_the_guard_with_no_earlier_reads_is_settled(log: Log) -> None:
    log.call("github_comment", COMMENT, trusted=None)
    assert replay(log, policy(flow=GUARD)).unchanged == 1


def test_untrusted_text_requires_approval(log: Log) -> None:
    log.read_issue()
    log.comment()
    assert only_change(replay(log, policy(flow=GUARD))) == (
        "allow",
        "approval_required",
        "flow.untrusted_author",
    )


def test_denying_on_untrusted_text_is_reported(log: Log) -> None:
    log.read_issue()
    log.comment()
    strict = policy(flow="{ enabled: true, on_untrusted_author: deny }")
    assert only_change(replay(log, strict))[1] == "deny"


def test_trusting_more_people_makes_a_label_unknown(log: Log) -> None:
    log.read_issue()
    log.comment()
    wider = "{ enabled: true, trusted_associations: [OWNER, MEMBER, COLLABORATOR, CONTRIBUTOR] }"
    assert [row.tool for row in replay(log, policy(flow=wider)).unknown] == ["github_comment"]


def test_trusting_fewer_people_makes_a_silent_read_unknown(log: Log) -> None:
    log.read_issue(untrusted=False)
    log.comment()
    narrower = "{ enabled: true, trusted_associations: [OWNER] }"
    assert [row.tool for row in replay(log, policy(flow=narrower)).unknown] == ["github_comment"]


def test_trusting_fewer_people_keeps_a_label_certain(log: Log) -> None:
    log.read_issue()
    log.comment()
    narrower = "{ enabled: true, trusted_associations: [OWNER] }"
    assert only_change(replay(log, policy(flow=narrower)))[2] == "flow.untrusted_author"


def test_a_silent_read_with_the_same_trust_sets_no_label(log: Log) -> None:
    log.read_issue(untrusted=False)
    log.comment()
    assert replay(log, policy(flow=GUARD)).unchanged == 2


def test_rereading_an_issue_may_extend_a_label_the_log_does_not_show(log: Log) -> None:
    log.read_issue()
    log.tick(minutes=50)
    log.read_issue(untrusted=False)
    log.tick(minutes=20)
    log.comment()
    report = replay(log, policy(flow=GUARD))
    assert [row.tool for row in report.unknown] == ["github_comment"]


def test_an_untrusted_label_with_no_reread_expires(log: Log) -> None:
    log.read_issue()
    log.tick(minutes=61)
    log.comment()
    assert replay(log, policy(flow=GUARD)).unchanged == 2


SINGLE = "{ enabled: true, single_repo: true }"


def test_single_repo_denies_a_second_repository(log: Log) -> None:
    log.read_public(OTHER)
    public_write(log)
    assert only_change(replay(log, policy(flow=SINGLE)))[2] == "flow.single_repo"


def test_single_repo_holds_to_the_first_repository_after_a_reread(log: Log) -> None:
    log.read_public(OTHER)
    log.read_public()
    log.read_public(OTHER)
    log.call("github_comment", {**COMMENT, "repo": OTHER}, trusted=TRUSTED)
    assert replay(log, policy(flow=SINGLE)).unchanged == 4


def test_single_repo_forgets_a_repository_after_the_window(log: Log) -> None:
    log.read_public(OTHER)
    log.tick(minutes=61)
    public_write(log)
    assert replay(log, policy(flow=SINGLE)).unchanged == 3


def test_single_repo_with_an_unknown_earlier_read_is_unknown(log: Log) -> None:
    log.call("github_get_file", {"repo": OTHER, "path": "a.py"}, "deny", "repos.allow")
    log.comment()
    report = replay(log, policy(flow=SINGLE))
    assert [row.tool for row in report.unknown] == ["github_comment"]


def test_single_repo_allows_the_same_repository(log: Log) -> None:
    public_write(log)
    log.comment()
    assert replay(log, policy(flow=SINGLE)).unchanged == 3


def test_single_repo_counts_earlier_writes(log: Log) -> None:
    log.comment()
    log.call("github_comment", {**COMMENT, "repo": OTHER}, trusted=TRUSTED)
    assert only_change(replay(log, policy(flow=SINGLE)))[2] == "flow.single_repo"


# Rate limits.


def test_a_lower_rate_limit_is_reported(log: Log) -> None:
    for _ in range(3):
        log.call("github_get_file", FILE)
    assert only_change(replay(log, policy(per_minute=2))) == (
        "allow",
        "deny",
        "rate_limits.default",
    )


def test_a_higher_rate_limit_is_reported(log: Log) -> None:
    log.call("github_get_file", FILE)
    log.call("github_get_file", FILE, "deny", "rate_limits.default")
    assert only_change(replay(log, policy(per_minute=5)))[1] == "allow"


def test_rate_limits_use_recorded_times(log: Log) -> None:
    log.call("github_get_file", FILE)
    log.tick(seconds=61)
    log.call("github_get_file", FILE)
    assert replay(log, policy(per_minute=1)).unchanged == 2


def test_a_restart_clears_rate_limits(log: Log) -> None:
    log.call("github_get_file", FILE)
    log.call("github_get_file", FILE, instance="two")
    assert replay(log, policy(per_minute=1)).unchanged == 2


def test_an_unknown_earlier_call_makes_a_rate_limit_unknown(log: Log) -> None:
    log.call("github_get_file", {"repo": REPO, "path": "[REDACTED]"})
    log.call("github_get_file", FILE)
    report = replay(log, policy(per_minute=1))
    assert [row.replayed for row in report.unknown] == [UNKNOWN, UNKNOWN]


# Trusting the log.


def test_a_tampered_log_is_refused(log: Log) -> None:
    log.call("github_get_file", FILE)
    log.path.write_bytes(log.path.read_bytes().replace(b"org/app", b"org/xxx"))
    with pytest.raises(ReplayError, match="failed verification"):
        replay(log, policy())


def test_a_missing_log_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="no audit log"):
        replay_log(tmp_path / "nothing.jsonl", policy())


def test_an_hmac_log_needs_its_key(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    key = b"k" * 32
    AuditLog(path, key).append({"event": "flow_reset", "principal": None})
    with pytest.raises(ReplayError, match="failed verification"):
        replay_log(path, policy())
    assert replay_log(path, policy(), key).decisions == 0


def test_an_unreadable_record_is_refused(log: Log) -> None:
    log.audit.append({"event": "tool_call_decision", "seq_override": 1, "args_redacted": [1]})
    rows = log.path.read_bytes()
    assert b"tool_call_decision" in rows
    report = replay(log, policy())
    assert report.unknown[0].reason == "this tool is not known"


# Against records the server really wrote.


@pytest.fixture
def github() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


API = "https://api.github.com"


def issue(number: int, association: str) -> dict[str, Any]:
    return {
        "number": number,
        "title": "t",
        "state": "open",
        "body": "text",
        "author_association": association,
        "user": {"login": "someone"},
        "comments": 0,
    }


@pytest.mark.anyio
async def test_replaying_a_real_run_with_its_own_policy_changes_nothing(
    tmp_path: Path, github: respx.MockRouter
) -> None:
    compiled = policy(flow=GUARD, extra='paths:\n  deny: ["secrets/**"]')
    client = GitHubClient("fake-token")
    audit = tmp_path / "audit.jsonl"
    github.get(f"{API}/repos/{REPO}").respond(json={"private": False})
    github.get(f"{API}/repos/{PRIVATE_REPO}").respond(json={"private": True})
    github.get(f"{API}/repos/{OTHER}").respond(json={"private": False})
    github.get(f"{API}/repos/{REPO}/issues").respond(json=[issue(1, "NONE")])
    github.get(f"{API}/repos/{PRIVATE_REPO}/issues").respond(json=[])
    github.get(f"{API}/repos/{OTHER}/issues").respond(json=[issue(2, "OWNER")])
    github.post(f"{API}/repos/{OTHER}/issues/1/comments").respond(json={"id": 9})
    pipeline = Pipeline(
        compiled,
        build_registry(compiled, client),
        AuditLog(audit),
        approvals=ApprovalStore(tmp_path / "approvals.db"),
        flow=FlowGuard(
            compiled.policy.flow_guard, FlowStore(tmp_path / "flow.db"), client.repo_is_private
        ),
    )
    agent = Principal(ME, "maintainer")
    await pipeline.call(agent, "ping", {})
    await pipeline.call(agent, "github_list_issues", {"repo": OTHER})
    await pipeline.call(agent, "github_comment", {"repo": OTHER, "number": 1, "body": "hi"})
    await pipeline.call(agent, "github_get_file", {"repo": REPO, "path": "secrets/key"})
    await pipeline.call(agent, "github_comment", {"repo": REPO, "body": "missing a number"})
    await pipeline.call(agent, "no_such_tool", {})
    await pipeline.call(agent, "github_list_issues", {"repo": PRIVATE_REPO})
    await pipeline.call(agent, "github_comment", {"repo": OTHER, "number": 1, "body": "leak"})
    await pipeline.call(agent, "github_list_issues", {"repo": REPO})
    await pipeline.call(agent, "github_comment", {"repo": PRIVATE_REPO, "number": 1, "body": "hi"})
    await client.aclose()
    calls_made = len(github.calls)

    report = replay_log(audit, compiled)

    assert len(github.calls) == calls_made
    assert report.decisions == 10
    assert not report.changed, report.changed
    assert not report.unknown, report.unknown

    relaxed = replay_log(audit, policy(flow="{ enabled: false }"))
    assert "flow.private_to_public" not in {row.reason for row in relaxed.changed}
    assert {row.replayed for row in relaxed.changed} >= {"allow"}


# The command line.


def write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "new.yaml"
    path.write_text(text, encoding="utf-8")
    return path


GOOD_POLICY = f"""\
version: 1
default: deny
repos:
  allow: ["{OTHER}"]
flow_guard:
  enabled: false
roles:
  maintainer:
    tools: [github_get_file]
rate_limits:
  default: {{ per_minute: 100 }}
stdio:
  role: maintainer
"""


def test_the_command_reports_changes(
    log: Log, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log.call("github_get_file", FILE)
    log.call("github_get_file", {"repo": OTHER, "path": "a.py"})
    log.call("github_get_file", {"repo": REPO, "path": "[REDACTED]"})
    code = main(
        ["policy", "replay", str(log.path), "--policy", str(write_policy(tmp_path, GOOD_POLICY))]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "3 decisions: 1 unchanged, 1 changed, 1 unknown" in out
    assert f"github_get_file  {REPO}: allow -> deny  (repos.allow)" in out
    assert "same calls" in out


def test_the_command_cleans_what_it_prints(
    log: Log, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log.call("github_\x1b[31mfake", FILE)
    main(["policy", "replay", str(log.path), "--policy", str(write_policy(tmp_path, GOOD_POLICY))])
    assert "\x1b" not in capsys.readouterr().out


def test_the_command_rejects_a_bad_policy(
    log: Log, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log.call("github_get_file", FILE)
    code = main(["policy", "replay", str(log.path), "--policy", str(write_policy(tmp_path, "no"))])
    assert code == 1
    assert capsys.readouterr().err


def test_the_command_reports_a_tampered_log(
    log: Log, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log.call("github_get_file", FILE)
    log.path.write_bytes(log.path.read_bytes().replace(b"org/app", b"org/xxx"))
    code = main(
        ["policy", "replay", str(log.path), "--policy", str(write_policy(tmp_path, GOOD_POLICY))]
    )
    assert code == 1
    assert "failed verification" in capsys.readouterr().err


def test_the_command_uses_the_home_log_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REPOWARD_HOME", str(tmp_path))
    AuditLog(tmp_path / "audit.jsonl").append({"event": "flow_reset", "principal": None})
    code = main(["policy", "replay", "--policy", str(write_policy(tmp_path, GOOD_POLICY))])
    assert code == 0
    assert "0 decisions" in capsys.readouterr().out
