import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from repoward.audit import AuditLog, AuditWriteError, verify_log
from repoward.catalog import TOOL_CATALOG, RiskClass
from repoward.pipeline import MAX_OUTPUT_CHARS, Pipeline
from repoward.policy.engine import Target
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal
from repoward.registry import ToolError, ToolInput, ToolOutput, ToolRegistry, ToolSpec
from repoward.validation import RepoName, RepoPath

pytestmark = pytest.mark.anyio

READER = Principal("alice", "reader")
CONTRIBUTOR = Principal("bob", "contributor")
MAINTAINER = Principal("carol", "maintainer")


class FileArgs(ToolInput):
    repo: RepoName
    path: RepoPath


class FailingAudit(AuditLog):
    """Fails on chosen events, as a full disk would."""

    def __init__(self, path: Path, failing: set[str]) -> None:
        super().__init__(path)
        self.failing = failing

    def append(self, fields: dict[str, Any]) -> dict[str, Any]:
        if fields.get("event") in self.failing:
            raise AuditWriteError("disk full")
        return super().append(fields)


class Harness:
    def __init__(self, policy: CompiledPolicy, tmp_path: Path) -> None:
        self.calls: list[str] = []
        self.path = tmp_path / "audit.jsonl"
        self.policy = policy
        self.registry = ToolRegistry()
        self.behavior: Callable[[], ToolOutput] = lambda: ToolOutput("done")
        for name in (
            "github_get_file",
            "github_commit_files",
            "github_delete_branch",
            "github_merge_pull_request",
        ):
            self.registry.register(self._spec(name))
        self.pipeline = Pipeline(policy, self.registry, AuditLog(self.path))

    def _spec(self, name: str) -> ToolSpec:
        async def handler(_: ToolInput) -> ToolOutput:
            self.calls.append(name)
            return self.behavior()

        def target(args: ToolInput) -> Target:
            assert isinstance(args, FileArgs)
            return Target(repo=args.repo, paths=[args.path])

        return ToolSpec(name, "test tool", TOOL_CATALOG[name], FileArgs, handler, target)

    def use_failing_audit(self, failing: set[str]) -> None:
        self.pipeline = Pipeline(self.policy, self.registry, FailingAudit(self.path, failing))

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_bytes().splitlines()]


@pytest.fixture
def harness(policy: CompiledPolicy, tmp_path: Path) -> Harness:
    return Harness(policy, tmp_path)


GOOD = {"repo": "org/sandbox", "path": "src/a.py"}


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def test_allowed_call_runs_and_writes_two_linked_records(harness: Harness) -> None:
    result = await harness.pipeline.call(READER, "github_get_file", GOOD)
    assert not result.is_error
    assert text(result) == "done"
    assert harness.calls == ["github_get_file"]
    decision, outcome = harness.records()
    assert decision["event"] == "tool_call_decision"
    assert decision["decision"] == "allow"
    assert decision["rule_id"] == "roles.reader.tools"
    assert decision["principal"] == "alice"
    assert decision["role"] == "reader"
    assert decision["args_redacted"] == GOOD
    assert len(decision["args_hash"]) == 64
    assert decision["policy_hash"] == harness.policy.sha256
    assert decision["session_id"] is None
    assert decision["instance_id"]
    assert outcome["event"] == "tool_call_outcome"
    assert outcome["request_id"] == decision["request_id"]
    assert outcome["result_status"] == "ok"
    assert outcome["duration_ms"] >= 0
    assert verify_log(harness.path).ok


@pytest.mark.parametrize(
    ("principal", "tool", "args", "rule_id"),
    [
        (READER, "does_not_exist", {}, "tool.unknown"),
        (READER, "ping", {}, "tool.unknown"),
        (READER, "github_get_file", {}, "input.invalid"),
        (READER, "github_get_file", {**GOOD, "extra": 1}, "input.invalid"),
        (READER, "github_get_file", {**GOOD, "path": "../x"}, "input.invalid"),
        (READER, "github_get_file", {**GOOD, "repo": "bad repo"}, "input.invalid"),
        (READER, "github_get_file", {**GOOD, "path": 5}, "input.invalid"),
        (READER, "github_commit_files", GOOD, "default.deny"),
        (Principal("x", "ghost"), "github_get_file", GOOD, "role.unknown"),
        (READER, "github_get_file", {**GOOD, "repo": "org/other"}, "repos.allow"),
        (READER, "github_get_file", {**GOOD, "path": ".env"}, "paths.deny"),
        (
            MAINTAINER,
            "github_merge_pull_request",
            GOOD,
            "dangerous_tools.github_merge_pull_request.disabled",
        ),
    ],
)
async def test_refused_calls_never_run_but_are_always_audited(
    harness: Harness, principal: Principal, tool: str, args: dict[str, Any], rule_id: str
) -> None:
    result = await harness.pipeline.call(principal, tool, args)
    assert result.is_error
    assert harness.calls == []
    records = harness.records()
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["rule_id"] == rule_id
    assert verify_log(harness.path).ok


async def test_none_arguments_are_treated_as_empty(harness: Harness) -> None:
    result = await harness.pipeline.call(READER, "github_get_file", None)
    assert result.is_error
    assert harness.records()[0]["rule_id"] == "input.invalid"


async def test_invalid_input_error_helps_without_echoing(harness: Harness) -> None:
    result = await harness.pipeline.call(
        READER, "github_get_file", {"repo": "org/sandbox", "path": "../ATTACKER"}
    )
    assert "path" in text(result)
    assert "ATTACKER" not in text(result)


async def test_secrets_in_arguments_never_reach_the_log(harness: Harness) -> None:
    secret = "ghp_" + "a" * 36
    await harness.pipeline.call(READER, secret, {"token": "hunter2", "note": secret})
    raw = harness.path.read_text(encoding="utf-8")
    assert secret not in raw
    assert "hunter2" not in raw


async def test_unusual_arguments_still_produce_a_valid_chain(harness: Harness) -> None:
    await harness.pipeline.call(READER, "\ud800tool", {"k\ud800": float("nan"), "big": "x" * 9999})
    assert verify_log(harness.path).ok


async def test_approval_required_does_not_execute(harness: Harness) -> None:
    result = await harness.pipeline.call(MAINTAINER, "github_delete_branch", GOOD)
    assert not result.is_error
    assert result.structured_content is not None
    assert result.structured_content["status"] == "approval_required"
    assert harness.calls == []
    assert harness.records()[0]["decision"] == "approval_required"


async def test_rate_limit_refuses_with_a_clear_error_and_is_audited(harness: Harness) -> None:
    for _ in range(2):
        assert not (await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)).is_error
    result = await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)
    assert result.is_error
    assert "Try again in" in text(result)
    assert harness.calls == ["github_commit_files"] * 2
    assert harness.records()[-1]["rule_id"] == "rate_limits.github_commit_files"


async def test_denied_calls_do_not_use_up_the_rate_limit(harness: Harness) -> None:
    for _ in range(5):
        await harness.pipeline.call(
            CONTRIBUTOR, "github_commit_files", {**GOOD, "repo": "org/other"}
        )
    assert not (await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)).is_error


async def test_tool_error_message_is_returned_and_redacted(harness: Harness) -> None:
    secret = "ghp_" + "a" * 36

    def fail() -> ToolOutput:
        raise ToolError(f"GitHub said no: {secret}")

    harness.behavior = fail
    result = await harness.pipeline.call(READER, "github_get_file", GOOD)
    assert result.is_error
    assert "GitHub said no" in text(result)
    assert secret not in text(result)
    outcome = harness.records()[-1]
    assert outcome["result_status"] == "error"
    assert secret not in outcome["error"]


async def test_unexpected_exception_reveals_nothing(harness: Harness) -> None:
    def crash() -> ToolOutput:
        raise RuntimeError("internal detail")

    harness.behavior = crash
    result = await harness.pipeline.call(READER, "github_get_file", GOOD)
    assert result.is_error
    assert "internal detail" not in text(result)
    outcome = harness.records()[-1]
    assert outcome["error"] == "RuntimeError"
    assert "internal detail" not in json.dumps(outcome)


async def test_output_is_redacted_before_truncation(harness: Harness) -> None:
    secret = "ghp_" + "a" * 36
    padding = "x" * (MAX_OUTPUT_CHARS - 5)
    harness.behavior = lambda: ToolOutput(padding + secret)
    output = text(await harness.pipeline.call(READER, "github_get_file", GOOD))
    assert "ghp_" not in output
    harness.behavior = lambda: ToolOutput("y" * (MAX_OUTPUT_CHARS + 500))
    output = text(await harness.pipeline.call(READER, "github_get_file", GOOD))
    assert output.endswith("[truncated 500 characters]")


async def test_write_tool_fails_closed_when_decision_cannot_be_logged(harness: Harness) -> None:
    harness.use_failing_audit({"tool_call_decision"})
    result = await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)
    assert result.is_error
    assert "not performed" in text(result)
    assert harness.calls == []


async def test_read_tool_proceeds_with_an_alert_when_logging_fails(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness.use_failing_audit({"tool_call_decision", "tool_call_outcome"})
    result = await harness.pipeline.call(READER, "github_get_file", GOOD)
    assert not result.is_error
    assert harness.calls == ["github_get_file"]
    assert "audit decision record failed" in capsys.readouterr().err


async def test_refusals_stay_refusals_when_logging_fails(harness: Harness) -> None:
    harness.use_failing_audit({"tool_call_decision"})
    result = await harness.pipeline.call(READER, "github_commit_files", GOOD)
    assert result.is_error
    assert harness.calls == []
    approval = await harness.pipeline.call(MAINTAINER, "github_delete_branch", GOOD)
    assert approval.structured_content is not None
    assert harness.calls == []


async def test_lost_outcome_warns_and_enters_degraded_mode(harness: Harness) -> None:
    harness.use_failing_audit({"tool_call_outcome"})
    first = await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)
    assert not first.is_error
    warning = first.content[-1]
    assert isinstance(warning, TextContent)
    assert "could not be audited" in warning.text
    assert harness.calls == ["github_commit_files"]

    second = await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)
    assert second.is_error
    assert harness.calls == ["github_commit_files"]
    assert harness.records()[-1]["rule_id"] == "audit.degraded"

    read = await harness.pipeline.call(READER, "github_get_file", GOOD)
    assert not read.is_error


async def test_lost_outcome_on_a_read_does_not_degrade(harness: Harness) -> None:
    harness.use_failing_audit({"tool_call_outcome"})
    await harness.pipeline.call(READER, "github_get_file", GOOD)
    result = await harness.pipeline.call(CONTRIBUTOR, "github_commit_files", GOOD)
    assert harness.calls == ["github_get_file", "github_commit_files"]
    assert len(result.content) == 2


def test_registry_refuses_names_and_risks_outside_the_catalog() -> None:
    async def handler(_: ToolInput) -> ToolOutput:
        return ToolOutput("x")

    registry = ToolRegistry()
    with pytest.raises(ValueError, match="catalog"):
        registry.register(
            ToolSpec("made_up", "d", RiskClass.READ, ToolInput, handler, lambda _: Target())
        )
    with pytest.raises(ValueError, match="catalog"):
        registry.register(
            ToolSpec("github_comment", "d", RiskClass.READ, ToolInput, handler, lambda _: Target())
        )
    spec = ToolSpec("ping", "d", RiskClass.READ, ToolInput, handler, lambda _: Target())
    registry.register(spec)
    with pytest.raises(ValueError, match="already"):
        registry.register(spec)
