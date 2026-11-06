import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

from repoward.adapters.github import GitHubClient
from repoward.audit import AuditLog, verify_log
from repoward.pipeline import Pipeline
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal
from repoward.server import build_registry, create_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
async def client(policy: CompiledPolicy, audit_path: Path) -> AsyncIterator[Client]:
    registry = build_registry(policy, GitHubClient(None))
    pipeline = Pipeline(policy, registry, AuditLog(audit_path))
    server = create_server(registry, pipeline, Principal("test", "reader"))
    async with Client(server, raise_exceptions=True) as connected:
        yield connected


def _text(content: object) -> str:
    assert isinstance(content, TextContent)
    return content.text


async def test_lists_ping_tool(client: Client) -> None:
    result = await client.list_tools()
    names = [tool.name for tool in result.tools]
    assert names == sorted(names)
    assert names == [
        "ci_get_job_logs",
        "ci_get_status",
        "github_get_file",
        "github_get_issue",
        "github_list_issues",
        "github_search_code",
        "ping",
    ]
    assert all(tool.input_schema["additionalProperties"] is False for tool in result.tools)


async def test_ping_is_governed_end_to_end(client: Client, audit_path: Path) -> None:
    result = await client.call_tool("ping", {})
    assert not result.is_error
    assert _text(result.content[0]) == "pong"
    report = verify_log(audit_path)
    assert report.ok
    assert report.records == 2


async def test_unknown_tool_is_readable_and_audited(client: Client, audit_path: Path) -> None:
    result = await client.call_tool("does_not_exist", {})
    assert result.is_error
    assert _text(result.content[0]) == "Unknown tool."
    assert verify_log(audit_path).records == 1


async def test_invalid_arguments_are_readable_and_audited(client: Client, audit_path: Path) -> None:
    result = await client.call_tool("ping", {"unexpected": True})
    assert result.is_error
    assert "unexpected" in _text(result.content[0])
    record = json.loads(audit_path.read_bytes().splitlines()[0])
    assert record["rule_id"] == "input.invalid"


async def test_role_without_ping_is_refused(policy: CompiledPolicy, audit_path: Path) -> None:
    registry = build_registry(policy, GitHubClient(None))
    pipeline = Pipeline(policy, registry, AuditLog(audit_path))
    server = create_server(registry, pipeline, Principal("test", "ghost"))
    async with Client(server, raise_exceptions=True) as connected:
        result = await connected.call_tool("ping", {})
    assert result.is_error
    assert verify_log(audit_path).records == 1


async def test_pipeline_crash_returns_a_readable_error(
    policy: CompiledPolicy, audit_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = build_registry(policy, GitHubClient(None))
    pipeline = Pipeline(policy, registry, AuditLog(audit_path))

    async def explode(*_: object) -> None:
        raise RuntimeError("secret detail")

    monkeypatch.setattr(pipeline, "call", explode)
    server = create_server(registry, pipeline, Principal("test", "reader"))
    async with Client(server, raise_exceptions=True) as connected:
        result = await connected.call_tool("ping", {})
    assert result.is_error
    assert "secret detail" not in _text(result.content[0])


async def test_real_stdio_process_is_governed(policy_file: Path, audit_path: Path) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "repoward.cli",
            "serve",
            "--policy",
            str(policy_file),
            "--audit",
            str(audit_path),
        ],
    )
    async with Client(params) as client:
        tools = await client.list_tools()
        result = await client.call_tool("ping", {})
        denied = await client.call_tool("github_merge_pull_request", {})
    assert "ping" in [tool.name for tool in tools.tools]
    assert _text(result.content[0]) == "pong"
    assert denied.is_error
    report = verify_log(audit_path)
    assert report.ok
    assert report.records == 3
