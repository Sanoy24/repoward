"""MCP server wiring.

This uses the SDK's low-level ``Server`` on purpose. Its single ``on_call_tool`` handler also
receives unknown tools and invalid arguments, so every attempt reaches the pipeline and is
audited. ``MCPServer`` would reject bad arguments before any code here ran.
"""

import os
from importlib.metadata import version
from pathlib import Path

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from repoward.adapters.github import GitHubClient
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog
from repoward.flow import FlowGuard, FlowStore
from repoward.pipeline import Pipeline, alert
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal, local_principal
from repoward.registry import ToolRegistry
from repoward.tools import ci_read, github_dangerous, github_read, github_write, system


def build_registry(policy: CompiledPolicy, github: GitHubClient) -> ToolRegistry:
    registry = ToolRegistry()
    system.register(registry)
    github_read.register(registry, github, policy)
    ci_read.register(registry, github)
    github_write.register(registry, github)
    github_dangerous.register(registry, github)
    return registry


def create_server(registry: ToolRegistry, pipeline: Pipeline, principal: Principal) -> Server:
    """Build the MCP server around one pipeline."""

    async def list_tools(
        ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(tools=registry.list_tools())

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        try:
            return await pipeline.call(principal, params.name, params.arguments)
        except Exception as exc:
            # A raised exception would reach the model as an unreadable protocol error.
            alert(f"pipeline failed: {type(exc).__name__}")
            return CallToolResult(
                content=[TextContent(type="text", text="The request could not be processed.")],
                is_error=True,
            )

    return Server(
        "repoward",
        version=version("repoward"),
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def run_stdio(
    policy: CompiledPolicy,
    audit_path: Path,
    approvals_path: Path,
    flow_path: Path,
    hmac_key: bytes | None,
) -> None:
    """Serve over stdio until the client closes the connection."""
    github = GitHubClient(os.environ.get("GITHUB_TOKEN"))
    registry = build_registry(policy, github)
    approval_rules = policy.policy.approvals
    approvals = ApprovalStore(
        approvals_path,
        approval_rules.ttl_minutes * 60.0,
        approval_rules.max_pending_per_principal,
    )
    rules = policy.policy.flow_guard
    flow = FlowGuard(rules, FlowStore(flow_path), github.repo_is_private) if rules.enabled else None
    pipeline = Pipeline(
        policy, registry, AuditLog(audit_path, hmac_key), approvals=approvals, flow=flow
    )
    server = create_server(registry, pipeline, local_principal(policy.policy.stdio.role))

    async def serve() -> None:
        try:
            async with stdio_server() as (read_stream, write_stream):
                await server.run(read_stream, write_stream, server.create_initialization_options())
        finally:
            await github.aclose()

    anyio.run(serve)
