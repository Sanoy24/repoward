"""MCP server wiring.

This uses the SDK's low-level ``Server`` on purpose. Its single ``on_call_tool`` handler also
receives unknown tools and invalid arguments, so every attempt reaches the pipeline and is
audited. ``MCPServer`` would reject bad arguments before any code here ran.
"""

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

from repoward.audit import AuditLog
from repoward.pipeline import Pipeline, alert
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal, local_principal
from repoward.registry import ToolRegistry
from repoward.tools import system


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    system.register(registry)
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


def run_stdio(policy: CompiledPolicy, audit_path: Path, hmac_key: bytes | None) -> None:
    """Serve over stdio until the client closes the connection."""
    registry = build_registry()
    pipeline = Pipeline(policy, registry, AuditLog(audit_path, hmac_key))
    server = create_server(registry, pipeline, local_principal(policy.policy.stdio.role))

    async def serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(serve)
