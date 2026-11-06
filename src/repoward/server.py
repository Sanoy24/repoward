"""MCP server wiring.

This uses the SDK's low-level ``Server`` on purpose. Its single ``on_call_tool`` handler also
receives unknown tools and invalid arguments, so every attempt can pass through one guarded path.
"""

from importlib.metadata import version

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

PING = Tool(
    name="ping",
    description="Check that the server is reachable.",
    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
)


def _text_result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)


async def _list_tools(
    ctx: ServerRequestContext, params: PaginatedRequestParams | None
) -> ListToolsResult:
    return ListToolsResult(tools=[PING])


async def _call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
    if params.name != PING.name:
        return _text_result("Unknown tool.", is_error=True)
    if params.arguments:
        return _text_result("ping takes no arguments.", is_error=True)
    return _text_result("pong")


def create_server() -> Server:
    """Build the MCP server."""
    return Server(
        "repoward",
        version=version("repoward"),
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )


async def _serve_stdio() -> None:
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run_stdio() -> None:
    """Serve over stdio until the client closes the connection."""
    anyio.run(_serve_stdio)
