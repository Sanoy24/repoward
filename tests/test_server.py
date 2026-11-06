import sys
from collections.abc import AsyncIterator

import pytest
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

from repoward.server import create_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def client() -> AsyncIterator[Client]:
    async with Client(create_server(), raise_exceptions=True) as connected:
        yield connected


def _text(content: object) -> str:
    assert isinstance(content, TextContent)
    return content.text


async def test_lists_ping_tool(client: Client) -> None:
    result = await client.list_tools()
    assert [tool.name for tool in result.tools] == ["ping"]


async def test_ping_returns_pong(client: Client) -> None:
    result = await client.call_tool("ping", {})
    assert not result.is_error
    assert _text(result.content[0]) == "pong"


async def test_unknown_tool_is_a_readable_error(client: Client) -> None:
    result = await client.call_tool("does_not_exist", {})
    assert result.is_error
    assert _text(result.content[0]) == "Unknown tool."


async def test_ping_rejects_arguments(client: Client) -> None:
    result = await client.call_tool("ping", {"unexpected": True})
    assert result.is_error


async def test_real_stdio_process_lists_and_calls_ping() -> None:
    params = StdioServerParameters(command=sys.executable, args=["-m", "repoward.cli", "serve"])
    async with Client(params) as client:
        tools = await client.list_tools()
        result = await client.call_tool("ping", {})
    assert [tool.name for tool in tools.tools] == ["ping"]
    assert _text(result.content[0]) == "pong"
