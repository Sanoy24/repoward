"""Structural proof that nothing can skip the pipeline. Fails if the design is bypassed."""

import ast
from pathlib import Path

import pytest

SOURCE = Path(__file__).parent.parent / "src" / "repoward"
FILES = sorted(SOURCE.rglob("*.py"))


def relative(path: Path) -> str:
    return path.relative_to(SOURCE).as_posix()


def imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


@pytest.mark.parametrize("path", FILES, ids=relative)
def test_tool_handlers_are_only_invoked_by_the_pipeline(path: Path) -> None:
    if relative(path) == "pipeline.py":
        return
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Attribute) and node.attr == "handler":
            pytest.fail(f"{relative(path)} touches a tool handler directly")


def test_the_pipeline_invokes_handlers_in_exactly_one_place() -> None:
    tree = ast.parse((SOURCE / "pipeline.py").read_text(encoding="utf-8"))
    uses = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "handler"]
    assert len(uses) == 1


@pytest.mark.parametrize("path", FILES, ids=relative)
def test_high_level_sdk_server_is_not_used(path: Path) -> None:
    found = imports(ast.parse(path.read_text(encoding="utf-8")))
    assert "mcp.server.MCPServer" not in found
    assert not any(name.startswith("mcp.server.mcpserver") for name in found)


@pytest.mark.parametrize("path", FILES, ids=relative)
def test_network_clients_stay_in_adapters(path: Path) -> None:
    if relative(path).startswith("adapters/"):
        return
    found = imports(ast.parse(path.read_text(encoding="utf-8")))
    for banned in ("httpx", "requests", "urllib.request", "socket", "subprocess"):
        assert banned not in found, f"{relative(path)} imports {banned}"


@pytest.mark.parametrize("path", FILES, ids=relative)
def test_no_eval_or_shell(path: Path) -> None:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}


def test_only_the_server_module_registers_with_the_sdk() -> None:
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        if "on_call_tool" in text:
            assert relative(path) == "server.py"
