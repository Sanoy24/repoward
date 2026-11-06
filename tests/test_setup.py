import json
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

from repoward.audit import verify_log
from repoward.cli import main
from repoward.flow import PRIVATE_READ, FlowStore
from repoward.policy.loader import PolicyError, load_policy
from repoward.setup import client_config, default_dir, starter_policy


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home"
    monkeypatch.setenv("REPOWARD_HOME", str(path))
    return path


def init(*args: str) -> int:
    return main(["init", "--repo", "org/repo", *args])


def test_default_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOWARD_HOME", str(tmp_path))
    assert default_dir() == tmp_path
    monkeypatch.delenv("REPOWARD_HOME")
    assert default_dir() == Path.home() / ".repoward"


def test_init_writes_a_policy_that_loads(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert init() == 0
    compiled = load_policy(home / "policy.yaml")
    assert compiled.policy.stdio.role == "reader"
    assert compiled.allowed_repos == {"org/repo"}
    assert "Next steps" in capsys.readouterr().out


def test_init_is_safe_by_default(home: Path) -> None:
    assert init() == 0
    policy = load_policy(home / "policy.yaml").policy
    assert policy.dangerous_tools["github_merge_pull_request"].enabled is False
    assert policy.pull_requests.allow_non_draft is False
    assert policy.flow_guard.enabled is True
    assert policy.flow_guard.on_private_to_public == "deny"


def test_init_with_several_repos_and_a_role(home: Path) -> None:
    code = main(["init", "--repo", "org/a", "--repo", "org/b", "--role", "contributor"])
    assert code == 0
    compiled = load_policy(home / "policy.yaml")
    assert compiled.allowed_repos == {"org/a", "org/b"}
    assert compiled.policy.stdio.role == "contributor"


def test_init_never_overwrites_a_policy(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home.mkdir()
    (home / "policy.yaml").write_text("my careful policy", encoding="utf-8")
    assert init() == 1
    assert "already exists" in capsys.readouterr().err
    assert (home / "policy.yaml").read_text(encoding="utf-8") == "my careful policy"


def test_init_refuses_a_bad_repo_and_writes_nothing(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init", "--repo", "not a repo"]) == 1
    assert "repos.allow" in capsys.readouterr().err
    assert not (home / "policy.yaml").exists()


def test_init_requires_a_repo_and_a_known_role(home: Path) -> None:
    with pytest.raises(SystemExit):
        main(["init"])
    with pytest.raises(SystemExit):
        init("--role", "maintainer")


def test_init_prints_a_config_with_no_real_secret(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "r" * 36)
    assert init() == 0
    out = capsys.readouterr().out
    assert "ghp_" not in out
    assert "<your-token>" in out
    assert "not a security boundary" in out


def test_client_config_is_valid_json_with_an_absolute_path(tmp_path: Path) -> None:
    config: dict[str, Any] = json.loads(client_config(tmp_path))
    server = config["mcpServers"]["repoward"]
    assert server["command"] == "uvx"
    assert server["args"][:3] == ["repoward", "serve", "--dir"]
    assert Path(server["args"][3]).is_absolute()


def test_starter_policy_is_checked_before_use() -> None:
    with pytest.raises(PolicyError):
        starter_policy(["bad repo"], "reader")


def test_serve_without_a_policy_says_what_to_do(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["serve"]) == 1
    assert "repoward init" in capsys.readouterr().err


def test_commands_default_to_the_home_directory(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert init() == 0
    capsys.readouterr()
    assert main(["validate-policy"]) == 0
    assert main(["approvals", "list"]) == 0
    assert (home / "approvals.db").exists()
    assert main(["flow", "status"]) == 0
    FlowStore(home / "flow.db").add("p", PRIVATE_READ, "org/a", 600.0)
    assert main(["flow", "reset"]) == 0
    assert verify_log(home / "audit.jsonl").records == 1
    assert main(["audit", "verify"]) == 0


@pytest.mark.anyio
async def test_serve_with_explicit_paths_leaves_the_default_directory_alone(
    policy_file: Path, tmp_path: Path
) -> None:
    unused = tmp_path / "unused-home"
    state = tmp_path / "state"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "repoward.cli",
            "serve",
            "--policy",
            str(policy_file),
            "--audit",
            str(state / "audit.jsonl"),
            "--approvals",
            str(state / "approvals.db"),
            "--flow",
            str(state / "flow.db"),
        ],
        env={"REPOWARD_HOME": str(unused)},
    )
    async with Client(params) as client:
        await client.call_tool("ping", {})
    assert not unused.exists()
    assert verify_log(state / "audit.jsonl").ok


@pytest.mark.anyio
async def test_init_then_serve_works_in_a_real_process(home: Path) -> None:
    assert init() == 0
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "repoward.cli", "serve", "--dir", str(home)],
    )
    async with Client(params) as client:
        result = await client.call_tool("ping", {})
    block = result.content[0]
    assert isinstance(block, TextContent)
    assert block.text == "pong"
    assert verify_log(home / "audit.jsonl").ok
