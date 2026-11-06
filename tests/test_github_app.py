"""GitHub App tokens: issued per call, limited to what each tool needs, and checked."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.types import CallToolResult, TextContent

from repoward.adapters.github import GitHubClient
from repoward.adapters.github_auth import (
    KEY_ENV,
    KEY_FILE_ENV,
    AppConfigError,
    AppTokens,
    load_private_key,
)
from repoward.audit import AuditLog
from repoward.catalog import TOOL_CATALOG, TOOL_PERMISSIONS
from repoward.cli import main
from repoward.pipeline import Pipeline
from repoward.policy.loader import PolicyError, parse_policy
from repoward.principal import Principal
from repoward.server import build_github_client, build_registry

pytestmark = pytest.mark.anyio

API = "https://api.github.com"
REPO = "org/sandbox"
MINT = f"{API}/app/installations/99/access_tokens"
AGENT = Principal("agent", "writer")
FAR_FUTURE = "2099-01-01T00:00:00Z"

POLICY = """\
version: 1
default: deny
github_auth:
  mode: app
  client_id: Iv1.abc
  installation_id: 99
repos:
  allow: ["org/sandbox", "org/other"]
flow_guard:
  enabled: false
roles:
  writer:
    tools: [github_list_issues, github_get_file, github_comment, ci_get_status]
rate_limits:
  default: { per_minute: 1000 }
stdio:
  role: writer
"""

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
PUBLIC_PEM = (
    _KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


class Clock:
    now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def github() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def mint_response(
    token: str = "installation-token",  # noqa: S107
    repo: str = REPO,
    permissions: dict[str, str] | None = None,
    expires_at: str = FAR_FUTURE,
) -> dict[str, Any]:
    return {
        "token": token,
        "expires_at": expires_at,
        "permissions": {"metadata": "read", **(permissions or {})},
        "repositories": [{"full_name": repo}],
    }


def mirror_mint(request: Any) -> Any:
    """Answer like GitHub, issuing exactly what was requested."""
    import httpx

    body = json.loads(request.content)
    return httpx.Response(
        201,
        json=mint_response(
            token="token-" + "-".join(f"{k}.{v}" for k, v in sorted(body["permissions"].items())),
            repo=f"org/{body['repositories'][0]}",
            permissions=body["permissions"],
        ),
    )


def pipeline_for(tmp_path: Path) -> tuple[Pipeline, GitHubClient]:
    policy = parse_policy(POLICY.encode())
    client = GitHubClient(AppTokens("Iv1.abc", 99, PRIVATE_PEM))
    return (
        Pipeline(policy, build_registry(policy, client), AuditLog(tmp_path / "a.jsonl")),
        client,
    )


def text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


# The app's signed identity


async def test_the_app_jwt_is_valid_and_short_lived(
    tmp_path: Path, github: respx.MockRouter
) -> None:
    route = github.post(MINT).mock(side_effect=mirror_mint)
    github.get(f"{API}/repos/{REPO}/issues").respond(json=[])
    pipeline, client = pipeline_for(tmp_path)
    await pipeline.call(AGENT, "github_list_issues", {"repo": REPO})
    await client.aclose()
    bearer = route.calls.last.request.headers["authorization"].removeprefix("Bearer ")
    claims = jwt.decode(bearer, PUBLIC_PEM, algorithms=["RS256"])
    assert claims["iss"] == "Iv1.abc"
    assert claims["exp"] - claims["iat"] <= 600
    assert jwt.get_unverified_header(bearer)["alg"] == "RS256"


# Each tool gets its own narrow token


async def test_each_tool_uses_a_token_limited_to_its_needs(
    tmp_path: Path, github: respx.MockRouter
) -> None:
    mint = github.post(MINT).mock(side_effect=mirror_mint)
    issues = github.get(f"{API}/repos/{REPO}/issues").respond(json=[])
    comment = github.post(f"{API}/repos/{REPO}/issues/1/comments").respond(201, json={"id": 1})
    pipeline, client = pipeline_for(tmp_path)

    await pipeline.call(AGENT, "github_list_issues", {"repo": REPO})
    await pipeline.call(AGENT, "github_comment", {"repo": REPO, "number": 1, "body": "x"})
    await client.aclose()

    bodies = [json.loads(call.request.content) for call in mint.calls]
    assert bodies[0] == {
        "repositories": ["sandbox"],
        "permissions": {"issues": "read", "pull_requests": "read"},
    }
    assert bodies[1]["permissions"] == {"issues": "write", "pull_requests": "write"}
    assert "write" not in issues.calls.last.request.headers["authorization"]
    assert "issues.write" in comment.calls.last.request.headers["authorization"]


async def test_each_repo_gets_its_own_token(tmp_path: Path, github: respx.MockRouter) -> None:
    mint = github.post(MINT).mock(side_effect=mirror_mint)
    github.get(f"{API}/repos/org/sandbox/issues").respond(json=[])
    github.get(f"{API}/repos/org/other/issues").respond(json=[])
    pipeline, client = pipeline_for(tmp_path)
    await pipeline.call(AGENT, "github_list_issues", {"repo": "org/sandbox"})
    await pipeline.call(AGENT, "github_list_issues", {"repo": "org/other"})
    await client.aclose()
    assert [json.loads(c.request.content)["repositories"] for c in mint.calls] == [
        ["sandbox"],
        ["other"],
    ]


async def test_read_tools_never_ask_for_write(tmp_path: Path) -> None:
    for tool, risk in TOOL_CATALOG.items():
        if risk.value == "read":
            assert "write" not in TOOL_PERMISSIONS[tool].values(), tool


def test_every_tool_declares_its_permissions() -> None:
    assert set(TOOL_PERMISSIONS) == set(TOOL_CATALOG)


# Caching


class Scope:
    repo = REPO
    permissions: ClassVar[dict[str, str]] = {"issues": "read"}


async def test_tokens_are_cached_then_refreshed(github: respx.MockRouter) -> None:
    import httpx

    clock = Clock()
    mint = github.post(MINT).respond(201, json=mint_response(permissions={"issues": "read"}))
    tokens = AppTokens("Iv1.abc", 99, PRIVATE_PEM, clock)
    async with httpx.AsyncClient(base_url=API) as http:
        scope: Any = Scope()
        await tokens.token(scope, http)
        clock.now += 599
        await tokens.token(scope, http)
        assert mint.call_count == 1
        clock.now += 2
        await tokens.token(scope, http)
        assert mint.call_count == 2


async def test_a_token_is_not_reused_near_its_expiry(github: respx.MockRouter) -> None:
    import httpx

    clock = Clock()
    clock.now = 1_700_000_000.0
    soon = "2023-11-14T22:13:50Z"  # 30 seconds after the clock
    mint = github.post(MINT).respond(
        201, json=mint_response(permissions={"issues": "read"}, expires_at=soon)
    )
    tokens = AppTokens("Iv1.abc", 99, PRIVATE_PEM, clock)
    async with httpx.AsyncClient(base_url=API) as http:
        scope: Any = Scope()
        await tokens.token(scope, http)
        await tokens.token(scope, http)
    assert mint.call_count == 2


# Failing closed


@pytest.mark.parametrize(
    ("document", "why"),
    [
        (mint_response(repo="evil/sandbox"), "another owner's repository"),
        (
            {**mint_response(), "repositories": [{"full_name": REPO}, {"full_name": "org/x"}]},
            "more repositories",
        ),
        ({**mint_response(), "repositories": []}, "no repositories"),
        (mint_response(permissions={"issues": "write", "pull_requests": "read"}), "higher level"),
        (
            mint_response(
                permissions={"issues": "read", "pull_requests": "read", "actions": "read"}
            ),
            "extra permission",
        ),
        (
            mint_response(
                permissions={"issues": "read", "pull_requests": "read"}, expires_at="soon"
            ),
            "date",
        ),
        (
            {**mint_response(permissions={"issues": "read", "pull_requests": "read"}), "token": ""},
            "token",
        ),
        ({"permissions": {}}, "shape"),
    ],
)
async def test_a_token_wider_than_requested_is_refused(
    tmp_path: Path, github: respx.MockRouter, document: dict[str, Any], why: str
) -> None:
    github.post(MINT).respond(201, json=document)
    route = github.get(f"{API}/repos/{REPO}/issues").respond(json=[])
    pipeline, client = pipeline_for(tmp_path)
    result = await pipeline.call(AGENT, "github_list_issues", {"repo": REPO})
    await client.aclose()
    assert result.is_error, why
    assert "does not match" in text(result)
    assert not route.called


@pytest.mark.parametrize(
    ("status", "expected"),
    [(422, "does not have the access"), (401, "invalid or expired"), (404, "Not found")],
)
async def test_mint_failures_explain_themselves(
    tmp_path: Path, github: respx.MockRouter, status: int, expected: str
) -> None:
    github.post(MINT).respond(status, json={"message": "INTERNAL"})
    pipeline, client = pipeline_for(tmp_path)
    result = await pipeline.call(AGENT, "github_list_issues", {"repo": REPO})
    await client.aclose()
    assert expected in text(result)
    assert "INTERNAL" not in text(result)


async def test_a_call_with_no_scope_gets_no_token(github: respx.MockRouter) -> None:
    mint = github.post(MINT).mock(side_effect=mirror_mint)
    client = GitHubClient(AppTokens("Iv1.abc", 99, PRIVATE_PEM))
    with pytest.raises(Exception, match="no repository scope"):
        await client.get_json("/repos/org/sandbox/issues")
    await client.aclose()
    assert not mint.called


async def test_identity_is_the_apps_bot_login(github: respx.MockRouter) -> None:
    github.get(f"{API}/app").respond(json={"slug": "my-app", "id": 1})
    client = GitHubClient(AppTokens("Iv1.abc", 99, PRIVATE_PEM))
    assert await client.identity() == "my-app[bot]"
    assert await client.identity() == "my-app[bot]"
    assert len(github.calls) == 1
    await client.aclose()


async def test_pat_identity_is_the_token_owner(github: respx.MockRouter) -> None:
    github.get(f"{API}/user").respond(json={"login": "someone"})
    client = GitHubClient("fake-token")
    assert await client.identity() == "someone"
    await client.aclose()


# Secrets and configuration


async def test_the_private_key_and_tokens_stay_out_of_the_log(
    tmp_path: Path, github: respx.MockRouter, capsys: pytest.CaptureFixture[str]
) -> None:
    github.post(MINT).mock(side_effect=mirror_mint)
    github.get(f"{API}/repos/{REPO}/issues").respond(json=[])
    pipeline, client = pipeline_for(tmp_path)
    await pipeline.call(AGENT, "github_list_issues", {"repo": REPO})
    await client.aclose()
    raw = (tmp_path / "a.jsonl").read_text(encoding="utf-8")
    captured = capsys.readouterr()
    for output in (raw, captured.out, captured.err):
        assert "PRIVATE KEY" not in output
        assert "token-issues" not in output


def test_a_bad_key_is_refused_at_startup_without_echoing_it() -> None:
    with pytest.raises(AppConfigError) as info:
        AppTokens("Iv1.abc", 99, "not-a-real-key-SECRET")
    assert "SECRET" not in str(info.value)
    assert info.value.__cause__ is None


def test_key_can_come_from_a_file_or_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    monkeypatch.delenv(KEY_ENV, raising=False)
    with pytest.raises(AppConfigError, match=KEY_FILE_ENV):
        load_private_key()
    monkeypatch.setenv(KEY_ENV, "from-env")
    assert load_private_key() == "from-env"
    path = tmp_path / "key.pem"
    path.write_text("from-file", encoding="utf-8")
    monkeypatch.setenv(KEY_FILE_ENV, str(path))
    assert load_private_key() == "from-file"
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "missing.pem"))
    with pytest.raises(AppConfigError):
        load_private_key()


def test_the_client_is_chosen_by_the_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_ENV, PRIVATE_PEM)
    client = build_github_client(parse_policy(POLICY.encode()))
    assert isinstance(client._provider, AppTokens)


def test_serve_reports_a_missing_key_clearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    monkeypatch.delenv(KEY_ENV, raising=False)
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    assert main(["serve", "--dir", str(tmp_path)]) == 1
    assert KEY_FILE_ENV in capsys.readouterr().err


@pytest.mark.parametrize(
    "auth",
    [
        "github_auth:\n  mode: app\n",
        "github_auth:\n  mode: app\n  client_id: Iv1.abc\n",
        "github_auth:\n  mode: app\n  installation_id: 9\n",
        "github_auth:\n  mode: pat\n  client_id: Iv1.abc\n",
        "github_auth:\n  mode: other\n",
        "github_auth:\n  private_key: oops\n",
    ],
)
def test_invalid_auth_settings_are_refused(auth: str) -> None:
    base = POLICY.replace(
        "github_auth:\n  mode: app\n  client_id: Iv1.abc\n  installation_id: 99\n", ""
    )
    with pytest.raises(PolicyError):
        parse_policy((base + auth).encode())
