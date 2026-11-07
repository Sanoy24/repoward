"""HTTP mode through a real server on a real socket. In-memory clients skip HTTP and auth."""

import base64
import hashlib
import hmac
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import httpx2
import jwt
import pytest
import respx
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from repoward.adapters.github import GitHubClient
from repoward.adapters.jwks import JwksKeys
from repoward.audit import AuditLog, verify_log
from repoward.cli import main
from repoward.flow import FlowGuard, FlowStore
from repoward.http_auth import JwtVerifier
from repoward.pipeline import Pipeline
from repoward.policy.loader import CompiledPolicy, PolicyError, parse_policy
from repoward.policy.replay import replay_log
from repoward.ratelimit import RateLimiter
from repoward.server import HttpConfigError, build_http_app, build_registry

ISSUER = "https://idp.example.test/"
AUDIENCE = "https://mcp.example.test/mcp"
JWKS_URI = "https://idp.example.test/jwks.json"
KID = "key-1"
ALICE = f"{ISSUER}|alice"
RESOURCE_LINE = f'resource_server_url: "{AUDIENCE}"'.encode()
LEGACY = "legacy"
MODERN = "2026-07-28"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_PEM = RSA_KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)


def jwk(key: Any = RSA_KEY, kid: str = KID, **extra: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**document, "kid": kid, **extra}


def jwks_bytes(*keys: dict[str, Any]) -> bytes:
    return json.dumps({"keys": list(keys or [jwk()])}).encode()


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "exp": now + 600,
        "iat": now,
        "groups": ["mcp-readers"],
    }
    base.update(overrides)
    return {name: value for name, value in base.items() if value is not None}


def token(key: Any = RSA_KEY, alg: str = "RS256", kid: str | None = KID, **overrides: Any) -> str:
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims(**overrides), key, algorithm=alg, headers=headers)


def policy_text(
    mapping: str = '"mcp-readers": reader\n    "mcp-admins": admin\n    "mcp-also-readers": reader',
    http_auth: str = "",
    per_minute: int = 1000,
) -> bytes:
    return f"""\
version: 1
default: deny
http_auth:
  issuer: "{ISSUER}"
  audience: "{AUDIENCE}"
  jwks_uri: "{JWKS_URI}"
  algorithms: [RS256]
  resource_server_url: "{AUDIENCE}"
  {http_auth}
identity_map:
  claim: groups
  mapping:
    {mapping}
flow_guard:
  enabled: false
roles:
  nobody:
    tools: []
  reader:
    tools: [ping]
  admin:
    inherits: reader
rate_limits:
  default: {{ per_minute: {per_minute} }}
stdio:
  role: nobody
""".encode()


class Stack:
    """A running server, with signing keys supplied directly and nothing else mocked."""

    def __init__(
        self,
        tmp_path: Path,
        policy: CompiledPolicy | None = None,
        github: GitHubClient | None = None,
    ) -> None:
        self.policy = policy or parse_policy(policy_text())
        self.audit = tmp_path / "audit.jsonl"

        async def fetch() -> bytes:
            return jwks_bytes()

        github = github or GitHubClient(None)
        registry = build_registry(self.policy, github)
        rules = self.policy.policy.flow_guard
        pipeline = Pipeline(
            self.policy,
            registry,
            AuditLog(self.audit),
            RateLimiter(self.policy.rate_limits),
            flow=(
                FlowGuard(rules, FlowStore(tmp_path / "flow.db"), github.repo_is_private)
                if rules.enabled
                else None
            ),
        )
        auth = self.policy.policy.http_auth
        identity = self.policy.policy.identity_map
        assert auth is not None
        assert identity is not None
        verifier = JwtVerifier(auth, identity.claim, JwksKeys(JWKS_URI, fetch))
        app = build_http_app(self.policy, registry, pipeline, "127.0.0.1", verifier)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        self.server = uvicorn.Server(
            uvicorn.Config(app, log_level="critical", access_log=False, lifespan="on")
        )
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True
        )
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            assert time.monotonic() < deadline, "the server did not start"
            time.sleep(0.02)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        self.socket.close()

    def decisions(self) -> list[dict[str, Any]]:
        rows = [json.loads(line) for line in self.audit.read_bytes().splitlines()]
        return [row for row in rows if row["event"] == "tool_call_decision"]

    def post(self, *, bearer: str | None = None, **headers: str) -> httpx.Response:
        sent = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **{name.replace("_", "-"): value for name, value in headers.items()},
        }
        if bearer is not None:
            sent["Authorization"] = f"Bearer {bearer}"
        return httpx.post(self.url, headers=sent, json=INITIALIZE, timeout=15)


INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    built = Stack(tmp_path)
    yield built
    built.stop()


def text(result: Any) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def connect(stack: Stack, bearer: str, mode: str, http: httpx2.AsyncClient | None = None) -> Client:
    client = http or httpx2.AsyncClient(headers={"Authorization": f"Bearer {bearer}"})
    return Client(streamable_http_client(stack.url, http_client=client), mode=mode)


# Rejected tokens.

GOOD_RESPONSE = 200


def test_a_valid_token_is_accepted(stack: Stack) -> None:
    assert stack.post(bearer=token()).status_code == GOOD_RESPONSE


def test_no_token_gets_a_401_that_points_at_the_metadata(stack: Stack) -> None:
    response = stack.post()
    assert response.status_code == 401
    assert "resource_metadata" in response.headers["www-authenticate"]


def test_the_metadata_names_the_issuer(stack: Stack) -> None:
    response = httpx.get(
        f"http://127.0.0.1:{stack.port}/.well-known/oauth-protected-resource/mcp", timeout=15
    )
    assert response.status_code == 200
    assert response.json()["authorization_servers"] == [ISSUER]
    assert response.json()["resource"] == AUDIENCE


def unsigned_token() -> str:
    def encode(value: dict[str, Any]) -> str:
        raw = json.dumps(value).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{encode({'alg': 'none', 'kid': KID})}.{encode(claims())}."


def public_key_used_as_a_shared_secret() -> str:
    def encode(value: dict[str, Any]) -> str:
        raw = json.dumps(value).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    body = f"{encode({'alg': 'HS256', 'kid': KID})}.{encode(claims())}"
    signature = hmac.new(PUBLIC_PEM, body.encode(), hashlib.sha256).digest()
    return f"{body}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def token_naming_its_own_keys() -> str:
    """Signed by an attacker, with headers pointing at the attacker's keys."""
    return jwt.encode(
        claims(),
        OTHER_KEY,
        algorithm="RS256",
        headers={
            "kid": KID,
            "jku": "https://evil.example/jwks.json",
            "x5u": "https://evil.example/c",
        },
    )


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(lambda: token(exp=int(time.time()) - 3600), id="expired"),
        pytest.param(lambda: token(aud="https://other.example/mcp"), id="wrong-audience"),
        pytest.param(lambda: token(iss="https://evil.example/"), id="wrong-issuer"),
        pytest.param(lambda: token(key=OTHER_KEY), id="bad-signature"),
        pytest.param(lambda: token(exp=None), id="no-exp"),
        pytest.param(lambda: token(iss=None), id="no-iss"),
        pytest.param(lambda: token(aud=None), id="no-aud"),
        pytest.param(lambda: token(sub=None), id="no-sub"),
        pytest.param(lambda: token(sub=""), id="empty-sub"),
        pytest.param(lambda: token(nbf=int(time.time()) + 3600), id="not-yet-valid"),
        pytest.param(unsigned_token, id="alg-none"),
        pytest.param(public_key_used_as_a_shared_secret, id="hs256-with-the-public-key"),
        pytest.param(lambda: token(kid="unknown"), id="unknown-kid"),
        pytest.param(lambda: token(kid=None), id="no-kid"),
        pytest.param(token_naming_its_own_keys, id="jku-and-x5u-are-ignored"),
        pytest.param(lambda: token(padding="x" * 20_000), id="too-large"),
        pytest.param(lambda: "not-a-jwt", id="garbage"),
    ],
)
def test_bad_tokens_are_refused_before_the_pipeline(stack: Stack, bad: Any) -> None:
    assert stack.post(bearer=bad()).status_code == 401
    assert not stack.audit.exists()


def test_rejections_are_logged_without_the_token(
    stack: Stack, capfd: pytest.CaptureFixture[str]
) -> None:
    bad = token(key=OTHER_KEY)
    stack.post(bearer=bad)
    captured = capfd.readouterr()
    assert "auth_rejected" in captured.err
    assert bad not in captured.err
    assert bad not in captured.out


def test_a_token_within_the_leeway_is_accepted(stack: Stack) -> None:
    assert stack.post(bearer=token(exp=int(time.time()) - 5)).status_code == GOOD_RESPONSE


def test_an_audience_list_holding_this_server_is_accepted(stack: Stack) -> None:
    assert stack.post(bearer=token(aud=["other", AUDIENCE])).status_code == GOOD_RESPONSE


# Both protocol eras, end to end.


@pytest.mark.anyio
@pytest.mark.parametrize("mode", [LEGACY, MODERN])
async def test_a_client_can_call_a_tool(stack: Stack, mode: str) -> None:
    async with connect(stack, token(), mode) as client:
        tools = await client.list_tools()
        assert "ping" in [tool.name for tool in tools.tools]
        result = await client.call_tool("ping", {})
    assert not result.is_error, text(result)
    decision = stack.decisions()[-1]
    assert decision["principal"] == ALICE
    assert decision["role"] == "reader"
    assert decision["groups"] == ["mcp-readers"]
    assert decision["decision"] == "allow"
    assert verify_log(stack.audit).ok


@pytest.mark.anyio
async def test_a_legacy_session_id_is_recorded_as_a_label(stack: Stack) -> None:
    async with connect(stack, token(), LEGACY) as client:
        await client.call_tool("ping", {})
    assert stack.decisions()[-1]["session_id"]


@pytest.mark.anyio
async def test_the_modern_era_has_no_session(stack: Stack) -> None:
    async with connect(stack, token(), MODERN) as client:
        await client.call_tool("ping", {})
    assert stack.decisions()[-1]["session_id"] is None


@pytest.mark.anyio
@pytest.mark.parametrize("mode", [LEGACY, MODERN])
@pytest.mark.parametrize(
    ("groups", "rule"),
    [
        pytest.param(["unrelated"], "identity.no_role", id="unmapped-group"),
        pytest.param([], "identity.no_role", id="no-groups"),
        pytest.param(None, "identity.no_role", id="no-claim"),
        pytest.param(7, "identity.no_role", id="not-a-list"),
        pytest.param([1, "mcp-readers"], "identity.no_role", id="not-strings"),
        pytest.param(["mcp-readers", "mcp-admins"], "identity.ambiguous_role", id="two-roles"),
    ],
)
async def test_a_valid_token_without_one_role_is_refused(
    stack: Stack, mode: str, groups: Any, rule: str
) -> None:
    async with connect(stack, token(groups=groups), mode) as client:
        result = await client.call_tool("ping", {})
    assert result.is_error
    assert "exactly one role" in text(result)
    decision = stack.decisions()[-1]
    assert decision["decision"] == "deny"
    assert decision["rule_id"] == rule
    assert decision["role"] is None


@pytest.mark.anyio
async def test_two_groups_for_one_role_are_fine(stack: Stack) -> None:
    async with connect(stack, token(groups=["mcp-readers", "mcp-also-readers"]), LEGACY) as client:
        assert not (await client.call_tool("ping", {})).is_error


@pytest.mark.anyio
async def test_a_single_group_string_is_accepted(stack: Stack) -> None:
    async with connect(stack, token(groups="mcp-readers"), LEGACY) as client:
        assert not (await client.call_tool("ping", {})).is_error


@pytest.mark.anyio
async def test_roles_do_not_combine(stack: Stack) -> None:
    async with connect(stack, token(groups=["mcp-admins"]), LEGACY) as client:
        assert not (await client.call_tool("ping", {})).is_error
    assert stack.decisions()[-1]["role"] == "admin"


# Identity comes from the current request, not from whoever opened the session.


@pytest.mark.anyio
async def test_a_role_lost_during_a_legacy_session_applies_at_once(stack: Stack) -> None:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token()}"})
    async with connect(stack, "", LEGACY, http) as client:
        assert not (await client.call_tool("ping", {})).is_error
        http.headers["Authorization"] = f"Bearer {token(groups=['unrelated'])}"
        result = await client.call_tool("ping", {})
        assert result.is_error
        assert stack.decisions()[-1]["rule_id"] == "identity.no_role"
        http.headers["Authorization"] = f"Bearer {token()}"


@pytest.mark.anyio
async def test_a_role_gained_during_a_legacy_session_applies_at_once(stack: Stack) -> None:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token(groups=['unrelated'])}"})
    async with connect(stack, "", LEGACY, http) as client:
        assert (await client.call_tool("ping", {})).is_error
        http.headers["Authorization"] = f"Bearer {token()}"
        assert not (await client.call_tool("ping", {})).is_error


def open_session(stack: Stack, bearer: str) -> str:
    response = stack.post(bearer=bearer)
    assert response.status_code == 200
    return response.headers["mcp-session-id"]


def test_another_user_cannot_use_a_session(stack: Stack) -> None:
    session = open_session(stack, token())
    other = stack.post(bearer=token(sub="mallory"), mcp_session_id=session)
    assert other.status_code == 404


def test_a_session_id_is_not_a_login(stack: Stack) -> None:
    session = open_session(stack, token())
    assert stack.post(mcp_session_id=session).status_code == 401


def test_an_expired_token_cannot_continue_a_session(stack: Stack) -> None:
    session = open_session(stack, token())
    expired = token(exp=int(time.time()) - 3600)
    assert stack.post(bearer=expired, mcp_session_id=session).status_code == 401


@pytest.mark.anyio
async def test_rate_limits_are_per_user(tmp_path: Path) -> None:
    built = Stack(tmp_path, parse_policy(policy_text(per_minute=1)))
    try:
        async with connect(built, token(), LEGACY) as client:
            assert not (await client.call_tool("ping", {})).is_error
            assert (await client.call_tool("ping", {})).is_error
        assert built.decisions()[-1]["rule_id"] == "rate_limits.default"
        async with connect(built, token(sub="bob"), LEGACY) as client:
            assert not (await client.call_tool("ping", {})).is_error
    finally:
        built.stop()


@pytest.mark.anyio
async def test_the_token_never_reaches_the_audit_log(stack: Stack) -> None:
    bearer = token()
    async with connect(stack, bearer, LEGACY) as client:
        await client.call_tool("ping", {})
    assert bearer.encode() not in stack.audit.read_bytes()


# Host and Origin checks.


def test_a_bad_host_is_refused(stack: Stack) -> None:
    assert stack.post(bearer=token(), Host="evil.example").status_code == 421


def test_a_bad_origin_is_refused(stack: Stack) -> None:
    assert stack.post(bearer=token(), Origin="https://evil.example").status_code == 403


def test_a_loopback_origin_is_allowed(stack: Stack) -> None:
    assert stack.post(bearer=token(), Origin="http://localhost:3000").status_code == GOOD_RESPONSE


def test_configured_hosts_replace_the_loopback_defaults(tmp_path: Path) -> None:
    settings = (
        'allowed_hosts: ["mcp.example.test"]\n  allowed_origins: ["https://app.example.test"]'
    )
    built = Stack(tmp_path, parse_policy(policy_text(http_auth=settings)))
    try:
        assert built.post(bearer=token()).status_code == 421
        good = {"Host": "mcp.example.test"}
        assert built.post(bearer=token(), **good).status_code == GOOD_RESPONSE
        allowed = built.post(bearer=token(), Origin="https://app.example.test", **good)
        assert allowed.status_code == GOOD_RESPONSE
        refused = built.post(bearer=token(), Origin="http://localhost:3000", **good)
        assert refused.status_code == 403
    finally:
        built.stop()


# Refusing to start.


def app_for(policy: CompiledPolicy, host: str) -> Any:
    github = GitHubClient(None)
    registry = build_registry(policy, github)
    pipeline = Pipeline(policy, registry, AuditLog(Path("unused.jsonl")))
    return build_http_app(policy, registry, pipeline, host)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "::", "mcp.example.test"])  # noqa: S104
def test_a_public_bind_needs_allowed_hosts(host: str) -> None:
    with pytest.raises(HttpConfigError, match="allowed_hosts"):
        app_for(parse_policy(policy_text()), host)


def test_a_public_bind_with_allowed_hosts_starts() -> None:
    settings = 'allowed_hosts: ["mcp.example.test"]'
    assert app_for(parse_policy(policy_text(http_auth=settings)), "0.0.0.0")  # noqa: S104


NO_AUTH_POLICY = b"""\
version: 1
default: deny
roles:
  reader:
    tools: [ping]
rate_limits:
  default: { per_minute: 10 }
stdio:
  role: reader
"""


def test_http_mode_refuses_to_run_without_auth() -> None:
    with pytest.raises(HttpConfigError, match="http_auth"):
        app_for(parse_policy(NO_AUTH_POLICY), "127.0.0.1")


def test_the_command_refuses_to_run_without_auth(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "policy.yaml").write_bytes(NO_AUTH_POLICY)
    assert main(["serve", "--http", "--dir", str(tmp_path)]) == 1
    assert "http_auth" in capsys.readouterr().err


def test_the_command_refuses_a_public_bind_without_allowed_hosts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "policy.yaml").write_bytes(policy_text())
    assert main(["serve", "--http", "--host", "0.0.0.0", "--dir", str(tmp_path)]) == 1  # noqa: S104
    assert "allowed_hosts" in capsys.readouterr().err


# Policy validation.


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        pytest.param(b"algorithms: [RS256]", b"algorithms: [HS256]", "", id="symmetric-algorithm"),
        pytest.param(b"algorithms: [RS256]", b"algorithms: [none]", "", id="no-algorithm"),
        pytest.param(b"algorithms: [RS256]", b"algorithms: []", "", id="empty-algorithms"),
        pytest.param(
            f'jwks_uri: "{JWKS_URI}"'.encode(),
            b'jwks_uri: "http://idp.example.test/jwks.json"',
            "https",
            id="plain-http-keys",
        ),
        pytest.param(
            f'resource_server_url: "{AUDIENCE}"'.encode(),
            b'resource_server_url: "http://mcp.example.test/mcp"',
            "https",
            id="plain-http-resource",
        ),
        pytest.param(b'"mcp-readers": reader', b'"mcp-readers": ghost', "ghost", id="unknown-role"),
        pytest.param(b"algorithms: [RS256]", b"algorithms: [RS256]\n  secret: x", "", id="extra"),
        pytest.param(b"claim: groups", b"claim: 7", "", id="claim-not-text"),
    ],
)
def test_bad_http_settings_are_refused(old: bytes, new: bytes, message: str) -> None:
    text_policy = policy_text()
    assert old in text_policy
    with pytest.raises(PolicyError) as caught:
        parse_policy(text_policy.replace(old, new))
    assert message in str([issue.message for issue in caught.value.issues])


def test_plain_http_on_this_machine_is_allowed_for_development() -> None:
    changed = policy_text().replace(
        f'jwks_uri: "{JWKS_URI}"'.encode(), b'jwks_uri: "http://127.0.0.1:9000/jwks.json"'
    )
    assert parse_policy(changed).policy.http_auth is not None


@pytest.mark.parametrize("section", [b"http_auth:", b"identity_map:"])
def test_auth_and_the_identity_map_go_together(section: bytes) -> None:
    lines = policy_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(section))
    end = next(i for i in range(start + 1, len(lines)) if not lines[i].startswith(b" "))
    with pytest.raises(PolicyError) as caught:
        parse_policy(b"".join(lines[:start] + lines[end:]))
    assert "set together" in str([issue.message for issue in caught.value.issues])


# Fetching keys.


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Keys:
    def __init__(self, *documents: dict[str, Any]) -> None:
        self.clock = Clock()
        self.fetches = 0
        self.body = jwks_bytes(*documents)
        self.fail = False
        self.keys = JwksKeys(JWKS_URI, self._fetch, self.clock)

    async def _fetch(self) -> bytes:
        self.fetches += 1
        if self.fail:
            raise OSError("down")
        return self.body


@pytest.mark.anyio
async def test_keys_are_cached() -> None:
    keys = Keys()
    assert await keys.keys.get(KID) is not None
    assert await keys.keys.get(KID) is not None
    assert keys.fetches == 1


@pytest.mark.anyio
async def test_a_flood_of_unknown_key_ids_causes_one_fetch() -> None:
    keys = Keys()
    for number in range(500):
        assert await keys.keys.get(f"unknown-{number}") is None
    assert keys.fetches == 1


@pytest.mark.anyio
async def test_a_rotated_key_is_found_after_the_throttle() -> None:
    keys = Keys()
    assert await keys.keys.get(KID) is not None
    keys.body = jwks_bytes(jwk(kid="key-2"))
    assert await keys.keys.get("key-2") is None
    keys.clock.now += 31
    assert await keys.keys.get("key-2") is not None
    assert await keys.keys.get(KID) is None


@pytest.mark.anyio
async def test_keys_survive_a_short_outage_but_not_a_long_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    keys = Keys()
    assert await keys.keys.get(KID) is not None
    keys.fail = True
    keys.clock.now += 3700
    assert await keys.keys.get(KID) is not None
    assert "could not refresh" in capsys.readouterr().err
    keys.clock.now += 90_000
    assert await keys.keys.get(KID) is None


@pytest.mark.anyio
async def test_no_keys_at_all_means_nothing_verifies() -> None:
    keys = Keys()
    keys.fail = True
    assert await keys.keys.get(KID) is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "document",
    [
        pytest.param({"kid": KID, "kty": "oct", "k": "c2VjcmV0"}, id="symmetric"),
        pytest.param(jwk(use="enc"), id="encryption-key"),
        pytest.param({"kid": KID, "kty": "RSA", "n": "!", "e": "!"}, id="malformed"),
        pytest.param({k: v for k, v in jwk().items() if k != "kid"}, id="no-kid"),
    ],
)
async def test_unusable_keys_are_skipped(document: dict[str, Any]) -> None:
    keys = Keys(document, jwk(kid="good"))
    assert await keys.keys.get(KID) is None
    assert await keys.keys.get("good") is not None


@pytest.mark.anyio
async def test_a_key_for_another_algorithm_is_refused() -> None:
    keys = Keys(jwk(alg="RS512"))
    rules = parse_policy(policy_text()).policy.http_auth
    assert rules is not None
    verifier = JwtVerifier(rules, "groups", keys.keys)
    assert await verifier.verify_token(token()) is None


@pytest.mark.anyio
async def test_a_junk_algorithm_fetches_nothing() -> None:
    keys = Keys()
    rules = parse_policy(policy_text()).policy.http_auth
    assert rules is not None
    verifier = JwtVerifier(rules, "groups", keys.keys)
    assert await verifier.verify_token(unsigned_token()) is None
    assert keys.fetches == 0


@pytest.mark.anyio
async def test_an_ec_key_verifies() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    document = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    keys = Keys({**document, "kid": KID})
    changed = policy_text().replace(b"algorithms: [RS256]", b"algorithms: [ES256]")
    rules = parse_policy(changed).policy.http_auth
    assert rules is not None
    verifier = JwtVerifier(rules, "groups", keys.keys)
    assert await verifier.verify_token(token(key, "ES256")) is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("response", "found"),
    [
        pytest.param(httpx.Response(200, content=jwks_bytes()), True, id="ok"),
        pytest.param(httpx.Response(500), False, id="server-error"),
        pytest.param(
            httpx.Response(302, headers={"location": "https://evil.example/jwks"}),
            False,
            id="redirect-not-followed",
        ),
        pytest.param(httpx.Response(200, content=b"not json"), False, id="not-json"),
        pytest.param(httpx.Response(200, content=b"[]"), False, id="wrong-shape"),
        pytest.param(httpx.Response(200, content=b'{"keys": 1}'), False, id="keys-not-a-list"),
        pytest.param(httpx.Response(200, content=b"x" * 1_100_000), False, id="too-large"),
    ],
)
async def test_fetching_keys_over_the_network(response: httpx.Response, found: bool) -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.get(JWKS_URI).mock(return_value=response)
        evil = router.get("https://evil.example/jwks").respond(200, content=jwks_bytes())
        result = await JwksKeys(JWKS_URI).get(KID)
    assert (result is not None) is found
    assert route.called
    assert not evil.called


# Policy replay on HTTP records.


def http_log(path: Path, groups: list[str] | None, rule: str = "roles.reader.tools") -> Path:
    log = AuditLog(path)
    log.append(
        {
            "event": "tool_call_decision",
            "request_id": "r1",
            "instance_id": "i1",
            "session_id": None,
            "principal": ALICE,
            "role": "reader",
            "tool": "ping",
            "policy_hash": "c" * 64,
            "flow_trusted": None,
            "args_redacted": {},
            "args_hash": "d" * 64,
            "decision": "allow",
            "rule_id": rule,
            **({} if groups is None else {"groups": groups}),
        }
    )
    return path


def test_replay_applies_an_edited_identity_map(tmp_path: Path) -> None:
    path = http_log(tmp_path / "audit.jsonl", ["mcp-readers"])
    assert replay_log(path, parse_policy(policy_text())).unchanged == 1
    edited = parse_policy(policy_text(mapping='"mcp-admins": admin'))
    report = replay_log(path, edited)
    assert report.changed[0].reason == "identity.no_role"
    assert report.changed[0].replayed == "deny"


def test_replay_finds_a_newly_ambiguous_caller(tmp_path: Path) -> None:
    path = http_log(tmp_path / "audit.jsonl", ["mcp-readers", "mcp-admins"])
    assert replay_log(path, parse_policy(policy_text())).changed[0].reason == (
        "identity.ambiguous_role"
    )


def test_replay_keeps_the_recorded_role_when_no_groups_were_logged(tmp_path: Path) -> None:
    path = http_log(tmp_path / "audit.jsonl", None)
    assert replay_log(path, parse_policy(policy_text())).unchanged == 1


def test_replay_says_unknown_for_redacted_groups(tmp_path: Path) -> None:
    path = http_log(tmp_path / "audit.jsonl", ["[REDACTED]"])
    assert replay_log(path, parse_policy(policy_text())).unknown


@pytest.mark.anyio
async def test_replaying_a_real_http_run_with_its_own_policy_changes_nothing(stack: Stack) -> None:
    async with connect(stack, token(), LEGACY) as client:
        await client.call_tool("ping", {})
    async with connect(stack, token(groups=["unrelated"]), MODERN) as client:
        await client.call_tool("ping", {})
    async with connect(stack, token(groups=["mcp-readers", "mcp-admins"]), MODERN) as client:
        await client.call_tool("ping", {})
    report = replay_log(stack.audit, stack.policy)
    assert report.decisions == 3
    assert not report.changed, report.changed
    assert not report.unknown, report.unknown


# Several users on one server.

PUBLIC_REPO = "org/public"
PRIVATE_REPO = "org/private"


def team_policy() -> CompiledPolicy:
    return parse_policy(
        policy_text()
        .replace(b"flow_guard:\n  enabled: false\n", b"")
        .replace(
            b"  reader:\n    tools: [ping]\n",
            b"  reader:\n    tools: [ping, github_list_issues, github_comment]\n",
        )
        + f'repos:\n  allow: ["{PUBLIC_REPO}", "{PRIVATE_REPO}"]\n'.encode()
    )


@pytest.mark.anyio
@pytest.mark.parametrize("mode", [LEGACY, MODERN])
async def test_one_users_flow_labels_do_not_touch_another(tmp_path: Path, mode: str) -> None:
    api = "https://api.github.com/repos"
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as router:
        router.route(host="127.0.0.1").pass_through()
        router.get(f"{api}/{PUBLIC_REPO}").respond(json={"private": False})
        router.get(f"{api}/{PRIVATE_REPO}").respond(json={"private": True})
        router.get(f"{api}/{PRIVATE_REPO}/issues").respond(json=[])
        posted = router.post(f"{api}/{PUBLIC_REPO}/issues/1/comments").respond(201, json={"id": 5})
        built = Stack(tmp_path, team_policy(), GitHubClient("fake-token"))
        comment = {"repo": PUBLIC_REPO, "number": 1, "body": "hello"}
        try:
            async with connect(built, token(), mode) as alice:
                read = await alice.call_tool("github_list_issues", {"repo": PRIVATE_REPO})
                assert not read.is_error, text(read)
                refused = await alice.call_tool("github_comment", comment)
                assert refused.is_error
                assert built.decisions()[-1]["rule_id"] == "flow.private_to_public"
                assert not posted.called
            async with connect(built, token(sub="bob"), mode) as bob:
                allowed = await bob.call_tool("github_comment", comment)
                assert not allowed.is_error, text(allowed)
                assert posted.call_count == 1
            # The same person on a new connection is still restricted.
            async with connect(built, token(), mode) as alice_again:
                assert (await alice_again.call_tool("github_comment", comment)).is_error
                assert posted.call_count == 1
        finally:
            built.stop()
    assert verify_log(built.audit).ok


# The real command, with keys fetched over a real connection.


class _JwksHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = jwks_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: Any) -> None:
        pass


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@pytest.mark.anyio
@pytest.mark.parametrize("mode", [LEGACY, MODERN])
async def test_the_serve_command_works_end_to_end(tmp_path: Path, mode: str) -> None:
    keys = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _JwksHandler)
    threading.Thread(target=keys.serve_forever, daemon=True).start()
    port = free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    (tmp_path / "policy.yaml").write_bytes(
        policy_text()
        .replace(JWKS_URI.encode(), f"http://127.0.0.1:{keys.server_address[1]}/jwks".encode())
        .replace(RESOURCE_LINE, f'resource_server_url: "{url}"'.encode())
    )
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "repoward.cli",
            "serve",
            "--http",
            "--port",
            str(port),
            "--dir",
            str(tmp_path),
        ],
        env={**os.environ, "GITHUB_TOKEN": ""},
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            assert process.poll() is None, "the server exited"
            assert time.monotonic() < deadline, "the server did not start"
            try:
                assert httpx.post(url, timeout=2).status_code == 401
                break
            except httpx.TransportError:
                time.sleep(0.1)
        login = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token()}"})
        async with Client(streamable_http_client(url, http_client=login), mode=mode) as client:
            result = await client.call_tool("ping", {})
        assert not result.is_error, text(result)
    finally:
        process.terminate()
        process.wait(timeout=15)
        keys.shutdown()
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_bytes().splitlines()]
    decisions = [row for row in records if row["event"] == "tool_call_decision"]
    assert decisions[-1]["principal"] == ALICE
    assert verify_log(tmp_path / "audit.jsonl").ok
