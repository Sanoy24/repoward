"""MCP server wiring.

This uses the SDK's low-level ``Server`` on purpose. Its single ``on_call_tool`` handler also
receives unknown tools and invalid arguments, so every attempt reaches the pipeline and is
audited. ``MCPServer`` would reject bad arguments before any code here ran.
"""

import os
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import uvicorn
from mcp.server import Server, ServerRequestContext
from mcp.server.auth.settings import AuthSettings
from mcp.server.stdio import stdio_server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)
from pydantic import AnyHttpUrl
from starlette.applications import Starlette

from repoward.adapters.github import GitHubClient
from repoward.adapters.github_auth import AppTokens, load_private_key
from repoward.approvals.store import ApprovalStore
from repoward.audit import AuditLog
from repoward.flow import FlowGuard, FlowStore
from repoward.http_auth import JwtVerifier, principal_from_request
from repoward.pipeline import Pipeline, alert
from repoward.policy.loader import CompiledPolicy, is_loopback
from repoward.principal import Principal, local_principal
from repoward.receipts import ReceiptLedger
from repoward.registry import ToolRegistry
from repoward.tools import ci_read, github_dangerous, github_read, github_write, system

_LOOPBACK_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
_LOOPBACK_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
_SESSION_ID_CHARS = 128
PrincipalSource = Principal | Callable[[ServerRequestContext[Any, Any]], Principal]


class HttpConfigError(Exception):
    """HTTP mode cannot start safely with these settings."""


def build_registry(policy: CompiledPolicy, github: GitHubClient) -> ToolRegistry:
    registry = ToolRegistry()
    system.register(registry)
    github_read.register(registry, github, policy)
    ci_read.register(registry, github)
    github_write.register(registry, github)
    github_dangerous.register(registry, github, policy.policy.approvals.github_review)
    return registry


def build_github_client(policy: CompiledPolicy) -> GitHubClient:
    """Choose credentials from the policy. Raises AppConfigError if they cannot be used."""
    auth = policy.policy.github_auth
    if auth.mode == "app":
        assert auth.client_id is not None  # noqa: S101
        assert auth.installation_id is not None  # noqa: S101
        return GitHubClient(AppTokens(auth.client_id, auth.installation_id, load_private_key()))
    return GitHubClient(os.environ.get("GITHUB_TOKEN"))


def _session_label(ctx: ServerRequestContext[Any, Any]) -> str | None:
    """A legacy session's id, for the audit log only. Sessions are never authentication."""
    headers = getattr(ctx.request, "headers", None)
    session = headers.get("mcp-session-id") if headers is not None else None
    return session[:_SESSION_ID_CHARS] if isinstance(session, str) else None


def create_server(registry: ToolRegistry, pipeline: Pipeline, principal: PrincipalSource) -> Server:
    """Build the MCP server around one pipeline."""

    async def list_tools(
        ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(tools=registry.list_tools())

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        try:
            caller = principal if isinstance(principal, Principal) else principal(ctx)
            return await pipeline.call(
                caller, params.name, params.arguments, session_id=_session_label(ctx)
            )
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


def _build_pipeline(
    policy: CompiledPolicy,
    github: GitHubClient,
    registry: ToolRegistry,
    audit_path: Path,
    approvals_path: Path,
    flow_path: Path,
    hmac_key: bytes | None,
) -> Pipeline:
    approval_rules = policy.policy.approvals
    approvals = ApprovalStore(
        approvals_path,
        approval_rules.ttl_minutes * 60.0,
        approval_rules.max_pending_per_principal,
    )
    rules = policy.policy.flow_guard
    flow = FlowGuard(rules, FlowStore(flow_path), github.repo_is_private) if rules.enabled else None
    receipts = (
        ReceiptLedger(github.post_commit_status, policy.sha256)
        if policy.policy.receipts.enabled
        else None
    )
    rotate_mb = policy.policy.audit.rotate_mb
    return Pipeline(
        policy,
        registry,
        AuditLog(audit_path, hmac_key, None if rotate_mb is None else rotate_mb * 1_000_000),
        approvals=approvals,
        flow=flow,
        receipts=receipts,
    )


def run_stdio(
    policy: CompiledPolicy,
    audit_path: Path,
    approvals_path: Path,
    flow_path: Path,
    hmac_key: bytes | None,
) -> None:
    """Serve over stdio until the client closes the connection."""
    github = build_github_client(policy)
    registry = build_registry(policy, github)
    pipeline = _build_pipeline(
        policy, github, registry, audit_path, approvals_path, flow_path, hmac_key
    )
    server = create_server(registry, pipeline, local_principal(policy.policy.stdio.role))

    async def serve() -> None:
        try:
            async with stdio_server() as (read_stream, write_stream):
                await server.run(read_stream, write_stream, server.create_initialization_options())
        finally:
            await github.aclose()

    anyio.run(serve)


def _transport_security(policy: CompiledPolicy, host: str) -> TransportSecuritySettings:
    """Set rebinding protection explicitly. The SDK turns it off for a non-loopback bind."""
    auth = policy.policy.http_auth
    assert auth is not None  # noqa: S101
    loopback = is_loopback(host)
    if not auth.allowed_hosts and not loopback:
        raise HttpConfigError(
            f"binding to {host} needs http_auth.allowed_hosts, which protects against DNS rebinding"
        )
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(auth.allowed_hosts) or _LOOPBACK_HOSTS,
        allowed_origins=list(auth.allowed_origins) or (_LOOPBACK_ORIGINS if loopback else []),
    )


def build_http_app(
    policy: CompiledPolicy,
    registry: ToolRegistry,
    pipeline: Pipeline,
    host: str,
    verifier: JwtVerifier | None = None,
) -> Starlette:
    """The ASGI app for HTTP mode. Raises HttpConfigError if it would not be safe to serve."""
    auth = policy.policy.http_auth
    identity = policy.policy.identity_map
    if auth is None or identity is None:
        raise HttpConfigError("HTTP mode needs http_auth and identity_map in the policy")
    security = _transport_security(policy, host)
    server = create_server(
        registry, pipeline, lambda ctx: principal_from_request(ctx.request, policy)
    )
    return server.streamable_http_app(
        streamable_http_path=urlsplit(auth.resource_server_url).path or "/mcp",
        transport_security=security,
        host=host,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(auth.issuer),
            resource_server_url=AnyHttpUrl(auth.resource_server_url),
            # The verifier checks the audience itself, as identity providers name them differently.
            validate_token_resource=False,
        ),
        token_verifier=verifier or JwtVerifier(auth, identity.claim),
    )


def run_http(
    policy: CompiledPolicy,
    audit_path: Path,
    approvals_path: Path,
    flow_path: Path,
    hmac_key: bytes | None,
    host: str,
    port: int,
) -> None:
    """Serve over HTTP with one worker, because rate limits and legacy sessions live in memory."""
    github = build_github_client(policy)
    registry = build_registry(policy, github)
    pipeline = _build_pipeline(
        policy, github, registry, audit_path, approvals_path, flow_path, hmac_key
    )
    app = build_http_app(policy, registry, pipeline, host)
    config = uvicorn.Config(
        app, host=host, port=port, log_level="warning", server_header=False, access_log=False
    )

    async def serve() -> None:
        try:
            await uvicorn.Server(config).serve()
        finally:
            await github.aclose()

    anyio.run(serve)
