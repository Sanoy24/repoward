"""The single guarded call path. Every tool attempt goes through `Pipeline.call`."""

import json
import sys
import time
import uuid
from typing import Any

import anyio.to_thread
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from repoward.audit import AuditLog, AuditWriteError
from repoward.canonical import canonical_json, sha256_hex
from repoward.catalog import RiskClass
from repoward.policy.engine import Effect, decide
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal
from repoward.ratelimit import RateLimiter
from repoward.registry import ToolError, ToolRegistry
from repoward.sanitize import redact_for_audit, redact_text, render_output

MAX_OUTPUT_CHARS = 100_000
_MAX_VALIDATION_ERRORS = 5


def _result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)


def _hash_args(args: Any) -> str:
    try:
        return sha256_hex(canonical_json(args))
    except (TypeError, ValueError):
        return sha256_hex(repr(args).encode("utf-8", "replace"))


def alert(message: str) -> None:
    """Report an operational problem on stderr. In stdio mode, stdout is the protocol."""
    print(f"repoward: {message}", file=sys.stderr, flush=True)


def _describe_invalid_input(exc: ValidationError) -> str:
    """Say what to fix without echoing the input back."""
    details = [
        f"{'.'.join(str(part) for part in error['loc']) or 'arguments'}: {error['msg']}"
        for error in exc.errors(include_url=False, include_input=False, include_context=False)
    ]
    return "Invalid arguments. " + "; ".join(details[:_MAX_VALIDATION_ERRORS])


class Pipeline:
    def __init__(
        self,
        policy: CompiledPolicy,
        registry: ToolRegistry,
        audit: AuditLog,
        limiter: RateLimiter | None = None,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._audit = audit
        self._limiter = limiter or RateLimiter(policy.rate_limits)
        self._instance_id = str(uuid.uuid4())
        self._degraded = False

    async def call(
        self,
        principal: Principal,
        tool: str,
        raw_args: dict[str, Any] | None,
        session_id: str | None = None,
    ) -> CallToolResult:
        request_id = str(uuid.uuid4())
        args: Any = raw_args if raw_args is not None else {}
        context: dict[str, Any] = {
            "request_id": request_id,
            "instance_id": self._instance_id,
            "session_id": session_id,
            "principal": principal.id,
            "role": principal.role,
            "tool": redact_for_audit(tool),
            "policy_hash": self._policy.sha256,
        }

        spec = self._registry.get(tool)
        if spec is None:
            return await self._refuse(context, args, "tool.unknown", "Unknown tool.")

        try:
            validated = spec.input_model.model_validate(args)
        except ValidationError as exc:
            return await self._refuse(context, args, "input.invalid", _describe_invalid_input(exc))
        normalized = validated.model_dump(mode="json")

        decision = decide(self._policy, principal, tool, spec.risk, spec.target(validated))
        if decision.effect is Effect.DENY:
            return await self._refuse(context, normalized, decision.rule_id, decision.message)

        hit = self._limiter.check(principal.id, tool)
        if hit is not None:
            message = f"Rate limit reached. Try again in {hit.retry_after_seconds} seconds."
            return await self._refuse(context, normalized, hit.rule_id, message)

        if decision.effect is Effect.APPROVAL_REQUIRED:
            await self._record_refusal(context, normalized, decision.effect, decision.rule_id)
            body = {"status": "approval_required", "summary": decision.message}
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(body))],
                structured_content=body,
            )

        mutating = spec.risk is not RiskClass.READ
        if mutating and self._degraded:
            return await self._refuse(
                context,
                normalized,
                "audit.degraded",
                "Changes are disabled because the audit log failed. An operator must restart.",
            )

        try:
            await self._write(
                self._decision_fields(context, normalized, decision.effect, decision.rule_id)
            )
        except AuditWriteError as exc:
            alert(f"audit decision record failed: {exc}")
            if mutating:
                return _result(
                    "The action was not performed because it could not be audited.", is_error=True
                )

        started = time.monotonic()
        status = "ok"
        error: str | None = None
        try:
            output = await spec.handler(validated)
            result = _result(render_output(output.text, output.untrusted, MAX_OUTPUT_CHARS))
        except ToolError as exc:
            status = "error"
            error = redact_text(str(exc))
            result = _result(error, is_error=True)
        except Exception as exc:
            status = "error"
            error = type(exc).__name__
            alert(f"tool {tool} failed: {error}")
            result = _result("The tool failed unexpectedly.", is_error=True)

        try:
            await self._write(
                {
                    "event": "tool_call_outcome",
                    "request_id": request_id,
                    "result_status": status,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "error": error,
                }
            )
        except AuditWriteError as exc:
            alert(f"audit outcome record failed: {exc}")
            if mutating:
                self._degraded = True
                alert("degraded mode: refusing further changes until restart")
                warning = "Warning: the action ran but its outcome could not be audited."
                result.content.append(TextContent(type="text", text=warning))
        return result

    @staticmethod
    def _decision_fields(
        context: dict[str, Any], args: Any, effect: Effect, rule_id: str
    ) -> dict[str, Any]:
        return {
            **context,
            "event": "tool_call_decision",
            "args_redacted": redact_for_audit(args),
            "args_hash": _hash_args(args),
            "decision": effect.value,
            "rule_id": rule_id,
        }

    async def _write(self, fields: dict[str, Any]) -> None:
        await anyio.to_thread.run_sync(self._audit.append, fields)

    async def _record_refusal(
        self, context: dict[str, Any], args: Any, effect: Effect, rule_id: str
    ) -> None:
        """Log an attempt that will not execute. Failing to log never turns it into a yes."""
        try:
            await self._write(self._decision_fields(context, args, effect, rule_id))
        except AuditWriteError as exc:
            alert(f"audit decision record failed: {exc}")

    async def _refuse(
        self, context: dict[str, Any], args: Any, rule_id: str, message: str
    ) -> CallToolResult:
        await self._record_refusal(context, args, Effect.DENY, rule_id)
        return _result(message, is_error=True)
