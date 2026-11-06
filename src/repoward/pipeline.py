"""The single guarded call path. Every tool attempt goes through `Pipeline.call`."""

import json
import sys
import time
import uuid
from typing import Any

import anyio.to_thread
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from repoward.approvals.store import ApprovalStore, ApprovalStoreError, TooManyPendingError
from repoward.audit import AuditLog, AuditWriteError
from repoward.canonical import canonical_json, sha256_hex
from repoward.catalog import RECEIPT_PERMISSIONS, TOOL_PERMISSIONS, RiskClass
from repoward.flow import FlowGuard, FlowStoreError
from repoward.policy.engine import Effect, decide, tighten
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal
from repoward.ratelimit import RateLimiter
from repoward.receipts import ReceiptLedger
from repoward.registry import (
    ReviewApproval,
    ToolError,
    ToolInput,
    ToolOutput,
    ToolRegistry,
    ToolSpec,
)
from repoward.sanitize import redact_for_audit, redact_text, render_output
from repoward.scope import call_scope

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
        approvals: ApprovalStore | None = None,
        flow: FlowGuard | None = None,
        receipts: ReceiptLedger | None = None,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._audit = audit
        self._limiter = limiter or RateLimiter(policy.rate_limits)
        self._instance_id = str(uuid.uuid4())
        self._approvals = approvals
        self._flow = flow
        self._receipts = receipts
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
            # What labels mean depends on this, so policy replay needs it. None means the guard
            # was off and no labels were recorded.
            "flow_trusted": None if self._flow is None else self._flow.trusted_associations,
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

        mutating = spec.risk is not RiskClass.READ
        repo = spec.target(validated).repo
        if mutating and self._flow is not None:
            flow_decision = await self._flow.check_write(principal.id, repo)
            decision = tighten(decision, flow_decision)
            if decision.effect is Effect.DENY:
                return await self._refuse(context, normalized, decision.rule_id, decision.message)

        hit = self._limiter.check(principal.id, tool)
        if hit is not None:
            message = f"Rate limit reached. Try again in {hit.retry_after_seconds} seconds."
            return await self._refuse(context, normalized, hit.rule_id, message)

        if mutating and self._degraded:
            return await self._refuse(
                context,
                normalized,
                "audit.degraded",
                "Changes are disabled because the audit log failed. An operator must restart.",
            )

        rule_id = decision.rule_id
        if decision.effect is Effect.APPROVAL_REQUIRED:
            args_hash = _hash_args(normalized)
            try:
                approval_id = await self._consume_approval(principal, tool, repo, args_hash)
            except ApprovalStoreError as exc:
                alert(str(exc))
                return await self._refuse(
                    context,
                    normalized,
                    "approvals.unavailable",
                    "This action needs approval, but approvals are unavailable right now.",
                )
            if approval_id is None:
                review = await self._find_review_approval(spec, validated, repo)
                if review is not None:
                    context = {
                        **context,
                        "approved_by": review.login,
                        "review_id": review.review_id,
                    }
                    rule_id = "approvals.github_review"
            if approval_id is None and rule_id != "approvals.github_review":
                return await self._request_approval(
                    context, principal, spec, validated, normalized, decision.rule_id, repo
                )
            if approval_id is not None:
                context = {**context, "approval_id": approval_id}
                rule_id = "approvals.consumed"

        try:
            await self._write(self._decision_fields(context, normalized, Effect.ALLOW, rule_id))
        except AuditWriteError as exc:
            alert(f"audit decision record failed: {exc}")
            if mutating:
                return _result(
                    "The action was not performed because it could not be audited.", is_error=True
                )

        started = time.monotonic()
        status = "ok"
        error: str | None = None
        output: ToolOutput | None = None
        try:
            with call_scope(repo, TOOL_PERMISSIONS[tool]):
                output = await spec.handler(validated)
            if not mutating and self._flow is not None:
                # Saved before the content is returned: unrecorded content is never handed over.
                for kind, source in await self._flow.record_read(principal.id, repo, output.taints):
                    await self._record_label(context, kind, source)
            result = _result(render_output(output.text, output.untrusted, MAX_OUTPUT_CHARS))
        except FlowStoreError as exc:
            status = "error"
            error = type(exc).__name__
            alert(f"flow guard could not save state: {exc}")
            result = _result(
                "The content was withheld because it could not be tracked.", is_error=True
            )
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
        if status == "ok" and output is not None and output.head_sha and repo is not None:
            await self._post_receipt(context, principal, repo, output.head_sha)
        return result

    async def _flow_labels(self, principal: Principal) -> str:
        if self._flow is None:
            return "off"
        try:
            return "yes" if await self._flow.has_labels(principal.id) else "no"
        except FlowStoreError as exc:
            alert(str(exc))
            return "unknown"

    async def _post_receipt(
        self, context: dict[str, Any], principal: Principal, repo: str, sha: str
    ) -> None:
        """Audit a receipt, then post it. It is informational, so failing never fails the call."""
        if self._receipts is None or self._degraded:
            return
        description = self._receipts.description(principal.id, await self._flow_labels(principal))
        if description is None:
            return
        request_id = context["request_id"]
        try:
            await self._write(
                {
                    "event": "receipt",
                    "request_id": request_id,
                    "principal": principal.id,
                    "repo": repo,
                    "sha": sha,
                    "description": description,
                }
            )
        except AuditWriteError as exc:
            alert(f"audit receipt record failed, so no receipt was posted: {exc}")
            return
        status = "ok"
        error: str | None = None
        try:
            with call_scope(repo, RECEIPT_PERMISSIONS):
                await self._receipts.post(repo, sha, description)
        except ToolError as exc:
            status = "error"
            error = redact_text(str(exc))
        except Exception as exc:
            status = "error"
            error = type(exc).__name__
        if error is not None:
            alert(f"receipt was not posted: {error}")
        try:
            await self._write(
                {
                    "event": "receipt_outcome",
                    "request_id": request_id,
                    "result_status": status,
                    "error": error,
                }
            )
        except AuditWriteError as exc:
            alert(f"audit receipt outcome failed: {exc}")
            self._degraded = True
            alert("degraded mode: refusing further changes until restart")

    async def _record_label(self, context: dict[str, Any], kind: str, source: str) -> None:
        try:
            await self._write(
                {
                    "event": "flow_label",
                    "request_id": context["request_id"],
                    "principal": context["principal"],
                    "kind": kind,
                    "source": source,
                }
            )
        except AuditWriteError as exc:
            alert(f"audit flow label record failed: {exc}")

    @staticmethod
    async def _find_review_approval(
        spec: ToolSpec, validated: ToolInput, repo: str | None
    ) -> ReviewApproval | None:
        """Look for a qualifying GitHub review. Any failure means no approval."""
        if spec.review_approval is None:
            return None
        try:
            with call_scope(repo, TOOL_PERMISSIONS[spec.name]):
                return await spec.review_approval(validated)
        except Exception as exc:
            alert(f"review check failed: {type(exc).__name__}")
            return None

    async def _consume_approval(
        self, principal: Principal, tool: str, repo: str | None, args_hash: str
    ) -> str | None:
        if self._approvals is None:
            raise ApprovalStoreError("no approval store is configured")
        return await anyio.to_thread.run_sync(
            self._approvals.consume, principal.id, tool, repo, args_hash
        )

    async def _request_approval(
        self,
        context: dict[str, Any],
        principal: Principal,
        spec: ToolSpec,
        validated: ToolInput,
        normalized: Any,
        rule_id: str,
        repo: str | None,
    ) -> CallToolResult:
        """Record a request for a human. The tool does not run."""
        assert self._approvals is not None  # noqa: S101
        details = ""
        if spec.approval_context is not None:
            try:
                with call_scope(repo, TOOL_PERMISSIONS[spec.name]):
                    details = await spec.approval_context(validated)
            except Exception as exc:
                details = "Could not fetch details from GitHub."
                alert(f"approval context failed: {type(exc).__name__}")
        if self._flow is not None:
            try:
                note = await self._flow.describe(principal.id)
            except FlowStoreError as exc:
                note = "Flow guard state is unavailable."
                alert(str(exc))
            details = "\n".join(part for part in (details, note) if part)
        try:
            approval = await anyio.to_thread.run_sync(
                self._approvals.request,
                principal.id,
                spec.name,
                repo,
                _hash_args(normalized),
                json.dumps(redact_for_audit(normalized), ensure_ascii=True, sort_keys=True),
                redact_text(details),
            )
        except TooManyPendingError:
            return await self._refuse(
                context,
                normalized,
                "approvals.too_many_pending",
                "Too many approval requests are waiting. Ask a human to review them.",
            )
        except ApprovalStoreError as exc:
            alert(str(exc))
            return await self._refuse(
                context,
                normalized,
                "approvals.unavailable",
                "This action needs approval, but approvals are unavailable right now.",
            )
        await self._record_refusal(
            {**context, "approval_id": approval.id},
            normalized,
            Effect.APPROVAL_REQUIRED,
            rule_id,
        )
        body = {
            "status": "approval_required",
            "approval_id": approval.id,
            "summary": (
                f"{spec.name} was not run. A human must approve request {approval.id}; "
                "then call the tool again with the same arguments."
            ),
        }
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(body))],
            structured_content=body,
        )

    @staticmethod
    def _decision_fields(
        context: dict[str, Any], args: Any, effect: Effect, rule_id: str
    ) -> dict[str, Any]:
        return {
            **context,
            "event": "tool_call_decision",
            "args_redacted": redact_for_audit(args, hide_content=True),
            "args_hash": _hash_args(args),
            "decision": effect.value,
            "rule_id": rule_id,
        }

    async def _write(self, fields: dict[str, Any]) -> None:
        record = await anyio.to_thread.run_sync(self._audit.append, fields)
        if self._receipts is not None:
            self._receipts.observe(record)

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
