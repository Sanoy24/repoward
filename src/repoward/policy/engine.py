"""The policy decision. Pure logic with no I/O, and default-deny."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from repoward.catalog import RiskClass
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal
from repoward.sanitize import contains_secret


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True)
class Target:
    """What a call touches. Paths must already be normalized by the input model."""

    repo: str | None = None
    paths: Sequence[str] = ()
    write_branches: Sequence[str] = ()
    non_draft: bool = False
    commit_files: int = 0
    commit_bytes: int = 0
    outbound: Sequence[str] = ()


@dataclass(frozen=True)
class Decision:
    effect: Effect
    rule_id: str
    message: str = ""


def decide(
    compiled: CompiledPolicy,
    principal: Principal,
    tool: str,
    risk: RiskClass,
    target: Target,
) -> Decision:
    """Decide one call. Messages reach the agent, so they reveal no policy details."""
    role = compiled.roles.get(principal.role)
    if role is None:
        return Decision(Effect.DENY, "role.unknown", "Your role is not permitted to use tools.")
    if tool not in role.tools:
        return Decision(
            Effect.DENY,
            "default.deny",
            f"Tool {tool} is not permitted for role {principal.role}; ask a maintainer.",
        )
    if risk is RiskClass.DANGEROUS:
        switch = compiled.policy.dangerous_tools.get(tool)
        if switch is None or not switch.enabled:
            return Decision(
                Effect.DENY,
                f"dangerous_tools.{tool}.disabled",
                f"Tool {tool} is disabled in this deployment.",
            )
    if target.repo is not None and target.repo.casefold() not in compiled.allowed_repos:
        return Decision(Effect.DENY, "repos.allow", "This repository is not permitted.")
    for path in target.paths:
        if compiled.path_is_denied(path):
            return Decision(Effect.DENY, "paths.deny", "A requested path is not permitted.")
    prefix = compiled.policy.branches.write_prefix
    if any(not branch.startswith(prefix) for branch in target.write_branches):
        return Decision(
            Effect.DENY,
            "branches.write_prefix",
            f"Writes are only permitted on branches starting with {prefix}",
        )
    if target.non_draft and not compiled.policy.pull_requests.allow_non_draft:
        return Decision(
            Effect.DENY,
            "pull_requests.allow_non_draft",
            "Only draft pull requests are permitted.",
        )
    limits = role.commit_limits
    if target.commit_files > limits.max_files or target.commit_bytes > limits.max_bytes:
        return Decision(
            Effect.DENY,
            "roles.commit_limits",
            f"Commits are limited to {limits.max_files} files and {limits.max_bytes} bytes.",
        )
    if any(contains_secret(text) for text in target.outbound):
        return Decision(
            Effect.DENY,
            "secrets.outbound",
            "The content appears to contain a credential, so it was not sent.",
        )
    if tool in role.require_approval:
        return Decision(
            Effect.APPROVAL_REQUIRED,
            f"roles.{principal.role}.require_approval",
            "This action requires human approval.",
        )
    return Decision(Effect.ALLOW, f"roles.{principal.role}.tools")
