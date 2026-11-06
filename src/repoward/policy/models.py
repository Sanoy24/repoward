"""Pydantic models for the policy file.

A section is only added here once the code that enforces it exists, so a setting can
never appear to work while doing nothing.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from repoward.validation import RepoName

AuthorAssociation = Literal[
    "OWNER",
    "MEMBER",
    "COLLABORATOR",
    "CONTRIBUTOR",
    "FIRST_TIME_CONTRIBUTOR",
    "FIRST_TIMER",
    "MANNEQUIN",
    "NONE",
]


_DEFAULT_TRUSTED: tuple[AuthorAssociation, ...] = ("OWNER", "MEMBER", "COLLABORATOR")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RepoRules(_Strict):
    allow: list[RepoName] = Field(default_factory=list)


class PathRules(_Strict):
    deny: list[str] = Field(default_factory=list)


class BranchRules(_Strict):
    write_prefix: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*/$")] = "agent/"


class PullRequestRules(_Strict):
    allow_non_draft: bool = False


class CommitLimits(_Strict):
    max_files: int = Field(default=20, gt=0)
    max_bytes: int = Field(default=200_000, gt=0)


class ApprovalRules(_Strict):
    ttl_minutes: int = Field(default=15, gt=0, le=1440)
    max_pending_per_principal: int = Field(default=20, gt=0)


class FlowGuardRules(_Strict):
    enabled: bool = True
    window_minutes: int = Field(default=60, gt=0, le=10_080)
    on_private_to_public: Literal["deny", "require_approval"] = "deny"
    on_untrusted_author: Literal["require_approval", "deny"] = "require_approval"
    trusted_associations: list[AuthorAssociation] = Field(
        default_factory=lambda: list(_DEFAULT_TRUSTED)
    )
    single_repo: bool = False


class DangerousTool(_Strict):
    enabled: bool


class Role(_Strict):
    inherits: str | None = None
    tools: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)
    commit_limits: CommitLimits | None = None


class RateLimit(_Strict):
    per_minute: int = Field(gt=0)


class StdioConfig(_Strict):
    role: str = "reader"


class Policy(_Strict):
    version: Literal[1]
    default: Literal["deny"]
    repos: RepoRules = Field(default_factory=RepoRules)
    paths: PathRules = Field(default_factory=PathRules)
    branches: BranchRules = Field(default_factory=BranchRules)
    pull_requests: PullRequestRules = Field(default_factory=PullRequestRules)
    dangerous_tools: dict[str, DangerousTool] = Field(default_factory=dict)
    approvals: ApprovalRules = Field(default_factory=ApprovalRules)
    flow_guard: FlowGuardRules = Field(default_factory=FlowGuardRules)
    roles: dict[str, Role]
    rate_limits: dict[str, RateLimit]
    stdio: StdioConfig = Field(default_factory=StdioConfig)
