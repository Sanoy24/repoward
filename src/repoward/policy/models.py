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


class GitHubReviewRules(_Strict):
    enabled: bool = False
    min_permission: Literal["write", "admin"] = "write"


class GitHubAuth(_Strict):
    mode: Literal["pat", "app"] = "pat"
    client_id: str | None = None
    installation_id: int | None = Field(default=None, gt=0)


class ApprovalRules(_Strict):
    ttl_minutes: int = Field(default=15, gt=0, le=1440)
    max_pending_per_principal: int = Field(default=20, gt=0)
    github_review: GitHubReviewRules = Field(default_factory=GitHubReviewRules)


class FlowGuardRules(_Strict):
    enabled: bool = True
    window_minutes: int = Field(default=60, gt=0, le=10_080)
    on_private_to_public: Literal["deny", "require_approval"] = "deny"
    on_untrusted_author: Literal["require_approval", "deny"] = "require_approval"
    trusted_associations: list[AuthorAssociation] = Field(
        default_factory=lambda: list(_DEFAULT_TRUSTED)
    )
    single_repo: bool = False


class ReceiptRules(_Strict):
    enabled: bool = False


class HttpAuth(_Strict):
    """How HTTP mode verifies callers. Holds addresses and names only, never a secret."""

    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    jwks_uri: str
    algorithms: list[
        Literal["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]
    ] = Field(min_length=1)
    resource_server_url: str
    leeway_seconds: int = Field(default=30, ge=0, le=60)
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)


class IdentityMap(_Strict):
    claim: str = Field(default="groups", min_length=1)
    mapping: dict[str, str] = Field(min_length=1)


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
    github_auth: GitHubAuth = Field(default_factory=GitHubAuth)
    approvals: ApprovalRules = Field(default_factory=ApprovalRules)
    flow_guard: FlowGuardRules = Field(default_factory=FlowGuardRules)
    receipts: ReceiptRules = Field(default_factory=ReceiptRules)
    roles: dict[str, Role]
    rate_limits: dict[str, RateLimit]
    stdio: StdioConfig = Field(default_factory=StdioConfig)
    http_auth: HttpAuth | None = None
    identity_map: IdentityMap | None = None
