"""Pydantic models for the policy file.

A section is only added here once the code that enforces it exists, so a setting can
never appear to work while doing nothing.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from repoward.validation import RepoName


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RepoRules(_Strict):
    allow: list[RepoName] = Field(default_factory=list)


class PathRules(_Strict):
    deny: list[str] = Field(default_factory=list)


class DangerousTool(_Strict):
    enabled: bool


class Role(_Strict):
    inherits: str | None = None
    tools: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)


class RateLimit(_Strict):
    per_minute: int = Field(gt=0)


class StdioConfig(_Strict):
    role: str = "reader"


class Policy(_Strict):
    version: Literal[1]
    default: Literal["deny"]
    repos: RepoRules = Field(default_factory=RepoRules)
    paths: PathRules = Field(default_factory=PathRules)
    dangerous_tools: dict[str, DangerousTool] = Field(default_factory=dict)
    roles: dict[str, Role]
    rate_limits: dict[str, RateLimit]
    stdio: StdioConfig = Field(default_factory=StdioConfig)
