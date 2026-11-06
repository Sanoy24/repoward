from pathlib import Path

import pytest

from repoward.policy.loader import CompiledPolicy, parse_policy

POLICY_YAML = """\
version: 1
default: deny
repos:
  allow: ["Org/Sandbox"]
paths:
  deny: [".github/**", "**/.env*", "**/secrets/**"]
dangerous_tools:
  github_merge_pull_request: { enabled: false }
  github_delete_branch: { enabled: true }
roles:
  reader:
    tools: [ping, github_get_file]
  contributor:
    inherits: reader
    tools: [github_commit_files]
  maintainer:
    inherits: contributor
    tools: [github_delete_branch, github_merge_pull_request]
    require_approval: [github_delete_branch, github_merge_pull_request]
rate_limits:
  default: { per_minute: 30 }
  github_commit_files: { per_minute: 2 }
stdio:
  role: reader
"""


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def policy() -> CompiledPolicy:
    return parse_policy(POLICY_YAML.encode())


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return path
