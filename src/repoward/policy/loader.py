"""Strict policy loading. Every problem is reported with its line number."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pathspec
import yaml
from pydantic import ValidationError

from repoward.canonical import sha256_hex
from repoward.catalog import TOOL_CATALOG, RiskClass
from repoward.policy.models import CommitLimits, Policy

_MAX_POLICY_BYTES = 1_000_000
_Loc = tuple[str | int, ...]


@dataclass(frozen=True)
class PolicyIssue:
    message: str
    line: int | None = None
    column: int | None = None


class PolicyError(Exception):
    def __init__(self, issues: list[PolicyIssue]) -> None:
        super().__init__("; ".join(issue.message for issue in issues))
        self.issues = issues


@dataclass(frozen=True)
class ResolvedRole:
    tools: frozenset[str]
    require_approval: frozenset[str]
    commit_limits: CommitLimits = field(default_factory=CommitLimits)


@dataclass(frozen=True)
class CompiledPolicy:
    policy: Policy
    sha256: str
    roles: dict[str, ResolvedRole]
    allowed_repos: frozenset[str]
    denied_paths: pathspec.PathSpec[Any]
    rate_limits: dict[str, int]

    def path_is_denied(self, normalized_path: str) -> bool:
        return self.denied_paths.match_file(normalized_path.casefold())


def _issue_at(message: str, mark: yaml.Mark) -> PolicyIssue:
    return PolicyIssue(message, mark.line + 1, mark.column + 1)


def _structure_issues(text: str) -> list[PolicyIssue]:
    """Reject YAML features that can silently change meaning."""
    issues: list[PolicyIssue] = []
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            issues.append(_issue_at("YAML anchors and aliases are not allowed", event.start_mark))

    def walk(node: yaml.Node) -> None:
        if isinstance(node, yaml.MappingNode):
            seen: set[str] = set()
            for key, value in node.value:
                if key.tag == "tag:yaml.org,2002:merge":
                    issues.append(_issue_at("YAML merge keys are not allowed", key.start_mark))
                elif isinstance(key, yaml.ScalarNode):
                    if key.value in seen:
                        issues.append(_issue_at(f"duplicate key '{key.value}'", key.start_mark))
                    seen.add(key.value)
                walk(value)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                walk(item)

    if not issues:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        if root is not None:
            walk(root)
    return issues


def _locate(root: yaml.Node | None, loc: _Loc) -> tuple[int | None, int | None]:
    """Find the deepest YAML node on a path, for error reporting."""
    if root is None:
        return None, None
    node = root
    for part in loc:
        child: yaml.Node | None = None
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode) and key.value == str(part):
                    child = value
                    break
        elif (
            isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value)
        ):
            child = node.value[part]
        if child is None:
            break
        node = child
    return node.start_mark.line + 1, node.start_mark.column + 1


def _resolve_roles(policy: Policy, problems: list[tuple[str, _Loc]]) -> dict[str, ResolvedRole]:
    resolved: dict[str, ResolvedRole] = {}
    reported: set[str] = set()

    def fail(name: str, message: str) -> None:
        if name not in reported:
            reported.add(name)
            problems.append((message, ("roles", name, "inherits")))

    def resolve(name: str, chain: tuple[str, ...]) -> ResolvedRole | None:
        if name in resolved:
            return resolved[name]
        role = policy.roles[name]
        tools = set(role.tools)
        approvals = set(role.require_approval)
        limits = role.commit_limits
        if role.inherits is not None:
            if role.inherits == name or role.inherits in chain:
                fail(name, f"role '{name}' has an inheritance cycle")
                return None
            if role.inherits not in policy.roles:
                fail(name, f"role '{name}' inherits unknown role '{role.inherits}'")
                return None
            parent = resolve(role.inherits, (*chain, name))
            if parent is None:
                return None
            tools |= parent.tools
            approvals |= parent.require_approval
            limits = limits or parent.commit_limits
        result = ResolvedRole(frozenset(tools), frozenset(approvals), limits or CommitLimits())
        resolved[name] = result
        return result

    for name in policy.roles:
        resolve(name, ())
    return resolved


def _semantic_problems(policy: Policy, resolved: dict[str, ResolvedRole]) -> list[tuple[str, _Loc]]:
    problems: list[tuple[str, _Loc]] = []
    for name, role in policy.roles.items():
        for section, tools in (("tools", role.tools), ("require_approval", role.require_approval)):
            for index, tool in enumerate(tools):
                if tool not in TOOL_CATALOG:
                    problems.append((f"unknown tool '{tool}'", ("roles", name, section, index)))
        effective = resolved.get(name)
        if effective is None:
            continue
        for tool in sorted(effective.require_approval - effective.tools):
            problems.append(
                (f"role '{name}' requires approval for '{tool}' but lacks it", ("roles", name))
            )
        for tool in sorted(effective.tools):
            if (
                TOOL_CATALOG.get(tool) is RiskClass.DANGEROUS
                and tool not in effective.require_approval
            ):
                problems.append(
                    (f"dangerous tool '{tool}' in role '{name}' needs approval", ("roles", name))
                )
    for tool in policy.dangerous_tools:
        if TOOL_CATALOG.get(tool) is not RiskClass.DANGEROUS:
            problems.append((f"'{tool}' is not a dangerous tool", ("dangerous_tools", tool)))
    auth = policy.github_auth
    if auth.mode == "app" and (not auth.client_id or auth.installation_id is None):
        problems.append(
            ("github_auth mode 'app' needs client_id and installation_id", ("github_auth",))
        )
    if auth.mode == "pat" and (auth.client_id or auth.installation_id is not None):
        problems.append(
            ("client_id and installation_id only apply to mode 'app'", ("github_auth",))
        )
    if "default" not in policy.rate_limits:
        problems.append(("rate_limits must define 'default'", ("rate_limits",)))
    for tool in policy.rate_limits:
        if tool != "default" and tool not in TOOL_CATALOG:
            problems.append((f"unknown tool '{tool}'", ("rate_limits", tool)))
    if policy.stdio.role not in policy.roles:
        problems.append((f"stdio role '{policy.stdio.role}' is not defined", ("stdio", "role")))
    for index, pattern in enumerate(policy.paths.deny):
        if not pattern.strip() or pattern.startswith("!"):
            problems.append(
                ("path patterns must not be empty or negated", ("paths", "deny", index))
            )
    return problems


def parse_policy(data: bytes) -> CompiledPolicy:
    if len(data) > _MAX_POLICY_BYTES:
        raise PolicyError([PolicyIssue("policy file is too large")])
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError([PolicyIssue("policy file must be UTF-8")]) from exc

    try:
        structure = _structure_issues(text)
        if structure:
            raise PolicyError(structure)
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        raw: Any = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        line = mark.line + 1 if mark else None
        column = mark.column + 1 if mark else None
        raise PolicyError([PolicyIssue(f"invalid YAML: {exc.problem}", line, column)]) from exc
    except yaml.YAMLError as exc:
        raise PolicyError([PolicyIssue("invalid YAML")]) from exc

    try:
        policy = Policy.model_validate(raw)
    except ValidationError as exc:
        issues = []
        for error in exc.errors(include_url=False, include_input=False):
            loc = tuple(error["loc"])
            line, column = _locate(root, loc)
            where = ".".join(str(part) for part in loc)
            issues.append(PolicyIssue(f"{where}: {error['msg']}", line, column))
        raise PolicyError(issues) from exc

    problems: list[tuple[str, _Loc]] = []
    resolved = _resolve_roles(policy, problems)
    problems += _semantic_problems(policy, resolved)
    if problems:
        issues = []
        for message, loc in problems:
            line, column = _locate(root, loc)
            issues.append(PolicyIssue(message, line, column))
        raise PolicyError(issues)

    return CompiledPolicy(
        policy=policy,
        sha256=sha256_hex(data),
        roles=resolved,
        allowed_repos=frozenset(repo.casefold() for repo in policy.repos.allow),
        denied_paths=pathspec.PathSpec.from_lines(
            "gitignore", [pattern.casefold() for pattern in policy.paths.deny]
        ),
        rate_limits={tool: limit.per_minute for tool, limit in policy.rate_limits.items()},
    )


def load_policy(path: Path) -> CompiledPolicy:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PolicyError([PolicyIssue(f"cannot read policy file: {exc.strerror}")]) from exc
    return parse_policy(data)
