from pathlib import Path

import pytest

from repoward.cli import main
from repoward.policy.loader import PolicyError, load_policy, parse_policy
from tests.conftest import POLICY_YAML

EXAMPLE = Path(__file__).parent.parent / "policy.example.yaml"


def issues_for(text: str) -> PolicyError:
    with pytest.raises(PolicyError) as info:
        parse_policy(text.encode())
    return info.value


def test_valid_policy_resolves_inheritance(policy_file: Path) -> None:
    compiled = load_policy(policy_file)
    assert compiled.roles["reader"].tools == {"ping", "github_get_file"}
    assert "ping" in compiled.roles["maintainer"].tools
    assert "github_commit_files" in compiled.roles["maintainer"].tools
    assert len(compiled.sha256) == 64


def test_example_policy_is_valid() -> None:
    load_policy(EXAMPLE)


def test_child_role_keeps_inherited_approval_requirement() -> None:
    text = POLICY_YAML.replace(
        "  maintainer:\n", "  owner:\n    inherits: maintainer\n  maintainer:\n"
    )
    compiled = parse_policy(text.encode())
    assert "github_delete_branch" in compiled.roles["owner"].require_approval


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("default: deny", "default: allow", "default"),
        ("version: 1", "version: 2", "version"),
        ("version: 1", 'version: "1"', "version"),
        ("default: deny", "default: deny\nextra: 1", "extra"),
        ("tools: [ping, github_get_file]", "tools: [ping, nope]", "unknown tool 'nope'"),
        ("inherits: reader", "inherits: ghost", "unknown role 'ghost'"),
        ("role: reader", "role: ghost", "stdio role 'ghost'"),
        ("per_minute: 30", "per_minute: 0", "rate_limits.default.per_minute"),
        ("per_minute: 30", 'per_minute: "30"', "rate_limits.default.per_minute"),
        ("default: { per_minute: 30 }", "other: { per_minute: 30 }", "unknown tool 'other'"),
        ('"Org/Sandbox"', '"not a repo"', "repos.allow.0"),
        ('".github/**"', '"!keep"', "negated"),
        ('".github/**"', '""', "negated"),
        ("github_delete_branch: { enabled: true }", "ping: { enabled: true }", "not a dangerous"),
        (
            "require_approval: [github_delete_branch, github_merge_pull_request]",
            "require_approval: [github_delete_branch]",
            "github_merge_pull_request' in role 'maintainer' needs approval",
        ),
        (
            "require_approval: [github_delete_branch, github_merge_pull_request]",
            "require_approval: [github_delete_branch, github_merge_pull_request, github_comment]",
            "requires approval for 'github_comment'",
        ),
    ],
)
def test_invalid_policies(old: str, new: str, expected: str) -> None:
    assert old in POLICY_YAML
    assert expected in str(issues_for(POLICY_YAML.replace(old, new)))


def test_inheritance_cycle_is_reported() -> None:
    text = POLICY_YAML.replace(
        "  reader:\n    tools: [ping, github_get_file]",
        "  reader:\n    inherits: maintainer\n    tools: [ping, github_get_file]",
    )
    assert "cycle" in str(issues_for(text))


def test_self_inheritance_is_a_cycle() -> None:
    text = POLICY_YAML.replace("  reader:\n", "  reader:\n    inherits: reader\n")
    assert "cycle" in str(issues_for(text))


def test_duplicate_keys_are_refused_with_a_line_number() -> None:
    error = issues_for("version: 1\nversion: 1\n")
    assert "duplicate key 'version'" in str(error)
    assert error.issues[0].line == 2


def test_nested_duplicate_keys_are_refused() -> None:
    text = POLICY_YAML.replace("  reader:\n", "  reader: {}\n  reader:\n")
    assert "duplicate key 'reader'" in str(issues_for(text))


def test_anchors_and_aliases_are_refused() -> None:
    assert "aliases" in str(issues_for("a: &x 1\nb: *x\n"))


def test_merge_keys_are_refused() -> None:
    assert "merge keys" in str(issues_for("a:\n  <<: {b: 1}\n"))


def test_python_tags_are_refused() -> None:
    assert "invalid YAML" in str(issues_for("a: !!python/object/apply:os.system ['x']\n"))


def test_malformed_yaml_reports_a_line() -> None:
    error = issues_for("version: 1\nroles: [\n")
    assert error.issues[0].line is not None


def test_non_utf8_and_oversized_are_refused() -> None:
    with pytest.raises(PolicyError, match="UTF-8"):
        parse_policy(b"\xff\xfe")
    with pytest.raises(PolicyError, match="too large"):
        parse_policy(b"#" * 1_000_001)


def test_empty_file_is_refused() -> None:
    issues_for("")


def test_schema_errors_carry_the_right_line() -> None:
    error = issues_for(POLICY_YAML.replace("per_minute: 30", "per_minute: 0"))
    line = POLICY_YAML.splitlines().index("  default: { per_minute: 30 }") + 1
    assert error.issues[0].line == line


def test_semantic_errors_carry_the_right_line() -> None:
    error = issues_for(POLICY_YAML.replace("role: reader", "role: ghost"))
    assert error.issues[0].line == POLICY_YAML.splitlines().index("  role: reader") + 1


def test_cli_prints_line_context(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(POLICY_YAML.replace("role: reader", "role: ghost"), encoding="utf-8")
    assert main(["validate-policy", str(path)]) == 1
    err = capsys.readouterr().err
    assert "stdio role 'ghost'" in err
    assert "role: ghost" in err
    assert "^" in err


def test_cli_accepts_a_good_policy(policy_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate-policy", str(policy_file)]) == 0
    assert "OK: 3 roles" in capsys.readouterr().out


def test_cli_reports_a_missing_file(tmp_path: Path) -> None:
    assert main(["validate-policy", str(tmp_path / "nope.yaml")]) == 1
