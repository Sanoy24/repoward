"""Release metadata must agree, or the registry and PyPI will reject or confuse a release."""

import importlib.util
import json
import re
import tomllib
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parent.parent


def project() -> dict[str, object]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    table: dict[str, object] = data["project"]
    return table


def server() -> dict[str, object]:
    document: dict[str, object] = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    return document


def test_versions_match() -> None:
    document = server()
    packages = document["packages"]
    assert isinstance(packages, list)
    assert document["version"] == project()["version"]
    assert packages[0]["version"] == project()["version"]


def test_registry_name_is_in_the_readme() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"mcp-name: {server()['name']}" in readme


def test_package_identifier_matches() -> None:
    packages = server()["packages"]
    assert isinstance(packages, list)
    assert packages[0]["identifier"] == project()["name"]


def test_registry_description_fits_its_limit() -> None:
    assert len(str(server()["description"])) <= 100


def test_changelog_has_the_current_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## \[{re.escape(str(project()['version']))}\]", changelog, re.M)


def test_the_example_policy_matches_what_init_offers() -> None:
    example = (ROOT / "policy.example.yaml").read_text(encoding="utf-8")
    for section in ("flow_guard:", "dangerous_tools:", "approvals:", "branches:"):
        assert section in example


def load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_package", ROOT / "scripts" / "check_package.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_package_checker_flags_stray_files() -> None:
    checker = load_checker()
    assert (
        checker.unexpected_in_wheel(["repoward/cli.py", "repoward-0.1.0.dist-info/METADATA"]) == []
    )
    assert checker.unexpected_in_wheel(["notes/plan.md"]) == ["notes/plan.md"]
    assert checker.unexpected_in_sdist(["repoward-0.1.0/src/repoward/cli.py"]) == []
    assert checker.unexpected_in_sdist(["repoward-0.1.0/README.md"]) == []
    assert checker.unexpected_in_sdist(["repoward-0.1.0/.env"]) == ["repoward-0.1.0/.env"]
    assert checker.unexpected_in_sdist(["repoward-0.1.0/.dev/notes.md"]) == [
        "repoward-0.1.0/.dev/notes.md"
    ]


def test_release_workflow_pins_actions_to_commits() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)", workflow)
    assert uses
    assert all(re.search(r"@[0-9a-f]{40}$", action) for action in uses)
