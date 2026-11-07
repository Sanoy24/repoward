"""The toxic flow attack over real HTTP, against real repositories. Skipped by default.

Needs GITHUB_WRITE_TOKEN, REPOWARD_LIVE_REPO and REPOWARD_LIVE_PRIVATE_REPO. Tokens are signed
locally, so this covers the server and GitHub but not a real identity provider. Nothing is posted:
the only write attempted is the one the flow guard must refuse.
"""

import os
import re
from pathlib import Path

import httpx
import pytest

from repoward.adapters.github import GitHubClient
from repoward.policy.loader import parse_policy
from tests.test_http_mode import LEGACY, MODERN, Stack, connect, policy_text, text, token

pytestmark = [pytest.mark.live, pytest.mark.anyio]

GITHUB_TOKEN = os.environ.get("GITHUB_WRITE_TOKEN", "")
PUBLIC = os.environ.get("REPOWARD_LIVE_REPO", "")
PRIVATE = os.environ.get("REPOWARD_LIVE_PRIVATE_REPO", "")


def comments(number: int) -> int:
    response = httpx.get(
        f"https://api.github.com/repos/{PUBLIC}/issues/{number}",
        headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
        timeout=30,
    )
    count: int = response.json()["comments"]
    return count


@pytest.mark.parametrize("mode", [LEGACY, MODERN])
async def test_the_attack_is_blocked_over_http(tmp_path: Path, mode: str) -> None:
    if not (GITHUB_TOKEN and PUBLIC and PRIVATE):
        pytest.skip("GITHUB_WRITE_TOKEN and both sandbox repositories are required")
    policy = parse_policy(
        policy_text()
        .replace(b"flow_guard:\n  enabled: false\n", b"")
        .replace(
            b"  reader:\n    tools: [ping]\n",
            b"  reader:\n    tools: [github_list_issues, github_get_file, github_comment]\n",
        )
        + f'repos:\n  allow: ["{PUBLIC}", "{PRIVATE}"]\n'.encode()
    )
    github = GitHubClient(GITHUB_TOKEN)
    built = Stack(tmp_path, policy, github)
    try:
        async with connect(built, token(), mode) as client:
            listing = await client.call_tool("github_list_issues", {"repo": PUBLIC})
            found = re.search(r"#(\d+): Prompt injection test fixture", text(listing))
            assert found, text(listing)
            number = int(found[1])
            before = comments(number)
            stolen = await client.call_tool(
                "github_get_file", {"repo": PRIVATE, "path": "notes/internal.txt"}
            )
            assert not stolen.is_error, text(stolen)
            leak = await client.call_tool(
                "github_comment", {"repo": PUBLIC, "number": number, "body": "must not be posted"}
            )
            assert leak.is_error
            assert "private content" in text(leak)
        assert built.decisions()[-1]["rule_id"] == "flow.private_to_public"
        assert built.decisions()[-1]["principal"].endswith("|alice")
        assert comments(number) == before
    finally:
        built.stop()  # The client's connections belonged to the server's event loop.
