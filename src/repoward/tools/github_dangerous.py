"""Dangerous tools. Policy requires human approval for these, bound to the exact arguments.

Both take the commit SHA the caller expects. That SHA is part of the approved arguments, so an
approval covers one specific commit and not just a pull request number or branch name.
"""

import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from pydantic import Field

from repoward.adapters.github import GitHubClient, file_url_path, repo_path
from repoward.catalog import RiskClass
from repoward.policy.engine import Target
from repoward.policy.models import GitHubReviewRules
from repoward.registry import (
    ReviewApproval,
    ToolError,
    ToolInput,
    ToolOutput,
    ToolRegistry,
    ToolSpec,
)
from repoward.validation import GitRef, RepoName

_SHA = re.compile(r"[0-9a-f]{40}")
CommitSha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]


class MergeInput(ToolInput):
    repo: RepoName
    number: int = Field(ge=1, le=2_147_483_647)
    head_sha: CommitSha
    merge_method: Literal["merge", "squash", "rebase"] = "squash"


class DeleteBranchInput(ToolInput):
    repo: RepoName
    branch: GitRef
    expected_sha: CommitSha


def _merge_target(args: ToolInput) -> Target:
    assert isinstance(args, MergeInput)  # noqa: S101
    return Target(repo=args.repo)


def _delete_target(args: ToolInput) -> Target:
    assert isinstance(args, DeleteBranchInput)  # noqa: S101
    return Target(repo=args.repo, write_branches=[args.branch])


_PERMISSION_RANK = {"none": 0, "read": 1, "write": 2, "admin": 3}
_DECISIVE_STATES = {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}
_REVIEW_PAGE_SIZE = 100
_MAX_REVIEW_PAGES = 5


async def _load_reviews(client: GitHubClient, repo: str, number: int) -> list[dict[str, Any]]:
    """All reviews, oldest first. Too many to read completely means nothing can be concluded."""
    reviews: list[dict[str, Any]] = []
    for page in range(1, _MAX_REVIEW_PAGES + 1):
        batch = await client.get_json(
            f"{repo_path(repo)}/pulls/{number}/reviews",
            {"per_page": _REVIEW_PAGE_SIZE, "page": page},
        )
        if not isinstance(batch, list):
            raise ToolError("GitHub returned an unexpected response.")
        reviews.extend(batch)
        if len(batch) < _REVIEW_PAGE_SIZE:
            return reviews
    raise ToolError("This pull request has too many reviews to check safely.")


async def _has_permission(client: GitHubClient, repo: str, login: str, minimum: str) -> bool:
    document = await client.get_json(
        f"{repo_path(repo)}/collaborators/{quote(login, safe='')}/permission"
    )
    level = document.get("permission") if isinstance(document, dict) else None
    return _PERMISSION_RANK.get(str(level), 0) >= _PERMISSION_RANK[minimum]


async def find_review_approval(
    client: GitHubClient, args: "MergeInput", minimum: str
) -> ReviewApproval | None:
    """Find a human review that approves exactly this commit.

    The reviewer must be a user other than the pull request's author and this server's own
    identity, and must have the required access. Any reviewer's outstanding request for changes
    blocks it. A person's latest decisive review is the one that counts.
    """
    pull = await client.get_json(f"{repo_path(args.repo)}/pulls/{args.number}")
    if not isinstance(pull, dict) or pull.get("state") != "open":
        return None
    if (pull.get("head") or {}).get("sha") != args.head_sha:
        return None
    author = str((pull.get("user") or {}).get("login", "")).casefold()
    if not author:
        return None
    own_identity = (await client.identity()).casefold()

    latest: dict[str, dict[str, Any]] = {}
    for review in await _load_reviews(client, args.repo, args.number):
        login = str((review.get("user") or {}).get("login", "")).casefold()
        if login and review.get("state") in _DECISIVE_STATES:
            latest[login] = review
    if any(review["state"] == "CHANGES_REQUESTED" for review in latest.values()):
        return None

    for login, review in latest.items():
        user = review.get("user") or {}
        if (
            review["state"] != "APPROVED"
            or review.get("commit_id") != args.head_sha
            or login in {author, own_identity}
            or user.get("type") != "User"
        ):
            continue
        name = str(user.get("login"))
        if await _has_permission(client, args.repo, name, minimum):
            return ReviewApproval(name, int(review["id"]))
    return None


def register(
    registry: ToolRegistry, client: GitHubClient, review_rules: GitHubReviewRules | None = None
) -> None:
    async def merge_review(args: ToolInput) -> ReviewApproval | None:
        assert isinstance(args, MergeInput)  # noqa: S101
        assert review_rules is not None  # noqa: S101
        return await find_review_approval(client, args, review_rules.min_permission)

    async def merge_context(args: ToolInput) -> str:
        """What the approver sees. This text comes from GitHub and is treated as untrusted."""
        assert isinstance(args, MergeInput)  # noqa: S101
        pull = await client.get_json(f"{repo_path(args.repo)}/pulls/{args.number}")
        head = pull.get("head") or {}
        base = pull.get("base") or {}
        lines = [
            f"Title: {pull.get('title')}",
            f"Into {base.get('ref')} from {head.get('ref')}",
            f"Author association: {pull.get('author_association')}",
            f"State: {pull.get('state')}, draft: {pull.get('draft')}, "
            f"mergeable: {pull.get('mergeable')}",
            f"Changes: {pull.get('changed_files')} files, +{pull.get('additions')} "
            f"-{pull.get('deletions')}",
        ]
        if head.get("sha") != args.head_sha:
            lines.append("WARNING: the pull request head is not the requested commit.")
        return "\n".join(lines)

    async def merge(args: ToolInput) -> ToolOutput:
        """Merge only if the head is still the approved commit; GitHub answers 409 if it moved.

        This uses the synchronous endpoint, so its outcome can be audited directly. It does not
        support merge queues. Rule bypass is never requested.
        """
        assert isinstance(args, MergeInput)  # noqa: S101
        result = await client.send_json(
            "PUT",
            f"{repo_path(args.repo)}/pulls/{args.number}/merge",
            {"sha": args.head_sha, "merge_method": args.merge_method},
        )
        if not isinstance(result, dict) or result.get("merged") is not True:
            raise ToolError("GitHub did not confirm the merge.")
        sha = str(result.get("sha", ""))
        if not _SHA.fullmatch(sha):
            raise ToolError("The merge ran, but GitHub returned an unexpected response.")
        return ToolOutput(f"Merged #{args.number} as {sha}.")

    async def delete_context(args: ToolInput) -> str:
        assert isinstance(args, DeleteBranchInput)  # noqa: S101
        reference = await client.get_json(
            f"{repo_path(args.repo)}/git/ref/heads/{file_url_path(args.branch)}"
        )
        current = (reference.get("object") or {}).get("sha")
        if current == args.expected_sha:
            return "The branch is at the requested commit."
        return "WARNING: the branch is not at the requested commit."

    async def delete_branch(args: ToolInput) -> ToolOutput:
        """Delete a branch if it is still at the approved commit.

        GitHub has no conditional delete, so a small window remains between check and delete.
        """
        assert isinstance(args, DeleteBranchInput)  # noqa: S101
        base = repo_path(args.repo)
        repository = await client.get_json(base)
        if not isinstance(repository, dict) or not repository.get("default_branch"):
            raise ToolError("GitHub returned an unexpected response.")
        if repository["default_branch"] == args.branch:
            raise ToolError("The default branch cannot be deleted.")
        path = f"{base}/git/refs/heads/{file_url_path(args.branch)}"
        reference = await client.get_json(f"{base}/git/ref/heads/{file_url_path(args.branch)}")
        current = reference.get("object") if isinstance(reference, dict) else None
        if not isinstance(current, dict) or current.get("sha") != args.expected_sha:
            raise ToolError("The branch has moved since approval, so it was not deleted.")
        await client.send_json("DELETE", path)
        return ToolOutput(f"Deleted branch {args.branch}.")

    registry.register(
        ToolSpec(
            "github_merge_pull_request",
            "Merge a pull request at an exact head commit. Requires human approval.",
            RiskClass.DANGEROUS,
            MergeInput,
            merge,
            _merge_target,
            merge_context,
            merge_review if review_rules is not None and review_rules.enabled else None,
        )
    )
    registry.register(
        ToolSpec(
            "github_delete_branch",
            "Delete a permitted branch at an exact commit. Requires human approval.",
            RiskClass.DANGEROUS,
            DeleteBranchInput,
            delete_branch,
            _delete_target,
            delete_context,
        )
    )
