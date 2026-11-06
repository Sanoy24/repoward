"""GitHub write tools. Limits and branch rules are enforced by policy before any of this runs."""

import re
from typing import Annotated, Any
from urllib.parse import quote

from pydantic import AfterValidator, Field, model_validator

from repoward.adapters.github import GitHubClient, file_url_path, repo_path
from repoward.catalog import RiskClass
from repoward.policy.engine import Target
from repoward.registry import ToolError, ToolInput, ToolOutput, ToolRegistry, ToolSpec
from repoward.validation import GitRef, RepoName, RepoPath

_SHA = re.compile(r"[0-9a-f]{40}")
_MAX_BODY_CHARS = 65_536
# The only file mode written. Symlink and submodule modes could point at denied paths.
_FILE_MODE = "100644"


def _single_line_or_text(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be empty")
    if any((ord(char) < 32 and char not in "\n\t") or 127 <= ord(char) < 160 for char in value):
        raise ValueError("must not contain control characters")
    return value


Message = Annotated[str, AfterValidator(_single_line_or_text), Field(max_length=5_000)]
Title = Annotated[str, AfterValidator(_single_line_or_text), Field(max_length=256)]


class CreateBranchInput(ToolInput):
    repo: RepoName
    branch: GitRef
    base: GitRef


class FileChange(ToolInput):
    path: RepoPath
    content: str


class CommitFilesInput(ToolInput):
    repo: RepoName
    branch: GitRef
    message: Message
    files: list[FileChange] = Field(default_factory=list, max_length=1_000)
    deletions: list[RepoPath] = Field(default_factory=list, max_length=1_000)

    @model_validator(mode="after")
    def _has_distinct_changes(self) -> "CommitFilesInput":
        paths = [change.path for change in self.files] + list(self.deletions)
        if not paths:
            raise ValueError("must change at least one file")
        if len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("must not change the same path twice")
        return self


class CreatePullRequestInput(ToolInput):
    repo: RepoName
    title: Title
    head: GitRef
    base: GitRef
    body: str = Field(default="", max_length=_MAX_BODY_CHARS)
    draft: bool = True


class CommentInput(ToolInput):
    repo: RepoName
    number: int = Field(ge=1, le=2_147_483_647)
    body: str = Field(min_length=1, max_length=_MAX_BODY_CHARS)


def _branch_target(args: ToolInput) -> Target:
    assert isinstance(args, CreateBranchInput)  # noqa: S101
    return Target(repo=args.repo, write_branches=[args.branch])


def _commit_target(args: ToolInput) -> Target:
    assert isinstance(args, CommitFilesInput)  # noqa: S101
    contents = [change.content for change in args.files]
    return Target(
        repo=args.repo,
        paths=[change.path for change in args.files] + list(args.deletions),
        write_branches=[args.branch],
        commit_files=len(args.files) + len(args.deletions),
        commit_bytes=sum(len(text.encode("utf-8", "replace")) for text in contents),
        outbound=[args.message, *contents],
    )


def _pull_request_target(args: ToolInput) -> Target:
    assert isinstance(args, CreatePullRequestInput)  # noqa: S101
    return Target(
        repo=args.repo,
        write_branches=[args.head],
        non_draft=not args.draft,
        outbound=[args.title, args.body],
    )


def _comment_target(args: ToolInput) -> Target:
    assert isinstance(args, CommentInput)  # noqa: S101
    return Target(repo=args.repo, outbound=[args.body])


def _sha_of(document: Any, *keys: str) -> str:
    """Pull a commit or tree SHA out of a response, refusing anything that is not one."""
    value = document
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ToolError("GitHub returned an unexpected response.")
    return value


def _ref_path(branch: str) -> str:
    return f"heads/{file_url_path(branch)}"


def register(registry: ToolRegistry, client: GitHubClient) -> None:
    async def create_branch(args: ToolInput) -> ToolOutput:
        assert isinstance(args, CreateBranchInput)  # noqa: S101
        base = repo_path(args.repo)
        sha = args.base
        if not _SHA.fullmatch(sha):
            commit = await client.get_json(f"{base}/commits/{file_url_path(args.base)}")
            sha = _sha_of(commit, "sha")
        await client.send_json(
            "POST", f"{base}/git/refs", {"ref": f"refs/heads/{args.branch}", "sha": sha}
        )
        return ToolOutput(f"Created branch {args.branch} at {sha}.")

    async def commit_files(args: ToolInput) -> ToolOutput:
        """Commit every change at once, as a fast-forward. Force is never used."""
        assert isinstance(args, CommitFilesInput)  # noqa: S101
        base = repo_path(args.repo)
        reference = await client.get_json(f"{base}/git/ref/{_ref_path(args.branch)}")
        parent = _sha_of(reference, "object", "sha")
        parent_commit = await client.get_json(f"{base}/git/commits/{parent}")
        base_tree = _sha_of(parent_commit, "tree", "sha")
        entries: list[dict[str, Any]] = [
            {"path": change.path, "mode": _FILE_MODE, "type": "blob", "content": change.content}
            for change in args.files
        ]
        entries += [
            {"path": path, "mode": _FILE_MODE, "type": "blob", "sha": None}
            for path in args.deletions
        ]
        tree = await client.send_json(
            "POST", f"{base}/git/trees", {"base_tree": base_tree, "tree": entries}
        )
        commit = await client.send_json(
            "POST",
            f"{base}/git/commits",
            {"message": args.message, "tree": _sha_of(tree, "sha"), "parents": [parent]},
        )
        sha = _sha_of(commit, "sha")
        await client.send_json(
            "PATCH", f"{base}/git/refs/{_ref_path(args.branch)}", {"sha": sha, "force": False}
        )
        return ToolOutput(f"Committed {len(entries)} changes to {args.branch} as {sha}.")

    async def create_pull_request(args: ToolInput) -> ToolOutput:
        assert isinstance(args, CreatePullRequestInput)  # noqa: S101
        result = await client.send_json(
            "POST",
            f"{repo_path(args.repo)}/pulls",
            {
                "title": args.title,
                "head": args.head,
                "base": args.base,
                "body": args.body,
                "draft": args.draft,
            },
        )
        if not isinstance(result, dict):
            raise ToolError("GitHub returned an unexpected response.")
        number = int(result["number"])
        if args.draft and result.get("draft") is not True:
            raise ToolError(f"Pull request #{number} was created but is not a draft. Check it.")
        kind = "draft pull request" if args.draft else "pull request"
        owner, name = args.repo.split("/", 1)
        url = f"https://github.com/{quote(owner)}/{quote(name)}/pull/{number}"
        return ToolOutput(f"Created {kind} #{number}: {url}")

    async def comment(args: ToolInput) -> ToolOutput:
        assert isinstance(args, CommentInput)  # noqa: S101
        result = await client.send_json(
            "POST",
            f"{repo_path(args.repo)}/issues/{args.number}/comments",
            {"body": args.body},
        )
        if not isinstance(result, dict):
            raise ToolError("GitHub returned an unexpected response.")
        return ToolOutput(f"Added comment {int(result['id'])} to #{args.number}.")

    registry.register(
        ToolSpec(
            "github_create_branch",
            "Create a branch from a branch, tag or commit SHA.",
            RiskClass.WRITE,
            CreateBranchInput,
            create_branch,
            _branch_target,
        )
    )
    registry.register(
        ToolSpec(
            "github_commit_files",
            "Commit text file changes and deletions to a permitted branch as one commit.",
            RiskClass.WRITE,
            CommitFilesInput,
            commit_files,
            _commit_target,
        )
    )
    registry.register(
        ToolSpec(
            "github_create_pull_request",
            "Open a pull request from a permitted branch. Draft by default.",
            RiskClass.WRITE,
            CreatePullRequestInput,
            create_pull_request,
            _pull_request_target,
        )
    )
    registry.register(
        ToolSpec(
            "github_comment",
            "Comment on an issue or pull request.",
            RiskClass.WRITE,
            CommentInput,
            comment,
            _comment_target,
        )
    )
