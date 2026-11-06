"""Read-only GitHub tools. Every piece of text GitHub users control is returned as untrusted."""

import base64
import binascii
import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field

from repoward.adapters.github import TEXT_MATCH_ACCEPT, GitHubClient, file_url_path, repo_path
from repoward.catalog import RiskClass
from repoward.policy.engine import Target
from repoward.policy.loader import CompiledPolicy
from repoward.registry import ToolError, ToolInput, ToolOutput, ToolRegistry, ToolSpec
from repoward.sanitize import ContentKind, UntrustedContent
from repoward.validation import GitRef, RepoName, RepoPath, normalize_path

MAX_FILE_BYTES = 1_000_000
_REGULAR_FILE_MODES = {"100644", "100755"}
_TREE_MODE = "040000"
_MAX_COMMENTS = 30
_SHA = re.compile(r"[0-9a-f]{40}")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_LABEL = re.compile(r"[^,\x00-\x1f]{1,50}")
_QUALIFIER = re.compile(r"[A-Za-z_]+:")
_OPERATOR = re.compile(r"\b(?:AND|OR|NOT)\b")


def _validate_login(value: str) -> str:
    if not _LOGIN.fullmatch(value):
        raise ValueError("must be a GitHub username")
    return value


def _validate_label(value: str) -> str:
    if not _LABEL.fullmatch(value):
        raise ValueError("must be 1 to 50 characters with no commas")
    return value


def _validate_query(value: str) -> str:
    """Refuse anything that could widen a search beyond the requested repository."""
    if _QUALIFIER.search(value) or _OPERATOR.search(value) or "(" in value or ")" in value:
        raise ValueError("must be plain search terms, without qualifiers, operators or parentheses")
    if not value.strip():
        raise ValueError("must contain a search term")
    return value


class ListIssuesInput(ToolInput):
    repo: RepoName
    state: Literal["open", "closed", "all"] = "open"
    labels: list[Annotated[str, AfterValidator(_validate_label)]] = Field(
        default_factory=list, max_length=10
    )
    assignee: Annotated[str, AfterValidator(_validate_login)] | None = None
    page: int = Field(default=1, ge=1, le=100)
    per_page: int = Field(default=30, ge=1, le=50)


class GetIssueInput(ToolInput):
    repo: RepoName
    number: int = Field(ge=1, le=2_147_483_647)


class SearchCodeInput(ToolInput):
    repo: RepoName
    query: Annotated[str, AfterValidator(_validate_query), Field(max_length=256)]
    page: int = Field(default=1, ge=1, le=10)
    per_page: int = Field(default=20, ge=1, le=30)


class GetFileInput(ToolInput):
    repo: RepoName
    path: RepoPath
    ref: GitRef | None = None


def _repo_target(args: ToolInput) -> Target:
    return Target(repo=getattr(args, "repo", None))


def _file_target(args: ToolInput) -> Target:
    assert isinstance(args, GetFileInput)  # noqa: S101
    return Target(repo=args.repo, paths=[args.path])


def _label_names(item: dict[str, Any]) -> str:
    names = [str(label.get("name", "")) for label in item.get("labels", [])]
    return ", ".join(names)


def register(registry: ToolRegistry, client: GitHubClient, policy: CompiledPolicy) -> None:
    async def list_issues(args: ToolInput) -> ToolOutput:
        assert isinstance(args, ListIssuesInput)  # noqa: S101
        params: dict[str, Any] = {
            "state": args.state,
            "page": args.page,
            "per_page": args.per_page,
        }
        if args.labels:
            params["labels"] = ",".join(args.labels)
        if args.assignee:
            params["assignee"] = args.assignee
        items = await client.get_json(f"{repo_path(args.repo)}/issues", params)
        if not isinstance(items, list):
            raise ToolError("GitHub returned an unexpected response.")
        lines = [f"{len(items)} results on page {args.page}."]
        titles = []
        for item in items:
            kind = "pull_request" if "pull_request" in item else "issue"
            lines.append(
                f"#{int(item['number'])} {kind} state={item.get('state')} "
                f"author_association={item.get('author_association')}"
            )
            titles.append(f"#{int(item['number'])}: {item.get('title')} [{_label_names(item)}]")
        untrusted = (
            (UntrustedContent(f"github-issues:{args.repo}", "\n".join(titles)),) if titles else ()
        )
        return ToolOutput("\n".join(lines), untrusted)

    async def get_issue(args: ToolInput) -> ToolOutput:
        assert isinstance(args, GetIssueInput)  # noqa: S101
        base = f"{repo_path(args.repo)}/issues/{args.number}"
        issue = await client.get_json(base)
        comments = await client.get_json(f"{base}/comments", {"per_page": _MAX_COMMENTS})
        if not isinstance(issue, dict) or not isinstance(comments, list):
            raise ToolError("GitHub returned an unexpected response.")
        kind = "pull_request" if "pull_request" in issue else "issue"
        total = int(issue.get("comments", len(comments)))
        lines = [
            f"#{args.number} {kind} state={issue.get('state')} "
            f"author_association={issue.get('author_association')}",
            f"Showing {len(comments)} of {total} comments.",
        ]
        source = f"github-issue:{args.repo}#{args.number}"
        author = (issue.get("user") or {}).get("login")
        parts = [
            UntrustedContent(
                source,
                f"Title: {issue.get('title')}\nAuthor: {author}\n"
                f"Labels: {_label_names(issue)}\n\n{issue.get('body') or ''}",
                ContentKind.MARKUP,
            )
        ]
        for comment in comments:
            comment_id = int(comment["id"])
            lines.append(
                f"Comment {comment_id} author_association={comment.get('author_association')}"
            )
            parts.append(
                UntrustedContent(
                    f"github-comment:{args.repo}#{args.number}/{comment_id}",
                    f"Author: {(comment.get('user') or {}).get('login')}\n\n"
                    f"{comment.get('body') or ''}",
                    ContentKind.MARKUP,
                )
            )
        return ToolOutput("\n".join(lines), tuple(parts))

    async def search_code(args: ToolInput) -> ToolOutput:
        assert isinstance(args, SearchCodeInput)  # noqa: S101
        result = await client.get_json(
            "/search/code",
            {"q": f"{args.query} repo:{args.repo}", "page": args.page, "per_page": args.per_page},
            accept=TEXT_MATCH_ACCEPT,
        )
        if not isinstance(result, dict):
            raise ToolError("GitHub returned an unexpected response.")
        kept: list[str] = []
        withheld = 0
        for item in result.get("items", []):
            # The query is sanitized, but this filter is what actually enforces the scope.
            full_name = str((item.get("repository") or {}).get("full_name", ""))
            path = str(item.get("path", ""))
            if full_name.casefold() != args.repo.casefold() or _path_is_withheld(policy, path):
                withheld += 1
                continue
            fragments = [str(match.get("fragment", "")) for match in item.get("text_matches", [])]
            kept.append(f"File: {path}\n" + "\n---\n".join(fragments))
        lines = [
            f"{len(kept)} results returned; {withheld} withheld by policy.",
            f"total_count={int(result.get('total_count', 0))} "
            f"incomplete_results={bool(result.get('incomplete_results'))}",
            "Code search covers the default branch and files under 384 KB.",
        ]
        untrusted = (
            (UntrustedContent(f"github-search:{args.repo}", "\n\n".join(kept)),) if kept else ()
        )
        return ToolOutput("\n".join(lines), untrusted)

    async def find_regular_file(args: GetFileInput) -> tuple[str, int]:
        """Walk the Git tree one folder at a time, returning the file's blob SHA and size.

        The tree is the only source that shows real modes. For a symlink to a normal file, the
        contents API returns the target's text and reports type "file", in folder listings too,
        so it would hand over denied files through a link at an allowed path.
        """
        base = repo_path(args.repo)
        tree_id = args.ref
        if tree_id is None:
            repository = await client.get_json(base)
            tree_id = (
                str(repository.get("default_branch", "")) if isinstance(repository, dict) else ""
            )
            if not tree_id:
                raise ToolError("GitHub returned an unexpected response.")
        segments = args.path.split("/")
        for index, segment in enumerate(segments):
            tree = await client.get_json(f"{base}/git/trees/{file_url_path(tree_id)}")
            if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
                raise ToolError("GitHub returned an unexpected response.")
            if tree.get("truncated"):
                raise ToolError("That directory is too large to read safely.")
            entry = next((item for item in tree["tree"] if item.get("path") == segment), None)
            if entry is None:
                raise ToolError("File not found.")
            sha = str(entry.get("sha", ""))
            mode = entry.get("mode")
            if index < len(segments) - 1:
                if mode != _TREE_MODE:
                    raise ToolError("That path is not a regular file.")
                if not _SHA.fullmatch(sha):
                    raise ToolError("GitHub returned an unexpected response.")
                tree_id = sha
                continue
            if mode not in _REGULAR_FILE_MODES:
                raise ToolError("That path is not a regular file.")
            if not _SHA.fullmatch(sha):
                raise ToolError("GitHub returned an unexpected response.")
            return sha, int(entry.get("size", 0))
        raise ToolError("File not found.")

    async def get_file(args: ToolInput) -> ToolOutput:
        assert isinstance(args, GetFileInput)  # noqa: S101
        sha, size = await find_regular_file(args)
        if size > MAX_FILE_BYTES:
            raise ToolError(f"The file is larger than the {MAX_FILE_BYTES} byte limit.")
        blob = await client.get_json(f"{repo_path(args.repo)}/git/blobs/{sha}")
        if not isinstance(blob, dict) or blob.get("encoding") != "base64":
            raise ToolError("GitHub returned an unexpected response.")
        try:
            raw = base64.b64decode(str(blob.get("content", "")))
            content = raw.decode("utf-8")
        except (binascii.Error, ValueError) as exc:
            raise ToolError("The file is binary and cannot be returned as text.") from exc
        return ToolOutput(
            f"File {args.path} sha={sha} bytes={len(raw)}.",
            (UntrustedContent(f"github-file:{args.repo}/{args.path}", content, ContentKind.FILE),),
        )

    registry.register(
        ToolSpec(
            "github_list_issues",
            "List issues and pull requests in a repository.",
            RiskClass.READ,
            ListIssuesInput,
            list_issues,
            _repo_target,
        )
    )
    registry.register(
        ToolSpec(
            "github_get_issue",
            "Read an issue or pull request with its comments. The text is untrusted.",
            RiskClass.READ,
            GetIssueInput,
            get_issue,
            _repo_target,
        )
    )
    registry.register(
        ToolSpec(
            "github_search_code",
            "Search code in one repository. Takes plain terms, not qualifiers. Default branch "
            "only, files under 384 KB. GitHub allows 10 searches per minute.",
            RiskClass.READ,
            SearchCodeInput,
            search_code,
            _repo_target,
        )
    )
    registry.register(
        ToolSpec(
            "github_get_file",
            "Read one regular text file. Symlinks and submodules are refused.",
            RiskClass.READ,
            GetFileInput,
            get_file,
            _file_target,
        )
    )


def _path_is_withheld(policy: CompiledPolicy, path: str) -> bool:
    try:
        return policy.path_is_denied(normalize_path(path))
    except ValueError:
        return True
