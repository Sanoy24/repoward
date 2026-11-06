"""Read-only CI tools.

Fine-grained tokens are documented as unable to call the Checks API, so status comes from the
Actions and commit status endpoints. Checks reported only through the Checks API do not appear.
"""

import re
from typing import Any

from pydantic import Field

from repoward.adapters.ci import fetch_job_log_tail
from repoward.adapters.github import GitHubClient, file_url_path, repo_path
from repoward.catalog import RiskClass
from repoward.policy.engine import Target
from repoward.registry import ToolError, ToolInput, ToolOutput, ToolRegistry, ToolSpec
from repoward.sanitize import ContentKind, UntrustedContent
from repoward.validation import GitRef, RepoName

_MAX_RUNS_WITH_JOBS = 3
_MAX_LOG_CHARS = 50_000
_SHA = re.compile(r"[0-9a-f]{40}")
_WORD = re.compile(r"[a-z_]{1,30}")


class CiStatusInput(ToolInput):
    repo: RepoName
    ref: GitRef


class JobLogsInput(ToolInput):
    repo: RepoName
    job_id: int = Field(ge=1)


def _repo_target(args: ToolInput) -> Target:
    return Target(repo=getattr(args, "repo", None))


def _enum(value: Any) -> str:
    """GitHub's status words are safe to show as trusted text; anything else is not."""
    text = str(value)
    return text if _WORD.fullmatch(text) else "unknown"


def register(registry: ToolRegistry, client: GitHubClient) -> None:
    async def ci_status(args: ToolInput) -> ToolOutput:
        assert isinstance(args, CiStatusInput)  # noqa: S101
        base = repo_path(args.repo)
        ref_filter = "head_sha" if _SHA.fullmatch(args.ref) else "branch"
        runs = await client.get_json(f"{base}/actions/runs", {ref_filter: args.ref, "per_page": 10})
        status = await client.get_json(f"{base}/commits/{file_url_path(args.ref)}/status")
        if not isinstance(runs, dict) or not isinstance(status, dict):
            raise ToolError("GitHub returned an unexpected response.")

        lines = [
            f"Combined commit status: {_enum(status.get('state'))}.",
            "Third-party checks reported only through the Checks API are not shown.",
        ]
        names: list[str] = []
        for index, run in enumerate(runs.get("workflow_runs", [])):
            run_id = int(run["id"])
            lines.append(
                f"Run {run_id} status={_enum(run.get('status'))} "
                f"conclusion={_enum(run.get('conclusion'))}"
            )
            names.append(f"Run {run_id}: {run.get('name')} on {run.get('head_branch')}")
            if index >= _MAX_RUNS_WITH_JOBS:
                continue
            jobs = await client.get_json(f"{base}/actions/runs/{run_id}/jobs")
            for job in jobs.get("jobs", []) if isinstance(jobs, dict) else []:
                job_id = int(job["id"])
                lines.append(
                    f"  Job {job_id} status={_enum(job.get('status'))} "
                    f"conclusion={_enum(job.get('conclusion'))}"
                )
                names.append(f"  Job {job_id}: {job.get('name')}")
        for entry in status.get("statuses", []):
            lines.append(f"Status state={_enum(entry.get('state'))}")
            names.append(f"Status: {entry.get('context')}: {entry.get('description')}")
        untrusted = (UntrustedContent(f"github-ci:{args.repo}", "\n".join(names)),) if names else ()
        return ToolOutput("\n".join(lines), untrusted)

    async def job_logs(args: ToolInput) -> ToolOutput:
        assert isinstance(args, JobLogsInput)  # noqa: S101
        text, cut = await fetch_job_log_tail(client, args.repo, args.job_id)
        shortened = cut or len(text) > _MAX_LOG_CHARS
        tail = text[-_MAX_LOG_CHARS:]
        note = "Showing the end of the log." if shortened else "Showing the whole log."
        return ToolOutput(
            f"Job {args.job_id}. {note}",
            (UntrustedContent(f"github-job-log:{args.repo}/{args.job_id}", tail, ContentKind.LOG),),
        )

    registry.register(
        ToolSpec(
            "ci_get_status",
            "Get workflow runs, jobs and commit status for a commit SHA or branch.",
            RiskClass.READ,
            CiStatusInput,
            ci_status,
            _repo_target,
        )
    )
    registry.register(
        ToolSpec(
            "ci_get_job_logs",
            "Read the end of a job's log, with secrets redacted. The text is untrusted.",
            RiskClass.READ,
            JobLogsInput,
            job_logs,
            _repo_target,
        )
    )
