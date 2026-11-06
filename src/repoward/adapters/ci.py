"""Job log download: the one place a redirect is followed, under strict rules."""

import re
from urllib.parse import urlsplit

import httpx

from repoward.adapters.github import TIMEOUT_SECONDS, USER_AGENT, GitHubClient, repo_path
from repoward.registry import ToolError

# Observed from a real job-log redirect. An unknown host fails closed; update this if GitHub
# moves its log storage.
_LOG_HOST = re.compile(r"productionresultssa\d+\.blob\.core\.windows\.net")
MAX_LOG_DOWNLOAD_BYTES = 20_000_000
LOG_TAIL_BYTES = 200_000


async def fetch_job_log_tail(client: GitHubClient, repo: str, job_id: int) -> tuple[str, bool]:
    """Return the end of a job's log, where failures are, and whether anything was cut."""
    location = await client.get_redirect_location(f"{repo_path(repo)}/actions/jobs/{job_id}/logs")
    parts = urlsplit(location)
    if parts.scheme != "https" or not _LOG_HOST.fullmatch(parts.hostname or ""):
        raise ToolError("GitHub redirected the log download to an unrecognized host.")

    tail = bytearray()
    total = 0
    cut = False
    # A separate client, so the GitHub token can never be sent to the storage host.
    try:
        async with (
            httpx.AsyncClient(
                follow_redirects=False,
                timeout=TIMEOUT_SECONDS,
                headers={"User-Agent": USER_AGENT},
            ) as http,
            http.stream("GET", location) as response,
        ):
            if response.status_code != 200:
                raise ToolError("The job log could not be downloaded.")
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                tail += chunk
                if len(tail) > LOG_TAIL_BYTES:
                    del tail[: len(tail) - LOG_TAIL_BYTES]
                    cut = True
                if total > MAX_LOG_DOWNLOAD_BYTES:
                    raise ToolError("The job log is too large to download.")
    except httpx.HTTPError as exc:
        raise ToolError("The job log could not be downloaded.") from exc
    return tail.decode("utf-8", "replace"), cut
