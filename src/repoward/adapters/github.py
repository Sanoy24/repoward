"""GitHub REST client. No tool input ever becomes a URL host; redirects are never followed."""

import json
import time
from typing import Any
from urllib.parse import quote

import httpx

from repoward.registry import ToolError

BASE_URL = "https://api.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "repoward"
TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 5_000_000
JSON_ACCEPT = "application/vnd.github+json"
TEXT_MATCH_ACCEPT = "application/vnd.github.text-match+json"


def repo_path(repo: str) -> str:
    owner, name = repo.split("/", 1)
    return f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"


def file_url_path(path: str) -> str:
    return "/".join(quote(segment, safe="") for segment in path.split("/"))


def _wait_seconds(response: httpx.Response) -> int | None:
    """How long GitHub asks us to wait, if this response is a rate limit."""
    retry_after = response.headers.get("retry-after", "")
    if retry_after.isdigit():
        return int(retry_after)
    if response.headers.get("x-ratelimit-remaining") == "0":
        reset = response.headers.get("x-ratelimit-reset", "")
        return max(1, int(reset) - int(time.time())) if reset.isdigit() else 60
    return None


def raise_for_status(response: httpx.Response) -> None:
    """Turn a failed response into a safe message. GitHub's own text is never passed on."""
    status = response.status_code
    if 200 <= status < 300:
        return
    if status in {403, 429}:
        wait = _wait_seconds(response)
        if wait is not None:
            raise ToolError(f"GitHub rate limit reached. Try again in {wait} seconds.")
    if status == 403:
        raise ToolError("GitHub refused the request; the token may lack permission.")
    if status == 401:
        raise ToolError("GitHub rejected the token; it may be invalid or expired.")
    if status == 404:
        raise ToolError("Not found, or the token cannot access it.")
    if status in {301, 302, 307, 308}:
        raise ToolError("GitHub answered with a redirect, which is not followed.")
    if status == 409:
        raise ToolError("GitHub reported a conflict; the branch may have moved.")
    if status == 422:
        raise ToolError("GitHub rejected the request as invalid.")
    raise ToolError(f"GitHub returned an unexpected status ({status}).")


class GitHubClient:
    def __init__(self, token: str | None) -> None:
        self._token = token
        self._http = httpx.AsyncClient(
            base_url=BASE_URL,
            follow_redirects=False,
            timeout=TIMEOUT_SECONDS,
            headers={
                "Accept": JSON_ACCEPT,
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            },
        )

    def _auth(self) -> dict[str, str]:
        if not self._token:
            raise ToolError("GITHUB_TOKEN is not set on the server.")
        return {"Authorization": f"Bearer {self._token}"}

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get_json(
        self, path: str, params: dict[str, Any] | None = None, accept: str = JSON_ACCEPT
    ) -> Any:
        """GET a JSON document."""
        return await self._request("GET", path, params, None, accept)

    async def send_json(self, method: str, path: str, body: dict[str, Any]) -> Any:
        """Send a change once. Writes are never retried, so a failure is never doubled."""
        return await self._request(method, path, None, body, JSON_ACCEPT)

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        body: dict[str, Any] | None,
        accept: str,
    ) -> Any:
        """Make one request, refusing response bodies over the size cap."""
        headers = {**self._auth(), "Accept": accept}
        try:
            async with self._http.stream(
                method, path, params=params, json=body, headers=headers
            ) as response:
                raise_for_status(response)
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ToolError("GitHub's response was too large to process.")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise ToolError("Could not reach GitHub.") from exc
        try:
            return json.loads(b"".join(chunks))
        except ValueError as exc:
            raise ToolError("GitHub returned a response that could not be read.") from exc

    async def get_redirect_location(self, path: str) -> str:
        """Request an endpoint that answers 302, returning where it points."""
        try:
            response = await self._http.get(path, headers=self._auth())
        except httpx.HTTPError as exc:
            raise ToolError("Could not reach GitHub.") from exc
        if response.status_code != 302:
            raise_for_status(response)
            raise ToolError("GitHub did not return the expected redirect.")
        location = response.headers.get("location")
        if not location:
            raise ToolError("GitHub's redirect had no destination.")
        return str(location)
