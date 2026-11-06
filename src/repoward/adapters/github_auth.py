"""GitHub App credentials: a short-lived token for each repository and permission set.

GitHub enforces these tokens' limits itself, so a read tool's token cannot write even if this
server has a bug. The App's private key remains a long-lived secret and must be kept from the agent.
"""

import os
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import jwt

from repoward.adapters.github import raise_for_status
from repoward.registry import ToolError
from repoward.scope import CallScope

KEY_ENV = "GITHUB_APP_PRIVATE_KEY"
KEY_FILE_ENV = "GITHUB_APP_PRIVATE_KEY_FILE"
_CACHE_SECONDS = 600.0
_EXPIRY_MARGIN_SECONDS = 60.0
_JWT_BACKDATE_SECONDS = 60
_JWT_LIFETIME_SECONDS = 540
_RANK = {"read": 1, "write": 2, "admin": 3}


class AppConfigError(Exception):
    """The GitHub App settings cannot be used."""


def load_private_key() -> str:
    """Read the App's key from the environment. The key itself never appears in an error."""
    path = os.environ.get(KEY_FILE_ENV)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise AppConfigError(f"cannot read the key file named by {KEY_FILE_ENV}") from exc
    key = os.environ.get(KEY_ENV)
    if not key:
        raise AppConfigError(f"github_auth mode 'app' needs {KEY_FILE_ENV} or {KEY_ENV}")
    return key


class AppTokens:
    def __init__(
        self,
        client_id: str,
        installation_id: int,
        private_key: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client_id = client_id
        self._installation_id = installation_id
        self._key = private_key
        self._clock = clock
        self._cache: dict[tuple[str, tuple[tuple[str, str], ...]], tuple[str, float]] = {}
        self._identity: str | None = None
        self._app_jwt()  # Refuse a bad key at startup, not on the first tool call.

    def _app_jwt(self) -> str:
        now = int(self._clock())
        try:
            return jwt.encode(
                {
                    "iat": now - _JWT_BACKDATE_SECONDS,
                    "exp": now + _JWT_LIFETIME_SECONDS,
                    "iss": self._client_id,
                },
                self._key,
                algorithm="RS256",
            )
        except (ValueError, TypeError, jwt.PyJWTError):
            raise AppConfigError("the GitHub App private key could not be used") from None

    async def token(self, scope: CallScope | None, http: httpx.AsyncClient) -> str:
        """A token for exactly this call's repository and permissions. Fails closed."""
        if scope is None or scope.repo is None or not scope.permissions:
            raise ToolError("This call has no repository scope, so no token was issued.")
        key = (scope.repo.casefold(), tuple(sorted(scope.permissions.items())))
        cached = self._cache.get(key)
        if cached is not None and self._clock() < cached[1]:
            return cached[0]
        token, expires_at = await self._mint(scope, http)
        self._cache[key] = (token, min(self._clock() + _CACHE_SECONDS, expires_at))
        return token

    async def _mint(self, scope: CallScope, http: httpx.AsyncClient) -> tuple[str, float]:
        assert scope.repo is not None  # noqa: S101
        name = scope.repo.split("/", 1)[1]
        try:
            response = await http.post(
                f"/app/installations/{self._installation_id}/access_tokens",
                headers={"Authorization": f"Bearer {self._app_jwt()}"},
                json={"repositories": [name], "permissions": dict(scope.permissions)},
            )
        except httpx.HTTPError as exc:
            raise ToolError("Could not reach GitHub.") from exc
        if response.status_code == 422:
            raise ToolError("The GitHub App does not have the access this tool needs.")
        raise_for_status(response)
        return self._check(response.json(), scope)

    def _check(self, document: Any, scope: CallScope) -> tuple[str, float]:
        """Confirm GitHub issued what was asked for, and nothing wider."""
        unexpected = ToolError("GitHub issued a token that does not match the request.")
        if not isinstance(document, dict):
            raise unexpected
        assert scope.repo is not None  # noqa: S101
        repositories = document.get("repositories")
        names = (
            [str(item.get("full_name", "")).casefold() for item in repositories]
            if isinstance(repositories, list)
            else []
        )
        if names != [scope.repo.casefold()]:
            raise unexpected
        granted = document.get("permissions")
        if not isinstance(granted, dict):
            raise unexpected
        for permission, level in granted.items():
            allowed = scope.permissions.get(permission)
            if permission == "metadata" and allowed is None:
                allowed = "read"
            if allowed is None or _RANK.get(str(level), 99) > _RANK.get(allowed, 0):
                raise unexpected
        token = document.get("token")
        expires = document.get("expires_at")
        if not isinstance(token, str) or not token or not isinstance(expires, str):
            raise unexpected
        try:
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise unexpected from None
        return token, expires_at - _EXPIRY_MARGIN_SECONDS

    async def identity(self, http: httpx.AsyncClient) -> str:
        """The login this App acts as on GitHub."""
        if self._identity is None:
            try:
                response = await http.get(
                    "/app", headers={"Authorization": f"Bearer {self._app_jwt()}"}
                )
            except httpx.HTTPError as exc:
                raise ToolError("Could not reach GitHub.") from exc
            raise_for_status(response)
            slug = response.json().get("slug") if response.content else None
            if not isinstance(slug, str) or not slug:
                raise ToolError("GitHub returned an unexpected response.")
            self._identity = f"{slug}[bot]"
        return self._identity
