"""Signing keys from one configured JWKS address.

The key id in a token is untrusted, so unknown ids can only trigger a refetch once in a while. Keys
named by a token itself (jku, x5u) are never used. Only asymmetric signing keys are kept.
"""

import json
import sys
import time
from collections.abc import Awaitable, Callable

import anyio
import httpx
import jwt

_REFRESH_SECONDS = 3600.0
_MIN_REFETCH_SECONDS = 30.0
_MAX_STALE_SECONDS = 86_400.0
_TIMEOUT_SECONDS = 5.0
_MAX_BYTES = 1_048_576
_ASYMMETRIC_KEY_TYPES = {"RSA", "EC", "OKP"}

Fetch = Callable[[], Awaitable[bytes]]


def _parse(body: bytes) -> dict[str, jwt.PyJWK]:
    document = json.loads(body)
    items = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise ValueError("no keys")
    keys: dict[str, jwt.PyJWK] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        kid = item.get("kid")
        if (
            not isinstance(kid, str)
            or item.get("kty") not in _ASYMMETRIC_KEY_TYPES
            or item.get("use", "sig") != "sig"
        ):
            continue
        try:
            keys[kid] = jwt.PyJWK.from_dict(item)
        except jwt.PyJWTError:
            continue  # One key this library cannot use should not take down the others.
    return keys


class JwksKeys:
    def __init__(
        self,
        uri: str,
        fetch: Fetch | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._uri = uri
        self._fetch = fetch or self._fetch_over_https
        self._clock = clock
        self._keys: dict[str, jwt.PyJWK] = {}
        self._loaded_at: float | None = None
        self._tried_at: float | None = None
        self._lock = anyio.Lock()

    async def _fetch_over_https(self) -> bytes:
        async with (
            httpx.AsyncClient(follow_redirects=False, timeout=_TIMEOUT_SECONDS) as client,
            client.stream("GET", self._uri) as response,
        ):
            response.raise_for_status()
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > _MAX_BYTES:
                    raise ValueError("JWKS is too large")
            return body

    def _may_fetch(self) -> bool:
        return self._tried_at is None or self._clock() - self._tried_at >= _MIN_REFETCH_SECONDS

    async def _refresh(self) -> None:
        async with self._lock:
            if not self._may_fetch():
                return
            self._tried_at = self._clock()
            try:
                self._keys = _parse(await self._fetch())
                self._loaded_at = self._clock()
            except (httpx.HTTPError, ValueError, OSError) as exc:
                # Tokens signed with known keys keep working through a short outage.
                print(f"repoward: could not refresh JWKS: {type(exc).__name__}", file=sys.stderr)

    async def get(self, kid: str) -> jwt.PyJWK | None:
        """The key with this id, or None. Keys too old to trust are not used."""
        age = None if self._loaded_at is None else self._clock() - self._loaded_at
        if kid not in self._keys or age is None or age >= _REFRESH_SECONDS:
            await self._refresh()
            age = None if self._loaded_at is None else self._clock() - self._loaded_at
        if age is None or age >= _MAX_STALE_SECONDS:
            return None
        return self._keys.get(kid)
