"""HTTP mode identity: this server is an OAuth resource server that verifies JWTs.

Every request is authenticated, and a client's token is never passed on to GitHub. A caller's
identity and role are worked out from the token on each call, so a changed role applies at once.
"""

import json
import sys
from typing import Any

import jwt
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from repoward.adapters.jwks import JwksKeys
from repoward.policy.loader import CompiledPolicy
from repoward.policy.models import HttpAuth
from repoward.principal import Principal, resolve_role

_MAX_TOKEN_CHARS = 16_384
_REQUIRED_CLAIMS = ["exp", "iss", "aud", "sub"]
NO_IDENTITY = "identity.none"


class _Rejected(Exception):
    """A token that failed a check made before the signature."""


def _log_rejection(reason: str) -> None:
    """Rejections stay out of the audit chain, so anonymous traffic cannot flood it."""
    print(json.dumps({"event": "auth_rejected", "reason": reason}), file=sys.stderr, flush=True)


class JwtVerifier:
    def __init__(self, rules: HttpAuth, role_claim: str, keys: JwksKeys | None = None) -> None:
        self._rules = rules
        self._role_claim = role_claim
        self._keys = keys or JwksKeys(rules.jwks_uri)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return the token's details if it is valid for this server, otherwise None."""
        try:
            return await self._verify(token)
        except (jwt.PyJWTError, _Rejected) as exc:
            _log_rejection(type(exc).__name__ if isinstance(exc, jwt.PyJWTError) else str(exc))
            return None

    async def _verify(self, token: str) -> AccessToken:
        if len(token) > _MAX_TOKEN_CHARS:
            raise _Rejected("token_too_large")
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        # Checked first, so that a junk token cannot cause a key fetch.
        if algorithm not in self._rules.algorithms:
            raise _Rejected("algorithm_not_allowed")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise _Rejected("no_key_id")
        key = await self._keys.get(kid)
        if key is None:
            raise _Rejected("unknown_key_id")
        if key.algorithm_name != algorithm:
            raise _Rejected("key_algorithm_mismatch")
        claims = jwt.decode(
            token,
            key.key,
            algorithms=[algorithm],
            issuer=self._rules.issuer,
            audience=self._rules.audience,
            leeway=self._rules.leeway_seconds,
            options={"require": _REQUIRED_CLAIMS},
        )
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject:
            raise _Rejected("bad_subject")
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or subject),
            scopes=[],
            expires_at=int(claims["exp"]) + self._rules.leeway_seconds,
            resource=self._rules.resource_server_url,
            subject=subject,
            claims={"iss": claims["iss"], self._role_claim: claims.get(self._role_claim)},
        )


def _groups(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return ()


def principal_from_request(request: Any, compiled: CompiledPolicy) -> Principal:
    """Who is making this request. With no verified token, a principal that is always refused."""
    scope = getattr(request, "scope", None)
    user = scope.get("user") if isinstance(scope, dict) else None
    if not isinstance(user, AuthenticatedUser):
        return Principal("unauthenticated", "", identity_problem=NO_IDENTITY)
    token = user.access_token
    claims = token.claims or {}
    identity_map = compiled.policy.identity_map
    groups = _groups(claims.get(identity_map.claim)) if identity_map is not None else ()
    role, problem = resolve_role(identity_map, groups)
    return Principal(f"{claims.get('iss')}|{token.subject}", role, groups, problem)
