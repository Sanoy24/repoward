"""Flow guard: decide each write by what this principal has already read.

Per-tool rules cannot stop the toxic flow, where a malicious public issue steers an agent to
read a private repository and publish it, because each call is allowed on its own. This guard
remembers two facts taken from GitHub, not from scanning content:

- private_read: the principal read content from a private repository.
- untrusted_input: the principal read text from an author outside the trusted associations.

State is keyed by principal and survives restarts. Only a person can clear it, through the
CLI. No tool can, and no agent-supplied value can start a clean slate, because an injected
agent would simply do that while the data stayed in its context.

The limits: this only sees this server's tools, and content can stay in an agent's context after
a label expires.
"""

import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import anyio.to_thread

from repoward.policy.engine import Decision, Effect
from repoward.policy.models import FlowGuardRules
from repoward.storage import transaction

PRIVATE_READ = "private_read"
UNTRUSTED_INPUT = "untrusted_input"
TOUCHED_REPO = "touched_repo"
_VISIBILITY_TTL_SECONDS = 60.0
_SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_labels (
    principal TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (principal, kind, source)
)
"""


class FlowStoreError(Exception):
    """Flow state could not be read or saved. Callers must fail closed."""


@dataclass(frozen=True)
class Taint:
    """Text a tool returned from someone. No association means treat as untrusted."""

    source: str
    association: str | None = None


@dataclass(frozen=True)
class FlowLabel:
    principal: str
    kind: str
    source: str
    first_seen: float
    expires_at: float


class FlowStore:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self._path = path
        self._clock = clock
        with transaction(self._path, FlowStoreError) as connection:
            connection.execute(_SCHEMA)

    def add(self, principal: str, kind: str, source: str, window_seconds: float) -> bool:
        """Set or extend a label. Returns True if it was not already active."""
        now = self._clock()
        with transaction(self._path, FlowStoreError) as connection:
            connection.execute("DELETE FROM flow_labels WHERE expires_at <= ?", (now,))
            active = connection.execute(
                "SELECT 1 FROM flow_labels WHERE principal = ? AND kind = ? AND source = ?",
                (principal, kind, source),
            ).fetchone()
            if active:
                connection.execute(
                    "UPDATE flow_labels SET expires_at = ? "
                    "WHERE principal = ? AND kind = ? AND source = ?",
                    (now + window_seconds, principal, kind, source),
                )
                return False
            connection.execute(
                "INSERT INTO flow_labels (principal, kind, source, first_seen, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (principal, kind, source, now, now + window_seconds),
            )
            return True

    def active(self, principal: str | None = None) -> list[FlowLabel]:
        now = self._clock()
        with transaction(self._path, FlowStoreError) as connection:
            connection.execute("DELETE FROM flow_labels WHERE expires_at <= ?", (now,))
            query = "SELECT principal, kind, source, first_seen, expires_at FROM flow_labels"
            params: tuple[str, ...] = ()
            if principal is not None:
                query += " WHERE principal = ?"
                params = (principal,)
            rows = connection.execute(query + " ORDER BY first_seen", params).fetchall()
        return [FlowLabel(*row) for row in rows]

    def reset(self, principal: str | None = None) -> int:
        """Clear labels. Only the operator CLI calls this."""
        with transaction(self._path, FlowStoreError) as connection:
            if principal is None:
                cursor = connection.execute("DELETE FROM flow_labels")
            else:
                cursor = connection.execute(
                    "DELETE FROM flow_labels WHERE principal = ?", (principal,)
                )
            return cursor.rowcount


def flow_rule(
    rules: FlowGuardRules, private_to_public: bool, other_repo: bool, untrusted: bool
) -> Decision | None:
    """Decide a write from what is known about the principal. None means no objection."""
    if private_to_public:
        if rules.on_private_to_public == "deny":
            return Decision(
                Effect.DENY,
                "flow.private_to_public",
                "This agent has read private content, so it cannot write to a public "
                "repository. A person can clear this with repoward flow reset.",
            )
        return Decision(
            Effect.APPROVAL_REQUIRED,
            "flow.private_to_public",
            "This write needs human approval because the agent has read private content.",
        )
    if other_repo:
        return Decision(
            Effect.DENY,
            "flow.single_repo",
            "This agent is limited to one repository until a person resets it.",
        )
    if untrusted:
        if rules.on_untrusted_author == "deny":
            return Decision(
                Effect.DENY,
                "flow.untrusted_author",
                "This agent has read text from an untrusted author, so it cannot write. "
                "A person can clear this with repoward flow reset.",
            )
        return Decision(
            Effect.APPROVAL_REQUIRED,
            "flow.untrusted_author",
            "This write needs human approval because the agent read untrusted text.",
        )
    return None


class FlowGuard:
    def __init__(
        self,
        rules: FlowGuardRules,
        store: FlowStore,
        repo_is_private: Callable[[str], Awaitable[bool]],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rules = rules
        self._store = store
        self._repo_is_private = repo_is_private
        self._clock = clock
        self._window = rules.window_minutes * 60.0
        self._visibility: dict[str, tuple[bool, float]] = {}

    @property
    def trusted_associations(self) -> list[str]:
        return sorted(self._rules.trusted_associations)

    async def _is_private(self, repo: str) -> bool | None:
        """Repository visibility, or None if GitHub could not say."""
        key = repo.casefold()
        cached = self._visibility.get(key)
        if cached is not None and self._clock() < cached[1]:
            return cached[0]
        try:
            private = await self._repo_is_private(repo)
        except Exception:
            return None
        self._visibility[key] = (private, self._clock() + _VISIBILITY_TTL_SECONDS)
        return private

    async def _active(self, principal: str) -> list[FlowLabel]:
        return await anyio.to_thread.run_sync(self._store.active, principal)

    async def _add(self, principal: str, kind: str, source: str) -> bool:
        return await anyio.to_thread.run_sync(
            self._store.add, principal, kind, source, self._window
        )

    async def check_write(self, principal: str, repo: str | None) -> Decision | None:
        """Decide a write. None means the guard has no objection. Fails closed."""
        try:
            labels = await self._active(principal)
            kinds = {label.kind for label in labels}
            # An unknown target is treated as public.
            private_to_public = (
                repo is not None
                and PRIVATE_READ in kinds
                and await self._is_private(repo) is not True
            )
            limited = self._rules.single_repo and repo is not None
            touched = [label.source for label in labels if label.kind == TOUCHED_REPO]
            other_repo = limited and bool(touched) and touched[0] != str(repo).casefold()
            decision = flow_rule(
                self._rules, private_to_public, other_repo, UNTRUSTED_INPUT in kinds
            )
            if limited and not private_to_public and not other_repo:
                await self._add(principal, TOUCHED_REPO, str(repo).casefold())
            return decision
        except FlowStoreError:
            return Decision(
                Effect.DENY,
                "flow.unavailable",
                "This write was blocked because the flow guard's state is unavailable.",
            )

    async def record_read(
        self, principal: str, repo: str | None, taints: Sequence[Taint]
    ) -> list[tuple[str, str]]:
        """Save what was just read, before it is returned. Raises FlowStoreError on failure."""
        added: list[tuple[str, str]] = []

        async def add(kind: str, source: str) -> None:
            if await self._add(principal, kind, source):
                added.append((kind, source))

        if repo is not None:
            # A repository of unknown visibility is treated as private.
            if await self._is_private(repo) is not False:
                await add(PRIVATE_READ, repo.casefold())
            if self._rules.single_repo:
                await add(TOUCHED_REPO, repo.casefold())
        trusted = set(self._rules.trusted_associations)
        for taint in taints:
            if taint.association not in trusted:
                await add(UNTRUSTED_INPUT, taint.source)
        return added

    async def describe(self, principal: str) -> str:
        """Why this principal's writes are restricted, for the person reviewing an approval."""
        labels = await self._active(principal)
        lines = [
            f"Flow guard: {label.kind} from {label.source}"
            for label in labels
            if label.kind != TOUCHED_REPO
        ]
        return "\n".join(lines)
