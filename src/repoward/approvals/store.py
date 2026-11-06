"""SQLite approval store. Each operation is one short transaction, so processes can share it."""

import secrets
import sqlite3
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from repoward.storage import transaction

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    principal TEXT NOT NULL,
    tool TEXT NOT NULL,
    repo TEXT,
    args_hash TEXT NOT NULL,
    args_redacted TEXT NOT NULL,
    context TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','consumed')),
    decided_by TEXT,
    decided_at REAL,
    expires_at REAL NOT NULL,
    consumed_at REAL
)
"""
_COLUMNS = (
    "id, ts, principal, tool, repo, args_hash, args_redacted, context, status, "
    "decided_by, decided_at, expires_at, consumed_at"
)


class ApprovalStoreError(Exception):
    """The store could not complete an operation. Callers must not execute anything."""


class TooManyPendingError(ApprovalStoreError):
    """This principal already has the maximum number of pending requests."""


@dataclass(frozen=True)
class Approval:
    id: str
    ts: float
    principal: str
    tool: str
    repo: str | None
    args_hash: str
    args_redacted: str
    context: str
    status: str
    decided_by: str | None
    decided_at: float | None
    expires_at: float
    consumed_at: float | None


class ApprovalStore:
    def __init__(
        self,
        path: Path,
        ttl_seconds: float = 900.0,
        max_pending_per_principal: int = 20,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = path
        self._ttl = ttl_seconds
        self._max_pending = max_pending_per_principal
        self._clock = clock
        with self._transaction() as connection:
            connection.execute(_SCHEMA)

    def _transaction(self) -> AbstractContextManager[sqlite3.Connection]:
        return transaction(self._path, ApprovalStoreError)

    def _expire(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            "UPDATE approvals SET status = 'expired' "
            "WHERE status IN ('pending', 'approved') AND expires_at <= ?",
            (now,),
        )

    def request(
        self,
        principal: str,
        tool: str,
        repo: str | None,
        args_hash: str,
        args_redacted: str,
        context: str,
    ) -> Approval:
        """Create a pending request, or return the identical one already waiting."""
        now = self._clock()
        with self._transaction() as connection:
            self._expire(connection, now)
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM approvals WHERE principal = ? AND tool = ? "  # noqa: S608
                "AND repo IS ? AND args_hash = ? AND status = 'pending'",
                (principal, tool, repo, args_hash),
            ).fetchone()
            if row is not None:
                return Approval(*row)
            pending = connection.execute(
                "SELECT COUNT(*) FROM approvals WHERE principal = ? AND status = 'pending'",
                (principal,),
            ).fetchone()[0]
            if pending >= self._max_pending:
                raise TooManyPendingError("too many pending approval requests")
            approval = Approval(
                id=secrets.token_hex(16),
                ts=now,
                principal=principal,
                tool=tool,
                repo=repo,
                args_hash=args_hash,
                args_redacted=args_redacted,
                context=context,
                status="pending",
                decided_by=None,
                decided_at=None,
                expires_at=now + self._ttl,
                consumed_at=None,
            )
            connection.execute(
                f"INSERT INTO approvals ({_COLUMNS}) "  # noqa: S608
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    approval.id,
                    approval.ts,
                    approval.principal,
                    approval.tool,
                    approval.repo,
                    approval.args_hash,
                    approval.args_redacted,
                    approval.context,
                    approval.status,
                    approval.decided_by,
                    approval.decided_at,
                    approval.expires_at,
                    approval.consumed_at,
                ),
            )
            return approval

    def consume(self, principal: str, tool: str, repo: str | None, args_hash: str) -> str | None:
        """Use up one matching approval, returning its id, or None if there is none.

        Consuming happens before the action runs, so each approval allows at most one attempt.
        """
        now = self._clock()
        with self._transaction() as connection:
            self._expire(connection, now)
            row = connection.execute(
                "SELECT id FROM approvals WHERE principal = ? AND tool = ? AND repo IS ? "
                "AND args_hash = ? AND status = 'approved' ORDER BY decided_at LIMIT 1",
                (principal, tool, repo, args_hash),
            ).fetchone()
            if row is None:
                return None
            cursor = connection.execute(
                "UPDATE approvals SET status = 'consumed', consumed_at = ? "
                "WHERE id = ? AND status = 'approved'",
                (now, row[0]),
            )
            return str(row[0]) if cursor.rowcount == 1 else None

    def decide(self, approval_id: str, approved: bool, decided_by: str) -> bool:
        """Approve or deny a pending request. An approval gets a fresh expiry window."""
        now = self._clock()
        status = "approved" if approved else "denied"
        with self._transaction() as connection:
            self._expire(connection, now)
            cursor = connection.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?, expires_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (status, decided_by, now, now + self._ttl, approval_id),
            )
            return cursor.rowcount == 1

    def get(self, approval_id: str) -> Approval | None:
        with self._transaction() as connection:
            self._expire(connection, self._clock())
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM approvals WHERE id = ?",  # noqa: S608
                (approval_id,),
            ).fetchone()
        return Approval(*row) if row is not None else None

    def list(self, include_all: bool = False) -> list[Approval]:
        condition = "" if include_all else "WHERE status = 'pending' "
        with self._transaction() as connection:
            self._expire(connection, self._clock())
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM approvals {condition}ORDER BY ts"  # noqa: S608
            ).fetchall()
        return [Approval(*row) for row in rows]
