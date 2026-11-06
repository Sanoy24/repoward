"""Short SQLite transactions, so several processes can safely share one database file."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_BUSY_TIMEOUT_SECONDS = 5.0


@contextmanager
def transaction(path: Path, error: type[Exception]) -> Iterator[sqlite3.Connection]:
    """Run one write-locked transaction. BEGIN IMMEDIATE makes check-then-update atomic."""
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=_BUSY_TIMEOUT_SECONDS, isolation_level=None)
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        raise error(f"database failed: {type(exc).__name__}") from exc
    finally:
        if connection is not None:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
