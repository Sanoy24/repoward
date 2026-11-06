"""What the current tool call may access, so a GitHub token can be limited to exactly that."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class CallScope:
    repo: str | None
    permissions: Mapping[str, str]


_current: ContextVar[CallScope | None] = ContextVar("repoward_call_scope", default=None)


def current_scope() -> CallScope | None:
    return _current.get()


@contextmanager
def call_scope(repo: str | None, permissions: Mapping[str, str]) -> Iterator[None]:
    token = _current.set(CallScope(repo, permissions))
    try:
        yield
    finally:
        _current.reset(token)
