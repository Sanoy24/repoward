"""Pull request receipts: a commit status summarizing how this server's run has gone so far.

A receipt is informational. It does not prove a change came through this server, because anyone
with the same permission could post the same status. It is built only from numbers and hashes this
server produced, so it holds no arguments or repository content.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

CONTEXT = "repoward/receipt"
MAX_DESCRIPTION_CHARS = 140  # GitHub's limit for a commit status description.
_POLICY_HASH_CHARS = 12

PostStatus = Callable[[str, str, str, str], Awaitable[None]]


@dataclass
class _Tally:
    first_seq: int
    denied: int = 0
    escalated: int = 0


class ReceiptLedger:
    """Counts one server process's decisions, per principal, as they reach the audit log."""

    def __init__(self, post: PostStatus, policy_hash: str) -> None:
        self._post = post
        self._policy_hash = policy_hash
        self._tallies: dict[str, _Tally] = {}
        self._last_seq = 0

    def observe(self, record: dict[str, Any]) -> None:
        seq = int(record["seq"])
        self._last_seq = seq
        if record.get("event") != "tool_call_decision":
            return
        tally = self._tallies.setdefault(str(record.get("principal")), _Tally(seq))
        if record.get("decision") == "deny":
            tally.denied += 1
        elif record.get("decision") == "approval_required":
            tally.escalated += 1

    def description(self, principal: str, flow_labels: str) -> str | None:
        """The receipt's text, or None if nothing has been recorded for this principal."""
        tally = self._tallies.get(principal)
        if tally is None:
            return None
        text = (
            f"policy {self._policy_hash[:_POLICY_HASH_CHARS]}; "
            f"audit seq {tally.first_seq}-{self._last_seq}; "
            f"{tally.denied} denied; {tally.escalated} escalated; flow labels: {flow_labels}"
        )
        return text[:MAX_DESCRIPTION_CHARS]

    async def post(self, repo: str, sha: str, description: str) -> None:
        await self._post(repo, sha, CONTEXT, description)
