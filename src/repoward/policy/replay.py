"""Policy replay: what a different policy would have decided for calls already in the audit log.

It reuses the real decision code and never contacts GitHub. Audit records deliberately leave out
content, and some facts were never recorded. Where a decision depends on one of those, every
possibility is tried: if they agree that is the answer, and if not the answer is `unknown`.
"""

import itertools
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from repoward.adapters.github import GitHubClient
from repoward.audit import verify_log
from repoward.catalog import UNTRUSTED_TEXT_TOOLS, RiskClass
from repoward.flow import PRIVATE_READ, TOUCHED_REPO, UNTRUSTED_INPUT, flow_rule
from repoward.policy.engine import Decision, Effect, Target, decide, tighten
from repoward.policy.loader import CompiledPolicy
from repoward.principal import Principal
from repoward.ratelimit import RateLimiter
from repoward.registry import ToolSpec
from repoward.sanitize import MAX_AUDIT_ITEMS, REDACTED
from repoward.server import build_registry

UNKNOWN = "unknown"
_REVIEW = "approvals.github_review"
_APPROVED = {"approvals.consumed", _REVIEW}
_REVIEWED = "approval_required (by review)"
_NOT_POLICY = {"tool.unknown", "input.invalid"}
# Refused because something was unavailable, so the log does not say what policy would have done.
_OPERATIONAL = {
    "audit.degraded",
    "approvals.unavailable",
    "approvals.too_many_pending",
    "flow.unavailable",
}
_FINGERPRINT = re.compile(r"\[(\d+) characters, sha256 [0-9a-f]{64}\]")
_CUT_SHORT = (REDACTED, "[TRUNCATED]", "\n[truncated ")
_MAX_UTF8_BYTES_PER_CHARACTER = 4
# Never sent anywhere. It stands for "the hidden text held a credential".
_ASSUMED_CREDENTIAL = "ghp_" + "0" * 36
# Denials the engine makes before its credential check, so the check's answer was never recorded.
_BEFORE_CREDENTIAL_CHECK = re.compile(
    r"role\.unknown|default\.deny|dangerous_tools\..*|repos\.allow|paths\.deny"
    r"|branches\.write_prefix|pull_requests\.allow_non_draft|roles\.commit_limits"
)


class ReplayError(Exception):
    """The log cannot be replayed, because it cannot be trusted or read."""


@dataclass(frozen=True)
class Row:
    seq: int
    tool: str
    repo: str | None
    recorded: str
    replayed: str
    reason: str


@dataclass
class ReplayReport:
    decisions: int = 0
    unchanged: int = 0
    changed: list[Row] = field(default_factory=list)
    unknown: list[Row] = field(default_factory=list)


@dataclass(frozen=True)
class _Verdict:
    """A replayed decision. No decision means the facts allow more than one answer."""

    decision: Decision | None
    reason: str = ""


@dataclass(frozen=True)
class _Sighting:
    """A label seen at some moment. If not certain, the label may or may not have been set."""

    kind: str
    source: str
    ts: float
    first_seen: float
    certain: bool


def _both(first: bool | None, second: bool | None) -> bool | None:
    if first is False or second is False:
        return False
    return True if first is True and second is True else None


def _cut_short(value: Any) -> bool:
    """Whether the audit log may have shortened or redacted this value."""
    if isinstance(value, str):
        return any(marker in value for marker in _CUT_SHORT)
    if isinstance(value, dict):
        return len(value) >= MAX_AUDIT_ITEMS or any(_cut_short(item) for item in value.values())
    if isinstance(value, list):
        return len(value) >= MAX_AUDIT_ITEMS or any(_cut_short(item) for item in value)
    return False


def _content_characters(args: dict[str, Any]) -> int | None:
    """Total length of committed file contents, which the log keeps as fingerprints."""
    total = 0
    for change in args.get("files", []):
        match = _FINGERPRINT.fullmatch(str(change.get("content", "")))
        if match is None:
            return None
        total += int(match[1])
    return total


def _load(path: Path, key: bytes | None) -> list[dict[str, Any]]:
    """Read a log only after its chain verifies. A tampered log gives meaningless answers."""
    if not path.exists():
        raise ReplayError(f"no audit log at {path}")
    report = verify_log(path, key)
    if not report.ok:
        raise ReplayError("the audit log failed verification: " + "; ".join(report.errors))
    try:
        return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]
    except (OSError, ValueError) as exc:
        raise ReplayError(f"cannot read the audit log: {exc}") from exc


class _Replay:
    def __init__(self, compiled: CompiledPolicy, records: list[dict[str, Any]]) -> None:
        self._compiled = compiled
        self._rules = compiled.policy.flow_guard
        self._window = self._rules.window_minutes * 60.0
        # Tool handlers are never called, and with no client they could not reach GitHub anyway.
        self._registry = build_registry(compiled, cast(GitHubClient, None))
        self._sightings: dict[str, list[_Sighting]] = {}
        self._untrusted_sources: dict[str, set[str]] = {}
        self._limiters: dict[str, tuple[RateLimiter, RateLimiter]] = {}
        self._now = 0.0
        self._outcomes = {
            r.get("request_id"): r.get("result_status")
            for r in records
            if r.get("event") == "tool_call_outcome"
        }
        self._labels: dict[Any, list[dict[str, Any]]] = {}
        for record in records:
            if record.get("event") == "flow_label":
                self._labels.setdefault(record.get("request_id"), []).append(record)
        self._private = {
            str(label.get("source")).casefold()
            for labels in self._labels.values()
            for label in labels
            if label.get("kind") == PRIVATE_READ
        }
        self._public = self._find_public(records)

    def _find_public(self, records: Iterable[dict[str, Any]]) -> set[str]:
        """Repositories the guard must have seen as public, going by what it recorded."""
        public: set[str] = set()
        for record in records:
            if record.get("event") != "tool_call_decision":
                continue
            repo = self._repo_of(record)
            if repo is None:
                continue
            refused_as_public = record.get("rule_id") == "flow.private_to_public"
            spec = self._registry.get(str(record.get("tool")))
            read_with_guard_on = (
                record.get("flow_trusted") is not None
                and spec is not None
                and spec.risk is RiskClass.READ
                and self._outcomes.get(record.get("request_id")) == "ok"
            )
            if (refused_as_public or read_with_guard_on) and repo not in self._private:
                public.add(repo)
        return public

    @staticmethod
    def _repo_of(record: dict[str, Any]) -> str | None:
        args = record.get("args_redacted")
        repo = args.get("repo") if isinstance(args, dict) else None
        return repo.casefold() if isinstance(repo, str) else None

    def _visibility(self, repo: str | None) -> bool | None:
        """Whether a repository is private, as far as the log shows."""
        if repo is None:
            return None
        if repo in self._private:
            return True
        return False if repo in self._public else None

    # Static policy.

    def _targets(self, record: dict[str, Any], spec: ToolSpec) -> tuple[Target, Target] | None:
        """The most and least restricted targets this record could stand for."""
        args = record.get("args_redacted")
        if not isinstance(args, dict) or _cut_short(args):
            return None
        try:
            target = spec.target(spec.input_model.model_validate(args))
        except ValidationError:
            return None
        characters = _content_characters(args)
        if characters is None:
            return None
        least = replace(target, commit_bytes=characters, outbound=())
        most = replace(target, commit_bytes=characters * _MAX_UTF8_BYTES_PER_CHARACTER, outbound=())
        if target.outbound:
            rule = str(record.get("rule_id"))
            if rule == "secrets.outbound":
                least = replace(least, outbound=(_ASSUMED_CREDENTIAL,))
                most = replace(most, outbound=(_ASSUMED_CREDENTIAL,))
            elif record.get("decision") == "deny" and _BEFORE_CREDENTIAL_CHECK.fullmatch(rule):
                most = replace(most, outbound=(_ASSUMED_CREDENTIAL,))
        return least, most

    def _static(self, record: dict[str, Any], spec: ToolSpec) -> _Verdict:
        targets = self._targets(record, spec)
        if targets is None:
            return _Verdict(None, "the log shortened or redacted its arguments")
        principal = Principal(str(record.get("principal")), self._compiled.policy.stdio.role)
        first, second = (
            decide(self._compiled, principal, spec.name, spec.risk, target) for target in targets
        )
        if (first.effect, first.rule_id) != (second.effect, second.rule_id):
            return _Verdict(None, "it depends on file sizes or text the log does not hold")
        return _Verdict(first)

    # Flow guard state, rebuilt from the log.

    def _live(self, principal: str, kind: str) -> list[_Sighting]:
        live = [
            sighting
            for sighting in self._sightings.get(principal, [])
            if self._now - sighting.ts < self._window
        ]
        self._sightings[principal] = live
        return [sighting for sighting in live if sighting.kind == kind]

    def _active(self, principal: str, kind: str) -> bool | None:
        live = self._live(principal, kind)
        if any(sighting.certain for sighting in live):
            return True
        return None if live else False

    def _other_repo(self, principal: str, repo: str | None) -> bool | None:
        if not self._rules.single_repo or repo is None:
            return False
        live = self._live(principal, TOUCHED_REPO)

        def conflict(sightings: list[_Sighting]) -> bool:
            # The guard holds a principal to the first repository it touched.
            if not sightings:
                return False
            return min(sightings, key=lambda sighting: sighting.first_seen).source != repo

        everything = conflict(live)
        return everything if everything == conflict([s for s in live if s.certain]) else None

    def _flow(self, principal: str, repo: str | None) -> tuple[bool, Decision | None]:
        """The guard's answer for a write. First value: whether the facts settle it."""
        private = self._visibility(repo)
        target_public = None if private is None else not private
        facts = (
            _both(self._active(principal, PRIVATE_READ), target_public),
            self._other_repo(principal, repo),
            self._active(principal, UNTRUSTED_INPUT),
        )
        answers = {
            flow_rule(self._rules, *combination)
            for combination in itertools.product(
                *(((True, False) if fact is None else (fact,)) for fact in facts)
            )
        }
        if len(answers) == 1:
            return True, answers.pop()
        return False, None

    def _see(self, principal: str, kind: str, source: str, certain: bool) -> None:
        if kind == UNTRUSTED_INPUT:
            self._untrusted_sources.setdefault(principal, set()).add(source.casefold())
        sightings = self._sightings.setdefault(principal, [])
        first_seen = min(
            (
                sighting.first_seen
                for sighting in sightings
                if sighting.kind == kind
                and sighting.source == source
                and self._now - sighting.ts < self._window
            ),
            default=self._now,
        )
        sightings.append(_Sighting(kind, source, self._now, first_seen, certain))

    def _record_write(self, principal: str, repo: str | None, verdict: _Verdict) -> None:
        if not self._rules.single_repo or repo is None:
            return
        blocked = verdict.decision is not None and verdict.decision.rule_id in {
            "flow.private_to_public",
            "flow.single_repo",
        }
        if not blocked:
            self._see(principal, TOUCHED_REPO, repo, verdict.decision is not None)

    def _record_read(
        self, record: dict[str, Any], tool: str, repo: str | None, verdict: _Verdict
    ) -> None:
        """Rebuild what this read would have labelled under the new policy."""
        decision = verdict.decision
        if decision is not None and decision.effect is Effect.DENY:
            return
        certain = decision is not None and decision.effect is Effect.ALLOW
        principal = str(record.get("principal"))
        ran = record.get("decision") == "allow"
        outcome = self._outcomes.get(record.get("request_id"))
        if ran and outcome == "error":
            return  # The same call is assumed to fail the same way, and failures set no labels.
        known_result = ran and outcome == "ok"
        if repo is not None:
            private = self._visibility(repo)
            if private is not False:
                self._see(
                    principal, PRIVATE_READ, repo, certain and known_result and private is True
                )
            if self._rules.single_repo:
                self._see(principal, TOUCHED_REPO, repo, certain and known_result)
        if tool not in UNTRUSTED_TEXT_TOOLS:
            return
        was_trusted = record.get("flow_trusted")
        new_trusted = set(self._rules.trusted_associations)
        labels = [
            label
            for label in self._labels.get(record.get("request_id"), [])
            if label.get("kind") == UNTRUSTED_INPUT
        ]
        if not known_result or was_trusted is None:
            self._see(principal, UNTRUSTED_INPUT, repo or "", False)
            return
        # Someone untrusted then is still untrusted if the trusted list only shrank, and someone
        # trusted then is still trusted if it only grew.
        for label in labels:
            self._see(
                principal,
                UNTRUSTED_INPUT,
                str(label.get("source")),
                certain and new_trusted <= set(was_trusted),
            )
        if not labels and not set(was_trusted) <= new_trusted:
            self._see(principal, UNTRUSTED_INPUT, repo or "", False)
        elif not labels and self._earlier_label_from(principal, repo):
            # Reading the same text again extends a label without logging it.
            self._see(principal, UNTRUSTED_INPUT, repo or "", False)

    def _earlier_label_from(self, principal: str, repo: str | None) -> bool:
        if repo is None:
            return False
        return any(repo in source for source in self._untrusted_sources.get(principal, ()))

    # Rate limits.

    def _limit(self, record: dict[str, Any], verdict: _Verdict, tool: str) -> _Verdict:
        """Count this call. One limiter counts calls known to happen, the other possible ones."""
        decision = verdict.decision
        if decision is not None and decision.effect is Effect.DENY:
            return verdict
        instance = str(record.get("instance_id"))
        limits = self._compiled.rate_limits
        if instance not in self._limiters:
            self._limiters[instance] = (
                RateLimiter(limits, lambda: self._now),
                RateLimiter(limits, lambda: self._now),
            )
        known, possible = self._limiters[instance]
        principal = str(record.get("principal"))
        possible_hit = possible.check(principal, tool)
        if decision is None:
            return verdict
        known_hit = known.check(principal, tool)
        if known_hit is not None:
            return _Verdict(Decision(Effect.DENY, known_hit.rule_id))
        if possible_hit is not None:
            return _Verdict(None, "a rate limit may apply, depending on earlier unknown calls")
        return verdict

    # One record.

    def _evaluate(self, record: dict[str, Any], spec: ToolSpec) -> _Verdict:
        principal = str(record.get("principal"))
        repo = self._repo_of(record)
        verdict = self._static(record, spec)
        decision = verdict.decision
        mutating = spec.risk is not RiskClass.READ
        if (
            mutating
            and self._rules.enabled
            and (decision is None or decision.effect != Effect.DENY)
        ):
            settled, flow = self._flow(principal, repo)
            if decision is not None:
                verdict = (
                    _Verdict(tighten(decision, flow))
                    if settled
                    else _Verdict(None, "it depends on flow labels the log cannot settle")
                )
            self._record_write(principal, repo, verdict)
        verdict = self._limit(record, verdict, spec.name)
        if not mutating and self._rules.enabled:
            self._record_read(record, spec.name, repo, verdict)
        return verdict

    def _labels_for_report(self, record: dict[str, Any], verdict: _Verdict) -> tuple[str, str, str]:
        rule = str(record.get("rule_id"))
        recorded = str(record.get("decision"))
        if rule in _APPROVED:
            recorded = _REVIEWED if rule == _REVIEW else Effect.APPROVAL_REQUIRED.value
        decision = verdict.decision
        if decision is None:
            return recorded, UNKNOWN, verdict.reason
        replayed = decision.effect.value
        reason = decision.rule_id
        if rule in _OPERATIONAL and decision.effect is not Effect.DENY:
            return recorded, UNKNOWN, f"it was refused because of {rule}, not policy"
        if rule == _REVIEW and decision.effect is Effect.APPROVAL_REQUIRED:
            review = self._compiled.policy.approvals.github_review
            if review.enabled and review.min_permission == "write":
                replayed = _REVIEWED
            elif review.enabled:
                return recorded, UNKNOWN, "the log does not record the reviewer's access level"
        return recorded, replayed, reason

    def run(self, records: list[dict[str, Any]]) -> ReplayReport:
        report = ReplayReport()
        for record in records:
            event = record.get("event")
            self._now = datetime.fromisoformat(str(record.get("ts"))).timestamp()
            if event == "flow_reset":
                self._reset(record.get("principal"))
            if event != "tool_call_decision":
                continue
            report.decisions += 1
            if record.get("rule_id") in _NOT_POLICY:
                report.unchanged += 1  # Refused before policy runs, whatever the policy says.
                continue
            spec = self._registry.get(str(record.get("tool")))
            verdict = (
                _Verdict(None, "this tool is not known")
                if spec is None
                else self._evaluate(record, spec)
            )
            recorded, replayed, reason = self._labels_for_report(record, verdict)
            row = Row(
                int(record.get("seq", 0)),
                str(record.get("tool")),
                self._repo_of(record),
                recorded,
                replayed,
                reason,
            )
            if replayed == UNKNOWN:
                report.unknown.append(row)
            elif replayed != recorded:
                report.changed.append(row)
            else:
                report.unchanged += 1
        return report

    def _reset(self, principal: Any) -> None:
        if principal is None:
            self._sightings.clear()
            self._untrusted_sources.clear()
        else:
            self._sightings.pop(str(principal), None)
            self._untrusted_sources.pop(str(principal), None)


def replay_log(path: Path, compiled: CompiledPolicy, key: bytes | None = None) -> ReplayReport:
    """Report which recorded decisions this policy would change. Raises ReplayError."""
    records = _load(path, key)
    try:
        return _Replay(compiled, records).run(records)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ReplayError(f"the audit log has a record that cannot be read: {exc}") from exc
