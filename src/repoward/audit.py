"""Append-only, hash-chained JSONL audit log.

The chain is tamper-evident, not tamper-proof. Anyone who can write the file can recompute a
plain SHA-256 chain, and no chain alone reveals deleted newest records. An HMAC key the
attacker cannot read covers the first case; off-host checkpoints cover the second.

With rotation on, a full log is renamed to an archive named by its sequence range, and the next
record continues the same chain. Verification walks the archives and the current file as one chain.
"""

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

from repoward.canonical import canonical_json

DEFAULT_KEY_ENV = "REPOWARD_AUDIT_HMAC_KEY"
GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 1
_ALG_SHA256 = "sha256"
_ALG_HMAC = "hmac-sha256"
_LOCK_TIMEOUT_SECONDS = 5.0
_TAIL_CHUNK_BYTES = 65_536
_MIN_KEY_BYTES = 32


class AuditWriteError(Exception):
    """A record could not be durably written."""


class AuditKeyError(Exception):
    """The configured HMAC key is unusable."""


def load_hmac_key(env_name: str) -> bytes | None:
    value = os.environ.get(env_name)
    if value is None:
        return None
    key = value.encode("utf-8")
    if len(key) < _MIN_KEY_BYTES:
        raise AuditKeyError(f"{env_name} must be at least {_MIN_KEY_BYTES} bytes")
    return key


def _digest(record: dict[str, Any], key: bytes | None) -> str:
    body = canonical_json({name: value for name, value in record.items() if name != "hash"})
    if key is None:
        return hashlib.sha256(body).hexdigest()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _read_tail(path: Path) -> dict[str, Any] | None:
    """Read the last record from disk. A torn final line is refused, never skipped."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        buffer = b""
        while position > 0 and buffer.count(b"\n") < 2:
            step = min(_TAIL_CHUNK_BYTES, position)
            position -= step
            handle.seek(position)
            buffer = handle.read(step) + buffer
    if not buffer.endswith(b"\n"):
        raise AuditWriteError("the audit log ends with an incomplete record")
    last_line = buffer[:-1].rsplit(b"\n", 1)[-1]
    try:
        record = json.loads(last_line)
    except ValueError as exc:
        raise AuditWriteError("the last audit record is not valid JSON") from exc
    if not isinstance(record, dict):
        raise AuditWriteError("the last audit record is not an object")
    return record


def _archive_pattern(path: Path) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(path.stem)}\.(\d{{12}})-(\d{{12}}){re.escape(path.suffix)}$")


def log_files(path: Path) -> list[Path]:
    """A log's archives, oldest first, then the current file if it exists."""
    pattern = _archive_pattern(path)
    archives: list[tuple[int, Path]] = []
    if path.parent.is_dir():
        for candidate in path.parent.iterdir():
            match = pattern.match(candidate.name)
            if match and candidate.is_file():
                archives.append((int(match[1]), candidate))
    files = [candidate for _, candidate in sorted(archives)]
    return [*files, path] if path.exists() else files


def _read_head_seq(path: Path) -> int:
    with path.open("rb") as handle:
        first = json.loads(handle.readline())
    return int(first["seq"])


class AuditLog:
    def __init__(
        self, path: Path, hmac_key: bytes | None = None, rotate_bytes: int | None = None
    ) -> None:
        self._path = path
        self._key = hmac_key
        self._alg = _ALG_SHA256 if hmac_key is None else _ALG_HMAC
        self._rotate_bytes = rotate_bytes
        self._lock = FileLock(f"{path}.lock", timeout=_LOCK_TIMEOUT_SECONDS)

    def _chain_tail(self) -> dict[str, Any] | None:
        """The newest record, which is in the newest archive just after a rotation."""
        tail = _read_tail(self._path)
        if tail is not None:
            return tail
        files = log_files(self._path)
        return _read_tail(files[-1]) if files and files[-1] != self._path else None

    def _rotate_if_full(self, tail: dict[str, Any] | None) -> None:
        if self._rotate_bytes is None or tail is None or not self._path.exists():
            return
        if self._path.stat().st_size < self._rotate_bytes:
            return
        first = _read_head_seq(self._path)
        archive = self._path.with_name(
            f"{self._path.stem}.{first:012d}-{int(tail['seq']):012d}{self._path.suffix}"
        )
        os.replace(self._path, archive)

    def append(self, fields: dict[str, Any]) -> dict[str, Any]:
        """Durably append one record, chained to whatever is on disk now.

        The tail is re-read every time because other processes share this file.
        """
        try:
            with self._lock:
                tail = self._chain_tail()
                if tail is not None and tail.get("alg") != self._alg:
                    raise AuditWriteError(
                        "the audit log uses a different hash mode; start a new log to change it"
                    )
                self._rotate_if_full(tail)
                record: dict[str, Any] = {
                    **fields,
                    "schema_version": SCHEMA_VERSION,
                    "seq": 1 if tail is None else int(tail["seq"]) + 1,
                    "ts": _utc_now(),
                    "alg": self._alg,
                    "prev_hash": GENESIS_HASH if tail is None else str(tail["hash"]),
                }
                record["hash"] = _digest(record, self._key)
                line = canonical_json(record) + b"\n"
                with self._path.open("ab") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
                return record
        except AuditWriteError:
            raise
        except (OSError, Timeout, KeyError, TypeError, ValueError) as exc:
            raise AuditWriteError(f"cannot write audit record: {type(exc).__name__}") from exc


@dataclass
class VerifyReport:
    records: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tip_seq: int = 0
    tip_hash: str = GENESIS_HASH

    @property
    def ok(self) -> bool:
        return not self.errors


def _load_anchors(path: Path, report: VerifyReport) -> list[dict[str, Any]]:
    anchors: list[dict[str, Any]] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            anchor = json.loads(raw)
            if not isinstance(anchor, dict) or "seq" not in anchor or "hash" not in anchor:
                raise ValueError
            anchors.append(anchor)
    except (OSError, ValueError):
        report.errors.append("the anchor file cannot be read")
    return anchors


def _record_error(record: Any, raw: bytes, key: bytes | None, prev: str, seq: int) -> str | None:
    """Return why a parsed line breaks the chain, or None if it is sound."""
    if not isinstance(record, dict) or canonical_json(record) != raw:
        return "record is not in canonical form"
    expected_alg = _ALG_SHA256 if key is None else _ALG_HMAC
    if record.get("alg") != expected_alg:
        return f"hash mode is {record.get('alg')!r}, expected {expected_alg!r}"
    if record.get("seq") != seq:
        return "sequence number is wrong"
    if record.get("prev_hash") != prev:
        return "does not chain to the previous record"
    claimed = record.get("hash")
    if not isinstance(claimed, str) or not hmac.compare_digest(claimed, _digest(record, key)):
        return "hash does not match its contents"
    return None


def _check_name(path: Path, current: Path, first: int, last: int) -> str | None:
    """An archive's name must match the records inside it."""
    if path == current:
        return None
    expected = f"{current.stem}.{first:012d}-{last:012d}{current.suffix}"
    return None if path.name == expected else f"{path.name}: name does not match its records"


def verify_log(
    path: Path, hmac_key: bytes | None = None, anchor_path: Path | None = None
) -> VerifyReport:
    """Check the whole chain across archives and the current file, stopping at the first break."""
    report = VerifyReport()
    files = log_files(path)
    if not files:
        report.errors.append("cannot read audit log: no such file")
        return report

    seen_hashes: dict[int, str] = {}
    open_calls: dict[str, int] = {}
    previous = GENESIS_HASH
    expected_seq: int | None = None
    several = len(files) > 1
    for file in files:
        where = f"{file.name} " if several else ""
        try:
            raw_lines = file.read_bytes().split(b"\n")
        except OSError as exc:
            report.errors.append(f"cannot read audit log: {exc.strerror}")
            return report
        if raw_lines[-1] != b"":
            report.errors.append(f"{where}line {len(raw_lines)}: incomplete final record")
            return report
        first_in_file: int | None = None
        for number, raw in enumerate(raw_lines[:-1], start=1):
            seq = 0
            try:
                record = json.loads(raw)
                if expected_seq is None:
                    # The oldest file left. Archives before it may have been removed on purpose.
                    expected_seq = int(record["seq"])
                    previous = str(record["prev_hash"])
                    if expected_seq != 1:
                        report.warnings.append(
                            f"the log starts at seq {expected_seq}; earlier archives are missing, "
                            "so only an anchor can show they were not changed"
                        )
                seq = expected_seq
                problem = _record_error(record, raw, hmac_key, previous, seq)
            except (ValueError, TypeError, KeyError):
                problem = "not valid JSON"
            if problem is not None:
                report.errors.append(f"{where}line {number}: {problem}")
                return report
            if first_in_file is None:
                first_in_file = seq
            previous = record["hash"]
            seen_hashes[seq] = previous
            report.records += 1
            report.tip_seq = seq
            report.tip_hash = previous
            expected_seq = seq + 1
            request_id = str(record.get("request_id"))
            if record.get("event") == "tool_call_decision" and record.get("decision") == "allow":
                open_calls[request_id] = report.tip_seq
            elif record.get("event") == "tool_call_outcome":
                open_calls.pop(request_id, None)
        if first_in_file is None:
            if file != path:
                report.errors.append(f"{file.name}: archive is empty")
                return report
            continue
        name_problem = _check_name(file, path, first_in_file, report.tip_seq)
        if name_problem is not None:
            report.errors.append(name_problem)
            return report

    for request_id, seq in open_calls.items():
        report.warnings.append(
            f"seq {seq}: allowed call {request_id} has no outcome; its result is unknown"
        )
    if anchor_path is None:
        report.warnings.append("no anchor file given, so deleted newest records go undetected")
    else:
        for anchor in _load_anchors(anchor_path, report):
            seq = anchor["seq"]
            if seq not in seen_hashes:
                report.errors.append(f"anchor at seq {seq}: record is missing (log truncated)")
            elif seen_hashes[seq] != anchor["hash"]:
                report.errors.append(f"anchor at seq {seq}: hash does not match")
    return report


def read_records(path: Path) -> list[dict[str, Any]]:
    """Every record across archives and the current file. Verify first."""
    records: list[dict[str, Any]] = []
    for file in log_files(path):
        records += [json.loads(line) for line in file.read_bytes().splitlines() if line.strip()]
    return records


def write_checkpoint(path: Path, out: Path, hmac_key: bytes | None = None) -> VerifyReport:
    """Verify the log, then append its tip to an anchor file meant to be stored off-host."""
    report = verify_log(path, hmac_key, anchor_path=out if out.exists() else None)
    if report.ok and report.records == 0:
        report.errors.append("the audit log is empty")
    if not report.ok:
        return report
    line = canonical_json({"seq": report.tip_seq, "hash": report.tip_hash, "ts": _utc_now()})
    try:
        with out.open("ab") as handle:
            handle.write(line + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        report.errors.append(f"cannot write anchor file: {exc.strerror}")
    return report
