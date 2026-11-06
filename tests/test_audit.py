import json
import subprocess
import sys
from pathlib import Path

import pytest

from repoward.audit import (
    GENESIS_HASH,
    AuditKeyError,
    AuditLog,
    AuditWriteError,
    load_hmac_key,
    verify_log,
    write_checkpoint,
)
from repoward.canonical import canonical_json
from repoward.cli import main

KEY = b"k" * 32


def fill(path: Path, count: int = 3, key: bytes | None = None) -> None:
    log = AuditLog(path, key)
    for index in range(count):
        log.append({"event": "test", "n": index})


def read(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def write(path: Path, records: list[dict[str, object]]) -> None:
    path.write_bytes(b"".join(canonical_json(record) + b"\n" for record in records))


def recompute_with_sha256(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """What an attacker with write access but no key can do."""
    import hashlib

    previous = GENESIS_HASH
    for record in records:
        record["alg"] = "sha256"
        record["prev_hash"] = previous
        record.pop("hash", None)
        record["hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
        previous = str(record["hash"])
    return records


def test_chain_links_and_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path)
    records = read(path)
    assert [record["seq"] for record in records] == [1, 2, 3]
    assert records[0]["prev_hash"] == GENESIS_HASH
    assert records[1]["prev_hash"] == records[0]["hash"]
    report = verify_log(path)
    assert report.ok
    assert report.records == 3
    assert report.tip_hash == records[-1]["hash"]


def test_empty_and_missing_logs(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    assert verify_log(empty).ok
    assert not verify_log(tmp_path / "nope.jsonl").ok


def test_timestamps_are_utc_milliseconds(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 1)
    timestamp = str(read(path)[0]["ts"])
    assert timestamp.endswith("Z")
    assert len(timestamp) == 24


@pytest.mark.parametrize("field", ["n", "seq", "prev_hash", "hash", "ts", "event"])
def test_editing_any_field_is_detected(tmp_path: Path, field: str) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path)
    records = read(path)
    records[1][field] = "tampered"
    write(path, records)
    report = verify_log(path)
    assert not report.ok
    assert report.records == 1


def test_deleting_a_middle_line_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path)
    records = read(path)
    write(path, [records[0], records[2]])
    assert not verify_log(path).ok


def test_reordering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path)
    records = read(path)
    write(path, [records[1], records[0], records[2]])
    assert not verify_log(path).ok


def test_reformatting_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 1)
    record = read(path)[0]
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert not verify_log(path).ok


def test_garbage_and_torn_lines_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path)
    data = path.read_bytes()
    path.write_bytes(data + b"not json\n")
    assert not verify_log(path).ok
    path.write_bytes(data[:-5])
    assert "incomplete" in verify_log(path).errors[0]


def test_plain_chain_cannot_detect_a_full_recompute(tmp_path: Path) -> None:
    """A documented limit: this is why HMAC mode exists."""
    path = tmp_path / "audit.jsonl"
    fill(path)
    records = read(path)
    records[1]["n"] = "tampered"
    write(path, recompute_with_sha256(records))
    assert verify_log(path).ok


def test_hmac_detects_a_full_recompute(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, key=KEY)
    assert verify_log(path, KEY).ok
    records = read(path)
    records[1]["n"] = "tampered"
    write(path, recompute_with_sha256(records))
    assert not verify_log(path, KEY).ok


def test_hmac_with_the_wrong_key_fails(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, key=KEY)
    assert not verify_log(path, b"x" * 32).ok


def test_hmac_log_cannot_be_verified_without_a_key(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, key=KEY)
    assert not verify_log(path).ok


def test_hash_mode_cannot_change_within_a_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 1, key=KEY)
    with pytest.raises(AuditWriteError, match="hash mode"):
        AuditLog(path).append({"event": "x"})
    assert verify_log(path, KEY).records == 1


def test_tail_truncation_needs_an_anchor(tmp_path: Path) -> None:
    """Without an anchor the shortened log still verifies, and the report says so."""
    path = tmp_path / "audit.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    fill(path)
    assert write_checkpoint(path, anchors).ok
    records = read(path)
    write(path, records[:2])
    unanchored = verify_log(path)
    assert unanchored.ok
    assert any("deleted newest" in warning for warning in unanchored.warnings)
    anchored = verify_log(path, anchor_path=anchors)
    assert not anchored.ok
    assert "truncated" in anchored.errors[0]


def test_records_after_the_last_anchor_can_still_be_cut(tmp_path: Path) -> None:
    """Checkpoints only protect history up to the newest checkpoint."""
    path = tmp_path / "audit.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    fill(path, 2)
    write_checkpoint(path, anchors)
    fill(path, 2)
    records = read(path)
    write(path, records[:2])
    assert verify_log(path, anchor_path=anchors).ok


def test_recompute_is_caught_by_an_anchor(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    fill(path)
    write_checkpoint(path, anchors)
    records = read(path)
    records[0]["n"] = "tampered"
    write(path, recompute_with_sha256(records))
    report = verify_log(path, anchor_path=anchors)
    assert not report.ok
    assert "does not match" in report.errors[0]


def test_checkpoint_refuses_a_broken_or_empty_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    path.write_bytes(b"")
    assert not write_checkpoint(path, anchors).ok
    path.write_bytes(b"junk\n")
    assert not write_checkpoint(path, anchors).ok
    assert not anchors.exists()


def test_bad_anchor_file_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    fill(path)
    anchors.write_text("junk\n", encoding="utf-8")
    assert not verify_log(path, anchor_path=anchors).ok


def test_allowed_call_without_outcome_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append({"event": "tool_call_decision", "decision": "allow", "request_id": "done"})
    log.append({"event": "tool_call_outcome", "request_id": "done"})
    log.append({"event": "tool_call_decision", "decision": "deny", "request_id": "denied"})
    log.append({"event": "tool_call_decision", "decision": "allow", "request_id": "lost"})
    report = verify_log(path)
    assert report.ok
    flagged = [warning for warning in report.warnings if "no outcome" in warning]
    assert len(flagged) == 1
    assert "lost" in flagged[0]


def test_unwritable_path_raises(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)  # a directory cannot be opened for appending
    with pytest.raises(AuditWriteError):
        log.append({"event": "x"})


def test_torn_tail_blocks_further_writes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path)
    path.write_bytes(path.read_bytes()[:-3])
    with pytest.raises(AuditWriteError, match="incomplete"):
        AuditLog(path).append({"event": "x"})


def test_large_record_tail_is_read_correctly(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append({"event": "big", "blob": "x" * 200_000})
    log.append({"event": "big", "blob": "y" * 200_000})
    log.append({"event": "after"})
    assert verify_log(path).records == 3


def test_concurrent_processes_keep_one_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    code = (
        "import sys; from pathlib import Path; from repoward.audit import AuditLog\n"
        "log = AuditLog(Path(sys.argv[1]))\n"
        "for n in range(25): log.append({'event': 'race', 'worker': sys.argv[2], 'n': n})\n"
    )
    workers = [
        subprocess.Popen([sys.executable, "-c", code, str(path), str(worker)])  # noqa: S603
        for worker in range(4)
    ]
    assert all(worker.wait(timeout=120) == 0 for worker in workers)
    report = verify_log(path)
    assert report.ok, report.errors
    assert report.records == 100


def test_short_keys_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_KEY", "short")
    with pytest.raises(AuditKeyError):
        load_hmac_key("AUDIT_KEY")
    monkeypatch.delenv("AUDIT_KEY")
    assert load_hmac_key("AUDIT_KEY") is None


def test_cli_verify_and_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    fill(path, key=KEY)
    monkeypatch.setenv("AUDIT_KEY", KEY.decode())
    assert (
        main(["audit", "checkpoint", str(path), "--out", str(anchors), "--key-env", "AUDIT_KEY"])
        == 0
    )
    assert (
        main(["audit", "verify", str(path), "--anchor", str(anchors), "--key-env", "AUDIT_KEY"])
        == 0
    )
    assert "OK: 3 records" in capsys.readouterr().out
    assert main(["audit", "verify", str(path)]) == 1
    assert "FAILED" in capsys.readouterr().out
