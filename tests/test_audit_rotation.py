"""Rotation keeps one unbroken chain across files, and verification covers all of them."""

import itertools
import json
import os
import threading
from pathlib import Path

import pytest

from repoward.audit import (
    AuditLog,
    AuditWriteError,
    log_files,
    read_records,
    verify_log,
    write_checkpoint,
)
from repoward.cli import main
from repoward.policy.loader import PolicyError, parse_policy
from repoward.policy.replay import replay_log

KEY = b"k" * 32
LIMIT = 400


def fill(path: Path, count: int, key: bytes | None = None, limit: int | None = LIMIT) -> AuditLog:
    log = AuditLog(path, key, rotate_bytes=limit)
    for number in range(count):
        log.append({"event": "flow_reset", "principal": f"p{number}"})
    return log


def archives(path: Path) -> list[Path]:
    return [file for file in log_files(path) if file != path]


def test_it_is_off_by_default(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 50, limit=None)
    assert log_files(path) == [path]


def test_a_full_file_becomes_an_archive(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    names = [file.name for file in archives(path)]
    assert names
    assert names[0].startswith("audit.000000000001-")
    assert all(file.stat().st_size >= LIMIT for file in archives(path))
    assert path.stat().st_size < LIMIT + 200


def test_the_chain_continues_across_files(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    records = read_records(path)
    assert [record["seq"] for record in records] == list(range(1, 31))
    for earlier, later in itertools.pairwise(records):
        assert later["prev_hash"] == earlier["hash"]
    report = verify_log(path)
    assert report.ok, report.errors
    assert report.records == 30
    assert report.tip_seq == 30


def test_an_archive_name_matches_its_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    for file in archives(path):
        seqs = [json.loads(line)["seq"] for line in file.read_bytes().splitlines()]
        assert file.name == f"audit.{seqs[0]:012d}-{seqs[-1]:012d}.jsonl"


def test_an_append_right_after_rotation_chains_to_the_archive(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = fill(path, 30)
    path.unlink()  # As if rotation had just happened and nothing was written since.
    record = log.append({"event": "flow_reset", "principal": None})
    last_archived = read_records(archives(path)[-1])[-1]
    assert record["prev_hash"] == last_archived["hash"]
    assert record["seq"] == last_archived["seq"] + 1
    assert verify_log(path).ok


def test_hmac_logs_rotate_and_verify(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30, KEY)
    assert archives(path)
    assert verify_log(path, KEY).ok
    assert not verify_log(path).ok


def test_editing_an_archive_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    first = archives(path)[0]
    first.write_bytes(first.read_bytes().replace(b'"p1"', b'"px"'))
    report = verify_log(path)
    assert not report.ok
    assert first.name in report.errors[0]


def test_removing_a_middle_archive_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 60)
    assert len(archives(path)) >= 3
    archives(path)[1].unlink()
    assert not verify_log(path).ok


def test_removing_the_oldest_archives_is_a_warning(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 60)
    oldest = archives(path)[0]
    oldest.unlink()
    report = verify_log(path)
    assert report.ok, report.errors
    assert any("earlier archives are missing" in warning for warning in report.warnings)


def test_an_anchor_still_catches_a_removed_oldest_archive(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 2)
    anchors = tmp_path / "anchors.jsonl"
    assert write_checkpoint(path, anchors).ok  # Anchors seq 2, which the oldest archive holds.
    fill(path, 58)
    oldest = archives(path)[0]
    assert oldest.name.startswith("audit.000000000001-")
    oldest.unlink()
    report = verify_log(path, anchor_path=anchors)
    assert not report.ok
    assert "record is missing" in report.errors[0]


def test_a_renamed_archive_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    first = archives(path)[0]
    renamed = first.with_name("audit.000000000001-000000000099.jsonl")
    assert renamed.name != first.name
    os.replace(first, renamed)
    assert not verify_log(path).ok


def test_an_empty_archive_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    (tmp_path / "audit.000000000000-000000000000.jsonl").write_bytes(b"")
    assert not verify_log(path).ok


def test_a_torn_archive_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    first = archives(path)[0]
    first.write_bytes(first.read_bytes()[:-5])
    assert not verify_log(path).ok


def test_unrelated_files_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    (tmp_path / "audit.old.jsonl").write_text("not a log", encoding="utf-8")
    (tmp_path / "audit.1-2.jsonl").write_text("not a log", encoding="utf-8")
    assert verify_log(path).ok


def test_a_torn_current_file_still_refuses_writes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = fill(path, 30)
    path.write_bytes(path.read_bytes() + b'{"partial')
    with pytest.raises(AuditWriteError):
        log.append({"event": "flow_reset", "principal": None})


def test_writers_in_parallel_keep_one_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"

    def write() -> None:
        log = AuditLog(path, rotate_bytes=LIMIT)
        for number in range(20):
            log.append({"event": "flow_reset", "principal": f"t{number}"})

    threads = [threading.Thread(target=write) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    report = verify_log(path)
    assert report.ok, report.errors
    assert report.records == 80
    assert archives(path)


def test_replay_reads_every_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, rotate_bytes=LIMIT)
    for number in range(12):
        log.append(
            {
                "event": "tool_call_decision",
                "request_id": f"r{number}",
                "instance_id": "i",
                "principal": "local:me",
                "role": "reader",
                "tool": "ping",
                "args_redacted": {},
                "decision": "allow",
                "rule_id": "roles.reader.tools",
            }
        )
    assert archives(path)
    policy = parse_policy(
        b"version: 1\ndefault: deny\nroles:\n  reader:\n    tools: [ping]\n"
        b"rate_limits:\n  default: { per_minute: 100 }\nstdio:\n  role: reader\n"
    )
    assert replay_log(path, policy).decisions == 12


def test_the_command_verifies_the_whole_series(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    fill(path, 30)
    assert main(["audit", "verify", str(path)]) == 0
    assert "OK: 30 records" in capsys.readouterr().out
    first = archives(path)[0]
    first.write_bytes(first.read_bytes().replace(b'"p1"', b'"px"'))
    assert main(["audit", "verify", str(path)]) == 1


BASE = b"""\
version: 1
default: deny
roles:
  reader:
    tools: [ping]
rate_limits:
  default: { per_minute: 10 }
stdio:
  role: reader
"""


def test_the_policy_setting() -> None:
    assert parse_policy(BASE).policy.audit.rotate_mb is None
    assert parse_policy(BASE + b"audit:\n  rotate_mb: 50\n").policy.audit.rotate_mb == 50


@pytest.mark.parametrize("value", [b"0", b"-1", b"'50'", b"1.5", b"200000"])
def test_bad_rotation_sizes_are_refused(value: bytes) -> None:
    with pytest.raises(PolicyError):
        parse_policy(BASE + b"audit:\n  rotate_mb: " + value + b"\n")
