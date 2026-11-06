from pathlib import Path

import pytest

from repoward.cli import main


def test_version_prints_and_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip()


def test_command_is_required() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main([])
    assert exit_info.value.code == 2


def test_serve_requires_policy_and_audit() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["serve"])
    assert exit_info.value.code == 2


def test_serve_refuses_a_bad_policy_before_starting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("default: allow\n", encoding="utf-8")
    assert (
        main(
            [
                "serve",
                "--policy",
                str(bad),
                "--audit",
                str(tmp_path / "a.jsonl"),
                "--approvals",
                str(tmp_path / "a.db"),
                "--flow",
                str(tmp_path / "f.db"),
            ]
        )
        == 1
    )
    assert "default" in capsys.readouterr().err


def test_serve_refuses_a_short_key(
    policy_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("REPOWARD_AUDIT_HMAC_KEY", "short")
    assert (
        main(
            [
                "serve",
                "--policy",
                str(policy_file),
                "--audit",
                str(tmp_path / "a.jsonl"),
                "--approvals",
                str(tmp_path / "a.db"),
                "--flow",
                str(tmp_path / "f.db"),
            ]
        )
        == 1
    )
    assert "at least 32 bytes" in capsys.readouterr().err
