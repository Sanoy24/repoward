"""The GitHub token in the OS keychain. Tests use an in-memory keychain, never the real one."""

import builtins
from collections.abc import Iterator
from typing import Any

import keyring
import keyring.backend
import keyring.errors
import pytest

from repoward.adapters import keychain
from repoward.cli import main
from repoward.server import personal_token

TOKEN = "github_pat_" + "x" * 40


class MemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self.store: dict[tuple[str, str], str] = {}
        self.fail = False

    def _check(self) -> None:
        if self.fail:
            raise keyring.errors.KeyringError("backend broke, token-like text " + TOKEN)

    def get_password(self, service: str, username: str) -> str | None:
        self._check()
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._check()
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self._check()
        if (service, username) not in self.store:
            raise keyring.errors.PasswordDeleteError("missing")
        del self.store[(service, username)]


@pytest.fixture
def memory(monkeypatch: pytest.MonkeyPatch) -> Iterator[MemoryKeyring]:
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield backend
    keyring.set_keyring(previous)


def prompt(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr("repoward.cli.getpass.getpass", lambda _prompt: value)


def test_set_stores_the_token_without_printing_it(
    memory: MemoryKeyring, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt(monkeypatch, f"  {TOKEN}\n")
    assert main(["token", "set"]) == 0
    assert memory.store[("repoward", "github-token")] == TOKEN
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err


@pytest.mark.parametrize("value", ["", "   ", "two words", "tab\tinside"])
def test_set_refuses_something_that_is_not_a_token(
    memory: MemoryKeyring, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    prompt(monkeypatch, value)
    assert main(["token", "set"]) == 1
    assert not memory.store


def test_status_and_delete(memory: MemoryKeyring, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["token", "status"]) == 0
    assert "No token is stored" in capsys.readouterr().out
    keychain.set_token(TOKEN)
    assert main(["token", "status"]) == 0
    assert "A token is stored" in capsys.readouterr().out
    assert main(["token", "delete"]) == 0
    assert "Removed" in capsys.readouterr().out
    assert main(["token", "delete"]) == 0
    assert "No token was stored" in capsys.readouterr().out


def test_status_says_when_the_environment_wins(
    memory: MemoryKeyring, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    keychain.set_token(TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    main(["token", "status"])
    assert "used instead" in capsys.readouterr().out


def test_the_server_uses_the_keychain_when_the_environment_has_none(
    memory: MemoryKeyring,
) -> None:
    assert personal_token() is None
    keychain.set_token(TOKEN)
    assert personal_token() == TOKEN


def test_the_environment_takes_precedence(
    memory: MemoryKeyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    keychain.set_token(TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    assert personal_token() == "from-env"


def test_an_empty_environment_value_falls_back_to_the_keychain(
    memory: MemoryKeyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    keychain.set_token(TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "")
    assert personal_token() == TOKEN


def test_a_broken_keychain_means_no_token_and_no_leak(
    memory: MemoryKeyring, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    memory.fail = True
    assert personal_token() is None
    for command in (["token", "status"], ["token", "delete"]):
        assert main(command) == 1
    prompt(monkeypatch, TOKEN)
    assert main(["token", "set"]) == 1
    captured = capsys.readouterr()
    assert "KeyringError" in captured.err
    assert TOKEN not in captured.out + captured.err


def test_without_the_extra_the_environment_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def no_keyring(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "keyring" or name.startswith("keyring."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_keyring)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert not keychain.available()
    assert personal_token() is None
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    assert personal_token() == "from-env"
    with pytest.raises(keychain.KeychainError, match=r"repoward\[keyring\]"):
        keychain.get_token()


def test_the_command_explains_how_to_install_the_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing() -> Any:
        raise keychain.KeychainError(keychain.INSTALL_HINT)

    monkeypatch.setattr(keychain, "_keyring", missing)
    assert main(["token", "status"]) == 1
    assert "repoward[keyring]" in capsys.readouterr().err
