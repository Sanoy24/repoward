"""The GitHub token in the OS keychain, through the optional `keyring` package.

This keeps the token out of MCP client config files, where it can be copied or committed by
mistake. It does not hide the token from an agent with a shell running as the same user, which
can read the keychain too. Running the server as its own user is what covers that.
"""

from typing import Any

SERVICE = "repoward"
ACCOUNT = "github-token"
INSTALL_HINT = "keychain support needs the keyring extra: pip install 'repoward[keyring]'"


class KeychainError(Exception):
    """The keychain could not be used. The message never holds the token."""


def _keyring() -> Any:
    try:
        import keyring
        import keyring.errors
    except ImportError as exc:
        raise KeychainError(INSTALL_HINT) from exc
    return keyring


def available() -> bool:
    try:
        _keyring()
    except KeychainError:
        return False
    return True


def get_token(service: str = SERVICE) -> str | None:
    keyring = _keyring()
    try:
        value = keyring.get_password(service, ACCOUNT)
    except keyring.errors.KeyringError as exc:
        raise KeychainError(f"the keychain could not be read: {type(exc).__name__}") from None
    return value if isinstance(value, str) and value else None


def set_token(token: str, service: str = SERVICE) -> None:
    keyring = _keyring()
    try:
        keyring.set_password(service, ACCOUNT, token)
    except keyring.errors.KeyringError as exc:
        raise KeychainError(f"the keychain could not be written: {type(exc).__name__}") from None


def delete_token(service: str = SERVICE) -> bool:
    """Remove the token. Returns False if there was none."""
    keyring = _keyring()
    try:
        keyring.delete_password(service, ACCOUNT)
    except keyring.errors.PasswordDeleteError:
        return False
    except keyring.errors.KeyringError as exc:
        raise KeychainError(f"the keychain could not be changed: {type(exc).__name__}") from None
    return True
