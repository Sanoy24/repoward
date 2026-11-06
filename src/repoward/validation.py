"""Input rules shared by policy files and tool arguments.

Error messages never echo the rejected value, because it may be attacker-controlled.
"""

import re
import unicodedata
from typing import Annotated

from pydantic import AfterValidator

_REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}")
_DRIVE = re.compile(r"[A-Za-z]:")
_MAX_PATH_CHARS = 4096


def validate_repo(value: str) -> str:
    if not _REPO.fullmatch(value):
        raise ValueError("must be a valid owner/name repository")
    name = value.split("/", 1)[1].casefold()
    if name in {".", ".."} or name.endswith(".git"):
        raise ValueError("must be a valid owner/name repository")
    return value


def normalize_path(value: str) -> str:
    """Return the NFC form of a safe repository-relative path, or raise."""
    if not value or len(value) > _MAX_PATH_CHARS:
        raise ValueError("path length is out of range")
    if any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
        raise ValueError("path must not contain control characters")
    if "\\" in value:
        raise ValueError("path must not contain backslashes")
    if value.startswith("/") or _DRIVE.match(value):
        raise ValueError("path must be relative")
    normalized = unicodedata.normalize("NFC", value)
    for segment in normalized.split("/"):
        if segment in {"", ".", ".."}:
            raise ValueError("path must not contain empty, '.' or '..' segments")
        if segment.casefold() == ".git":
            raise ValueError("path must not touch the .git directory")
    return normalized


RepoName = Annotated[str, AfterValidator(validate_repo)]
RepoPath = Annotated[str, AfterValidator(normalize_path)]
