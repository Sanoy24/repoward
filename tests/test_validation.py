import pytest

from repoward.validation import normalize_path, validate_repo


@pytest.mark.parametrize("repo", ["org/repo", "a-b/c.d_e", "O/R"])
def test_valid_repos(repo: str) -> None:
    assert validate_repo(repo) == repo


@pytest.mark.parametrize(
    "repo",
    [
        "",
        "org",
        "org/",
        "/repo",
        "a/b/c",
        "org/..",
        "org/.",
        "org/repo.git",
        "org/REPO.GIT",
        "-org/repo",
        "org/re po",
        "org/repo\n",
        "a" * 40 + "/repo",
    ],
)
def test_invalid_repos(repo: str) -> None:
    with pytest.raises(ValueError):
        validate_repo(repo)


def test_error_does_not_echo_the_value() -> None:
    with pytest.raises(ValueError) as info:
        validate_repo("attacker text")
    assert "attacker" not in str(info.value)


@pytest.mark.parametrize("path", ["a.txt", "src/a.py", ".env", "a/.hidden/b", "..a/b.."])
def test_valid_paths(path: str) -> None:
    assert normalize_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/etc/passwd",
        "C:/x",
        "c:x",
        "a/../b",
        "..",
        "./a",
        "a//b",
        "a/",
        "a\\b",
        "a\x00b",
        "a\nb",
        "a\x85b",
        ".git/config",
        "a/.GIT/config",
        "x" * 4097,
    ],
)
def test_invalid_paths(path: str) -> None:
    with pytest.raises(ValueError):
        normalize_path(path)


def test_paths_are_normalized_to_nfc() -> None:
    assert normalize_path("cafe\u0301.txt") == "caf\u00e9.txt"
