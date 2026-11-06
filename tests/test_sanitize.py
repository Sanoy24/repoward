import pytest

from repoward.sanitize import REDACTED, redact_for_audit, redact_text, truncate_text


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_" + "a" * 36,
        "github_pat_" + "a1_" * 10,
        "AKIA" + "A" * 16,
        "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\nunterminated",
    ],
)
def test_secrets_are_redacted(secret: str) -> None:
    result = redact_text(f"before {secret} after")
    assert secret not in result
    assert REDACTED in result


@pytest.mark.parametrize(
    ("text", "kept", "gone"),
    [
        ("Authorization: token abc123", "Authorization:", "abc123"),
        ("Bearer abc.def-123", "Bearer", "abc.def-123"),
        ("export API_KEY=hunter2", "API_KEY=", "hunter2"),
        ("DB_PASSWORD = hunter2", "DB_PASSWORD", "hunter2"),
    ],
)
def test_labelled_secrets_keep_the_label(text: str, kept: str, gone: str) -> None:
    result = redact_text(text)
    assert kept in result
    assert gone not in result


@pytest.mark.parametrize(
    "secret",
    ["ghp_" + "a" * 36, "github_pat_" + "a" * 30, "AKIA" + "A" * 16, "eyJabcde.eyJabcde.sig"],
)
def test_secrets_glued_to_other_text_are_still_redacted(secret: str) -> None:
    assert secret not in redact_text(f"xxx{secret}yyy")


def test_ordinary_text_is_unchanged() -> None:
    assert redact_text("the token is valid in this path") == "the token is valid in this path"


def test_lone_surrogates_become_storable() -> None:
    redact_text("a\ud800b").encode("utf-8")


def test_truncation_says_how_much_was_cut() -> None:
    assert truncate_text("abcdef", 2) == "ab\n[truncated 4 characters]"
    assert truncate_text("ab", 2) == "ab"


def test_secret_on_the_cut_line_does_not_survive_when_redacted_first() -> None:
    secret = "ghp_" + "a" * 36
    assert "ghp_" not in truncate_text(redact_text(secret), 10)


def test_audit_redaction_handles_sensitive_keys_and_nesting() -> None:
    value = {"token": "plain", "nested": {"note": "ghp_" + "b" * 36}, "n": 1, "ok": True, "x": None}
    result = redact_for_audit(value)
    assert result["token"] == REDACTED
    assert result["nested"]["note"] == REDACTED
    assert (result["n"], result["ok"], result["x"]) == (1, True, None)


def test_audit_redaction_is_bounded() -> None:
    deep: object = "x"
    for _ in range(20):
        deep = [deep]
    assert "[TRUNCATED]" in str(redact_for_audit(deep))
    assert len(redact_for_audit(list(range(1000)))) == 50
    assert len(redact_for_audit("y" * 10_000)) < 600
    assert redact_for_audit(1.5) == "[float]"
