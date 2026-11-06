"""Secret redaction and size limits. Best effort: patterns cannot catch every secret."""

import re
from typing import Any

REDACTED = "[REDACTED]"
_MAX_AUDIT_STRING = 512
_MAX_ITEMS = 50
_MAX_DEPTH = 6
_SENSITIVE_KEY = re.compile(r"authorization|password|passwd|secret|token|api_?key", re.I)

_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
            re.S,
        ),
        REDACTED,
    ),
    (re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), REDACTED),
    (re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"), REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), REDACTED),
    (re.compile(r"(?im)^(\s*authorization\s*:\s*).+$"), rf"\g<1>{REDACTED}"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"), f"Bearer {REDACTED}"),
    (
        re.compile(
            r"(?im)^(\s*(?:export\s+)?[A-Z0-9_]*"
            r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*).+$"
        ),
        rf"\g<1>{REDACTED}",
    ),
)


def redact_text(text: str) -> str:
    """Replace known secret patterns, and lone surrogates that cannot be stored as UTF-8."""
    cleaned = text.encode("utf-8", "replace").decode("utf-8")
    for pattern, replacement in _REPLACEMENTS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def truncate_text(text: str, limit: int) -> str:
    """Cut text to a limit with an explicit note. Always redact first."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n[truncated {len(text) - limit} characters]"


def redact_for_audit(value: Any, depth: int = 0) -> Any:
    """Return a bounded, redacted copy of a JSON-like value."""
    if depth >= _MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return truncate_text(redact_text(value), _MAX_AUDIT_STRING)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:_MAX_ITEMS]:
            safe_key = truncate_text(redact_text(str(key)), _MAX_AUDIT_STRING)
            sensitive = _SENSITIVE_KEY.search(safe_key) is not None
            result[safe_key] = REDACTED if sensitive else redact_for_audit(item, depth + 1)
        return result
    if isinstance(value, list | tuple):
        return [redact_for_audit(item, depth + 1) for item in list(value)[:_MAX_ITEMS]]
    return f"[{type(value).__name__}]"
