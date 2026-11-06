import pytest

from repoward.canonical import canonical_json

BACKSLASH = chr(92)
QUOTE = chr(34)


def test_keys_are_sorted_and_compact() -> None:
    assert canonical_json({"b": 1, "a": [True, None]}) == b'{"a":[true,null],"b":1}'


def test_key_order_does_not_change_the_bytes() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_rfc_8785_string_vector() -> None:
    """The string example from RFC 8785 section 3.2.2.2."""
    value = chr(0x20AC) + "$" + chr(0x0F) + chr(0x0A) + "A'B" + QUOTE + BACKSLASH * 2 + QUOTE + "/"
    expected = (
        QUOTE
        + chr(0x20AC)
        + "$"
        + BACKSLASH
        + "u000f"
        + BACKSLASH
        + "nA'B"
        + BACKSLASH
        + QUOTE
        + BACKSLASH * 4
        + BACKSLASH
        + QUOTE
        + "/"
        + QUOTE
    )
    assert canonical_json(value).decode("utf-8") == expected


def test_nan_is_refused() -> None:
    with pytest.raises(ValueError):
        canonical_json(float("nan"))
