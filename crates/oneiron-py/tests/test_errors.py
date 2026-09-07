"""The typed error contract (ONE-1441 §Typed error contract, I7).

These run against the translation layer directly, with no vault, because the
property under test is that the engine's payload survives the boundary
unedited — including codes this package has never heard of.
"""

import json

import pytest

from oneiron import OneironError
from oneiron import _translate  # noqa: PLC2701 — the seam under test


def native_raise(payload: object):
    """Builds what the native boundary actually raises: JSON in a message."""

    def operation():
        raise RuntimeError(json.dumps(payload))

    return operation


def test_preserves_code_message_and_suggestions() -> None:
    with pytest.raises(OneironError) as caught:
        _translate(
            native_raise(
                {
                    "code": "LEASE_REQUIRED",
                    "message": "deep recall requires a budget lease",
                    "suggestions": ["Use effort 'standard'."],
                }
            )
        )
    error = caught.value
    assert error.code == "LEASE_REQUIRED"
    assert error.message == "deep recall requires a budget lease"
    assert error.suggestions == ("Use effort 'standard'.",)


def test_unknown_future_codes_pass_through() -> None:
    with pytest.raises(OneironError) as caught:
        _translate(
            native_raise({"code": "SOME_FUTURE_CODE", "message": "m", "suggestions": ["s"]})
        )
    assert caught.value.code == "SOME_FUTURE_CODE"


def test_suggestions_are_never_empty() -> None:
    with pytest.raises(OneironError) as caught:
        _translate(native_raise({"code": "BAD_REQUEST", "message": "m", "suggestions": []}))
    assert len(caught.value.suggestions) > 0


def test_unparseable_payload_becomes_typed_internal_error() -> None:
    def operation():
        raise RuntimeError("<html>502 Bad Gateway</html>")

    with pytest.raises(OneironError) as caught:
        _translate(operation)
    assert caught.value.code == "INTERNAL_SERVER_ERROR"
    assert len(caught.value.suggestions) > 0


def test_already_typed_errors_pass_straight_through() -> None:
    original = OneironError("FORBIDDEN", "no", ["reconnect"])

    def operation():
        raise original

    with pytest.raises(OneironError) as caught:
        _translate(operation)
    assert caught.value is original
