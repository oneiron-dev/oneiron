"""Count errors through the public wrapper and real, installed native extension.

The native wheel can be reused unchanged; the public wrapper must be current.
Remote refusals use no server and must occur before HTTP dispatch.
"""

import pytest

from oneiron import Oneiron, OneironError
from oneiron import _translate  # noqa: PLC2701 — the error seam under test


INVALID_COUNTS = [
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(-0.5, id="negative-fraction"),
    pytest.param(0.5, id="fraction-below-one"),
    pytest.param(1.5, id="fraction"),
    pytest.param(1.0, id="float-not-python-int"),
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="infinity"),
    pytest.param(float("-inf"), id="negative-infinity"),
    pytest.param(2**32 + 1, id="u32-wraparound"),
    pytest.param(2**53 - 1, id="js-safe-edge-over-cap"),
    pytest.param(2**53, id="js-unsafe-over-cap"),
    pytest.param(2**64, id="usize-overflow"),
    pytest.param(2**256, id="huge-integer"),
    pytest.param(-(2**256), id="huge-negative-integer"),
    pytest.param(1e300, id="huge-float"),
]


def bad_request(operation, field: str) -> OneironError:
    with pytest.raises(OneironError) as caught:
        operation()
    error = caught.value
    assert error.code == "BAD_REQUEST"
    assert isinstance(error.message, str) and error.message.strip()
    assert error.suggestions
    assert all(isinstance(suggestion, str) and suggestion for suggestion in error.suggestions)
    # PyO3 overflow messages omit argument names; wrapper suggestions supply them.
    assert any(field in text for text in (error.message, *error.suggestions))
    assert error.__suppress_context__  # No raw extraction exception in the traceback.
    return error


@pytest.mark.parametrize("dimensions", [*INVALID_COUNTS, 16_385, 256.5])
def test_dimensions_reject_bad_counts_without_creating_vault(tmp_path, dimensions) -> None:
    path = tmp_path / "refused-vault"
    bad_request(lambda: Oneiron.open(path, dimensions=dimensions), "dimensions")
    assert not path.exists()


@pytest.mark.parametrize("dimensions", [1, 256, 16_384])
def test_dimensions_accept_valid_integer_controls(tmp_path, dimensions) -> None:
    memory = Oneiron.open(tmp_path / "vault", dimensions=dimensions)
    assert isinstance(memory.receipts(1), list)


@pytest.fixture(scope="module")
def embedded_memory(tmp_path_factory):
    memory = Oneiron.open(tmp_path_factory.mktemp("numeric-counts") / "vault")
    witnessed = memory.witness(
        {
            "conversation_ref": "11111111111111111111111111111111",
            "messages": [
                {"author": "user", "message_type": "dialogue", "content": "window seat", "order": 0}
            ],
        }
    )
    memory.claim_upsert(
        {
            "predicate": "preference.travel.seat",
            "subject_ref": witnessed["turn_short_id"],
            "value": {"seat": "window"},
            "confidence": 1.0,
            "source": "user_stated",
        }
    )
    return memory


@pytest.fixture(scope="module", params=["embedded", "remote"])
def memory(request, embedded_memory):
    if request.param == "embedded":
        return embedded_memory
    # No server or waiting network fixture. Invalid counts must never be sent.
    return Oneiron.connect("http://127.0.0.1:9", "numeric-count-probe")


@pytest.mark.parametrize("verb", ["recall", "receipts"])
@pytest.mark.parametrize("limit", [*INVALID_COUNTS, 1000.5, 1001])
def test_limits_reject_bad_counts_before_dispatch(memory, verb, limit) -> None:
    if verb == "recall":
        bad_request(lambda: memory.recall("window seat", limit=limit), "limit")
    else:
        bad_request(lambda: memory.receipts(limit), "limit")


@pytest.mark.parametrize("limit", [1, 10, 100, 1000])
def test_limits_accept_valid_integer_controls(embedded_memory, limit) -> None:
    pack = embedded_memory.recall("window seat", limit=limit)
    assert pack["pack_version"] == 1
    assert 0 < len(pack["items"]) <= limit
    assert 0 < len(embedded_memory.receipts(limit)) <= limit


def test_omitted_counts_preserve_defaults(embedded_memory) -> None:
    assert embedded_memory.recall("window seat") == embedded_memory.recall("window seat", limit=10)
    assert embedded_memory.receipts() == embedded_memory.receipts(100)


@pytest.mark.parametrize("exception", [TypeError, ValueError, OverflowError])
def test_argument_errors_are_bad_request_with_correction_suggestions(exception) -> None:
    def operation():
        raise exception("limit cannot be extracted")

    error = bad_request(lambda: _translate(operation), "limit")
    assert any("positive Python integers" in suggestion for suggestion in error.suggestions)


def test_malformed_native_payload_stays_internal_error() -> None:
    def operation():
        raise RuntimeError("invalid native payload")

    with pytest.raises(OneironError) as caught:
        _translate(operation)
    assert caught.value.code == "INTERNAL_SERVER_ERROR"
    assert caught.value.suggestions
