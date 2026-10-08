"""The embedded behaviour matrix (ONE-1441 §Test/Embedded, §Quickstarts G8).

The Node suite runs the same matrix; both must agree, because the two packages
are one contract with two spellings.
"""

import math
import time

import pytest

from oneiron import Oneiron, OneironError


@pytest.fixture()
def memory(tmp_path):
    return Oneiron.open(tmp_path / "vault")


def test_divergent_reopen_options_are_bad_request(tmp_path) -> None:
    Oneiron.open(tmp_path / "vault", dimensions=256)
    with pytest.raises(OneironError) as caught:
        Oneiron.open(tmp_path / "vault", dimensions=512)
    assert caught.value.code == "BAD_REQUEST"


@pytest.fixture()
def quickstart(memory):
    witnessed = memory.witness(
        {
            "conversation_ref": "11111111111111111111111111111111",
            "messages": [
                {
                    "author": "user",
                    "message_type": "dialogue",
                    "content": "I prefer a window seat when I fly.",
                    "order": 0,
                }
            ],
        }
    )
    claimed = memory.claim_upsert(
        {
            "id": "22222222222222222222222222222222",
            "predicate": "preference.travel.seat",
            "subject_ref": witnessed["turn_short_id"],
            "value": {"seat": "window"},
            "confidence": 1.0,
            "source": "user_stated",
        }
    )
    return memory, witnessed, claimed


def test_g8_recall_returns_pack_version_one_and_finds_the_claim(quickstart) -> None:
    memory, _, _ = quickstart
    recalled = memory.recall("window seat")
    assert recalled["pack_version"] == 1
    texts = " ".join(item["value_text"] for item in recalled["items"]).lower()
    assert "window seat" in texts


def test_g8_receipts_carries_at_least_one_real_gate_row(quickstart) -> None:
    memory, _, _ = quickstart
    receipts = memory.receipts()
    assert len(receipts) > 0
    for row in receipts:
        assert row["receipt_ref"]
        assert isinstance(row["outcome"], str)
        assert isinstance(row["reason_codes"], list)


def test_omitted_timestamp_is_stamped_in_unix_seconds(quickstart) -> None:
    # The witness above omitted `occurred_at`, so the gate rows it produced
    # carry a boundary-stamped time. Seconds, not milliseconds: a milliseconds
    # value would be ~1000x larger and centuries in the future.
    memory, _, _ = quickstart
    now = math.floor(time.time())
    for row in memory.receipts():
        assert abs(row["created_at"] - now) <= 300


def test_negative_timestamp_is_refused_before_core_entry(memory) -> None:
    with pytest.raises(OneironError) as caught:
        memory.witness(
            {
                "conversation_ref": "11111111111111111111111111111111",
                "messages": [
                    {"author": "user", "message_type": "dialogue", "content": "hi", "order": 0}
                ],
                "occurred_at": -1,
            }
        )
    assert caught.value.code == "BAD_REQUEST"


@pytest.mark.parametrize("confidence", [float("nan"), float("inf")])
def test_non_finite_confidence_is_refused_before_narrowing(memory, confidence) -> None:
    with pytest.raises(OneironError) as caught:
        memory.claim_upsert(
            {
                "predicate": "preference.travel.seat",
                "subject_ref": "11111111111111111111111111111111",
                "value": {"seat": "window"},
                "confidence": confidence,
                "source": "user_stated",
            }
        )
    assert caught.value.code == "BAD_REQUEST"


def test_malformed_actor_key_is_refused(memory) -> None:
    with pytest.raises(OneironError) as caught:
        memory.as_actor("not-an-actor-key")
    assert caught.value.code
    assert len(caught.value.suggestions) > 0
