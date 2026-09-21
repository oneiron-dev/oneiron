"""Agent verbs through the public Python SDK and the real PyO3 extension."""

import pytest

from oneiron import Oneiron, OneironError


@pytest.fixture()
def agent_memory(tmp_path):
    memory = Oneiron.open(tmp_path / "vault")
    witnessed = memory.witness({
        "conversation_ref": "11111111111111111111111111111111",
        "messages": [{
            "author": "user", "message_type": "dialogue",
            "content": "Python SDK result", "order": 0,
        }],
    })
    result = "22222222222222222222222222222222"
    claim = memory.claim_upsert({
        "id": result, "predicate": "preference.sdk_result",
        "subject_ref": witnessed["turn_short_id"], "value": "ready",
        "confidence": 1.0, "source": "user_stated",
    })
    owner = next(
        row["actor_ref"] for row in memory.receipts()
        if row["receipt_ref"] == claim["receipt_ref"]
    )
    return memory, owner, result


@pytest.mark.parametrize("answer_first", [False, True])
def test_ask_wait_resumes_only_once_in_both_orders(agent_memory, answer_first):
    memory, owner, result = agent_memory
    spec = {
        "question": {"text": "Choose the Python result"}, "holders": [owner],
        "idempotency_key": "python-ask",
        "outcome_binding": {
            "source": {"kind": "claim", "predicate": "preference.sdk_outcome"},
            "horizon": 60, "mapping": {"won": True}, "noise_weight": 0.8,
        },
    }
    receipt = memory.tasks.ask(spec)
    handle = receipt["handle"]
    retry = memory.tasks.ask(spec)
    assert retry["handle"] == handle
    assert retry["replayed"] is True
    if not answer_first:
        assert "Pending" in memory.tasks.wait(handle, "caller-step")
        # A parked step does not suspend the caller or block another task.
        other = memory.tasks.ask({
            "question": {"text": "Keep working"}, "holders": [owner],
            "idempotency_key": "unrelated",
        })
        assert other["handle"] != handle
    answer = memory.tasks.answer(handle, result)
    assert answer["result_ref"] == result
    assert answer["question_version"] == 1
    assert len(answer["answer_ref"]) == 32
    assert memory.tasks.wait(handle, "caller-step") == {"Ready": answer}
    assert memory.tasks.wait(handle, "caller-step") == {"AlreadyResumed": answer}
    assert memory.tasks.answer(handle, result) == answer
    # Consumption is per step, not per task handle.
    assert memory.tasks.wait(handle, "another-step") == {"Ready": answer}
    assert memory.tasks.wait(handle, "another-step") == {"AlreadyResumed": answer}
    memory.claim_upsert({
        "id": "33333333333333333333333333333333",
        "predicate": "preference.sdk_outcome", "subject_ref": result,
        "value": "won", "confidence": 1.0, "source": "user_stated",
    })
    pairs = memory.tasks.outcomes(handle)
    assert pairs
    assert all(
        pair["outcome"]["label"] and pair["outcome"]["answer"] == answer["answer_ref"]
        for pair in pairs
    )


def test_task_burst_is_counted_not_rate_refused(agent_memory):
    memory, owner, _ = agent_memory
    handles = set()
    counts = []
    for index in range(12):
        receipt = memory.tasks.ask({
            "question": {"text": "Burst"}, "holders": [owner],
            "idempotency_key": f"burst-{index}",
        })
        handles.add(receipt["handle"]["task_ref"])
        counts.append(receipt["count"])
    assert len(handles) == 12
    assert counts == list(range(counts[0], counts[0] + 12))


def test_room_refusal_preserves_typed_error_without_creating_a_room(agent_memory):
    memory, _, _ = agent_memory
    before = memory.rooms.list()
    with pytest.raises(OneironError) as caught:
        memory.rooms.messages("44444444444444444444444444444444")
    assert caught.value.code == "BAD_REQUEST"
    assert caught.value.suggestions
    assert memory.rooms.list() == before
