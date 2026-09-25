"""Agent verbs through the public Python SDK and the real PyO3 extension."""

import pytest

from oneiron import Oneiron, OneironError

# Every ask needs a deadline; this one lies far past any test run.
UNTIL = 4_102_444_800


def ask_spec(intent_key, owner, question, outcome_binding=None):
    """The typed ask: the owner answers one question TURN, the first word decides."""
    what = {"reference": {"turn": question}, "revision": 1, "options": {}, "context_refs": []}
    if outcome_binding is not None:
        what["outcome_binding"] = outcome_binding
    return {
        "intent_key": intent_key, "who": {"people": [owner]}, "what": what,
        "until": UNTIL, "decide": "first",
    }


@pytest.fixture()
def agent_memory(tmp_path):
    memory = Oneiron.open(tmp_path / "vault")
    # Ask words cite readable units. A claim needs a scoped read grant that
    # the SDK cannot give, so the question and the result are both TURNs.
    question = "55555555555555555555555555555555"
    result = "22222222222222222222222222222222"
    for turn_ref, content in ((question, "Choose the Python result"), (result, "Python SDK result")):
        memory.witness({
            "conversation_ref": "11111111111111111111111111111111",
            "turn_ref": turn_ref,
            "messages": [{
                "author": "user", "message_type": "dialogue",
                "content": content, "order": 0,
            }],
        })
    claim = memory.claim_upsert({
        "predicate": "preference.sdk_result", "subject_ref": result,
        "value": "ready", "confidence": 1.0, "source": "user_stated",
    })
    owner = next(
        row["actor_ref"] for row in memory.receipts()
        if row["receipt_ref"] == claim["receipt_ref"]
    )
    return memory, owner, result, question


@pytest.mark.parametrize("answer_first", [False, True])
def test_ask_wait_resumes_only_once_in_both_orders(agent_memory, answer_first):
    memory, owner, result, question = agent_memory
    spec = ask_spec("python-ask", owner, question, outcome_binding={
        "source": {"kind": "claim", "predicate": "preference.sdk_outcome"},
        "horizon": 60, "mapping": {"won": True}, "noise_weight": 0.8,
    })
    receipt = memory.tasks.ask(spec)
    handle = receipt["handle"]
    retry = memory.tasks.ask(spec)
    assert retry["handle"] == handle
    assert retry["idempotent_replay"] is True
    if not answer_first:
        assert "Pending" in memory.tasks.wait(handle, "caller-step")
        # A parked step does not suspend the caller or block another task.
        other = memory.tasks.ask(ask_spec("unrelated", owner, question))
        assert other["handle"] != handle
    word = {"result_ref": result, "option": None}
    answer = memory.tasks.answer(handle, word)
    assert answer["result_ref"] == result
    assert answer["actor_ref"] == owner
    assert answer["task_ref"] in receipt["task_refs"]
    ready = memory.tasks.wait(handle, "caller-step")
    settled = ready["Ready"]
    assert settled["decision"] == {"first": answer}
    assert settled["coverage"]["met"] is True
    assert settled["settlement"]["revision"] == 1
    assert len(settled["settlement"]["outcome_answer_ref"]) == 32
    # The step resumed once; a later wait reads the same settled result.
    assert memory.tasks.wait(handle, "caller-step") == ready
    assert memory.tasks.answer(handle, word) == answer
    # Waiting is bound per step, not per task handle.
    assert memory.tasks.wait(handle, "another-step") == ready
    assert memory.tasks.wait(handle, "another-step") == ready
    memory.claim_upsert({
        "id": "33333333333333333333333333333333",
        "predicate": "preference.sdk_outcome", "subject_ref": result,
        "value": "won", "confidence": 1.0, "source": "user_stated",
    })
    # The outcome reader needs a scoped read grant on the outcome fact, and
    # the ask id is never one. With no grant the owner gets no pair.
    assert memory.tasks.outcomes(handle) == []


def test_task_burst_is_admitted_not_rate_refused(agent_memory):
    memory, owner, _, question = agent_memory
    handles = set()
    tasks = set()
    for index in range(12):
        receipt = memory.tasks.ask(ask_spec(f"burst-{index}", owner, question))
        assert receipt["idempotent_replay"] is False
        handles.add(receipt["handle"]["group_ref"])
        tasks.update(receipt["task_refs"])
    assert len(handles) == 12
    assert len(tasks) == 12


def test_room_refusal_preserves_typed_error_without_creating_a_room(agent_memory):
    memory, _, _, _ = agent_memory
    before = memory.rooms.list()
    with pytest.raises(OneironError) as caught:
        memory.rooms.messages("44444444444444444444444444444444")
    assert caught.value.code == "BAD_REQUEST"
    assert caught.value.suggestions
    assert memory.rooms.list() == before
