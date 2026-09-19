"""Generated language projections forward typed data, without a second domain model."""
import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]

class AgentSdkProjectionTests(unittest.TestCase):
    def test_python_ask_wait_answer_and_room_arguments(self):
        spec = importlib.util.spec_from_file_location("generated_agent_verbs", ROOT / "crates/oneiron-py/python/oneiron/agent_verbs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        calls=[]
        def invoke(method, payload):
            calls.append((method,payload))
            return {"method":method,"value":payload}
        tasks=module.TasksVerbs(invoke)
        rooms=module.RoomsVerbs(invoke)
        question={"question":{"text":"Proceed?"},"holders":["person"],"idempotency_key":"one"}
        handle={"task_ref":"task"}
        self.assertEqual(tasks.ask(question)["value"],question)
        self.assertEqual(tasks.wait(handle,"step-b")["value"],{"handle":handle,"step_key":"step-b"})
        self.assertEqual(tasks.answer(handle,"result")["value"],{"handle":handle,"result_ref":"result"})
        self.assertEqual(tasks.outcomes(handle)["value"],handle)
        rooms.list();rooms.messages("room");rooms.claim("room","turn");rooms.speak({"conversation_ref":"room"})
        self.assertEqual([name for name,_ in calls],["tasks_ask","tasks_wait","tasks_answer","tasks_outcomes","rooms_list","rooms_messages","rooms_claim","rooms_speak"])
        self.assertEqual(calls[6][1],{"room_ref":"room","turn_ref":"turn"})

if __name__ == "__main__": unittest.main()
