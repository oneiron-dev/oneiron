"""Generated language projections forward typed data, without a second domain model."""
import importlib.util
import json
import sys
import types
from unittest.mock import patch
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]

class AgentSdkProjectionTests(unittest.TestCase):
    def test_manifest_removal_suppresses_facade_bindings(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        generator.ROWS = [row for row in generator.ROWS if row["name"] != "key_value_get"]
        outputs = generator.outputs()
        for path, spelling in [
            ("crates/oneiron/src/task_verb/sdk_generated.rs", '"key_value_get"'),
            ("crates/oneiron-server/src/api/facade/agent_verbs.rs", "fn key_value_get("),
            ("crates/oneiron-remote/src/agent_verbs.rs", "fn key_value_get("),
            ("crates/oneiron-napi/src/facade/client/agent_verbs.rs", "fn key_value_get("),
            ("crates/oneiron-py/src/lib.rs", "fn key_value_get("),
            ("packages/oneiron/src/index.ts", "keyValueGet(request:"),
            ("packages/oneiron/src/native.ts", "keyValueGet(requestJson:"),
            ("crates/oneiron-py/python/oneiron/__init__.py", "def key_value_get("),
            ("crates/oneiron-py/python/oneiron/__init__.pyi", "def key_value_get("),
        ]:
            self.assertNotIn(spelling, outputs[path], path)

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
        rooms.messages("room", after="last-turn", limit=5)
        self.assertEqual(calls[-1], ("rooms_messages", {"room_ref":"room", "after":"last-turn", "limit":5}))

    def test_public_python_namespaces_decode_native_results_and_translate_refusals(self):
        package_path = ROOT / "crates/oneiron-py/python/oneiron"
        calls = []
        class NativeClient:
            @staticmethod
            def connect(url, key):
                return NativeClient()
            def tasks_ask(self, value):
                calls.append(json.loads(value))
                return json.dumps({"handle": {"task_ref": "task"}, "count": 1, "replayed": False})
            def tasks_wait(self, value):
                raise RuntimeError(json.dumps({"code": "FORBIDDEN", "message": "denied", "suggestions": ["Use the owning actor."]}))
            def rooms_list(self, value):
                return "[]"
        name = "_agent_sdk_fixture"
        native = types.ModuleType(name + "._native")
        native.NativeClient = NativeClient
        spec = importlib.util.spec_from_file_location(name, package_path / "__init__.py", submodule_search_locations=[str(package_path)])
        package = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {name: package, name + "._native": native}):
            spec.loader.exec_module(package)
            client = package.Oneiron.connect("https://example.invalid", "credential")
            question = {"question": {"text": "Proceed?"}, "holders": ["person"], "idempotency_key": "one"}
            receipt = client.tasks.ask(question)
            self.assertEqual(calls, [question])
            self.assertEqual(receipt["handle"], {"task_ref": "task"})
            self.assertEqual(client.rooms.list(), [])
            with self.assertRaises(package.OneironError) as refusal:
                client.tasks.wait(receipt["handle"])
            self.assertEqual(refusal.exception.code, "FORBIDDEN")

if __name__ == "__main__": unittest.main()
