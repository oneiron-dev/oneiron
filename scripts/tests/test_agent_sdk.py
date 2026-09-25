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
    def test_facade_handler_decodes_each_call_once(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        server = generator.outputs()["crates/oneiron-server/src/api/facade/agent_verbs.rs"]
        handlers = server.split("async fn ")[1:]
        self.assertTrue(any("sdk::invoke(" in handler for handler in handlers))
        for handler in handlers:
            if "sdk::invoke(" in handler:
                self.assertNotIn("sdk::validate_input(", handler, handler.split("(", 1)[0])
        # describe uses facade_input instead of invoke; it still needs admission.
        self.assertIn('sdk::validate_input("describe", &value)?;', server)

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

    def test_facade_row_name_drives_every_binding_body(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        for row in generator.ROWS:
            if row["name"] == "witness":
                row["name"] = "observe"
        outputs = generator.outputs()
        for path, spelling in [
            ("crates/oneiron-remote/src/agent_verbs.rs", "pub fn observe("),
            ("crates/oneiron-napi/src/facade/client/agent_verbs.rs", "pub fn observe("),
            ("crates/oneiron-py/src/lib.rs", "fn observe("),
            ("crates/oneiron-uniffi/src/facade_generated.rs", "fn observe("),
            ("packages/oneiron/src/index.ts", "observe(turn: WitnessTurn)"),
            ("packages/oneiron/src/native.ts", "observe(turn: WitnessTurn)"),
            ("crates/oneiron-py/python/oneiron/__init__.py", "def observe("),
            ("crates/oneiron-py/python/oneiron/__init__.pyi", "def observe("),
        ]:
            self.assertIn(spelling, outputs[path], path)

    def test_manifest_removal_suppresses_mcp_dispatch_and_catalog(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        generator.ROWS = [row for row in generator.ROWS if row["name"] != "rooms.claim"]
        outputs = generator.outputs()
        self.assertNotIn('"rooms.claim"', outputs["crates/oneiron/src/task_verb/sdk_generated.rs"])
        self.assertNotIn('"rooms.claim"', outputs["crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs"])
        self.assertNotIn('"rooms.claim"', outputs["crates/oneiron/src/task_verb/verb_catalog.rs"])

    def test_mcp_none_suppresses_projection_but_keeps_sdk_method(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        for row in generator.ROWS:
            if row["name"] == "rooms.claim":
                row["mcp"] = "none"
        outputs = generator.outputs()
        self.assertIn('"rooms.claim"', outputs["crates/oneiron/src/task_verb/sdk_generated.rs"])
        self.assertNotIn('"rooms.claim"', outputs["crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs"])
        self.assertIn('fn rooms_claim(', outputs["crates/oneiron/src/task_verb/sdk_generated.rs"])

    def test_board_context_row_controls_engine_mcp_and_catalog_projections(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        outputs = generator.outputs()
        core = outputs["crates/oneiron/src/task_verb/sdk_generated.rs"]
        self.assertIn("pub fn board_expand<S:", core)
        self.assertIn('"board.expand"', outputs["crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs"])
        self.assertNotIn("fn board_expand(", outputs["crates/oneiron-remote/src/agent_verbs.rs"])
        generator.ROWS = [row for row in generator.ROWS if row["name"] != "board.expand"]
        outputs = generator.outputs()
        self.assertNotIn("pub fn board_expand<S:", outputs["crates/oneiron/src/task_verb/sdk_generated.rs"])
        self.assertNotIn('"board.expand"', outputs["crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs"])
        self.assertNotIn('"board.expand"', outputs["crates/oneiron/src/task_verb/verb_catalog.rs"])

    def test_task_rows_forward_inputs_through_python_namespace(self):
        spec = importlib.util.spec_from_file_location("generated_agent_verbs", ROOT / "crates/oneiron-py/python/oneiron/agent_verbs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        calls = []
        tasks = module.TasksVerbs(lambda name, value: calls.append((name, value)))
        request = {"task_ref": "task"}
        tasks.update(request)
        create = {"spec": {"goal": "review"}, "label": "review"}
        tasks.create(create)
        self.assertEqual(calls, [("tasks_update", request), ("tasks_create", create)])

    def test_retired_task_names_leave_every_generated_output(self):
        spec = importlib.util.spec_from_file_location("sdk_generator", ROOT / "scripts/sdk/generate.py")
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        outputs = {path: text for path, text in generator.outputs().items() if text is not None}
        for path, text in outputs.items():
            for retired in ["check", "expand", "ack", "cancel"]:
                for spelling in ["tasks." + retired, "tasks_" + retired, "tasks" + retired.title()]:
                    self.assertNotIn(spelling, text, path)
        catalog = "crates/oneiron/src/task_verb/verb_catalog.rs"
        routes = "crates/oneiron-server/src/api/facade/agent_verbs.rs"
        remote = "crates/oneiron-remote/src/agent_verbs.rs"
        napi = "crates/oneiron-napi/src/facade/client/agent_verbs.rs"
        pyo3 = "crates/oneiron-py/src/lib.rs"
        python = "crates/oneiron-py/python/oneiron/__init__.py"
        python_tasks = "crates/oneiron-py/python/oneiron/agent_verbs.py"
        typescript = "packages/oneiron/src/index.ts"
        typescript_tasks = "packages/oneiron/src/agent-verbs.ts"
        for path, spelling in [
            (catalog, '=> "describe"'), (catalog, '=> "tasks.update"'), (catalog, '=> "cancel"'),
            (routes, '"/describe"'), (routes, '"/tasks.update"'), (routes, '"/cancel"'),
            (remote, 'typed_agent_verb("describe"'), (remote, 'typed_agent_verb("tasks.update"'), (remote, 'typed_agent_verb("cancel"'),
            (napi, 'agent_verb("describe"'), (napi, 'agent_verb("tasks.update"'), (napi, 'agent_verb("cancel"'),
            (pyo3, 'agent_verb("describe"'), (pyo3, 'agent_verb("tasks.update"'), (pyo3, 'agent_verb("cancel"'),
            (python, "def describe(self, task_ref: str | None = None)"), (python_tasks, '"tasks_update"'), (python, "def cancel(self, task_ref: str)"),
            (typescript, "describe(taskRef?: string)"), (typescript_tasks, '"tasksUpdate"'), (typescript, "cancel(taskRef: string)"),
        ]:
            self.assertIn(spelling, outputs[path], path)

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
        question={"intent_key":"one","who":{"people":["person"]},"what":{"reference":{"turn":"question"},"revision":1,"options":{},"context_refs":[]},"until":100,"decide":"first"}
        handle={"group_ref":"group"}
        self.assertEqual(tasks.ask(question)["value"],question)
        self.assertEqual(tasks.wait(handle,"step-b")["value"],{"handle":handle,"step_key":"step-b"})
        word={"result_ref":"result","option":None}
        self.assertEqual(tasks.answer(handle,word)["value"],{"handle":handle,"word":word})
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
                return json.dumps({"handle": {"group_ref": "group"}, "task_refs": ["task"], "hold": None, "idempotent_replay": False})
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
            question = {"intent_key":"one","who":{"people":["person"]},"what":{"reference":{"turn":"question"},"revision":1,"options":{},"context_refs":[]},"until":100,"decide":"first"}
            receipt = client.tasks.ask(question)
            self.assertEqual(calls, [question])
            self.assertEqual(receipt["handle"], {"group_ref": "group"})
            self.assertEqual(client.rooms.list(), [])
            with self.assertRaises(package.OneironError) as refusal:
                client.tasks.wait(receipt["handle"])
            self.assertEqual(refusal.exception.code, "FORBIDDEN")

if __name__ == "__main__": unittest.main()
