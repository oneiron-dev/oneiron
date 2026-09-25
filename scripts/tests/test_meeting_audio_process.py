"""Synthetic protocol isolation tests. No models, installation or qualification."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

runtime = load("meeting_audio_runtime")
process = load("meeting_audio_process")

class ProcessTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in process.CODE_FILES:
            shutil.copyfile(ROOT / name, self.root / name)
        self.leaf = self.root / "leaf.json"
        self.leaf.write_text(json.dumps({"version": 1, "packages": {}, "asr": None,
            "alignment": None, "diarization": None, "cleanup": None}))
        self.spec = {"backend": "process", "interpreter": sys.executable,
            "python_version": sys.version.split()[0], "script": str(self.root / "meeting-audio-worker.py"),
            "code_sha256": {name: runtime.file_digest(self.root / name) for name in process.CODE_FILES},
            "profile": str(self.leaf), "profile_sha256": runtime.file_digest(self.leaf), "timeout_seconds": 10}

    def parent(self, stage="alignment"):
        profile = {"version": 1, "packages": {}, "asr": None,
            "alignment": None, "diarization": None, "cleanup": None}
        profile[stage] = self.spec
        path = self.root / "parent.json"
        path.write_text(json.dumps(profile))
        return runtime.LocalRuntime(path, runtime.file_digest(path))

    def test_real_separate_interpreter_reports_capability_not_inference(self):
        for stage in ["alignment", "diarization"]:
            parent = self.parent(stage)
            self.assertFalse(parent.available(stage))
            receipt = parent.process_capabilities(stage)
            self.assertFalse(receipt["model_execution"])
            self.assertEqual(receipt["runtime_binding"]["profile_sha256"], self.spec["profile_sha256"])
            self.assertEqual(receipt["runtime_binding"]["python_version"], sys.version.split()[0])

    def test_profile_code_and_interpreter_bindings_refuse_drift(self):
        parent = self.parent()
        self.assertFalse(parent.available("alignment"))
        self.leaf.write_text("{}")
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "ProcessProfileDigestMismatch"):
            parent.available("alignment")
        self.spec["profile_sha256"] = runtime.file_digest(self.leaf)
        (self.root / "meeting-audio-worker.py").write_text("# changed")
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "ProcessCodeDigestMismatch"):
            process.check_files(self.spec, runtime.RuntimeRefusal)

    def test_wrong_python_binding_and_nested_delegation_refuse(self):
        self.spec["python_version"] = "0.0.fixture"
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "ProcessRuntimeBindingMismatch"):
            self.parent().available("alignment")
        self.spec["python_version"] = sys.version.split()[0]
        profile = json.loads(self.leaf.read_text())
        profile["alignment"] = self.spec.copy()
        self.leaf.write_text(json.dumps(profile))
        self.spec["profile_sha256"] = runtime.file_digest(self.leaf)
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidProcessFrame"):
            self.parent().available("alignment")

    def test_process_output_and_lifetime_are_bounded(self):
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "ProcessOutputTooLarge"):
            process.exchange([sys.executable, "-c", "import sys; sys.stdout.write('x' * 1100000)"], b"x", 10, runtime.RuntimeRefusal)
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "ProcessPortTimedOut"):
            process.exchange([sys.executable, "-c", "import os; r,w=os.pipe(); os.read(r,1)"], b"x", 1, runtime.RuntimeRefusal)

    def test_untrusted_word_or_track_output_is_not_repaired(self):
        words = [{"start_ms": 0, "end_ms": 10, "text": "hi", "confidence": None}]
        self.assertEqual(runtime.checked_process_words(words, "hi", 10, runtime.RuntimeRefusal), words)
        for changed in [{**words[0], "start_ms": True}, {**words[0], "end_ms": 11}, {**words[0], "confidence": 1.0}]:
            with self.assertRaises(runtime.RuntimeRefusal):
                runtime.checked_process_words([changed], "hi", 10, runtime.RuntimeRefusal)
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "AlignmentTextMismatch"):
            runtime.checked_process_words(words, "else", 10, runtime.RuntimeRefusal)
        with self.assertRaises(runtime.RuntimeRefusal):
            runtime.checked_process_tracks([{"start_ms": 0, "end_ms": 11, "speaker_cluster": "A"}], 10, runtime.RuntimeRefusal)

if __name__ == "__main__":
    unittest.main()
