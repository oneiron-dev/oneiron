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

if __name__ == "__main__":
    unittest.main()
