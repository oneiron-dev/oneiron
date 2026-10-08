"""Synthetic protocol/API fixtures only. No audio inference or model qualification."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "meeting_audio_runtime.py"
spec = importlib.util.spec_from_file_location("meeting_audio_runtime", MODULE)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "model"
        self.snapshot.mkdir()
        self.file = self.snapshot / "config.json"
        self.file.write_text("{}")
        self.profile = {"version": 1, "packages": {}, "asr": None,
                        "alignment": None, "diarization": None, "cleanup": None}
        self.path = self.root / "profile.json"

    def descriptor(self, model):
        return {"model_id": model, "snapshot": str(self.snapshot), "access_ref": "synthetic-fixture-not-a-license",
                "files": {"config.json": runtime.file_digest(self.file)}}

    def load(self):
        data = json.dumps(self.profile).encode()
        self.path.write_bytes(data)
        return runtime.LocalRuntime(self.path, runtime.digest(data))

    def configure(self, stage, model):
        self.profile[stage] = self.descriptor(model)
        self.profile["packages"].update({name: "fixture" for name in runtime.REQUIREMENTS[stage]})

    def test_only_exact_runtime_and_actual_tree_bytes_are_available(self):
        self.configure("alignment", runtime.ALIGNER)
        loaded = self.load()
        with patch.object(runtime, "version", return_value="other"):
            self.assertFalse(loaded.available("alignment"))
        with patch.object(runtime, "version", return_value="fixture"):
            self.assertTrue(loaded.available("alignment"))
        self.file.write_text('{"changed":true}')
        with patch.object(runtime, "version", return_value="fixture"):
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "ModelTreeDigestMismatch"):
                self.load().available("alignment")

    def test_unlisted_file_traversal_and_remote_code_refuse(self):
        self.configure("alignment", runtime.ALIGNER)
        (self.snapshot / "unlisted.txt").write_text("not permitted")
        with patch.object(runtime, "version", return_value="fixture"):
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "ModelTreeDigestMismatch"):
                self.load().available("alignment")
        (self.snapshot / "unlisted.txt").unlink()
        self.profile["alignment"]["files"] = {"../other": "0" * 64}
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidRuntimeProfile"):
            self.load()
        self.file.write_text('{"auto_map":{"AutoModel":"remote.Model"}}')
        self.configure("alignment", runtime.ALIGNER)
        with patch.object(runtime, "version", return_value="fixture"):
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "UnsupportedModelConfig"):
                self.load().available("alignment")



if __name__ == "__main__":
    unittest.main()
