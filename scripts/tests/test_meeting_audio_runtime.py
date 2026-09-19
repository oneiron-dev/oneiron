"""Synthetic protocol/API fixtures only. No audio inference or model qualification."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
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

    def test_profile_schema_digest_duplicate_keys_and_future_versions_refuse(self):
        self.load()
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "RuntimeProfileDigestMismatch"):
            runtime.LocalRuntime(self.path, "0" * 64)
        for data in [b'{"version":1,"version":1}', b'{"version":NaN}']:
            self.path.write_bytes(data)
            with self.assertRaises(runtime.RuntimeRefusal):
                runtime.LocalRuntime(self.path, runtime.digest(data))
        self.profile["version"] = 2
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidRuntimeProfile"):
            self.load()

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

    def test_alignment_uses_real_fields_and_never_guesses_missing_words_or_language(self):
        items = [SimpleNamespace(text="Hello,", start_time=0.0, end_time=0.1234),
                 SimpleNamespace(text="world!", start_time=0.1234, end_time=0.5)]
        words = runtime.aligned_words(items, "Hello, world!", 500)
        self.assertEqual([(w["start_ms"], w["end_ms"], w["confidence"]) for w in words], [(0, 123, None), (123, 500, None)])
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "AlignmentTextMismatch"):
            runtime.aligned_words(items, "Different words", 500)
        loaded = self.load()
        for language in [None, "uk", "Ukrainian"]:
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "ForcedAlignmentLanguageUnsupported"):
                loaded.alignment_language(language)
        self.assertEqual(loaded.alignment_language("ja"), "Japanese")
        for timestamp in [-1, float("nan"), float("inf"), True, 1.0]:
            with self.assertRaises(runtime.RuntimeRefusal):
                runtime.milliseconds(timestamp, 500)

    def test_qwen_documented_api_is_local_and_word_times_are_not_asr_chunk_times(self):
        self.configure("alignment", runtime.ALIGNER)
        loaded = self.load()
        calls = []
        def load_model(path, **kwargs):
            calls.append((path, kwargs))
            def align(**request):
                calls.append(request)
                return [[SimpleNamespace(text="hi", start_time=0.02, end_time=0.1)]]
            return SimpleNamespace(align=align)
        modules = {"torch": SimpleNamespace(float32="fixture-f32"),
                   "qwen_asr": SimpleNamespace(Qwen3ForcedAligner=SimpleNamespace(from_pretrained=load_model))}
        with patch.object(runtime, "version", return_value="fixture"), patch.dict("sys.modules", modules):
            words = loaded.align([0.0] * 1600, "hi", "en", 100)
        self.assertEqual(words[0]["start_ms"], 20)
        self.assertEqual(calls[0], (str(self.snapshot), {"dtype": "fixture-f32", "device_map": "cpu"}))
        self.assertEqual(calls[1]["language"], "English")
        self.assertEqual(calls[1]["audio"][1], 16000)

    def test_one_global_exclusive_pass_keeps_provider_labels_and_rejects_overlap(self):
        self.configure("diarization", runtime.COMMUNITY)
        loaded = self.load()
        items = [(SimpleNamespace(start=0.0, end=0.2), "track0", "A"),
                 (SimpleNamespace(start=0.2, end=0.4), "track1", "B")]
        calls = []
        class Annotation:
            def itertracks(self, yield_label):
                self_test.assertTrue(yield_label)
                return iter(items)
        self_test = self
        def pipeline(request):
            calls.append(request)
            return SimpleNamespace(exclusive_speaker_diarization=Annotation())
        def load_model(path):
            self.assertEqual(path, str(self.snapshot))
            return pipeline
        modules = {"torch": SimpleNamespace(from_numpy=lambda samples: SimpleNamespace(unsqueeze=lambda axis: (axis, len(samples)))),
                   "pyannote.audio": SimpleNamespace(Pipeline=SimpleNamespace(from_pretrained=load_model))}
        with patch.object(runtime, "version", return_value="fixture"), patch.dict("sys.modules", modules):
            tracks = loaded.diarize([0.0] * 6400, 400)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], {"waveform": (0, 6400), "sample_rate": 16000})
        self.assertEqual([track["speaker_cluster"] for track in tracks], ["A", "B"])
        items[1] = (SimpleNamespace(start=0.1, end=0.4), "track1", "B")
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidExclusiveDiarization"):
            runtime.exclusive_tracks(items, 400)

    def test_cleanup_requires_pinned_instructions_and_strict_exact_count_output(self):
        self.configure("cleanup", "fixture-cleanup-model")
        instructions = self.root / "instructions.txt"
        instructions.write_text("{{TRANSCRIPT_JSON}}")
        self.profile["cleanup"].update(instructions=str(instructions), instructions_sha256=runtime.file_digest(instructions),
                                       max_tokens=256, max_input_tokens=70)
        loaded = self.load()
        calls = []
        tokenizer = SimpleNamespace(encode=lambda text: list(text), apply_chat_template=lambda messages, **kwargs: messages[0]["content"])
        def generate(model, tokenizer, **request):
            calls.append(request)
            return json.dumps({"texts": [turn["text"] for turn in json.loads(request["prompt"])]})
        modules = {"mlx_lm": SimpleNamespace(load=lambda *args, **kwargs: ("fixture", tokenizer), generate=generate),
                   "mlx_lm.sample_utils": SimpleNamespace(make_sampler=lambda **kwargs: "fixture-sampler")}
        turns = [{"text": str(i) * 20} for i in range(7)]
        with patch.object(runtime, "version", return_value="fixture"), patch.dict("sys.modules", modules):
            self.assertEqual(loaded.cleanup(turns), [turn["text"] for turn in turns])
        self.assertGreater(len(calls), 1)
        self.assertTrue(all(len(call["prompt"]) <= 70 for call in calls))
        for text in ['{"texts":[]}', '{"texts":[" "]}', '{"texts":["hi"],"extra":true}', '{"texts":["hi"],"texts":["hi"]}', 'not-json']:
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidCleanupOutput"):
                runtime.cleanup_texts(text, 1)
        instructions.write_text("changed")
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "CleanupInstructionsDigestMismatch"):
            loaded.instructions(self.profile["cleanup"])


if __name__ == "__main__":
    unittest.main()
