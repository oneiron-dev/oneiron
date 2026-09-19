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
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidAlignmentOutput"):
            runtime.aligned_words([SimpleNamespace(text="を", start_time=4.0, end_time=4.0)], "を", 6000)
        loaded = self.load()
        for language in [None, "uk", "Ukrainian"]:
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "ForcedAlignmentLanguageUnsupported"):
                loaded.alignment_language(language)
        self.assertEqual(loaded.alignment_language("ja"), "Japanese")
        for timestamp in [-1, float("nan"), float("inf"), True, 1.0]:
            with self.assertRaises(runtime.RuntimeRefusal):
                runtime.milliseconds(timestamp, 500)

    def test_acoustic_tokens_keep_original_unspoken_punctuation_and_refuse_missing_words(self):
        items = [SimpleNamespace(text="hello", start_time=0.0, end_time=0.2),
                 SimpleNamespace(text="world", start_time=0.3, end_time=0.5)]
        words = runtime.aligned_words(items, '“Hello, world!”', 500)
        self.assertEqual([w["text"] for w in words], ['“Hello,', 'world!”'])
        self.assertEqual([(w["start_ms"], w["end_ms"]) for w in words], [(0,200), (300,500)])
        for text in ["hello changed world", "hello there", "hello world extra"]:
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "AlignmentTextMismatch"):
                runtime.aligned_words(items, text, 500)
        self.assertFalse(runtime.registered_moss_config({"model_type":"moss_transcribe_diarize", "auto_map":{"AutoModel":"evil.run"}}))

    def test_ukrainian_timing_is_explicit_and_is_not_russian_asr(self):
        self.configure("uk_alignment", runtime.UK_ALIGNER)
        loaded = self.load()
        with patch.object(runtime, "version", return_value="fixture"):
            self.assertEqual(loaded.alignment_models(), {"Ukrainian": runtime.UK_ALIGNER})
            self.assertEqual(loaded.alignment_model("uk"), runtime.UK_ALIGNER)
            self.assertEqual(loaded.alignment_language("uk"), "Ukrainian")
        bridge_spec = importlib.util.spec_from_file_location("audio_bridge", MODULE.with_name("meeting-audio-native.py"))
        bridge = importlib.util.module_from_spec(bridge_spec)
        bridge_spec.loader.exec_module(bridge)
        host = bridge.NativeHost(self.root, Path("/missing-ffmpeg"), self.snapshot)
        with patch.object(host, "runtime", return_value=loaded), patch.object(runtime, "version", return_value="fixture"):
            capabilities = host.capabilities()
        self.assertEqual(capabilities["alignment_languages"], ["Ukrainian"])
        self.assertEqual(capabilities["transcribe_pack_languages"], [])
        self.assertNotIn("transcribe_pack", capabilities["operations"])
        self.assertFalse(capabilities["artifact_capable"])
        for language in ["uk", "uk-UA", "Ukrainian"]:
            with self.assertRaisesRegex(bridge.Refusal, "AsrLanguageUnsupported"):
                bridge.NativeHost.validate_asr_options({"model_id": runtime.ASR, "glossary": [], "language_hint": language})

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
        self.assertEqual(calls[0], (str(self.snapshot), {"dtype": "fixture-f32", "device_map": "cpu", "local_files_only": True}))
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

    def test_split_ports_bind_language_audio_model_and_full_file_without_local_provider_import(self):
        from types import SimpleNamespace
        process = runtime.process_module()
        descriptor = {"backend": "process", "interpreter": "/fixture/python", "python_version": "fixture",
            "script": "/fixture/meeting-audio-worker.py", "profile": "/fixture/profile.json",
            "profile_sha256": "a" * 64, "code_sha256": {name: "b" * 64 for name in process.CODE_FILES},
            "timeout_seconds": 10}
        self.profile.update(alignment=descriptor, diarization=descriptor)
        loaded = self.load()
        body, calls = b"\0\0" * 1600, []
        def invoke(spec, stage, operation, data, options, error, parse):
            calls.append((stage, operation, data, options))
            if operation == "capabilities":
                return {"available": True, "stage": stage, "model_execution": False,
                    "models_by_language": {"English": runtime.ALIGNER} if stage == "alignment" else {},
                    "model_id": runtime.COMMUNITY, "model_files_sha256": "c" * 64}
            model = runtime.ALIGNER if stage == "alignment" else runtime.COMMUNITY
            proof = {"model_id": model, "input_sha256": runtime.digest(data), "execution": "measured",
                     "invocation_id": "synthetic-unit-not-native-proof", "language": "English",
                     "transcript_sha256": runtime.digest(b"hi"), "full_file_samples": 1600}
            return {"runtime_binding": {"fixture": True}, "provenance": proof, "aligner_model": model,
                "words": [{"text": "hi", "start_ms": 0, "end_ms": 100, "confidence": None}],
                "exclusive_tracks": [{"start_ms": 0, "end_ms": 100, "speaker_cluster": "A"}]}
        fake = SimpleNamespace(check_files=lambda *args: None, call=invoke)
        with patch.object(runtime, "process_module", return_value=fake), patch.object(runtime, "process_pcm", return_value=body):
            words = loaded.align([0.0] * 1600, "hi", "en", 100)
            tracks = loaded.diarize([0.0] * 1600, 100)
        self.assertEqual(words[0]["text"], "hi")
        self.assertEqual(tracks[0]["speaker_cluster"], "A")
        self.assertEqual([call[:2] for call in calls], [("alignment", "capabilities"), ("alignment", "align_words"),
            ("diarization", "capabilities"), ("diarization", "diarize_full_file")])
        self.assertEqual(calls[1][3], {"transcript": "hi", "language": "English"})
        self.assertEqual(calls[3][2], body)
        self.assertIsNotNone(loaded.last_alignment_provenance)
        self.assertIsNotNone(loaded.last_diarization_provenance)

    def test_moss_is_one_global_decode_and_never_invents_word_timestamps(self):
        self.configure("moss", runtime.MOSS)
        self.profile["moss"]["max_tokens"] = 128
        loaded = self.load()
        calls = []
        class FixtureModel:
            sample_rate = 16000
            def generate(self, audio, **options):
                calls.append((len(audio), options))
                return SimpleNamespace(generation_tokens=12, segments=[
                    {"start": 0.0, "end": 0.2, "text": "[S01] hello", "speaker_id": "S01"},
                    {"start": 0.2, "end": 0.4, "text": "[S02] there", "speaker_id": "S02"}])
        FixtureModel.__module__ = "mlx_audio.stt.models.moss_transcribe_diarize.moss_transcribe_diarize"
        def load_model(path, error):
            self.assertEqual(path, self.snapshot)
            self.assertIs(error, runtime.RuntimeRefusal)
            return FixtureModel()
        with patch.object(runtime, "version", return_value="fixture"), patch.object(runtime, "load_registered_moss", side_effect=load_model):
            tracks = loaded.moss([0.0] * 6400, 400)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], 6400)
        self.assertFalse(calls[0][1]["stream"])
        self.assertEqual(tracks[0]["speaker_cluster"], "S01")
        self.assertEqual(tracks[1]["speaker_cluster"], "S02")
        self.assertEqual(tracks[1]["start_ms"], 200)
        self.assertNotIn("words", tracks[0])
        # The installed SDK's no-match fallback has full-file start/end but no
        # speaker_id. It is not a real parsed speaker segment and must refuse.
        FixtureModel.generate = lambda *args, **kwargs: SimpleNamespace(generation_tokens=12,
            segments=[{"start":0.0,"end":0.4,"text":"unparsed output"}])
        with patch.object(runtime, "version", return_value="fixture"), patch.object(runtime, "load_registered_moss", side_effect=load_model):
            with self.assertRaisesRegex(runtime.RuntimeRefusal, "InvalidMossOutput"):
                loaded.moss([0.0]*6400,400)
        self.profile["moss"]["model_id"] = "unrelated-model"
        with self.assertRaisesRegex(runtime.RuntimeRefusal, "UnsupportedMossConfiguration"):
            self.load()



if __name__ == "__main__":
    unittest.main()
