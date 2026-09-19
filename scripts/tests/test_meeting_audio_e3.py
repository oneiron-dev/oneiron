"""Synthetic E3 orchestration and receipt-binding cases; no real models or audio."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import subprocess
import sys
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "meeting-audio-e3.py"
spec = importlib.util.spec_from_file_location("meeting_audio_e3", SCRIPT)
e3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e3)


class E3Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.reference = {"language": "en", "tokenizer": "fixture-word-ids", "words": [
            {"word_id": "w1", "start_ms": 0, "end_ms": 200, "principal_id": "person:fixture-a"},
            {"word_id": "w2", "start_ms": 200, "end_ms": 400, "principal_id": "person:fixture-b"}]}
        self.tracks = [{"start_ms": 0, "end_ms": 200, "speaker_cluster": "S01"},
                       {"start_ms": 200, "end_ms": 400, "speaker_cluster": "S02"}]
        self.mapping = {"S01": "person:fixture-a", "S02": "person:fixture-b"}

    def test_named_accuracy_does_not_fit_a_permutation_to_reference_truth(self):
        result = e3.score_words(self.reference, self.tracks, self.mapping)
        self.assertEqual(result["correct"], 2)
        wrong = {"S01": "person:fixture-b", "S02": "person:fixture-a"}
        self.assertEqual(e3.score_words(self.reference, self.tracks, wrong)["wrong_speaker"], 2)
        self.assertEqual(e3.score_words(self.reference, self.tracks, {})["missing_words"], 2)
        self.assertEqual(e3.score_words(self.reference, [], self.mapping)["missing_words"], 2)
        with self.assertRaisesRegex(e3.bridge.Refusal, "InvalidReference"):
            e3.checked_reference(dict(self.reference, words=self.reference["words"] * 2))

    def capture_fixture(self):
        audio = b"synthetic callback fixture; not playable media"
        ref = e3.encoded(self.reference)
        (self.root / "fixture.bin").write_bytes(audio)
        (self.root / "reference.json").write_bytes(ref)
        cohort = {"schema": "oneiron.audio.e3.cohort.v1", "corpus_id": "synthetic-unit-fixture", "files": [
            {"file_id": "fixture", "audio_path": "fixture.bin", "audio_sha256": e3.checksum(audio),
             "reference_path": "reference.json", "reference_sha256": e3.checksum(ref),
             "consent_ref": "fixture-not-real-consent"}]}
        (self.root / "cohort.json").write_bytes(e3.encoded(cohort))
        workspace = self.root / "workspace"
        workspace.mkdir()
        output = self.root / "capture"
        output.mkdir()
        args = SimpleNamespace(cohort=self.root / "cohort.json", output=output, workspace=workspace,
             ffmpeg=Path("/fixture"), model_snapshot=Path("/fixture"), runtime_profile=Path("/fixture"),
             runtime_profile_sha256="a" * 64)
        calls = []
        tracks = self.tracks
        class FixtureHost:
            def __init__(self, *args):
                pass
            def capabilities(self):
                return {"operations": [row[0] for row in e3.ARMS.values()], "artifact_capable": False, "e1_e3_evidence": False}
            def dispatch(self, operation, body, options):
                calls.append(operation)
                if operation == "decode":
                    pcm = b"\0\0" * 16000
                    return {"pcm_sha256": e3.checksum(pcm)}, pcm
                field = next(row[1] for row in e3.ARMS.values() if row[0] == operation)
                return {field: tracks, "provenance": {"execution": "measured", "input_sha256": e3.checksum(body),
                        "invocation_id": "synthetic-" + operation, "model_id": "fixture-" + next(row[2] for row in e3.ARMS.values() if row[0] == operation)}}, b""
        fixture_profile = SimpleNamespace(profile={stage: {"model_id": "fixture-" + stage, "files": {"fixture": "b" * 64}}
            for _op, _field, stage in e3.ARMS.values()})
        with patch.object(e3, "ProcessPorts", FixtureHost), patch.object(e3.runtime, "LocalRuntime", return_value=fixture_profile):
            result = e3.capture(args)
        self.assertEqual(calls, ["decode", "community1_exclusive_full_file", "moss_e3_full_file"])
        self.assertFalse(result["e1_e3_qualified"])
        self.assertFalse(result["named_principal_scored"])
        return output

    def matching_fixture(self, output):
        completion = e3.read_json(output / "completion.json")
        record = e3.read_json(output / completion["records"][0]["path"])
        matches = {"schema": "oneiron.audio.e3.enrollment_matches.v1", "enrollment_sha256": "c" * 64,
          "enrollment_consent_ref": "fixture-not-consent", "matcher_model_sha256": "d" * 64,
          "matcher_runtime_sha256": "e" * 64, "matches": [
            {"file_id": "fixture", "arm": arm, "audio_sha256": record["audio_sha256"],
             "tracks_sha256": record["arms"][arm]["tracks_sha256"], "receipt_ref": "fixture-not-native",
             "cluster_to_principal": self.mapping} for arm in e3.ARMS]}
        path = self.root / "matches.json"
        path.write_bytes(e3.encoded(matches))
        return path, matches

    def test_synthetic_capture_completion_is_distinct_from_setup_and_named_scoring(self):
        output = self.capture_fixture()
        self.assertEqual(e3.read_json(output / "setup.json")["phase"], "setup")
        self.assertEqual(e3.read_json(output / "completion.json")["phase"], "capture_complete")
        path, _ = self.matching_fixture(output)
        result = e3.score(output, path)
        self.assertEqual(result["scores"]["fixture"]["community1"]["correct"], 2)
        self.assertEqual(result["scores"]["fixture"]["moss"]["correct"], 2)
        self.assertFalse(result["e1_e3_qualified"])

    def test_wrong_output_matching_receipt_and_capture_drift_refuse(self):
        output = self.capture_fixture()
        path, matches = self.matching_fixture(output)
        matches["matches"][0]["tracks_sha256"] = "f" * 64
        path.write_bytes(e3.encoded(matches))
        with self.assertRaisesRegex(e3.bridge.Refusal, "EnrollmentOutputBindingMismatch"):
            e3.score(output, path)
        path, _ = self.matching_fixture(output)
        completion = e3.read_json(output / "completion.json")
        (output / completion["records"][0]["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(e3.bridge.Refusal, "CaptureDigestMismatch"):
            e3.score(output, path)

    def test_setup_or_failed_completion_is_never_a_scored_capture(self):
        (self.root / "completion.json").write_bytes(e3.encoded({"phase": "failed"}))
        with self.assertRaisesRegex(e3.bridge.Refusal, "CaptureNotComplete"):
            e3.score(self.root, self.root / "no-matches.json")

    def test_real_cli_records_missing_backend_as_failure_not_model_completion(self):
        workspace = self.root / "workspace"
        workspace.mkdir()
        profile = self.root / "profile.json"
        profile.write_bytes(e3.encoded({"version": 1, "packages": {}, "asr": None,
            "alignment": None, "diarization": None, "cleanup": None}))
        cohort = self.root / "cohort.json"
        cohort.write_bytes(e3.encoded({"schema": "oneiron.audio.e3.cohort.v1", "corpus_id": "fixture", "files": [{}]}))
        output = self.root / "capture"
        command = [sys.executable, str(SCRIPT), "capture", "--workspace", str(workspace),
            "--ffmpeg", sys.executable, "--model-snapshot", str(workspace),
            "--runtime-profile", str(profile), "--runtime-profile-sha256", e3.checksum(profile.read_bytes()),
            "--cohort", str(cohort), "--output", str(output)]
        result = subprocess.run(command, capture_output=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertEqual(e3.read_json(output / "setup.json")["phase"], "setup")
        completed = (output / "completion.json").read_bytes()
        self.assertEqual(json.loads(completed)["error"], "E3BackendUnavailable")
        self.assertEqual(json.loads(completed)["phase"], "failed")
        self.assertFalse((output / "events.jsonl").exists())
        again = subprocess.run(command, capture_output=True, timeout=20, check=False)
        self.assertEqual(again.returncode, 2)
        self.assertEqual((output / "completion.json").read_bytes(), completed)



if __name__ == "__main__":
    unittest.main()
