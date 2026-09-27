#!/usr/bin/env python3
"""Test-only framed host for the encoded MP4 adapter acceptance test.

The decoded PCM is a retained, hash-bound ffmpeg decode of the exact public
MP4. Model ports are synthetic and marked fixture in every provenance receipt.
Never use this for model quality or claim this test runs a decoder on the host.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zlib
import sys
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("workspace", "ffmpeg", "model-snapshot", "runtime-profile", "runtime-profile-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    profile_bytes = Path(args.runtime_profile).read_bytes()
    assert digest(profile_bytes) == args.runtime_profile_sha256
    profile = json.loads(profile_bytes)
    header = json.loads(sys.stdin.buffer.readline())
    body = sys.stdin.buffer.read()
    assert header["protocol"] == "oneiron.meeting_audio.host.v1"
    assert len(body) == header["input_bytes"] and digest(body) == header["input_sha256"]
    stage = header["operation"]
    options = header["options"]
    pcm = b""
    def provenance(model):
        return {"invocation_id": str(uuid.uuid4()), "model_id": model,
                "input_sha256": digest(body), "execution": "fixture"}
    if stage == "capabilities":
        result = {
            "packages": {}, "asr_model_id": profile["asr"]["model_id"],
            "asr_snapshot": args.model_snapshot,
            "operations": ["decode", "silero_vad", "transcribe_pack", "community1_exclusive_full_file", "cleanup_turns"],
            "artifact_capable": True, "missing": [], "e1_e3_evidence": False,
            "python_executable": sys.executable, "python_version": sys.version.split()[0],
            "script_sha256": digest(Path(__file__).read_bytes()),
            "runtime_profile_sha256": args.runtime_profile_sha256,
            "runtime_helper_sha256": digest(Path(__file__).with_name("meeting_audio_runtime.py").read_bytes()),
        }
    elif stage == "decode":
        # The bridge consumes the encoded MP4 bytes, but this fixture host uses
        # retained canonical PCM. Build runners need no installed ffmpeg.
        assert digest(body) == profile["fixture_mp4_sha256"]
        pcm = zlib.decompress(Path(profile["fixture_pcm_zlib"]).read_bytes())
        assert digest(pcm) == profile["fixture_pcm_sha256"]
        assert pcm and len(pcm) % 2 == 0
        result = {"sample_rate": 16000, "channels": 1, "format": "s16le",
                  "samples": len(pcm) // 2, "pcm_sha256": digest(pcm)}
    elif stage == "silero_vad":
        duration = len(body) // 32
        result = {"spans": [{"start_ms": 100, "end_ms": duration - 100}],
                  "provenance": provenance("fixture-vad")}
    elif stage == "transcribe_pack":
        assert options["model_id"] == profile["asr"]["model_id"]
        assert options["glossary"] == ["Ada", "製品名"]
        assert options["language_hint"] == "English"
        result = {"words": [{"start_ms": 500, "end_ms": 900, "text": "allice",
                  "confidence": 0.8, "acoustic_candidates": ["Alice"]}],
                  "aligner_model": profile["alignment"]["model_id"],
                  "provenance": provenance(profile["asr"]["model_id"])}
    elif stage == "community1_exclusive_full_file":
        result = {"exclusive_tracks": [{"start_ms": 0, "end_ms": len(body) // 32,
                  "speaker_cluster": "fixture-speaker"}],
                  "provenance": provenance(profile["diarization"]["model_id"])}
    elif stage == "cleanup_turns":
        prompt = profile["cleanup"]["instructions"]
        assert digest(Path(prompt).read_bytes()) == profile["cleanup"]["instructions_sha256"]
        turns = json.loads(body)
        assert len(turns) == 1 and turns[0]["text"] == "allice"
        result = {"texts": ["Alice."], "provenance": provenance(profile["cleanup"]["model_id"])}
    else:
        raise ValueError(stage)
    reply = {"protocol": "oneiron.meeting_audio.host.v1", "request_id": header["request_id"],
             "ok": True, "result": result, "body_bytes": len(pcm)}
    sys.stdout.buffer.write(json.dumps(reply, separators=(",", ":")).encode() + b"\n" + pcm)


if __name__ == "__main__":
    main()
