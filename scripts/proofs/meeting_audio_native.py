#!/usr/bin/env python3
"""Public synthetic-file proof only. Not a multilingual/identity benchmark."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--workspace", required=True, type=Path)
parser.add_argument("--bridge", required=True, type=Path)
parser.add_argument("--model-snapshot", required=True, type=Path)
parser.add_argument("--ffmpeg", required=True, type=Path)
args = parser.parse_args()
workspace = args.workspace.resolve(strict=True)
os.chdir(workspace)
spec = importlib.util.spec_from_file_location("meeting_audio_native", args.bridge)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
bridge.configure_workspace(workspace)
proof = workspace / "evidence"
proof.mkdir(exist_ok=True)
trace = []

def run(argv, **kwargs):
    started = time.monotonic()
    result = subprocess.run(argv, capture_output=True, check=False, **kwargs)
    trace.append({"command": list(map(str, argv)), "exit_code": result.returncode,
                  "elapsed_seconds": time.monotonic() - started})
    if result.returncode:
        raise RuntimeError(f"command failed: {argv[0]}: {result.returncode}")
    return result


def call(operation, body, options):
    request = {"protocol": bridge.PROTOCOL, "request_id": str(uuid.uuid4()),
               "operation": operation, "input_bytes": len(body),
               "input_sha256": bridge.sha256(body), "options": options}
    argv = [sys.executable, str(args.bridge), "--workspace", str(workspace),
            "--model-snapshot", str(args.model_snapshot), "--ffmpeg", str(args.ffmpeg)]
    result = subprocess.run(argv, input=bridge.encode_header(request) + body,
                            capture_output=True, check=False)
    (proof / (operation + ".stderr.txt")).write_bytes(result.stderr)
    header_bytes, separator, raw = result.stdout.partition(b"\n")
    if not separator:
        raise RuntimeError(f"missing framed output from {operation}")
    header = json.loads(header_bytes)
    assert header["request_id"] == request["request_id"]
    assert header["protocol"] == bridge.PROTOCOL and header["body_bytes"] == len(raw)
    trace.append({"operation": operation, "request": request,
                  "exit_code": result.returncode, "response": header})
    (proof / (operation + ".json")).write_text(json.dumps(header, indent=2, ensure_ascii=False))
    (proof / "trace.json").write_text(json.dumps(trace, indent=2, ensure_ascii=False))
    return result.returncode, header, raw


self_test = run([sys.executable, str(args.bridge), "--self-test"])
(proof / "self-test.txt").write_bytes(self_test.stdout)
# Fred is the installed built-in MacinTalk voice, not a downloaded voice.
voices = run(["/usr/bin/say", "-v", "?"]).stdout.decode()
assert any(line.startswith("Fred ") for line in voices.splitlines())
(proof / "installed-voice.txt").write_text("\n".join(line for line in voices.splitlines()
                                                         if line.startswith("Fred ")) + "\n")
reference = "The library opens at nine. Please bring the blue notebook.\nThe train leaves at noon. We will meet by the station.\n"
(proof / "reference.txt").write_text(reference)
(proof / "synthesis-input.txt").write_text(reference.replace("\n", " [[slnc 1200]] "))
run(["/usr/bin/say", "-v", "Fred", "-r", "145", "-f", str(proof / "synthesis-input.txt"),
     "-o", str(proof / "public-speech.aiff")])
run([str(args.ffmpeg), "-hide_banner", "-nostdin", "-v", "error", "-y",
     "-f", "lavfi", "-i", "color=c=black:s=320x240:r=10",
     "-i", str(proof / "public-speech.aiff"), "-filter:a", "adelay=1000:all=1,apad=pad_dur=1",
     "-c:v", "mpeg4", "-q:v", "5", "-pix_fmt", "yuv420p", "-c:a", "aac",
     "-shortest", "-movflags", "+faststart", str(proof / "public-speech.mp4")])
source = (proof / "public-speech.mp4").read_bytes()
code, decoded, pcm = call("decode", source, {})
assert code == 0 and decoded["ok"] and pcm
(proof / "public-speech.s16le").write_bytes(pcm)
code, vad, _ = call("silero_vad", pcm, {})
assert code == 0 and vad["ok"] and vad["result"]["spans"]
options = {"model_id": bridge.ASR_MODEL, "glossary": ["notebook", "station"], "language_hint": "English"}
code, asr, _ = call("transcribe_text", pcm, options)
assert code == 0 and asr["ok"] and asr["result"]["text"].strip()
assert asr["result"]["word_timestamps"] is None
for operation, options, expected in [
    ("transcribe_pack", options, "ForcedAlignmentUnavailable"),
    ("community1_exclusive_full_file", {}, "Community1Unavailable"),
]:
    code, refusal, _ = call(operation, pcm, options)
    assert code == 2 and not refusal["ok"] and refusal["error"]["code"] == expected
code, capabilities, _ = call("capabilities", b"", {})
assert code == 0 and not capabilities["result"]["artifact_capable"]
version = run([str(args.ffmpeg), "-version"]).stdout.decode().splitlines()[0]
(proof / "trace.json").write_text(json.dumps(trace, indent=2, ensure_ascii=False))
manifest = {
    "proof_class": "real_inference_on_public_synthetic_audio",
    "python": sys.version, "interpreter": sys.executable, "machine": platform.machine(),
    "ffmpeg": version, "model_snapshot": str(args.model_snapshot),
    "packages": capabilities["result"]["packages"],
    "source_sha256": bridge.sha256(source), "pcm_sha256": bridge.sha256(pcm),
    "pcm_samples": len(pcm) // 2, "duration_ms": (len(pcm) + 31) // 32,
    "source": "synthetic macOS installed Fred TTS; no private human audio",
    "speaker_identity": "not inferred", "word_alignment": "unavailable",
    "normalizer_artifact": None, "e1": "not run", "e3": "not run",
    "files": {p.name: bridge.sha256(p.read_bytes()) for p in proof.iterdir() if p.is_file() and p.name != "manifest.json"},
}
(proof / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
(proof / "trace.json").write_text(json.dumps(trace, indent=2, ensure_ascii=False))
print(json.dumps({"decode_vad_text_asr": "passed", "source_sha256": manifest["source_sha256"],
                  "duration_ms": manifest["duration_ms"], "text": asr["result"]["text"],
                  "artifact": "refused: forced alignment/community-1 unavailable"}))
