#!/usr/bin/env python3
"""One offline model port in an explicitly provisioned, isolated interpreter.

This worker does not install dependencies, select defaults, or assert qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


bridge = module("meeting_audio_native", "meeting-audio-native.py")
runtime = module("meeting_audio_runtime", "meeting_audio_runtime.py")
process = module("meeting_audio_process", "meeting_audio_process.py")


class Port:
    def __init__(self, stage, path, checksum):
        self.stage = stage
        self.runtime = runtime.LocalRuntime(path, checksum, error=bridge.Refusal)
        if any(isinstance(value, dict) and value.get("backend") == "process"
               for key, value in self.runtime.profile.items() if key not in {"version", "packages"}):
            raise bridge.Refusal("NestedProcessPortRefused")
        self.binding = {"profile_sha256": checksum, "python_version": sys.version.split()[0],
                        "code_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                        for name in process.CODE_FILES}}

    def dispatch(self, operation, body, options):
        native = self.runtime
        if operation == "capabilities":
            if body or options:
                raise bridge.Refusal("UnexpectedBodyOrOptions")
            models = native.alignment_models() if self.stage == "alignment" else {}
            ready = bool(models) if self.stage == "alignment" else native.available(self.stage)
            selected = "uk_alignment" if self.stage == "alignment" and runtime.ALIGNER not in models.values() else self.stage
            return {"available": ready, "stage": self.stage, "runtime_binding": self.binding,
                    "model_id": native.profile[selected]["model_id"] if ready else None,
                    "models_by_language": models,
                    "model_files_sha256": hashlib.sha256(json.dumps(native.profile[selected]["files"],
                        ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if ready else None,
                    "model_execution": False}, b""
        if self.stage == "alignment" and operation == "align_words":
            if (set(options) != {"transcript", "language"} or not isinstance(options["transcript"], str)
                    or not options["transcript"].strip() or len(options["transcript"].encode()) > 65536
                    or not body or len(body) % 2 or len(body) > 16000 * 2 * 120):
                raise bridge.Refusal("InvalidAlignmentRequest")
            import numpy as np
            audio = np.frombuffer(body, dtype="<i2").astype(np.float32) / 32768.0
            words = native.align(audio, options["transcript"], options["language"], (len(body) // 2 + 15) // 16)
            return {"words": words, "aligner_model": native.alignment_model(options["language"]),
                    "runtime_binding": self.binding,
                    "provenance": bridge.provenance(native.alignment_model(options["language"]), body,
                        transcript_sha256=hashlib.sha256(options["transcript"].encode()).hexdigest(),
                        language=options["language"])}, b""
        if self.stage == "diarization" and operation == "diarize_full_file":
            if options or not body or len(body) % 2:
                raise bridge.Refusal("InvalidDiarizationRequest")
            import numpy as np
            audio = np.frombuffer(body, dtype="<i2").astype(np.float32) / 32768.0
            tracks = native.diarize(audio, (len(body) // 2 + 15) // 16)
            return {"exclusive_tracks": tracks, "runtime_binding": self.binding,
                    "provenance": bridge.provenance(runtime.COMMUNITY, body, full_file_samples=len(body) // 2)}, b""
        raise bridge.Refusal("UnknownOperation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=["alignment", "diarization"], required=True)
    parser.add_argument("--runtime-profile", type=Path, required=True)
    parser.add_argument("--runtime-profile-sha256", required=True)
    args = parser.parse_args()
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", PYANNOTE_METRICS_ENABLED="0")
    # Importing providers only happens after validated framed operation dispatch.
    host = Port(args.stage, args.runtime_profile, args.runtime_profile_sha256)
    bridge.serve(host, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    main()
