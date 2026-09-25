#!/usr/bin/env python3
"""Offline native meeting-audio host. Uses existing ffmpeg, Silero and MLX only.

One request per process: bounded JSON header + LF + exact raw input bytes.
One response: JSON header + LF + optional raw decoded PCM. Optional local model
ports require a hash-pinned host profile; missing ports are explicit refusals.
Run this with an existing native interpreter, NOT an inline-metadata launcher.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

PROTOCOL = "oneiron.meeting_audio.host.v1"
ASR_MODEL = "mlx-community/Qwen3-ASR-1.7B-8bit"
COMMUNITY_MODEL = "pyannote/speaker-diarization-community-1"
MAX_HEADER = 1024 * 1024
MAX_INPUT = 256 * 1024 * 1024
MAX_PCM = 2 * 16000 * 7200  # Refuse beyond two hours; do not truncate silently.


class Refusal(Exception):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encode_header(header):
    return json.dumps(header, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8") + b"\n"


def read_request(stream):
    line = stream.readline(MAX_HEADER + 1)
    if len(line) > MAX_HEADER or not line.endswith(b"\n"):
        raise Refusal("InvalidHeader")
    try:
        header = json.loads(line)
    except (ValueError, UnicodeError) as error:
        raise Refusal("InvalidHeader") from error
    if not isinstance(header, dict) or set(header) != {
        "protocol", "request_id", "operation", "input_bytes", "input_sha256", "options"
    }:
        raise Refusal("InvalidHeader")
    size = header["input_bytes"]
    if (header["protocol"] != PROTOCOL or type(size) is not int
            or not 0 <= size <= MAX_INPUT
            or not isinstance(header["request_id"], str)
            or not 0 < len(header["request_id"]) <= 128
            or not isinstance(header["operation"], str)
            or not isinstance(header["options"], dict)):
        raise Refusal("InvalidHeader")
    body = stream.read(size + 1)
    if len(body) != size:
        raise Refusal("InputLengthMismatch")
    if sha256(body) != header["input_sha256"]:
        raise Refusal("InputDigestMismatch")
    return header, body


def configure_workspace(path):
    if not path.is_absolute() or not path.is_dir():
        raise Refusal("WorkspaceUnavailable")
    path = path.resolve(strict=True)
    # No model/dependency install. All incidental runtime files stay here.
    for name in ["tmp", "cache", "matplotlib", "hf-modules", "numba"]:
        (path / name).mkdir(exist_ok=True)
    os.environ.update({
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1",
        "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(path / "tmp"),
        "XDG_CACHE_HOME": str(path / "cache"),
        "MPLCONFIGDIR": str(path / "matplotlib"),
        "HF_MODULES_CACHE": str(path / "hf-modules"),
        "NUMBA_CACHE_DIR": str(path / "numba"),
        "TOKENIZERS_PARALLELISM": "false", "PYANNOTE_METRICS_ENABLED": "0",
    })
    sys.dont_write_bytecode = True
    return path


def package_version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def runtime_source_hashes():
    return {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in
            ["meeting_audio_runtime.py", "meeting_audio_process.py", "meeting_audio_ctc.py"]}


def provenance(model, body, **details):
    return {
        "invocation_id": str(uuid.uuid4()), "model_id": model,
        "input_sha256": sha256(body), "execution": "measured",
        "runtime_components_sha256": runtime_source_hashes(), **details,
    }


class NativeHost:
    def __init__(self, workspace, ffmpeg, model_snapshot, runtime_profile=None, runtime_profile_sha256=None):
        self.workspace = workspace
        self.ffmpeg = ffmpeg
        self.model_snapshot = model_snapshot
        self.runtime_profile = runtime_profile
        self.runtime_profile_sha256 = runtime_profile_sha256
        self.loaded_runtime = None

    def runtime(self):
        if self.runtime_profile is None:
            return None
        if self.loaded_runtime is None:
            path = Path(__file__).with_name("meeting_audio_runtime.py")
            spec = importlib.util.spec_from_file_location("meeting_audio_runtime", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.loaded_runtime = module.LocalRuntime(self.runtime_profile, self.runtime_profile_sha256, error=Refusal)
        return self.loaded_runtime

    def capabilities(self):
        runtime = self.runtime()
        ports = {"alignment": "transcribe_pack", "diarization": "community1_exclusive_full_file", "cleanup": "cleanup_turns"}
        available = {stage: runtime is not None and runtime.available(stage) for stage in ports}
        alignment_languages = sorted(runtime.alignment_models()) if runtime is not None else []
        pack_languages = [language for language in alignment_languages if language != "Ukrainian"]
        # A timing-only UK worker does not make the Qwen ASR artifact lane ready.
        available["alignment"] = available["alignment"] and bool(pack_languages)
        asr_ready = runtime is not None and runtime.available("asr")
        if asr_ready and Path(runtime.profile["asr"]["snapshot"]) != self.model_snapshot:
            raise Refusal("AsrSnapshotBindingMismatch")
        decoder_ready = self.ffmpeg.is_absolute() and self.ffmpeg.is_file()
        missing = {"alignment": "forced_word_alignment", "diarization": "community1_exclusive_full_file", "cleanup": "cleanup_model"}
        return {
            "packages": {name: package_version(name) for name in [
                "mlx", "mlx-metal", "mlx-lm", "mlx-audio", "torch", "silero-vad",
                "onnxruntime", "pyannote.audio", "qwen-asr",
            ]},
            "asr_model_id": ASR_MODEL,
            "asr_snapshot": str(self.model_snapshot),
            "operations": ["decode", "silero_vad", "transcribe_text"] + [port for stage, port in ports.items() if available[stage]]
                          + (["moss_e3_full_file"] if runtime is not None and runtime.available("moss") else []),
            "artifact_capable": all(available.values()) and asr_ready and decoder_ready,
            "alignment_languages": alignment_languages,
            "transcribe_pack_languages": pack_languages,
            "missing": [missing[stage] for stage in ports if not available[stage]]
                       + ([] if runtime is None or asr_ready else ["pinned_asr_model"])
                       + ([] if runtime is None or decoder_ready else ["decoder"]),
            "runtime_profile_sha256": self.runtime_profile_sha256,
            "runtime_helper_sha256": sha256(Path(__file__).with_name("meeting_audio_runtime.py").read_bytes()),
            "runtime_components_sha256": runtime_source_hashes(),
            "e1_e3_evidence": False,
            "python_executable": sys.executable,
            "python_version": sys.version.split()[0],
            "script_sha256": sha256(Path(__file__).read_bytes()),
        }

    def decode(self, body):
        if not body or not self.ffmpeg.is_absolute() or not self.ffmpeg.is_file():
            raise Refusal("DecoderUnavailable" if body else "InvalidAudio")
        with tempfile.TemporaryDirectory(dir=self.workspace / "tmp") as directory:
            source = Path(directory) / "source.media"
            target = Path(directory) / "decoded.s16le"
            source.write_bytes(body)
            command = [str(self.ffmpeg), "-hide_banner", "-nostdin", "-v", "error",
                       "-protocol_whitelist", "file,pipe",
                       "-format_whitelist", "mov,mp3,wav,matroska,webm,ogg,flac,aiff,aac",
                       "-i", str(source),
                       "-map", "0:a:0", "-vn", "-sn", "-dn", "-ac", "1", "-ar", "16000",
                       "-threads", "1", "-t", "7200.001", "-f", "s16le",
                       "-acodec", "pcm_s16le", str(target)]
            try:
                result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, check=False, timeout=300)
            except subprocess.TimeoutExpired:
                raise Refusal("DecodeTimedOut") from None
            if result.returncode != 0:
                raise Refusal("DecodeFailed", {"exit_code": result.returncode})
            size = target.stat().st_size
            if size == 0 or size % 2:
                raise Refusal("InvalidAudio")
            if size > MAX_PCM:
                raise Refusal("AudioTooLong")
            pcm = target.read_bytes()
        return {
            "sample_rate": 16000, "channels": 1, "format": "s16le",
            "samples": len(pcm) // 2, "pcm_sha256": sha256(pcm),
            "provenance": provenance("ffmpeg", body),
        }, pcm

    @staticmethod
    def pcm(body):
        if not body or len(body) % 2 or len(body) > MAX_PCM:
            raise Refusal("InvalidPcm")
        import numpy as np
        return np.frombuffer(body, dtype="<i2").astype(np.float32) / 32768.0

    def vad(self, body):
        audio = self.pcm(body)
        from silero_vad import get_speech_timestamps, load_silero_vad
        # This loader reads the wheel's own ONNX file, never torch.hub or HF.
        model = load_silero_vad(onnx=True)
        # Engine packing owns the 250ms padding. VAD gets the COMPLETE PCM.
        segments = get_speech_timestamps(
            audio, model, sampling_rate=16000, threshold=0.5,
            min_speech_duration_ms=0, min_silence_duration_ms=100,
            speech_pad_ms=0, return_seconds=False,
        )
        previous_end = 0
        spans = []
        for segment in segments:
            start, end = int(segment["start"]), int(segment["end"])
            if start < previous_end or not start < end <= len(audio):
                raise Refusal("InvalidVadOutput")
            # Round outwards so detected samples are not deleted by quantization.
            spans.append({"start_ms": start // 16, "end_ms": (end + 15) // 16})
            previous_end = end
        return {"spans": spans, "provenance": provenance(
            "silero-vad", body, package_version=package_version("silero-vad"),
            full_file_samples=len(audio), threshold=0.5, speech_pad_ms=0,
        )}, b""

    @staticmethod
    def validate_asr_options(options):
        if set(options) != {"model_id", "glossary", "language_hint"}:
            raise Refusal("InvalidAsrOptions")
        glossary, language = options["glossary"], options["language_hint"]
        if (options["model_id"] != ASR_MODEL or not isinstance(glossary, list)
                or any(not isinstance(s, str) or not s.strip() for s in glossary)
                or language is not None and (not isinstance(language, str) or not language.strip())):
            raise Refusal("InvalidAsrOptions")
        # This pinned Qwen ASR family does not declare Ukrainian support.
        # A Ukrainian timing backend is not permission to relabel its ASR arm.
        if language is not None and (language.casefold() in {"uk", "ukr", "ukrainian"}
                                     or language.casefold().startswith("uk-")):
            raise Refusal("AsrLanguageUnsupported")
        return glossary, language

    def transcribe_text(self, body, options):
        glossary, language = self.validate_asr_options(options)
        snapshot = self.model_snapshot
        runtime = self.runtime()
        if runtime is not None and Path(runtime.require("asr")["snapshot"]) != snapshot:
            raise Refusal("AsrSnapshotBindingMismatch")
        if not snapshot.is_absolute() or not snapshot.is_dir():
            raise Refusal("AsrModelUnavailable")
        required = ["config.json", "tokenizer_config.json", "preprocessor_config.json",
                    "model.safetensors", "vocab.json", "merges.txt"]
        if any(not (snapshot / name).is_file() for name in required):
            raise Refusal("AsrModelUnavailable")
        config = json.loads((snapshot / "config.json").read_text())
        tokenizer = json.loads((snapshot / "tokenizer_config.json").read_text())
        if config.get("model_type") != "qwen3_asr" or config.get("auto_map") or tokenizer.get("auto_map"):
            raise Refusal("UnsupportedModelConfig")
        audio = self.pcm(body)
        import inspect
        from mlx_audio.stt.utils import load_model
        # Path (not a hub ID) bypasses mlx-audio's get_model_path downloader.
        model = load_model(snapshot, strict=True)
        required_args = {"system_prompt", "chunk_duration", "min_chunk_duration", "max_tokens"}
        if not required_args <= set(inspect.signature(model.generate).parameters):
            raise Refusal("AsrApiMismatch")
        # Exact immutable domain data only. No previous transcript, no CLI
        # context fallback (generate_transcription silently filters that key).
        context = json.dumps(glossary, ensure_ascii=False, separators=(",", ":"))
        # Do not let the library re-split a core-owned pack or pad its short tail.
        max_tokens = 8192
        output = model.generate(
            audio, language=language, system_prompt=context,
            chunk_duration=max(1200.0, len(audio) / 16000.0 + 1.0),
            min_chunk_duration=0.0, batch_size=1, max_tokens=max_tokens,
            temperature=0.0, verbose=False,
        )
        if output.generation_tokens >= max_tokens:
            raise Refusal("AsrTokenBudgetExhausted")
        if not output.text.strip():
            raise Refusal("EmptyAsr")
        # Qwen's 'segments' span input chunks, NOT words or acoustic alignment.
        return {
            "text": output.text, "segments": output.segments,
            "timestamp_kind": "input_chunk_only", "word_timestamps": None,
            "generation_tokens": output.generation_tokens,
            "glossary_sha256": sha256(context.encode("utf-8")),
            "provenance": provenance(ASR_MODEL, body,
                model_snapshot=str(snapshot), revision=snapshot.name,
                package_version=package_version("mlx-audio")),
        }, b""

    def dispatch(self, operation, body, options):
        if operation == "transcribe_text":
            return self.transcribe_text(body, options)
        if operation == "transcribe_pack":
            self.validate_asr_options(options)
            runtime = self.runtime()
            if runtime is None:
                raise Refusal("ForcedAlignmentUnavailable")
            runtime.require("alignment")
            language = runtime.alignment_language(options["language_hint"])
            text, _ = self.transcribe_text(body, options)
            words = runtime.align(self.pcm(body), text["text"], language, (len(body) // 2 + 15) // 16)
            return {"words": words, "aligner_model": runtime.alignment_model(language),
                    "provenance": provenance(ASR_MODEL, body, runtime_profile_sha256=self.runtime_profile_sha256,
                                             runtime_helper_sha256=sha256(Path(__file__).with_name("meeting_audio_runtime.py").read_bytes()),
                                             alignment_runtime=runtime.last_alignment_provenance)}, b""
        if options:
            raise Refusal("UnexpectedOptions")
        if operation == "capabilities":
            if body:
                raise Refusal("UnexpectedBody")
            return self.capabilities(), b""
        if operation == "decode":
            return self.decode(body)
        if operation == "silero_vad":
            return self.vad(body)
        if operation == "community1_exclusive_full_file":
            runtime = self.runtime()
            if runtime is None:
                raise Refusal("Community1Unavailable")
            tracks = runtime.diarize(self.pcm(body), (len(body) // 2 + 15) // 16)
            return {"exclusive_tracks": tracks, "provenance": provenance(COMMUNITY_MODEL, body,
                    runtime_profile_sha256=self.runtime_profile_sha256, full_file_samples=len(body) // 2,
                    diarization_runtime=runtime.last_diarization_provenance)}, b""
        if operation == "moss_e3_full_file":
            runtime = self.runtime()
            if runtime is None:
                raise Refusal("MossBackendUnavailable")
            tracks = runtime.moss(self.pcm(body), (len(body) // 2 + 15) // 16)
            return {"segment_tracks": tracks, "timestamp_kind": "segment_not_word",
                    "provenance": provenance(runtime.profile["moss"]["model_id"], body,
                        runtime_profile_sha256=self.runtime_profile_sha256, full_file_samples=len(body) // 2)}, b""
        if operation == "cleanup_turns":
            runtime = self.runtime()
            if runtime is None:
                raise Refusal("CleanupBackendUnavailable")
            try:
                turns = json.loads(body)
            except (ValueError, UnicodeError):
                raise Refusal("InvalidCleanupInput") from None
            texts = runtime.cleanup(turns)
            return {"texts": texts, "provenance": provenance(runtime.profile["cleanup"]["model_id"], body,
                    runtime_profile_sha256=self.runtime_profile_sha256)}, b""
        raise Refusal("UnknownOperation")


def serve(host, input_stream, output_stream):
    request_id = None
    started = time.monotonic()
    try:
        header, body = read_request(input_stream)
        request_id = header["request_id"]
        # Third-party Python progress output must not corrupt the frame.
        with contextlib.redirect_stdout(sys.stderr):
            result, output_body = host.dispatch(header["operation"], body, header["options"])
        response = {"ok": True, "result": result}
        exit_code = 0
    except Refusal as error:
        response = {"ok": False, "error": {"code": error.code, "details": error.details}}
        output_body, exit_code = b"", 2
    except Exception as error:
        # Do not serialize arbitrary exception strings: native tools may include
        # audio text, local paths or credentials in errors. Keep a typed class.
        response = {"ok": False, "error": {
            "code": "NativeRuntimeFailure", "details": {"exception_type": type(error).__name__}}}
        output_body, exit_code = b"", 3
    response.update(protocol=PROTOCOL, request_id=request_id,
                    body_bytes=len(output_body), elapsed_seconds=time.monotonic() - started)
    encoded = encode_header(response)
    if len(encoded) > MAX_HEADER:
        encoded = encode_header({"protocol": PROTOCOL, "request_id": request_id,
                                 "body_bytes": 0, "ok": False,
                                 "error": {"code": "ResponseTooLarge", "details": {}}})
        output_body, exit_code = b"", 3
    output_stream.write(encoded)
    output_stream.write(output_body)
    output_stream.flush()
    return exit_code


def self_test():
    body = b"\x01\x00\xff\xff"
    header = {"protocol": PROTOCOL, "request_id": "self-test", "operation": "silero_vad",
              "input_bytes": len(body), "input_sha256": sha256(body), "options": {}}
    assert read_request(io.BytesIO(encode_header(header) + body)) == (header, body)
    for bad_body, code in [(body[:-1], "InputLengthMismatch"),
                           (body + b"x", "InputLengthMismatch"),
                           (b"\x00" * len(body), "InputDigestMismatch")]:
        try:
            read_request(io.BytesIO(encode_header(header) + bad_body))
        except Refusal as error:
            assert error.code == code
        else:
            raise AssertionError(code)
    host = NativeHost(Path("."), Path("/missing"), Path("/missing"))
    for operation, code in [("transcribe_pack", "ForcedAlignmentUnavailable"),
                            ("community1_exclusive_full_file", "Community1Unavailable"),
                            ("cleanup_turns", "CleanupBackendUnavailable")]:
        header["operation"] = operation
        header["options"] = ({"model_id": ASR_MODEL, "glossary": [], "language_hint": None}
                             if operation == "transcribe_pack" else {})
        output = io.BytesIO()
        assert serve(host, io.BytesIO(encode_header(header) + body), output) == 2
        result = json.loads(output.getvalue())
        assert result["error"]["code"] == code and result["body_bytes"] == 0
        assert result["request_id"] == "self-test" and not result["ok"]
    capabilities = host.capabilities()
    assert not capabilities["artifact_capable"] and not capabilities["e1_e3_evidence"]
    assert capabilities["script_sha256"] == sha256(Path(__file__).read_bytes())
    options = {"model_id": ASR_MODEL, "glossary": ["notebook"], "language_hint": "English"}
    assert host.validate_asr_options(options) == (["notebook"], "English")
    for bad_options in [dict(options, previous_transcript="old words"),
                        dict(options, model_id="different-model"),
                        dict(options, glossary=[" "])]:
        try:
            host.validate_asr_options(bad_options)
        except Refusal as error:
            assert error.code == "InvalidAsrOptions"
        else:
            raise AssertionError("invalid ASR options accepted")
    print("native-host protocol self-test: protocol and capability checks passed (no models invoked)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--ffmpeg", type=Path)
    parser.add_argument("--model-snapshot", type=Path)
    parser.add_argument("--runtime-profile", type=Path)
    parser.add_argument("--runtime-profile-sha256")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.workspace is None or args.ffmpeg is None or args.model_snapshot is None:
        parser.error("--workspace, --ffmpeg and --model-snapshot are required")
    if (args.runtime_profile is None) != (args.runtime_profile_sha256 is None):
        parser.error("runtime profile path and SHA-256 must be supplied together")
    try:
        workspace = configure_workspace(args.workspace)
    except Refusal as error:
        sys.stderr.write(error.code + "\n")
        return 2
    host = NativeHost(workspace, args.ffmpeg, args.model_snapshot,
                      args.runtime_profile, args.runtime_profile_sha256)
    return serve(host, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
