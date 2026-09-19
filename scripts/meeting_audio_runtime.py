"""Optional offline model adapters; no acquisition, fallback language or qualification.

A host-owned JSON profile and every model/prompt file are explicitly hash pinned.
Importing this module loads only the standard library. Provider imports occur only
at an invoked, validated port. Unit conversion helpers do not call any model.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import unicodedata

ASR = "mlx-community/Qwen3-ASR-1.7B-8bit"
ALIGNER = "Qwen/Qwen3-ForcedAligner-0.6B"
COMMUNITY = "pyannote/speaker-diarization-community-1"
MOSS = "OpenMOSS-Team/MOSS-Transcribe-Diarize"
LANGUAGES = ("Chinese", "English", "Cantonese", "French", "German", "Italian",
             "Japanese", "Korean", "Portuguese", "Russian", "Spanish")
REQUIREMENTS = {"asr": {"mlx-audio", "mlx", "silero-vad", "onnxruntime"}, "alignment": {"qwen-asr", "torch"},
                "diarization": {"pyannote.audio", "torch"},
                "cleanup": {"mlx-lm", "mlx"}, "moss": {"mlx-audio", "mlx"}}


class RuntimeRefusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def hash_string(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("non-finite number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)


def version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def milliseconds(value, duration_ms, error=RuntimeRefusal):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise error("InvalidNativeTimestamp")
    # One quantizer for shared boundaries preserves exclusivity. No clipping,
    # evenly spaced words or guessed timestamps repair invalid native output.
    if value < 0 or value * 1000 > duration_ms:
        raise error("InvalidNativeTimestamp")
    return int(round(value * 1000))


def aligned_words(items, transcript, duration_ms, error=RuntimeRefusal):
    words = []
    previous_end = 0
    for item in items:
        start = milliseconds(item.start_time, duration_ms, error)
        end = milliseconds(item.end_time, duration_ms, error)
        if not isinstance(item.text, str) or not item.text.strip() or start < previous_end or end <= start:
            raise error("InvalidAlignmentOutput")
        words.append({"start_ms": start, "end_ms": end, "text": item.text, "confidence": None})
        previous_end = end
    # Permit token boundary whitespace only. Do not invent punctuation, replace
    # words or relabel another transcript as alignment of the ASR result.
    compact = lambda text: "".join(unicodedata.normalize("NFC", text).split())
    if not words or compact("".join(word["text"] for word in words)) != compact(transcript):
        raise error("AlignmentTextMismatch")
    return words


def exclusive_tracks(items, duration_ms, error=RuntimeRefusal):
    tracks = []
    previous_end = 0
    for segment, _track, speaker in items:
        start = milliseconds(segment.start, duration_ms, error)
        end = milliseconds(segment.end, duration_ms, error)
        if (start < previous_end or end <= start or not isinstance(speaker, str)
                or not speaker.strip() or len(speaker) > 128):
            raise error("InvalidExclusiveDiarization")
        tracks.append({"start_ms": start, "end_ms": end, "speaker_cluster": speaker})
        previous_end = end
    if not tracks:
        raise error("EmptyDiarization")
    return tracks


class LocalRuntime:
    def __init__(self, path, expected_digest, error=RuntimeRefusal):
        self.error = error
        if not path.is_absolute() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise error("RuntimeProfileUnavailable")
        data = path.read_bytes()
        if not hash_string(expected_digest) or digest(data) != expected_digest:
            raise error("RuntimeProfileDigestMismatch")
        try:
            profile = strict_json(data)
        except (ValueError, UnicodeError):
            raise error("InvalidRuntimeProfile") from None
        if (not isinstance(profile, dict) or set(profile) not in [{"version", "packages", "asr", "alignment", "diarization", "cleanup"},
                    {"version", "packages", "asr", "alignment", "diarization", "cleanup", "moss"}]
                or type(profile["version"]) is not int or profile["version"] != 1
                or not isinstance(profile["packages"], dict)):
            raise error("InvalidRuntimeProfile")
        profile.setdefault("moss", None)
        packages = profile["packages"]
        if any(not isinstance(v, str) or not v.strip() for v in packages.values()):
            raise error("InvalidRuntimeProfile")
        for stage in REQUIREMENTS:
            spec = profile[stage]
            if spec is None:
                continue
            fields = {"model_id", "snapshot", "files", "access_ref"}
            if stage == "moss":
                fields |= {"max_tokens"}
            if stage == "cleanup":
                fields |= {"instructions", "instructions_sha256", "max_tokens", "max_input_tokens"}
            if (not isinstance(spec, dict) or set(spec) != fields
                    or not REQUIREMENTS[stage] <= packages.keys()
                    or any(not isinstance(spec[k], str) or not spec[k].strip()
                           for k in ["model_id", "snapshot", "access_ref"])
                    or not Path(spec["snapshot"]).is_absolute()
                    or not isinstance(spec["files"], dict) or not spec["files"]):
                raise error("InvalidRuntimeProfile")
            for name, checksum in spec["files"].items():
                parts = name.split("/")
                if (not name or "\\" in name or any(p in {"", ".", ".."} for p in parts)
                        or not hash_string(checksum)):
                    raise error("InvalidRuntimeProfile")
            if stage == "moss" and (spec["model_id"] != MOSS or type(spec["max_tokens"]) is not int
                    or not 1 <= spec["max_tokens"] <= 65536):
                raise error("UnsupportedMossConfiguration")
            if stage == "asr" and spec["model_id"] != ASR:
                raise error("UnsupportedAsrModel")
            if stage == "alignment" and spec["model_id"] != ALIGNER:
                raise error("UnsupportedAligner")
            if stage == "diarization" and spec["model_id"] != COMMUNITY:
                raise error("UnsupportedDiarizationModel")
            if stage == "cleanup" and (not isinstance(spec["instructions"], str)
                    or not Path(spec["instructions"]).is_absolute()
                    or not hash_string(spec["instructions_sha256"])
                    or type(spec["max_tokens"]) is not int or not 1 <= spec["max_tokens"] <= 8192
                    or type(spec["max_input_tokens"]) is not int or not 1 <= spec["max_input_tokens"] <= 32768):
                raise error("InvalidRuntimeProfile")
        self.profile = profile
        self.profile_digest = expected_digest
        self.checked = set()

    def available(self, stage):
        spec = self.profile[stage]
        if spec is None:
            return False
        if stage in self.checked:
            return True
        if any(version(name) != value for name, value in self.profile["packages"].items()):
            return False
        snapshot = Path(spec["snapshot"])
        if not snapshot.is_dir():
            return False
        paths = list(snapshot.rglob("*"))
        if any(path.is_symlink() and path.is_dir() for path in paths):
            raise self.error("UnsafeModelTree")
        files = {path.relative_to(snapshot).as_posix(): path for path in paths if path.is_file()}
        if files.keys() != spec["files"].keys() or any(file_digest(path) != spec["files"][name] for name, path in files.items()):
            raise self.error("ModelTreeDigestMismatch")
        # Refuse remote-code model/tokenizer configuration. HF snapshot file
        # symlinks to local cached blobs are allowed but the actual bytes hash.
        for name in ["config.json", "tokenizer_config.json"]:
            if name in files:
                try:
                    config = strict_json(files[name].read_bytes())
                except (ValueError, UnicodeError):
                    raise self.error("UnsupportedModelConfig") from None
                if not isinstance(config, dict) or config.get("auto_map"):
                    raise self.error("UnsupportedModelConfig")
        if stage == "cleanup":
            self.instructions(spec)
        self.checked.add(stage)
        return True

    def require(self, stage):
        if not self.available(stage):
            raise self.error({"asr": "AsrModelUnavailable", "alignment": "ForcedAlignmentUnavailable", "diarization": "Community1Unavailable",
                              "cleanup": "CleanupBackendUnavailable", "moss": "MossBackendUnavailable"}[stage])
        return self.profile[stage]

    def instructions(self, spec):
        path = Path(spec["instructions"])
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise self.error("CleanupInstructionsUnavailable")
        data = path.read_bytes()
        if digest(data) != spec["instructions_sha256"]:
            raise self.error("CleanupInstructionsDigestMismatch")
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            raise self.error("InvalidCleanupInstructions") from None
        if text.count("{{TRANSCRIPT_JSON}}") != 1:
            raise self.error("InvalidCleanupInstructions")
        return text

    def alignment_language(self, language):
        aliases = {"en": "English", "ja": "Japanese", "zh": "Chinese", "yue": "Cantonese",
                   "fr": "French", "de": "German", "it": "Italian", "ko": "Korean",
                   "pt": "Portuguese", "ru": "Russian", "es": "Spanish"}
        language = aliases.get(language, language)
        if language not in LANGUAGES:
            raise self.error("ForcedAlignmentLanguageUnsupported")
        return language

    def align(self, audio, transcript, language, duration_ms):
        spec = self.require("alignment")
        language = self.alignment_language(language)
        import torch
        from qwen_asr import Qwen3ForcedAligner
        model = Qwen3ForcedAligner.from_pretrained(spec["snapshot"], dtype=torch.float32, device_map="cpu")
        output = model.align(audio=(audio, 16000), text=transcript, language=language)
        if len(output) != 1:
            raise self.error("InvalidAlignmentOutput")
        return aligned_words(output[0], transcript, duration_ms, self.error)

    def diarize(self, audio, duration_ms):
        spec = self.require("diarization")
        import torch
        from pyannote.audio import Pipeline
        pipeline = Pipeline.from_pretrained(spec["snapshot"])
        # One call on the entire decoded file. No pack/chunk parameter exists.
        output = pipeline({"waveform": torch.from_numpy(audio.copy()).unsqueeze(0), "sample_rate": 16000})
        exclusive = getattr(output, "exclusive_speaker_diarization", None)
        if exclusive is None:
            raise self.error("ExclusiveDiarizationUnavailable")
        return exclusive_tracks(exclusive.itertracks(yield_label=True), duration_ms, self.error)

    def moss(self, audio, duration_ms):
        spec = self.require("moss")
        from mlx_audio.stt.utils import load_model
        model = load_model(Path(spec["snapshot"]), strict=True)
        if not type(model).__module__.startswith("mlx_audio.stt.models.moss_transcribe_diarize."):
            raise self.error("MossApiMismatch")
        if model.sample_rate != 16000:
            raise self.error("MossSampleRateMismatch")
        # One autoregressive decode of the complete file. The SDK may partition
        # encoder features internally, but we never decode/recluster by pack.
        output = model.generate(audio, max_tokens=spec["max_tokens"], temperature=0.0,
                                verbose=False, stream=False)
        count = getattr(output, "generation_tokens", None)
        if type(count) is not int or count >= spec["max_tokens"]:
            raise self.error("MossTokenBudgetExhausted")
        segments = getattr(output, "segments", None)
        if not isinstance(segments, list) or not segments:
            raise self.error("InvalidMossOutput")
        tracks = []
        previous_start = 0
        for segment in segments:
            if not isinstance(segment, dict) or not {"start", "end", "text", "speaker_id"} <= segment.keys():
                raise self.error("InvalidMossOutput")
            start = milliseconds(segment["start"], duration_ms, self.error)
            end = milliseconds(segment["end"], duration_ms, self.error)
            speaker = segment["speaker_id"]
            if (end <= start or start < previous_start or not isinstance(segment["text"], str)
                    or not isinstance(speaker, str) or not speaker.strip()):
                raise self.error("InvalidMossOutput")
            tracks.append({"start_ms": start, "end_ms": end, "speaker_cluster": speaker,
                           "text": segment["text"]})
            previous_start = start
        return tracks

    def cleanup(self, turns):
        spec = self.require("cleanup")
        if not isinstance(turns, list) or not turns or len(turns) > 10000:
            raise self.error("InvalidCleanupInput")
        from mlx_lm import generate, load
        from mlx_lm.sample_utils import make_sampler
        model, tokenizer = load(Path(spec["snapshot"]), tokenizer_config={"trust_remote_code": False})
        template = self.instructions(spec)
        def prompt_for(group):
            instructions = template.replace("{{TRANSCRIPT_JSON}}", json.dumps(group, ensure_ascii=False, allow_nan=False))
            return tokenizer.apply_chat_template([{"role": "user", "content": instructions}], tokenize=False, add_generation_prompt=True)
        def generate_group(group):
            prompt = prompt_for(group)
            if len(tokenizer.encode(prompt)) > spec["max_input_tokens"]:
                raise self.error("CleanupInputTooLong")
            text = generate(model, tokenizer, prompt=prompt, max_tokens=spec["max_tokens"], sampler=make_sampler(temp=0.0), verbose=False)
            if len(tokenizer.encode(text)) >= spec["max_tokens"]:
                raise self.error("CleanupTokenBudgetExhausted")
            return cleanup_texts(text, len(group), self.error)
        result, group = [], []
        for turn in turns:
            if group and len(tokenizer.encode(prompt_for(group + [turn]))) > spec["max_input_tokens"]:
                result.extend(generate_group(group))
                group = []
            group.append(turn)
        if group:
            result.extend(generate_group(group))
        return result


def cleanup_texts(text, count, error=RuntimeRefusal):
    try:
        output = strict_json(text)
    except (ValueError, UnicodeError):
        raise error("InvalidCleanupOutput") from None
    if (not isinstance(output, dict) or set(output) != {"texts"} or not isinstance(output["texts"], list)
            or len(output["texts"]) != count or any(not isinstance(t, str) or not t.strip() for t in output["texts"])):
        raise error("InvalidCleanupOutput")
    return output["texts"]
