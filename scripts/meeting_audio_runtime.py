"""Optional offline model adapters; no acquisition, fallback language or qualification.

A host-owned JSON profile and every model/prompt file are explicitly hash pinned.
Importing this module loads only the standard library. Provider imports occur only
at an invoked, validated port. Unit conversion helpers do not call any model.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import math
from pathlib import Path
import unicodedata

ASR = "mlx-community/Qwen3-ASR-1.7B-8bit"
ALIGNER = "Qwen/Qwen3-ForcedAligner-0.6B"
UK_ALIGNER = "Yehor/w2v-xls-r-uk"
COMMUNITY = "pyannote/speaker-diarization-community-1"
MOSS = "OpenMOSS-Team/MOSS-Transcribe-Diarize"
LANGUAGES = ("Chinese", "English", "Cantonese", "French", "German", "Italian",
             "Japanese", "Korean", "Portuguese", "Russian", "Spanish")
REQUIREMENTS = {"asr": {"mlx-audio", "mlx", "silero-vad", "onnxruntime"}, "alignment": {"qwen-asr", "torch"},
                "diarization": {"pyannote.audio", "torch"},
                "cleanup": {"mlx-lm", "mlx"}, "moss": {"mlx-audio", "mlx", "mlx-lm"},
                "uk_alignment": {"torch", "transformers"}}


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
        if (not isinstance(profile, dict)
                or not {"version", "packages", "asr", "alignment", "diarization", "cleanup"} <= set(profile)
                or not set(profile) <= {"version", "packages", "asr", "alignment", "diarization", "cleanup", "moss", "uk_alignment"}
                or type(profile["version"]) is not int or profile["version"] != 1
                or not isinstance(profile["packages"], dict)):
            raise error("InvalidRuntimeProfile")
        profile.setdefault("moss", None)
        profile.setdefault("uk_alignment", None)
        packages = profile["packages"]
        if any(not isinstance(v, str) or not v.strip() for v in packages.values()):
            raise error("InvalidRuntimeProfile")
        for stage in REQUIREMENTS:
            spec = profile[stage]
            if spec is None:
                continue
            if isinstance(spec, dict) and spec.get("backend") == "process":
                if stage not in {"alignment", "diarization"}:
                    raise error("UnsupportedProcessPort")
                process_module().validate_spec(spec, error)
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
            if stage == "uk_alignment" and spec["model_id"] != UK_ALIGNER:
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
        self.process_capability_cache = {}
        self.last_alignment_provenance = None
        self.last_diarization_provenance = None

    def available(self, stage):
        spec = self.profile[stage]
        if spec is None:
            return False
        if spec.get("backend") == "process":
            return self.process_capabilities(stage)["available"]
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

    def process_capabilities(self, stage):
        spec = self.profile[stage]
        process_module().check_files(spec, self.error)
        if stage not in self.process_capability_cache:
            result = process_module().call(spec, stage, "capabilities", b"", {}, self.error, strict_json)
            if (type(result.get("available")) is not bool or result.get("stage") != stage
                    or result.get("model_execution") is not False):
                raise self.error("InvalidProcessCapabilities")
            models = result.get("models_by_language")
            if stage == "alignment" and (not isinstance(models, dict)
                    or any((language not in LANGUAGES or model != ALIGNER) and (language != "Ukrainian" or model != UK_ALIGNER)
                           for language, model in models.items())
                    or result["available"] != bool(models)):
                raise self.error("InvalidProcessCapabilities")
            if stage == "diarization" and result["available"] and (result.get("model_id") != COMMUNITY
                    or not hash_string(result.get("model_files_sha256"))):
                raise self.error("InvalidProcessCapabilities")
            self.process_capability_cache[stage] = result
        return self.process_capability_cache[stage]

    def alignment_models(self):
        if self.profile["alignment"] is not None and self.profile["alignment"].get("backend") == "process":
            return self.process_capabilities("alignment")["models_by_language"]
        models = {language: ALIGNER for language in LANGUAGES} if self.available("alignment") else {}
        if self.available("uk_alignment"):
            models["Ukrainian"] = UK_ALIGNER
        return models

    def alignment_model(self, language):
        language = self.alignment_language(language)
        if self.profile["alignment"] is not None and self.profile["alignment"].get("backend") == "process":
            return self.process_capabilities("alignment")["models_by_language"][language]
        return self.require("uk_alignment" if language == "Ukrainian" else "alignment")["model_id"]

    def model_identity(self, stage):
        spec = self.require(stage)
        if spec.get("backend") == "process":
            result = self.process_capabilities(stage)
            return result["model_id"], result["model_files_sha256"]
        files = json.dumps(spec["files"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return spec["model_id"], digest(files)

    def require(self, stage):
        if not self.available(stage):
            raise self.error({"asr": "AsrModelUnavailable", "alignment": "ForcedAlignmentUnavailable", "diarization": "Community1Unavailable",
                              "cleanup": "CleanupBackendUnavailable", "moss": "MossBackendUnavailable", "uk_alignment": "ForcedAlignmentUnavailable"}[stage])
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
                   "pt": "Portuguese", "ru": "Russian", "es": "Spanish", "uk": "Ukrainian"}
        language = aliases.get(language, language)
        supported = (*LANGUAGES, "Ukrainian") if self.profile["uk_alignment"] is not None else LANGUAGES
        if self.profile["alignment"] is not None and self.profile["alignment"].get("backend") == "process":
            supported = self.process_capabilities("alignment")["models_by_language"]
        if language not in supported:
            raise self.error("ForcedAlignmentLanguageUnsupported")
        return language

    def align(self, audio, transcript, language, duration_ms):
        language = self.alignment_language(language)
        primary = self.profile["alignment"]
        external = primary is not None and primary.get("backend") == "process"
        stage = "uk_alignment" if language == "Ukrainian" and not external else "alignment"
        spec = self.require(stage)
        if stage == "uk_alignment":
            path = Path(__file__).with_name("meeting_audio_ctc.py")
            module_spec = importlib.util.spec_from_file_location("meeting_audio_ctc", path)
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)
            return checked_process_words(module.align(audio, transcript, spec["snapshot"], self.error), transcript, duration_ms, self.error)
        if external:
            body = process_pcm(audio, self.error)
            result = process_module().call(spec, "alignment", "align_words", body,
                {"transcript": transcript, "language": language}, self.error, strict_json)
            model = self.alignment_model(language)
            provenance = checked_process_provenance(result, body, model, self.error)
            if (result.get("aligner_model") != model or provenance.get("language") != language
                    or provenance.get("transcript_sha256") != digest(transcript.encode())):
                raise self.error("ProcessAlignmentBindingMismatch")
            words = checked_process_words(result.get("words"), transcript, duration_ms, self.error)
            self.last_alignment_provenance = {"runtime_binding": result["runtime_binding"], "provenance": provenance}
            return words
        import torch
        from qwen_asr import Qwen3ForcedAligner
        model = Qwen3ForcedAligner.from_pretrained(spec["snapshot"], dtype=torch.float32, device_map="cpu", local_files_only=True)
        output = model.align(audio=(audio, 16000), text=transcript, language=language)
        if len(output) != 1:
            raise self.error("InvalidAlignmentOutput")
        return aligned_words(output[0], transcript, duration_ms, self.error)

    def diarize(self, audio, duration_ms):
        spec = self.require("diarization")
        if spec.get("backend") == "process":
            body = process_pcm(audio, self.error)
            result = process_module().call(spec, "diarization", "diarize_full_file", body, {}, self.error, strict_json)
            provenance = checked_process_provenance(result, body, COMMUNITY, self.error)
            if provenance.get("full_file_samples") != len(audio):
                raise self.error("ProcessDiarizationBindingMismatch")
            tracks = checked_process_tracks(result.get("exclusive_tracks"), duration_ms, self.error)
            self.last_diarization_provenance = {"runtime_binding": result["runtime_binding"], "provenance": provenance}
            return tracks
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


def process_module():
    path = Path(__file__).with_name("meeting_audio_process.py")
    spec = importlib.util.spec_from_file_location("meeting_audio_process", path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def process_pcm(audio, error):
    import numpy as np
    samples = np.asarray(audio)
    scaled = samples * 32768.0
    if (samples.ndim != 1 or not len(samples) or not np.isfinite(scaled).all()
            or (scaled < -32768).any() or (scaled > 32767).any()
            or not (scaled == np.rint(scaled)).all()):
        raise error("InvalidProcessPcm")
    return scaled.astype("<i2").tobytes()


def checked_process_provenance(result, body, model, error):
    provenance = result.get("provenance")
    if (not isinstance(provenance, dict) or provenance.get("model_id") != model
            or provenance.get("input_sha256") != digest(body) or provenance.get("execution") != "measured"
            or not isinstance(provenance.get("invocation_id"), str) or not provenance["invocation_id"]):
        raise error("ProcessProvenanceMismatch")
    return provenance


def checked_process_words(words, transcript, duration_ms, error):
    if not isinstance(words, list) or not words:
        raise error("InvalidAlignmentOutput")
    previous = 0
    for word in words:
        if (not isinstance(word, dict) or set(word) != {"start_ms", "end_ms", "text", "confidence"}
                or type(word["start_ms"]) is not int or type(word["end_ms"]) is not int
                or not previous <= word["start_ms"] < word["end_ms"] <= duration_ms
                or not isinstance(word["text"], str) or not word["text"].strip() or word["confidence"] is not None):
            raise error("InvalidAlignmentOutput")
        previous = word["end_ms"]
    compact = lambda text: "".join(unicodedata.normalize("NFC", text).split())
    if compact("".join(word["text"] for word in words)) != compact(transcript):
        raise error("AlignmentTextMismatch")
    return words


def checked_process_tracks(tracks, duration_ms, error):
    if not isinstance(tracks, list) or not tracks:
        raise error("InvalidExclusiveDiarization")
    previous = 0
    for track in tracks:
        if (not isinstance(track, dict) or set(track) != {"start_ms", "end_ms", "speaker_cluster"}
                or type(track["start_ms"]) is not int or type(track["end_ms"]) is not int
                or not previous <= track["start_ms"] < track["end_ms"] <= duration_ms
                or not isinstance(track["speaker_cluster"], str) or not track["speaker_cluster"].strip()
                or len(track["speaker_cluster"]) > 128):
            raise error("InvalidExclusiveDiarization")
        previous = track["end_ms"]
    return tracks
