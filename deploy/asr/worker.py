"""The local speech-recognition worker (FIX 8318): Whisper through
transformers on one CUDA device, launched by the engine's supervisor.

The supervisor installs the pinned weights and gives this worker their
directory, the weights manifest it verified them against and its launch
manifest. The launch and every pinned file are checked, and the weights load
from that directory alone, before the loopback listener opens. No request
loads a model, downloads anything or falls back to CPU, and no code from the
weights' repository runs.

`POST /v1/audio/transcriptions` takes the OpenAI-compatible form the
engine's media client sends: `model`, `file` (a PCM16 WAV, mono or stereo,
at any rate a host records), `response_format` = `json` and an optional
`language`. The clip is downmixed to mono, resampled to 16 kHz and
transcribed whole, however long: Whisper's long-form decoding goes window by
window, greedily, in the language it detects unless the call names one. The
answer is `{"text", "duration", "model", "usage"}`; `usage` holds one
inference receipt naming this worker, and the launch manifest's digest.

One transcription runs at a time; a request past it waits. `GET /health` is
liveness only; `GET /stats` (bearer) reports queued and active requests and
the CUDA allocator's reservation.
"""
import argparse
import io
import json
import math
import re
import sys
import uuid
import wave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import worker_support
except ImportError:
    # Run from the source tree, where the shared module sits beside this
    # directory; a supervisor's bundle holds both side by side.
    sys.path.append(str(Path(__file__).resolve().parent.parent / "media-worker"))
    import worker_support

KIND = "asr"
ROUTE = "/v1/audio/transcriptions"
# The documented default checkpoint an operator's manifest pins; no house pin
# exists, so the manifest names its commit and every file.
ASR_MODEL_REPO = "openai/whisper-large-v3"
ASR_BACKEND = "transformers_whisper"
ASR_DTYPE = "float16"
ASR_SAMPLE_RATE = 16000
ASR_NUM_BEAMS = 1
ASR_DO_SAMPLE = False
# None: the language each clip is detected in.
ASR_LANGUAGE = None
ASR_TASK = "transcribe"
ASR_RESPONSE_FORMAT = "json"
# Whisper's window: a longer clip is decoded long-form, window by window.
WHISPER_WINDOW_SAMPLES = 30 * ASR_SAMPLE_RATE
# The rates a host records at, as the engine's own WAV checks bound them.
MIN_INPUT_RATE = 8000
MAX_INPUT_RATE = 192000


def decode_wav(data):
    """A PCM16 WAV's samples as mono float32 at `ASR_SAMPLE_RATE`, and its
    length in seconds."""
    import numpy as np
    try:
        with wave.open(io.BytesIO(data), "rb") as clip:
            channels = clip.getnchannels()
            width = clip.getsampwidth()
            rate = clip.getframerate()
            raw = clip.readframes(clip.getnframes())
    except (wave.Error, EOFError) as error:
        raise ValueError(f"not a PCM WAV: {error}") from None
    if width != 2 or channels not in (1, 2) or not MIN_INPUT_RATE <= rate <= MAX_INPUT_RATE:
        raise ValueError("a PCM16 WAV, mono or stereo, at a host's rate")
    samples = np.frombuffer(raw[:len(raw) // (2 * channels) * 2 * channels], dtype="<i2")
    samples = samples.astype(np.float32) / 32768.0
    if channels == 2:
        samples = samples.reshape(-1, 2).mean(axis=1)
    if not samples.size:
        raise ValueError("the clip holds no audio")
    seconds = samples.size / rate
    if rate != ASR_SAMPLE_RATE:
        from scipy.signal import resample_poly
        common = math.gcd(rate, ASR_SAMPLE_RATE)
        samples = resample_poly(samples, ASR_SAMPLE_RATE // common, rate // common)
    return samples.astype(np.float32), seconds


def form_parts(content_type, body):
    """A `multipart/form-data` body's parts by name: `(filename, bytes)`."""
    match = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not (content_type or "").lower().startswith("multipart/form-data") or not match:
        raise ValueError("a multipart/form-data body")
    delimiter = b"\r\n--" + match.group(1).encode("latin-1")
    chunks = (b"\r\n" + body).split(delimiter)
    parts = {}
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            return parts
        head, blank, data = chunk.partition(b"\r\n\r\n")
        if not head.startswith(b"\r\n") or not blank:
            raise ValueError("a malformed form part")
        disposition = next((line for line in head.decode("latin-1").split("\r\n")
                            if line.lower().startswith("content-disposition:")), "")
        name = re.search(r';\s*name="([^"]*)"', disposition)
        filename = re.search(r';\s*filename="([^"]*)"', disposition)
        if not name or name.group(1) in parts:
            raise ValueError("a form part without a name, or named twice")
        parts[name.group(1)] = (filename.group(1) if filename else None, data)
    raise ValueError("an unterminated form")


class WhisperBackend:
    """Whisper on `MEDIA_DEVICE`, loaded from the verified directory alone."""

    def __init__(self, weights_dir):
        import torch
        from transformers import WhisperForConditionalGeneration, WhisperProcessor
        worker_support.require_cuda(torch)
        self.torch = torch
        self.dtype = getattr(torch, ASR_DTYPE)
        # The concrete Whisper classes run no repository code.
        self.processor = WhisperProcessor.from_pretrained(weights_dir, local_files_only=True)
        model = WhisperForConditionalGeneration.from_pretrained(
            weights_dir, local_files_only=True, use_safetensors=True, trust_remote_code=False,
            torch_dtype=self.dtype)
        self.model = model.to(worker_support.MEDIA_DEVICE).eval()

    def __call__(self, audio, language):
        long_form = audio.size > WHISPER_WINDOW_SAMPLES
        extract = self.processor.feature_extractor
        if long_form:
            inputs = extract(audio, sampling_rate=ASR_SAMPLE_RATE, return_tensors="pt",
                             truncation=False, padding="longest", return_attention_mask=True)
        else:
            inputs = extract(audio, sampling_rate=ASR_SAMPLE_RATE, return_tensors="pt",
                             return_attention_mask=True)
        features = inputs.input_features.to(worker_support.MEDIA_DEVICE, dtype=self.dtype)
        mask = inputs.attention_mask.to(worker_support.MEDIA_DEVICE)
        with self.torch.inference_mode():
            tokens = self.model.generate(features, attention_mask=mask, task=ASR_TASK,
                                         language=language, num_beams=ASR_NUM_BEAMS,
                                         do_sample=ASR_DO_SAMPLE, return_timestamps=long_form)
        return self.processor.batch_decode(tokens, skip_special_tokens=True)[0].strip()


class Worker:
    def __init__(self, backend, identity, wire_model, credential):
        self.backend = backend
        self.identity = identity
        self.wire_model = wire_model
        self.credential = credential
        self.boot_id = uuid.uuid4().hex
        self.gate = worker_support.InferenceGate()
        self.activity = worker_support.RequestActivity()

    def transcribe(self, content_type, body, ticket):
        parts = form_parts(content_type, body)
        # Other OpenAI transcription fields (prompt, temperature, ...) are accepted and
        # unused: this worker decodes greedily with its fixed settings.
        if "file" not in parts:
            raise ValueError("no audio file")

        def field(name):
            return parts[name][1].decode("utf-8") if name in parts else None

        if field("model") != self.wire_model:
            raise ValueError("another model")
        if field("response_format") not in (None, ASR_RESPONSE_FORMAT):
            raise ValueError("an unsupported response format")
        language = field("language") or ASR_LANGUAGE
        audio, seconds = decode_wav(parts["file"][1])
        with self.gate.hold(ticket):
            text = self.backend(audio, language)
        usage = {"inference_calls": [worker_support.inference_receipt(KIND, self.identity,
                                                                     self.boot_id)],
                 "launch_manifest": self.identity.launch_manifest}
        return json.dumps({"text": text, "duration": seconds, "model": self.wire_model,
                           "usage": usage}, separators=(",", ":")).encode()


class TranscriptionServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        self.address_family = worker_support.listen_family(address[0])
        super().__init__(address, handler)


def handler_for(worker):
    class Handler(BaseHTTPRequestHandler):
        def authorized(self):
            if worker_support.authorized(self.headers, worker.credential):
                return True
            self.send_error(401, "unauthorized")
            return False

        def do_GET(self):
            if self.path == "/health":
                # Liveness only: the listener opens after the model loads.
                worker_support.send_bytes(self, 200, "application/json", b"")
                return
            if not self.authorized():
                return
            if self.path != "/stats":
                self.send_error(404)
                return
            worker_support.send_bytes(self, 200, "application/json",
                                      worker_support.stats_body(worker.activity))

        def do_POST(self):
            if not self.authorized():
                return
            if self.path != ROUTE:
                self.send_error(404)
                return
            # Counted from here until the response is cleaned up, its caller
            # gone or not; it waits for the gate, never refused for room.
            with worker.activity.admit() as ticket:
                try:
                    length = int(self.headers.get("Content-Length", ""))
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete upload")
                    data = worker.transcribe(self.headers.get("Content-Type"), body, ticket)
                except (ValueError, TypeError, UnicodeError, KeyError):
                    self.send_error(400, "invalid transcription request")
                    return
                except Exception:
                    # Model/runtime errors do not echo the audio or its text.
                    self.send_error(503, "transcription failed")
                    return
                worker_support.send_bytes(self, 200, "application/json", data)

        def log_message(self, format, *args):
            # Do not log URL, auth, audio or text.
            pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--weights-dir", required=True)
    parser.add_argument("--weights-manifest", required=True,
                        help=f"the manifest the checkpoint was verified against "
                             f"(the documented default: {ASR_MODEL_REPO})")
    parser.add_argument("--launch-manifest", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--credential-env", required=True,
                        help="the environment variable holding the bearer credential")
    args = parser.parse_args()
    credential = worker_support.credential(args.credential_env)
    identity = worker_support.verify_launch(KIND, args.model_id, args.weights_dir,
                                            args.weights_manifest, args.launch_manifest)
    print(f"MODEL_LOAD_START backend={ASR_BACKEND} revision={identity.revision}", flush=True)
    backend = WhisperBackend(args.weights_dir)
    worker = Worker(backend, identity, args.model_id, credential)
    server = TranscriptionServer((args.host, args.port), handler_for(worker))
    server.serve_forever()


if __name__ == "__main__":
    main()
