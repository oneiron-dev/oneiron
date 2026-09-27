"""Always-warm, loopback-only VoxCPM2 worker. Run on a CUDA host, not in the vault.

Install a CUDA-matched PyTorch build and voxcpm==2.0.3. Set VOXCPM_REV to
an audited full Hugging Face commit. Weights are downloaded at boot, then
loaded onto CUDA before the HTTP listener opens. No request loads a model.
"""

import argparse
import json
import os
import struct
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODEL_ID = "openbmb/VoxCPM2"
MAX_BODY = 17 * 1024 * 1024
MAX_PCM = 2 * 1024 * 1024


def unpack(body):
    if len(body) < 4:
        raise ValueError("missing metadata")
    n = struct.unpack("!I", body[:4])[0]
    if not 0 < n <= 32_768 or len(body) <= 4 + n:
        raise ValueError("invalid metadata length")
    meta = json.loads(body[4:4+n])
    if not isinstance(meta, dict):
        raise ValueError("invalid metadata")
    return meta, body[4+n:]


def pack(meta, audio):
    header = json.dumps(meta, separators=(",", ":")).encode()
    return struct.pack("!I", len(header)) + header + audio


class Worker:
    def __init__(self, model, checkpoint, runtime_dir, credential):
        if len(credential) < 32:
            raise ValueError("worker credential too short")
        self.credential = credential
        self.model = model
        self.checkpoint = checkpoint
        self.boot_id = uuid.uuid4().hex
        self.sample_rate = int(model.tts_model.sample_rate)
        if not 8000 <= self.sample_rate <= 192000:
            raise ValueError("invalid VoxCPM2 sample rate")
        self.runtime_dir = Path(runtime_dir)
        self.lock = threading.Lock()

    def target(self):
        return {"model": "VoxCPM2", "checkpoint": self.checkpoint,
                "boot_id": self.boot_id, "sample_rate": self.sample_rate}

    def render(self, meta, wav):
        target = meta.get("target")
        if not isinstance(target, dict) or target.get("warm") != self.target():
            raise ValueError("stale or mismatched warm target")
        if not all(isinstance(target.get(k), str) and target[k] for k in
                   ("source_pack", "owner", "register")):
            raise ValueError("missing reference identity")
        text = meta.get("text")
        transcript = meta.get("transcript")
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 8192:
            raise ValueError("invalid text")
        if not isinstance(transcript, str) or not transcript.strip() or len(transcript) > 16384:
            raise ValueError("invalid reference transcript")
        if not wav.startswith(b"RIFF") or wav[8:12] != b"WAVE":
            raise ValueError("reference must be WAV")
        # The reference is request-scoped, owner-only, and erased after inference.
        # Serialize model.generate; the model is loaded once and shared by requests.
        with self.lock:
            with tempfile.TemporaryDirectory(dir=self.runtime_dir, prefix="ref-") as directory:
                reference = Path(directory) / "reference.wav"
                reference.write_bytes(wav)
                samples = self.model.generate(text=text, prompt_wav_path=str(reference),
                                              prompt_text=transcript,
                                              reference_wav_path=str(reference))
        import numpy as np
        values = np.asarray(samples)
        if values.ndim != 1 or not np.isfinite(values).all() or not values.size:
            raise ValueError("invalid model output")
        if values.size * 2 > MAX_PCM:
            raise ValueError("render exceeded bounded PCM response")
        pcm = (np.clip(values, -1.0, 1.0) * 32767).astype("<i2").tobytes()
        return pack({"target": target, "sample_rate": self.sample_rate, "channels": 1}, pcm)


def handler_for(worker):
    class Handler(BaseHTTPRequestHandler):
        def authorized(self):
            if self.headers.get("Authorization") == "Bearer " + worker.credential:
                return True
            self.send_error(401, "unauthorized")
            return False

        def do_GET(self):
            if not self.authorized():
                return
            if self.path != "/ready":
                self.send_error(404)
                return
            data = json.dumps(worker.target()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if not self.authorized():
                return
            if self.path != "/render":
                self.send_error(404)
                return
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if not 5 <= n <= MAX_BODY:
                    raise ValueError("request size")
                meta, wav = unpack(self.rfile.read(n))
                data = worker.render(meta, wav)
            except (ValueError, TypeError, UnicodeError, KeyError, json.JSONDecodeError):
                self.send_error(400, "invalid render request")
                return
            except Exception:
                # Model/runtime failures do not echo raw prompts or reference bytes.
                self.send_error(503, "render failed")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            # Do not log the URL or request content. The listener is loopback only.
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument("--runtime-dir", required=True)
    args = parser.parse_args()
    revision = os.environ["VOXCPM_REV"]
    if len(revision) != 40 or any(ch not in "0123456789abcdef" for ch in revision):
        raise ValueError("VOXCPM_REV must be a full immutable commit")
    runtime_dir = Path(args.runtime_dir)
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if runtime_dir.is_symlink() or runtime_dir.stat().st_mode & 0o077:
        raise ValueError("runtime directory must be private")
    import torch
    from huggingface_hub import snapshot_download
    from voxcpm import VoxCPM
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA required; refusing CPU fallback")
    snapshot = snapshot_download(repo_id=MODEL_ID, revision=revision)
    model = VoxCPM.from_pretrained(snapshot, load_denoiser=False, device="cuda:0",
                                   local_files_only=True)
    worker = Worker(model, revision, runtime_dir, os.environ["VOXCPM_TOKEN"])
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(worker))
    server.serve_forever()


if __name__ == "__main__":
    main()
