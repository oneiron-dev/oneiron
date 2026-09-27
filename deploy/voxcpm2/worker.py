"""Always-warm, loopback-only VoxCPM2 worker on a CUDA host.

Weights are pinned and loaded before the listener opens. No request loads a model.
The deployment policy is the vault's resolved *ceiling*; each request can narrow it.
"""
import argparse
import hmac
import json
import os
import socket
import struct
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODEL_ID = "openbmb/VoxCPM2"
FIELDS = ("max_text_bytes", "max_pcm_bytes", "max_ref_bytes", "max_queued_renders",
          "max_inflight_uploads", "upload_read_deadline_ms", "http_deadline_ms",
          "max_header_bytes")
# MessagePack u64/4-byte framing and PCM16 are structural; deployment policy
# supplies all behavior-deciding waits and budgets, including larger values.
WIRE_U64 = (1 << 64) - 1
WIRE_USIZE = (1 << (8 * struct.calcsize("P"))) - 1


def validate_limits(limits):
    if (not isinstance(limits, dict) or set(limits) != set(FIELDS)
            or any(type(limits[k]) is not int or not 0 < limits[k] <= WIRE_U64
                   for k in FIELDS)
            or any(limits[k] > WIRE_USIZE for k in (
                "max_text_bytes", "max_pcm_bytes", "max_ref_bytes",
                "max_queued_renders", "max_inflight_uploads"))
            or limits["max_header_bytes"] > (1 << 32) - 1
            or limits["max_ref_bytes"] + limits["max_header_bytes"] + 4 > WIRE_USIZE
            or limits["max_pcm_bytes"] + limits["max_header_bytes"] + 4 > WIRE_USIZE
            or limits["max_pcm_bytes"] % 2
            or limits["max_ref_bytes"] < 12
            or limits["upload_read_deadline_ms"] > limits["http_deadline_ms"]):
        raise ValueError("invalid serving policy")
    return limits


def load_policy(path):
    data = json.loads(Path(path).read_text())
    if (not isinstance(data, dict) or set(data) != {"precedence", "vault", "holders"}
            or data["precedence"] != "nested_narrowing" or data["holders"] != []):
        raise ValueError("worker needs a vault-ceiling manifest row without holder rows")
    return validate_limits(data["vault"])


def unpack(body, max_header=32768, *, include_header_length=False):
    if len(body) < 4:
        raise ValueError("missing metadata")
    n = struct.unpack("!I", body[:4])[0]
    if not 0 < n <= max_header or len(body) <= 4 + n:
        raise ValueError("invalid metadata length")
    meta = json.loads(body[4:4+n])
    if not isinstance(meta, dict):
        raise ValueError("invalid metadata")
    if include_header_length:
        return meta, body[4+n:], n
    return meta, body[4+n:]


def pack(meta, audio):
    header = json.dumps(meta, separators=(",", ":")).encode()
    return struct.pack("!I", len(header)) + header + audio


class Worker:
    def __init__(self, model, checkpoint, runtime_dir, credential, limits):
        if len(credential) < 32:
            raise ValueError("worker credential too short")
        self.limits = validate_limits(limits)
        self.credential = credential
        self.model = model
        self.checkpoint = checkpoint
        self.boot_id = uuid.uuid4().hex
        self.sample_rate = int(model.tts_model.sample_rate)
        if not 8000 <= self.sample_rate <= 192000:
            raise ValueError("invalid VoxCPM2 sample rate")
        self.runtime_dir = Path(runtime_dir)
        self.lock = threading.Lock()
        self.admission = threading.BoundedSemaphore(self.limits["max_inflight_uploads"])

    def target(self):
        return {"model": "VoxCPM2", "checkpoint": self.checkpoint,
                "boot_id": self.boot_id, "sample_rate": self.sample_rate,
                "limits": self.limits}

    def render(self, meta, wav, header_bytes):
        target = meta.get("target")
        if not isinstance(target, dict) or target.get("warm") != self.target():
            raise ValueError("stale or mismatched warm target")
        if not all(isinstance(target.get(k), str) and target[k] for k in
                   ("source_pack", "owner", "register", "reference_revision")):
            raise ValueError("missing reference identity")
        effective = validate_limits(target.get("limits"))
        if any(effective[k] > self.limits[k] for k in FIELDS):
            raise ValueError("request widens worker policy")
        if header_bytes > effective["max_header_bytes"]:
            raise ValueError("request metadata exceeds narrowed policy")
        response_meta = {"target": target, "sample_rate": self.sample_rate, "channels": 1}
        if len(json.dumps(response_meta, separators=(",", ":")).encode()) > effective["max_header_bytes"]:
            raise ValueError("response metadata exceeds narrowed policy")
        text = meta.get("text")
        transcript = meta.get("transcript")
        if (not isinstance(text, str) or not text.strip()
                or len(text.encode()) > effective["max_text_bytes"]):
            raise ValueError("invalid text")
        if not isinstance(transcript, str) or not transcript.strip() or len(transcript) > 16384:
            raise ValueError("invalid reference transcript")
        if (len(wav) > effective["max_ref_bytes"] or not wav.startswith(b"RIFF")
                or wav[8:12] != b"WAVE"):
            raise ValueError("invalid WAV reference")
        # The reference is request-scoped, owner-only, and erased after inference.
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
        if values.size * 2 > effective["max_pcm_bytes"]:
            raise ValueError("render exceeded policy PCM budget")
        pcm = (np.clip(values, -1.0, 1.0) * 32767).astype("<i2").tobytes()
        return pack(response_meta, pcm)


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, upload_deadline_ms):
        self.upload_deadline_ms = upload_deadline_ms
        self._upload_lock = threading.Lock()
        self._uploads = {}
        super().__init__(address, handler)

    def get_request(self):
        sock, addr = super().get_request()
        duration = self.upload_deadline_ms / 1000
        sock.settimeout(duration)
        deadline = time.monotonic() + duration
        def expire():
            try:
                # SHUT_RD unblocks a buffered readline/read1 already inside
                # parsing headers or reading a dribbled body.
                sock.shutdown(socket.SHUT_RD)
            except OSError:
                pass
        timer = threading.Timer(duration, expire)
        timer.daemon = True
        with self._upload_lock:
            self._uploads[id(sock)] = (deadline, timer)
        timer.start()
        return sock, addr

    def upload_deadline(self, sock):
        with self._upload_lock:
            return self._uploads[id(sock)][0]

    def disarm_upload(self, sock):
        with self._upload_lock:
            entry = self._uploads.pop(id(sock), None)
        if entry is not None:
            entry[1].cancel()

    def finish_request(self, request, client_address):
        try:
            super().finish_request(request, client_address)
        finally:
            self.disarm_upload(request)


def handler_for(worker):
    class Handler(BaseHTTPRequestHandler):
        def authorized(self):
            if hmac.compare_digest(self.headers.get("Authorization", ""),
                                   "Bearer " + worker.credential):
                return True
            self.send_error(401, "unauthorized")
            return False

        def do_GET(self):
            self.server.disarm_upload(self.connection)
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

        def read_body(self):
            n = int(self.headers.get("Content-Length", "0"))
            max_body = worker.limits["max_ref_bytes"] + worker.limits["max_header_bytes"] + 4
            if not 5 <= n <= max_body:
                raise ValueError("request size")
            deadline = self.server.upload_deadline(self.connection)
            parts = []
            remaining = n
            while remaining:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("upload deadline")
                self.connection.settimeout(left)
                piece = self.rfile.read1(min(65536, remaining))
                if time.monotonic() >= deadline:
                    raise TimeoutError("upload deadline")
                if not piece:
                    raise ValueError("incomplete upload")
                parts.append(piece)
                remaining -= len(piece)
            return unpack(b"".join(parts), worker.limits["max_header_bytes"],
                          include_header_length=True)

        def do_POST(self):
            if not self.authorized():
                return
            if self.path != "/render":
                self.send_error(404)
                return
            if not worker.admission.acquire(blocking=False):
                self.send_error(429, "worker upload slots full")
                return
            try:
                try:
                    meta, wav, header_bytes = self.read_body()
                    self.server.disarm_upload(self.connection)
                    data = worker.render(meta, wav, header_bytes)
                except (TimeoutError, socket.timeout):
                    self.send_error(408, "upload deadline exceeded")
                    return
                except (ValueError, TypeError, UnicodeError, KeyError):
                    self.send_error(400, "invalid render request")
                    return
                except Exception:
                    # Model/runtime errors do not echo raw prompts or ref bytes.
                    self.send_error(503, "render failed")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            finally:
                worker.admission.release()

        def log_message(self, format, *args):
            # Do not log URL, auth, text, or reference bytes.
            pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--policy-file", required=True)
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
    policy = load_policy(args.policy_file)
    worker = Worker(model, revision, runtime_dir, os.environ["VOXCPM_TOKEN"], policy)
    server = BoundedHTTPServer(("127.0.0.1", args.port), handler_for(worker),
                               policy["upload_read_deadline_ms"])
    server.serve_forever()


if __name__ == "__main__":
    main()
