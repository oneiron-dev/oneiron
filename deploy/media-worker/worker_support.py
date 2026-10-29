"""What every media worker (VoxCPM2 speech, local ASR) shares under the
engine's supervisor (FIX 8318): its launch checked before any weights load,
the receipt each inference answers with, the one inference gate, and the
activity its bearer `/stats` reports.

A managed launch is given its weights directory, the weights manifest the
supervisor verified that directory against (the exact JSON whose SHA-256 is
the install record's digest), and the supervisor's launch manifest.
`verify_launch` checks that the launch names this worker's kind, its wire
model and that weights manifest, then hashes every pinned file again before
anything loads. Its digests are the identity the worker answers with: the
weights manifest's as `model`, the launch's build as `runtime`, and the
launch manifest's own SHA-256, echoed beside every answer.

It loads no model and downloads nothing.
"""
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

# One inference at a time per worker: "serial first" (FIX 8318). A request
# past it waits for the gate; none is refused or batched for room.
MEDIA_INFERENCE_SLOTS = 1
# The device a media worker runs on, once CUDA_VISIBLE_DEVICES has masked
# the host's devices to the one its row names.
MEDIA_DEVICE = "cuda:0"
# A media worker without CUDA does not start: it never serves from the CPU.
ALLOW_MEDIA_CPU_FALLBACK = False
# The shortest bearer credential a worker takes.
MIN_CREDENTIAL_CHARS = 32
# The launch-manifest schema the supervisor writes.
LAUNCH_SCHEMA_VERSION = 1
HASH_CHUNK = 8 << 20
MIB = 1 << 20


class LaunchError(Exception):
    """Why a launch is not the one this worker was given."""


class LaunchIdentity:
    """What a verified launch answers with: the weights manifest's digest
    (`model`), the launch's build digest (`runtime`), the launch manifest's
    own digest, and the weights' commit."""

    def __init__(self, model, runtime, launch_manifest, revision):
        self.model = model
        self.runtime = runtime
        self.launch_manifest = launch_manifest
        self.revision = revision


def lower_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(ch in "0123456789abcdef" for ch in value))


def sha256_file(path):
    """A file's size and the SHA-256 of its bytes, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def pinned_path(directory, name):
    """`name` under `directory`, when it is a plain relative path."""
    path = PurePosixPath(name) if isinstance(name, str) and name else None
    if path is None or path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise LaunchError(f"the weights manifest pins {name!r}, not a plain relative path")
    return Path(directory).joinpath(*path.parts)


def verify_launch(kind, wire_model, weights_dir, weights_manifest, launch_manifest):
    """Checks the launch before anything loads: the launch manifest names
    `kind`, `wire_model`, a 64-hex runtime and the weights manifest by its
    SHA-256, and every file that manifest pins is in `weights_dir` at its
    size and SHA-256. Returns the launch's identity."""
    launch_bytes = Path(launch_manifest).read_bytes()
    weights_bytes = Path(weights_manifest).read_bytes()
    try:
        launch = json.loads(launch_bytes)
        weights = json.loads(weights_bytes)
    except ValueError as error:
        raise LaunchError(f"a manifest is not JSON: {error}") from None
    if not isinstance(launch, dict) or launch.get("schema_version") != LAUNCH_SCHEMA_VERSION:
        raise LaunchError(f"{launch_manifest} is not a schema {LAUNCH_SCHEMA_VERSION} launch manifest")
    if launch.get("kind") != kind:
        raise LaunchError(f"the launch is for a {launch.get('kind')!r} worker, not {kind!r}")
    if launch.get("wire_model") != wire_model:
        raise LaunchError("the launch names another wire model")
    runtime = launch.get("runtime")
    if not lower_hex(runtime, 64):
        raise LaunchError("the launch names no 64-hex runtime")
    model = hashlib.sha256(weights_bytes).hexdigest()
    if launch.get("weights_record_sha256") != model or launch.get("backend_model") != model:
        raise LaunchError(f"the launch does not name {weights_manifest}")
    if not isinstance(weights, dict) or not lower_hex(weights.get("revision"), 40):
        raise LaunchError(f"{weights_manifest} names no full commit")
    files = weights.get("files")
    if not isinstance(files, list) or not files:
        raise LaunchError(f"{weights_manifest} pins no file")
    for entry in files:
        if not isinstance(entry, dict):
            raise LaunchError(f"{weights_manifest} pins a file it does not describe")
        path = pinned_path(weights_dir, entry.get("path"))
        try:
            measured = sha256_file(path)
        except OSError as error:
            raise LaunchError(f"{path}: {error}") from None
        if measured != (entry.get("bytes"), entry.get("sha256")):
            raise LaunchError(f"{path} does not hash as {weights_manifest} pins it")
    return LaunchIdentity(model, runtime, hashlib.sha256(launch_bytes).hexdigest(),
                          weights["revision"])


def worker_descriptor(kind, identity, epoch):
    """The worker as the engine reads it (`WorkerDescriptor`): its kind, the
    identity its verified launch gives with this incarnation's epoch, and
    how its build is known. Without a launch only the epoch is named."""
    fields = {"backend_epoch": epoch}
    if identity is not None:
        fields.update(model=identity.model, runtime=identity.runtime)
    return {"kind": kind, "identity": fields,
            "build_evidence": "verified_artifacts" if identity is not None else "unknown"}


def inference_receipt(kind, identity, epoch):
    """One physical request's receipt (`InferenceCallReceipt`): the worker
    that answered, and no count, wait or time, none of which it measures."""
    return {"worker": worker_descriptor(kind, identity, epoch)}


class RequestTicket:
    """One request's place in its worker's activity: queued from admission,
    active once it holds the inference gate, gone when its response is
    cleaned up."""

    def __init__(self, activity):
        self._activity = activity
        self._active = False

    def start(self):
        with self._activity._lock:
            if not self._active:
                self._active = True
                self._activity._queued -= 1
                self._activity._active += 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        with self._activity._lock:
            if self._active:
                self._activity._active -= 1
            else:
                self._activity._queued -= 1
        return False


class RequestActivity:
    """The requests a worker holds, for its `/stats`: each counted from its
    admission, before its body is read, through its response's cleanup. A
    request whose caller went away stays counted until its work ends, so an
    idle stop never cuts it."""

    def __init__(self):
        self._lock = threading.Lock()
        self._queued = 0
        self._active = 0

    def admit(self):
        with self._lock:
            self._queued += 1
        return RequestTicket(self)

    def snapshot(self):
        with self._lock:
            return self._queued, self._active


class InferenceGate:
    """`MEDIA_INFERENCE_SLOTS` inferences at once; a request past them
    waits for one."""

    def __init__(self):
        self._slots = threading.BoundedSemaphore(MEDIA_INFERENCE_SLOTS)

    @contextmanager
    def hold(self, ticket=None):
        with self._slots:
            if ticket is not None:
                ticket.start()
            yield


def resident_mib():
    """The CUDA allocator's reservation on this worker's device, in MiB,
    measured now; None where torch or CUDA is not loaded."""
    torch = sys.modules.get("torch")
    if torch is None or not torch.cuda.is_available():
        return None
    return int(torch.cuda.memory_reserved(MEDIA_DEVICE) // MIB)


def stats_body(activity):
    """`/stats`: queued and active requests, and the measured reservation
    when there is one."""
    queued, active = activity.snapshot()
    body = {"queued": queued, "active": active}
    mib = resident_mib()
    if mib is not None:
        body["resident_mib"] = mib
    return json.dumps(body, separators=(",", ":")).encode()


def require_cuda(torch):
    if not ALLOW_MEDIA_CPU_FALLBACK and not torch.cuda.is_available():
        raise RuntimeError("CUDA required; refusing CPU fallback")


def credential(name):
    """The bearer credential in the environment variable `name`, which the
    supervisor sets from its provider's `key_env`."""
    value = os.environ.get(name, "")
    if len(value) < MIN_CREDENTIAL_CHARS:
        raise ValueError(f"{name} must hold a credential of {MIN_CREDENTIAL_CHARS} or more characters")
    return value


def authorized(headers, secret):
    return hmac.compare_digest(headers.get("Authorization", ""), "Bearer " + secret)


def listen_family(host):
    """The address family a loopback `host` listens on."""
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def send_bytes(handler, status, content_type, data):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
