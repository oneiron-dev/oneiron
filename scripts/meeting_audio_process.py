"""Hash-bound, offline subprocess ports for incompatible native model runtimes.

No installer or resolver. Each call uses the operator's explicit interpreter,
code manifest and profile. A successful capability probe is not model execution.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
import uuid

CODE_FILES = {"meeting-audio-worker.py", "meeting-audio-native.py", "meeting_audio_runtime.py", "meeting_audio_process.py", "meeting_audio_ctc.py"}
PROTOCOL = "oneiron.meeting_audio.host.v1"
MAX_REPLY = 1024 * 1024
MAX_AUDIO = 16000 * 2 * 7200


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_spec(spec, error):
    fields = {"backend", "interpreter", "python_version", "script", "code_sha256", "profile", "profile_sha256", "timeout_seconds"}
    if (not isinstance(spec, dict) or set(spec) != fields or spec["backend"] != "process"
            or any(not isinstance(spec[k], str) or not Path(spec[k]).is_absolute() for k in ["interpreter", "script", "profile"])
            or not isinstance(spec["python_version"], str) or not spec["python_version"].strip()
            or type(spec["timeout_seconds"]) is not int or not 1 <= spec["timeout_seconds"] <= 7200
            or not isinstance(spec["code_sha256"], dict) or set(spec["code_sha256"]) != CODE_FILES
            or Path(spec["script"]).name != "meeting-audio-worker.py"):
        raise error("InvalidProcessRuntimeProfile")
    for value in [spec["profile_sha256"], *spec["code_sha256"].values()]:
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise error("InvalidProcessRuntimeProfile")


def check_files(spec, error):
    validate_spec(spec, error)
    executable = Path(spec["interpreter"])
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise error("ProcessInterpreterUnavailable")
    for name, checksum in spec["code_sha256"].items():
        path = Path(spec["script"]).with_name(name)
        if not path.is_file() or path.stat().st_size > MAX_REPLY or sha(path.read_bytes()) != checksum:
            raise error("ProcessCodeDigestMismatch")
    if sha(Path(__file__).read_bytes()) != spec["code_sha256"]["meeting_audio_process.py"]:
        raise error("ProcessCodeDigestMismatch")
    profile = Path(spec["profile"])
    if not profile.is_file() or profile.stat().st_size > MAX_REPLY or sha(profile.read_bytes()) != spec["profile_sha256"]:
        raise error("ProcessProfileDigestMismatch")


def exchange(command, request, timeout, error):
    if os.name != "posix":
        raise error("ProcessPlatformUnsupported")
    environment = dict(os.environ)
    environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", PYANNOTE_METRICS_ENABLED="0", PYTHONDONTWRITEBYTECODE="1")
    deadline = time.monotonic() + timeout
    output = bytearray()
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=environment, start_new_session=True) as child:
        try:
            with selectors.DefaultSelector() as selector:
                for stream, event in [(child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ)]:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event)
                sent = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise error("ProcessPortTimedOut")
                    for key, _ in selector.select(remaining):
                        if key.fileobj is child.stdin:
                            try:
                                sent += os.write(child.stdin.fileno(), request[sent:sent + 65536])
                            except BrokenPipeError:
                                sent = len(request)
                            if sent == len(request):
                                selector.unregister(child.stdin)
                                child.stdin.close()
                        else:
                            data = os.read(child.stdout.fileno(), 65536)
                            if not data:
                                selector.unregister(child.stdout)
                                child.stdout.close()
                            else:
                                output.extend(data)
                                if len(output) > MAX_REPLY:
                                    raise error("ProcessOutputTooLarge")
            try:
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise error("ProcessPortTimedOut") from None
            return child.returncode, bytes(output)
        finally:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()


def call(spec, stage, operation, body, options, error, parse):
    check_files(spec, error)
    if stage not in {"alignment", "diarization"} or len(body) > MAX_AUDIO:
        raise error("InvalidProcessRequest")
    request_id = str(uuid.uuid4())
    header = {"protocol": PROTOCOL, "request_id": request_id, "operation": operation,
              "input_bytes": len(body), "input_sha256": sha(body), "options": options}
    encoded = json.dumps(header, ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > MAX_REPLY:
        raise error("ProcessRequestTooLarge")
    command = [spec["interpreter"], "-I", "-B", spec["script"], "--stage", stage, "--runtime-profile", spec["profile"],
               "--runtime-profile-sha256", spec["profile_sha256"]]
    status, output = exchange(command, encoded + b"\n" + body, spec["timeout_seconds"], error)
    try:
        line, separator, trailing = output.partition(b"\n")
        reply = parse(line)
        if (not separator or trailing or not isinstance(reply, dict) or reply.get("protocol") != PROTOCOL
                or reply.get("request_id") != request_id or type(reply.get("body_bytes")) is not int or reply["body_bytes"] != 0):
            raise ValueError("frame")
    except (ValueError, UnicodeError):
        raise error("InvalidProcessFrame") from None
    if status != 0 or reply.get("ok") is not True:
        raise error("ProcessPortRefused")
    result = reply.get("result")
    if not isinstance(result, dict):
        raise error("InvalidProcessFrame")
    binding = result.get("runtime_binding")
    expected = {"profile_sha256": spec["profile_sha256"], "code_sha256": spec["code_sha256"],
                "python_version": spec["python_version"]}
    if binding != expected:
        raise error("ProcessRuntimeBindingMismatch")
    return result
