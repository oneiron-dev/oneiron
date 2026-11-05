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
PROTOCOL = "oneiron.meeting_audio.host.v2"
# No request, reply, audio, code file or profile is refused by its size (Rule 5).
# How often a port call still within its profile's bound tells its bridge so,
# which the host reads as progress (CALLS, FIX 3765). The port's own bound,
# `timeout_seconds` without output, judges a stall; no cap bounds a long one.
PROGRESS_EVERY_SECONDS = 30


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_spec(spec, error):
    fields = {"backend", "interpreter", "python_version", "script", "code_sha256", "profile", "profile_sha256", "timeout_seconds"}
    if (not isinstance(spec, dict) or set(spec) != fields or spec["backend"] != "process"
            or any(not isinstance(spec[k], str) or not Path(spec[k]).is_absolute() for k in ["interpreter", "script", "profile"])
            or not isinstance(spec["python_version"], str) or not spec["python_version"].strip()
            or type(spec["timeout_seconds"]) is not int or spec["timeout_seconds"] < 1
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
        if not path.is_file() or sha(path.read_bytes()) != checksum:
            raise error("ProcessCodeDigestMismatch")
    if sha(Path(__file__).read_bytes()) != spec["code_sha256"]["meeting_audio_process.py"]:
        raise error("ProcessCodeDigestMismatch")
    profile = Path(spec["profile"])
    if not profile.is_file() or sha(profile.read_bytes()) != spec["profile_sha256"]:
        raise error("ProcessProfileDigestMismatch")


class _WorkerUnitFailed(Exception):
    """The worker ended its relayed unit failed. Private: it only travels
    from the relay loop through the parent gate (which emits one parent
    `unit_failed` for it) back to the relay loop, which then reads the
    worker's final error reply. It never leaves this module."""


def _relay_exchange(command, request, idle, error, environment, progress, units, request_id, stage, parse):
    """One port call whose units the host admits one by one (FIX 11501).

    The request goes out as in `exchange`, but stdin stays open for admission
    answers. Each validated worker `unit` line runs as one top-level parent
    unit via the parent gate's own `run` (which owns admission, indexes and
    terminal events); the worker is answered over its stdin and its lines are
    consumed to its end. Returns only the final reply line for `call` to
    validate as usual."""
    if stage == "alignment":
        allowed = {"alignment_window"}
    elif stage == "diarization":
        allowed = {"diarization"}
    else:
        raise error("InvalidProcessRequest")
    progress_fn = progress if progress is not None else units.progress
    last_output = time.monotonic()
    buf = bytearray()
    worker_seq = {}
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=environment, start_new_session=True) as child:
        try:
            with selectors.DefaultSelector() as selector:
                for stream, event in [(child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ)]:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event)
                sent = 0
                broken = False
                request_sent = False
                while selector.get_map():
                    remaining = last_output + idle - time.monotonic()
                    if remaining <= 0:
                        raise error("ProcessPortStalled")
                    ready = selector.select(min(remaining, PROGRESS_EVERY_SECONDS))
                    if not ready:
                        progress_fn()
                    for key, _ in ready:
                        if key.fileobj is child.stdin:
                            try:
                                sent += os.write(child.stdin.fileno(), request[sent:sent + 65536])
                            except BrokenPipeError:
                                sent = len(request)
                                broken = True
                            if sent == len(request):
                                selector.unregister(child.stdin)
                                if broken:
                                    try:
                                        child.stdin.close()
                                    except OSError:
                                        pass
                                else:
                                    os.set_blocking(child.stdin.fileno(), True)
                                    request_sent = True
                        else:
                            data = os.read(child.stdout.fileno(), 65536)
                            if not data:
                                selector.unregister(child.stdout)
                                child.stdout.close()
                            else:
                                buf.extend(data)
                                last_output = time.monotonic()
                    if request_sent:
                        break
                if broken:
                    # The worker died before reading the request: whatever it
                    # wrote is validated below as one legacy reply.
                    try:
                        child.wait(timeout=max(0.001, last_output + idle - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        raise error("ProcessPortStalled") from None
                    return child.returncode, bytes(buf)

                def next_line():
                    """Next worker stdout line, or None at a clean EOF. Ticks
                    parent progress while waiting; worker silence past `idle`
                    stalls. Only worker bytes reset the idle clock."""
                    nonlocal last_output
                    while True:
                        mark = buf.find(b"\n")
                        if mark >= 0:
                            line = bytes(buf[:mark])
                            del buf[:mark + 1]
                            return line
                        remaining = last_output + idle - time.monotonic()
                        if remaining <= 0:
                            raise error("ProcessPortStalled")
                        if not selector.select(min(remaining, PROGRESS_EVERY_SECONDS)):
                            progress_fn()
                            continue
                        data = os.read(child.stdout.fileno(), 65536)
                        if not data:
                            if buf:
                                raise error("InvalidProcessFrame")
                            return None
                        buf.extend(data)
                        last_output = time.monotonic()

                def checked(raw):
                    try:
                        obj = parse(raw)
                    except (ValueError, UnicodeError):
                        raise error("InvalidProcessFrame") from None
                    if (not isinstance(obj, dict) or obj.get("protocol") != PROTOCOL
                            or obj.get("request_id") != request_id):
                        raise error("InvalidProcessFrame")
                    return obj

                def checked_unit(obj):
                    unit = obj.get("unit")
                    if (not isinstance(unit, dict) or set(unit) != {"kind", "index", "audio_ms"}
                            or unit["kind"] not in allowed
                            or type(unit["index"]) is not int or type(unit["audio_ms"]) is not int
                            or unit["index"] < 0 or unit["audio_ms"] < 0
                            or unit["index"] != worker_seq.get(unit["kind"], 0)):
                        raise error("InvalidProcessFrame")
                    worker_seq[unit["kind"]] = unit["index"] + 1
                    return unit["kind"], unit["audio_ms"]

                def answer_worker(admitted):
                    line = b'{"admitted":true}\n' if admitted else b'{"admitted":false}\n'
                    while line:
                        line = line[os.write(child.stdin.fileno(), line):]

                def relay_unit():
                    """Runs inside the parent gate once the host admitted this
                    unit: admits the worker, then consumes its lines to its end."""
                    nonlocal last_output
                    # The host admission wait is not worker silence: restart the
                    # idle clock before waiting for the admitted unit's output.
                    last_output = time.monotonic()
                    try:
                        answer_worker(True)
                    except BrokenPipeError:
                        raise error("ProcessPortRefused") from None
                    while True:
                        raw = next_line()
                        if raw is None:
                            raise error("InvalidProcessFrame")
                        obj = checked(raw)
                        if "event" not in obj:
                            raise error("InvalidProcessFrame")
                        name = obj["event"]
                        if name == "progress":
                            if "unit" in obj:
                                raise error("InvalidProcessFrame")
                            progress_fn()
                        elif name == "unit_done":
                            if obj.get("usage") is not None and not isinstance(obj["usage"], dict):
                                raise error("InvalidProcessFrame")
                            return
                        elif name == "unit_failed":
                            raise _WorkerUnitFailed()
                        else:
                            raise error("InvalidProcessFrame")

                final = None
                while True:
                    raw = next_line()
                    if raw is None:
                        raise error("InvalidProcessFrame")
                    obj = checked(raw)
                    if "event" not in obj:
                        final = raw
                        break
                    name = obj["event"]
                    if name == "progress":
                        if "unit" in obj:
                            raise error("InvalidProcessFrame")
                        progress_fn()
                    elif name == "unit":
                        kind, audio_ms = checked_unit(obj)
                        try:
                            units.run(kind, audio_ms, relay_unit, usage=None)
                        except _WorkerUnitFailed:
                            pass
                        except error as refused:
                            if getattr(refused, "code", None) in {"RunAdmissionRefused", "InvalidAdmission"}:
                                try:
                                    answer_worker(False)
                                except OSError:
                                    pass
                                raise
                            raise
                        finally:
                            # A host admission wait is not worker silence.
                            last_output = time.monotonic()
                    else:
                        raise error("InvalidProcessFrame")
                if next_line() is not None:
                    raise error("InvalidProcessFrame")
            try:
                child.stdin.close()
            except OSError:
                pass
            try:
                child.wait(timeout=max(0.001, last_output + idle - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise error("ProcessPortStalled") from None
            return child.returncode, final + b"\n"
        finally:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()


def exchange(command, request, idle, error, progress=None, units=None, request_id=None, stage=None, parse=None):
    """Runs one port call while it writes within `idle` seconds of its last
    output; `progress` is told every PROGRESS_EVERY_SECONDS meanwhile.

    With `units` None the worker's stdin closes after the request and its
    stdout is one reply line. With a unit gate each worker unit line is
    relayed as one top-level unit the host admits (FIX 11501): the parent
    gate owns admission, indexes and terminal events, while answers are
    piped back over the worker's still-open stdin.

    The worker stays in this bridge's process group, which the engine
    started and owns: an engine deadline kills and reaps the bridge and every
    worker together. A stall seen here kills and reaps the worker itself."""
    if os.name != "posix":
        raise error("ProcessPlatformUnsupported")
    environment = dict(os.environ)
    environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", PYANNOTE_METRICS_ENABLED="0", PYTHONDONTWRITEBYTECODE="1")
    if units is not None:
        return _relay_exchange(command, request, idle, error, environment, progress, units, request_id, stage, parse)
    last_output = time.monotonic()
    output = bytearray()
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=environment) as child:
        try:
            with selectors.DefaultSelector() as selector:
                for stream, event in [(child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ)]:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event)
                sent = 0
                while selector.get_map():
                    remaining = last_output + idle - time.monotonic()
                    if remaining <= 0:
                        raise error("ProcessPortStalled")
                    ready = selector.select(min(remaining, PROGRESS_EVERY_SECONDS))
                    if not ready and progress is not None:
                        progress()
                    for key, _ in ready:
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
                                last_output = time.monotonic()
            try:
                child.wait(timeout=max(0.001, last_output + idle - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise error("ProcessPortStalled") from None
            return child.returncode, bytes(output)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def call(spec, stage, operation, body, options, error, parse, progress=None, units=None):
    check_files(spec, error)
    if stage not in {"alignment", "diarization"}:
        raise error("InvalidProcessRequest")
    request_id = str(uuid.uuid4())
    header = {"protocol": PROTOCOL, "request_id": request_id, "operation": operation,
              "input_bytes": len(body), "input_sha256": sha(body), "options": options}
    encoded = json.dumps(header, ensure_ascii=False, allow_nan=False).encode()
    command = [spec["interpreter"], "-I", "-B", spec["script"], "--stage", stage, "--runtime-profile", spec["profile"],
               "--runtime-profile-sha256", spec["profile_sha256"]]
    status, output = exchange(command, encoded + b"\n" + body, spec["timeout_seconds"], error, progress,
                              units=units, request_id=request_id, stage=stage, parse=parse)
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
