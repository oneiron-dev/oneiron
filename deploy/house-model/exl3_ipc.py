"""The house EXL3 server's native channel (DESIGN-V2 §8, R1): the host's
calls over a Unix socket, into the same scheduler the HTTP routes feed.

Transport. One AF_UNIX stream socket at `--native-socket`, its folder made
this user's alone (0700) and the socket 0600. A connection is answered only
when its peer runs as this process's own user (SO_PEERCRED on Linux,
getpeereid elsewhere); any other is closed before a byte is read.

Codec v1. Each frame is a u64 big-endian payload length, then that many
bytes of UTF-8 JSON: `{"v": 1, "op", "request_id", "epoch"?, "seq"?,
"body"}`. Request ids and sequence numbers are u64; the epoch is the
Generator's 32-hex incarnation, which every frame this side sends names. A
call's input travels as ONE descriptor passed with SCM_RIGHTS on its
`generate` frame, described by `{"buffer_id", "fd_index": 0, "offset": 0,
"length", "encoding"}`: a sealed memfd on Linux, a read-only POSIX shared
memory object elsewhere. Its descriptor count, type, access, seals and size
are checked against the description exactly; nothing caps its length. v1
takes one encoding, `chat_json` (`{"messages", "tools"?}`): the worker still
renders and tokenizes. Every other request field rides in the frame's
`params` exactly as the HTTP route takes it.

Ops, host to worker, and what each gets back:

- `hello`: `hello`, with the schema, the worker's descriptor (kind, identity,
  build evidence), its model id, epoch, launch manifest digest, capabilities
  and reported versions.
- `generate` (the epoch it expects; `input`; `params`; `stream`; reserved
  `priority`, `deadline`, `work_class`, taken and ignored): `accepted`, or
  `refused` before anything ran; then `first_token`, with `stream` each
  `token` (`phase`, safe `text`), and exactly one terminal: `final`
  (`outcome` done or error, the reply's fields, `usage.inference_calls` as
  the HTTP reply carries it, partial counts on error, cheap stats), or
  `released` once the host cancelled.
- `cancel`: `cancel_ack` (`found`), then the call's `released`, sent only
  after the scheduler thread has cancelled its Job (which frees its pages and
  recurrent slot) and given back its place and reservation. A call that
  already ended gets `found: false` and no second terminal.
- `stats` (`detail`: `full`, the default, or `cheap`): `stats`, taken on the
  scheduler thread (`exl3_stats.py`).
- `drain`: no new call is taken, on either transport; `drained` once every
  accepted call has ended, with no deadline.
- `shutdown`: `shutdown`, then the server stops; what is left fails.

Codec v1.1 adds the session ops (DESIGN-V2 R2, `exl3_session/ops.py`),
advertised as `capabilities.sessions` `{minor: 1, ops}` only when the server
loaded its session layer: `session.create`, `session.fork` and
`session.append` (each with an input region), `session.suffix_commit`,
`session.checkpoint`, `session.drop`, each answered by a frame of its own
name or `refused`; and `session.generate`, a `generate` whose `session`
field names the working branch it runs on, with the same events. A
connection's close cancels its calls, never its sessions: a session lives
until it is dropped, evicted, or the incarnation ends.

A connection that closes cancels its calls. The HTTP routes are untouched.
"""
import array
import ctypes
import ctypes.util
import fcntl
import json
import mmap
import os
import platform
import socket
import stat
import struct
import sys
import threading
import time
import uuid
from importlib import metadata

import cache_usage
import exl3_tools

# The codec this server speaks.
SCHEMA_VERSION = 1
# A frame's length prefix: u64, big-endian.
HEADER_BYTES = 8
# The input encodings v1 reads.
INPUT_ENCODINGS = ("chat_json",)
# The ops a host may send.
OPS = ("hello", "generate", "cancel", "stats", "drain", "shutdown")
# Generate fields v1 takes and does not act on yet (R4 enforces them).
RESERVED_FIELDS = ("priority", "deadline", "work_class")
# Linux's memfd seal ABI (fcntl.h: F_LINUX_SPECIFIC_BASE + 10, F_SEAL_*),
# for a Python built without the names; the kernel's values never change.
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
# Ancillary room per read: a v1 frame carries at most one descriptor; the
# room for more lets a frame that carries more be seen and refused.
FD_ROOM = 8
FD_BYTES = array.array("i").itemsize
# How much one read asks for: a read size, never a cap on a frame.
RECV_CHUNK = 1 << 20
# How long the accept loop pauses after a failed accept, seconds.
ACCEPT_RETRY_S = 0.05
U64_MAX = (1 << 64) - 1


class ProtocolError(Exception):
    """A frame this side cannot read: the connection closes."""


class Refusal(Exception):
    """A call refused before anything ran."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code

    def body(self):
        return {"code": self.code, "message": str(self)}


def is_u64(value):
    return type(value) is int and 0 <= value <= U64_MAX


def is_epoch(value):
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def close_fds(fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
    fds.clear()


_LIBC = None


def peer_uid(sock):
    """The user the peer of `sock` runs as."""
    if sys.platform.startswith("linux"):
        size = struct.calcsize("iII")
        _pid, uid, _gid = struct.unpack("iII", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
        return uid
    global _LIBC
    if _LIBC is None:
        _LIBC = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    if _LIBC.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return uid.value


def bind(path):
    """The listening socket at `path`: its folder this user's alone, a stale
    socket there removed, the socket itself 0600."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    os.chmod(parent, 0o700)
    try:
        if stat.S_ISSOCK(os.lstat(path).st_mode):
            os.unlink(path)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        listener.bind(path)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    listener.listen()
    return listener


def _recv_exact(sock, size, fds, eof_ok=False):
    """`size` bytes from `sock`, keeping every descriptor that rides with
    them in `fds`; None at a clean end before the first byte when
    `eof_ok`."""
    parts = []
    got = 0
    while got < size:
        data, ancdata, flags, _ = sock.recvmsg(min(size - got, RECV_CHUNK), socket.CMSG_SPACE(FD_ROOM * FD_BYTES))
        for level, kind, cdata in ancdata:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = array.array("i")
                received.frombytes(cdata[:len(cdata) - (len(cdata) % FD_BYTES)])
                fds.extend(received)
        if flags & socket.MSG_CTRUNC:
            raise ProtocolError("a frame carried more descriptors than this side reads")
        if not data:
            if eof_ok and got == 0:
                return None
            raise ProtocolError("the stream ended inside a frame")
        parts.append(data)
        got += len(data)
    return b"".join(parts)


def recv_frame(sock):
    """One frame's payload and the descriptors that came with it, or None at
    a clean end of stream."""
    fds = []
    try:
        header = _recv_exact(sock, HEADER_BYTES, fds, eof_ok=True)
        if header is None:
            close_fds(fds)
            return None
        length = int.from_bytes(header, "big")
        payload = _recv_exact(sock, length, fds) if length else b""
    except BaseException:
        close_fds(fds)
        raise
    return payload, fds


def encode_frame(envelope):
    payload = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return len(payload).to_bytes(HEADER_BYTES, "big") + payload


def parse_envelope(payload):
    """A frame's envelope, checked; ProtocolError when it is not one."""
    try:
        envelope = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("a frame is not UTF-8 JSON") from None
    if not isinstance(envelope, dict) or not isinstance(envelope.get("op"), str):
        raise ProtocolError("a frame is not an envelope")
    if not is_u64(envelope.get("request_id")):
        raise ProtocolError("a frame names no u64 request id")
    if envelope.get("epoch") is not None and not is_epoch(envelope["epoch"]):
        raise ProtocolError("a frame's epoch is not 32 hex digits")
    if envelope.get("seq") is not None and not is_u64(envelope["seq"]):
        raise ProtocolError("a frame's seq is not a u64")
    body = envelope.get("body")
    if body is None:
        envelope["body"] = {}
    elif not isinstance(body, dict):
        raise ProtocolError("a frame's body is not an object")
    return envelope


def map_region(fd, offset, length):
    """The `length` bytes at `offset` of the region behind `fd`, once it is
    shown immutable: sealed against write, grow and shrink on Linux, opened
    read-only elsewhere, of a regular kind, and its size what the call
    says."""
    info = os.fstat(fd)
    mode = info.st_mode
    end = offset + length
    if sys.platform.startswith("linux"):
        if not stat.S_ISREG(mode):
            raise Refusal("invalid_input", "the input is not a memory region")
        try:
            seals = fcntl.fcntl(fd, F_GET_SEALS)
        except OSError as error:
            raise Refusal("invalid_input", f"the input region's seals cannot be read: {error}") from error
        needed = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK
        if seals & needed != needed:
            raise Refusal("invalid_input", "the input region is not sealed read-only")
        if info.st_size != end:
            raise Refusal("invalid_input", f"the input region holds {info.st_size} bytes, not {end}")
    else:
        if any(test(mode) for test in (stat.S_ISDIR, stat.S_ISCHR, stat.S_ISBLK, stat.S_ISFIFO, stat.S_ISSOCK,
                                       stat.S_ISLNK)):
            raise Refusal("invalid_input", "the input is not a memory region")
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise Refusal("invalid_input", "the input region is not read-only")
        if info.st_size < end:
            raise Refusal("invalid_input", f"the input region holds {info.st_size} bytes, under {end}")
    with mmap.mmap(fd, length, access=mmap.ACCESS_READ, offset=offset) as view:
        return view[:length]


def read_input(description, fds):
    """A call's conversation from its one input region. Closes every
    descriptor the frame carried, whatever happens."""
    try:
        if not isinstance(description, dict):
            raise Refusal("invalid_input", "the call names no input buffer")
        if len(fds) != 1:
            raise Refusal("invalid_input", f"the call carried {len(fds)} descriptors, not one")
        offset, length = description.get("offset"), description.get("length")
        if not is_u64(description.get("buffer_id")) or description.get("fd_index") != 0 \
                or type(description.get("fd_index")) is not int or offset != 0 or type(offset) is not int:
            raise Refusal("invalid_input", "the input buffer is not one whole region at descriptor 0")
        if not is_u64(length) or length < 1:
            raise Refusal("invalid_input", "the input buffer names no length")
        if description.get("encoding") not in INPUT_ENCODINGS:
            raise Refusal("unsupported_encoding", f"this worker reads {', '.join(INPUT_ENCODINGS)} only")
        data = map_region(fds[0], offset, length)
    except (OSError, ValueError, OverflowError) as error:
        raise Refusal("invalid_input", f"the input region cannot be read: {error}") from None
    finally:
        close_fds(fds)
    try:
        conversation = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("invalid_input", "the input is not UTF-8 JSON") from None
    if not isinstance(conversation, dict) or not isinstance(conversation.get("messages"), list) \
            or set(conversation) - {"messages", "tools"}:
        raise Refusal("invalid_input", "the input is not {messages, tools?}")
    return conversation


def reported_versions():
    """The installed runtime's versions, as its packages report them."""
    versions = {"python": platform.python_version()}
    for name in cache_usage.RUNTIME_DISTRIBUTIONS:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            pass
    return versions


def never():
    return False


class NativeServer:
    """The native socket's listener: one thread accepts, one per connection
    reads, one per call runs it."""

    def __init__(self, path, state):
        self.path = path
        self.state = state
        self.uid = os.geteuid()
        self.listener = None
        self.closed = threading.Event()

    def start(self):
        self.listener = bind(self.path)
        threading.Thread(target=self._accept, name="exl3-native-accept", daemon=True).start()
        print(f"NATIVE_READY schema={SCHEMA_VERSION} epoch={self.state.identity.epoch}", flush=True)

    def _accept(self):
        while not self.closed.is_set():
            try:
                sock, _ = self.listener.accept()
            except OSError:
                if self.closed.is_set():
                    return
                time.sleep(ACCEPT_RETRY_S)
                continue
            try:
                uid = peer_uid(sock)
            except OSError:
                uid = None
            if uid != self.uid:
                print(f"NATIVE_PEER_REFUSED uid={uid}", flush=True)
                sock.close()
                continue
            connection = Connection(self, sock)
            threading.Thread(target=connection.run, name="exl3-native-connection", daemon=True).start()

    def hello(self):
        identity = self.state.identity
        body = {
            "schema": SCHEMA_VERSION,
            "worker": {"kind": "exl3", "identity": identity.record(None),
                       "build_evidence": identity.build_evidence},
            "model": self.state.model_id,
            "epoch": identity.epoch,
            "capabilities": {"ops": list(OPS), "input_encodings": list(INPUT_ENCODINGS), "stream": True,
                             "tool_calls": True, "reserved": list(RESERVED_FIELDS)},
            "versions": reported_versions(),
        }
        if self.state.sessions is not None:
            body["capabilities"]["sessions"] = self.state.sessions.capability()
        if identity.launch_manifest is not None:
            body[cache_usage.LAUNCH_MANIFEST_KEY] = identity.launch_manifest
        return body

    def close(self):
        self.closed.set()
        if self.listener is not None:
            for close in (lambda: self.listener.shutdown(socket.SHUT_RDWR), self.listener.close):
                try:
                    close()
                except OSError:
                    pass
        try:
            if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                os.unlink(self.path)
        except OSError:
            pass


class Connection:
    """One host connection: its reader, and the calls it started."""

    def __init__(self, server, sock):
        self.server = server
        self.state = server.state
        self.sock = sock
        self.write_lock = threading.Lock()
        self.closed = False
        self.lock = threading.Lock()
        self.calls = {}

    def send(self, op, request_id, body, seq=None):
        """Writes one frame, whole; False once the connection is gone. Every
        refusal, error terminal and failed write reaches the log with its
        cause."""
        if op == "refused" or (op == "final" and body.get("outcome") == "error"):
            detail = body if op == "refused" else body.get("error")
            print(f"NATIVE_REPLY_ERROR op={op} request_id={request_id} detail={detail!r}", flush=True)
        envelope = {"v": SCHEMA_VERSION, "op": op, "request_id": request_id,
                    "epoch": self.state.identity.epoch, "body": body}
        if seq is not None:
            envelope["seq"] = seq
        frame = encode_frame(envelope)
        with self.write_lock:
            if self.closed:
                return False
            try:
                self.sock.sendall(frame)
                return True
            except OSError as error:
                print(f"NATIVE_SEND_ERROR op={op} request_id={request_id} {type(error).__name__}: {error}",
                      flush=True)
                self.closed = True
                return False

    def run(self):
        try:
            while True:
                frame = recv_frame(self.sock)
                if frame is None:
                    break
                payload, fds = frame
                try:
                    envelope = parse_envelope(payload)
                except ProtocolError:
                    close_fds(fds)
                    raise
                self.dispatch(envelope, fds)
        except Exception as error:  # a connection that fails closes; the server goes on
            print(f"NATIVE_CONNECTION_CLOSED {type(error).__name__}: {error}", flush=True)
        finally:
            self.close()

    def dispatch(self, envelope, fds):
        op, request_id, body = envelope["op"], envelope["request_id"], envelope["body"]
        version = envelope.get("v")
        if type(version) is not int or version != SCHEMA_VERSION:
            close_fds(fds)
            self.send("refused", request_id, Refusal("unsupported_version",
                                                      f"this worker speaks schema {SCHEMA_VERSION}").body())
            return
        if op == "generate":
            self.generate(envelope, fds)
            return
        sessions = self.state.sessions
        if sessions is not None and op in sessions.capability()["ops"]:
            if op == "session.generate":
                self.generate(envelope, fds, session=True)
            else:
                # A commit or a drop waits on the scheduler, with no
                # deadline: each op runs on a thread of its own.
                threading.Thread(target=self.session_op, args=(envelope, fds), name="exl3-native-session",
                                 daemon=True).start()
            return
        if fds:
            close_fds(fds)
            self.send("refused", request_id, Refusal("invalid_input", f"{op} carries no descriptor").body())
            return
        if op == "hello":
            self.send("hello", request_id, self.server.hello())
        elif op == "cancel":
            self.cancel(request_id)
        elif op == "stats":
            detail = body.get("detail", "full")
            threading.Thread(target=self.stats, args=(request_id, detail), daemon=True).start()
        elif op == "drain":
            threading.Thread(target=self.drain, args=(request_id,), daemon=True).start()
        elif op == "shutdown":
            self.send("shutdown", request_id, {})
            self.state.shutdown()
        else:
            self.send("refused", request_id, Refusal("unknown_op", f"no op {op!r}").body())

    def session_op(self, envelope, fds):
        """One session op other than `session.generate`, answered by a frame
        of its own name or `refused` (exl3_session/ops.py)."""
        op, request_id, body = envelope["op"], envelope["request_id"], envelope["body"]
        sessions = self.state.sessions
        try:
            if envelope.get("epoch") != self.state.identity.epoch:
                raise Refusal("epoch_mismatch", "the op names another incarnation of this worker")
            conversation = None
            if op in sessions.WITH_INPUT:
                conversation = read_input(body.get("input"), fds)
            elif fds:
                raise Refusal("invalid_input", f"{op} carries no descriptor")
            answer = sessions.answer(op, body, conversation)
        except Refusal as refusal:
            close_fds(fds)
            self.send("refused", request_id, refusal.body())
            return
        except sessions.Refused as refused:
            self.send("refused", request_id, Refusal(refused.code, str(refused)).body())
            return
        except Exception as error:
            print(f"NATIVE_SESSION_ERROR op={op} {type(error).__name__}: {error}", flush=True)
            self.send("refused", request_id, Refusal("server_error", f"{type(error).__name__}: {error}").body())
            return
        self.send(op, request_id, answer)

    def generate(self, envelope, fds, session=False):
        """A `generate`, or with `session` a `session.generate`: the same call
        on the working branch its `session` field names."""
        request_id, body = envelope["request_id"], envelope["body"]
        epoch = self.state.identity.epoch
        sessions = self.state.sessions
        branch = None
        try:
            if envelope.get("epoch") != epoch:
                raise Refusal("epoch_mismatch", "the call names another incarnation of this worker")
            params = body.get("params", {})
            if not isinstance(params, dict) or "messages" in params or "tools" in params:
                raise Refusal("invalid_request", "params must be an object without messages or tools")
            stream = body.get("stream", False)
            if not isinstance(stream, bool):
                raise Refusal("invalid_request", "stream must be true or false")
            conversation = read_input(body.get("input"), fds)
            if session:
                try:
                    branch = sessions.claim_call(body.get("session"))
                except sessions.Refused as refused:
                    raise Refusal(refused.code, str(refused)) from None
        except Refusal as refusal:
            close_fds(fds)
            self.send("refused", request_id, refusal.body())
            return
        # Accepted: the first-token time starts here, once the input is in
        # and before it is rendered.
        accepted_ns = time.monotonic_ns()
        with self.lock:
            if request_id in self.calls:
                refusal = Refusal("duplicate_request", "a call with this id is still open on this connection")
            elif not self.state.scheduler.accept():
                refusal = Refusal("draining", "the worker takes no new call")
            else:
                refusal = None
                call = NativeCall(self, request_id, params, conversation, stream, accepted_ns, branch)
                self.calls[request_id] = call
        if refusal is not None:
            if branch is not None:
                # Nothing ran on it: the branch stays open.
                sessions.unclaim(branch)
            self.send("refused", request_id, refusal.body())
            return
        if branch is not None:
            # A drop of its session cancels the call.
            sessions.bind_call(branch, lambda: call.cancel(ack=False))
        call.emit("accepted", {"epoch": epoch})
        threading.Thread(target=call.run, name="exl3-native-call", daemon=True).start()

    def cancel(self, request_id):
        with self.lock:
            call = self.calls.get(request_id)
        if call is None:
            self.send("cancel_ack", request_id, {"found": False})
            return
        call.cancel(ack=True)

    def stats(self, request_id, detail):
        full = detail != "cheap"
        snapshot = self.state.scheduler.snapshot(full)
        if snapshot is None:
            snapshot = {"detail": "full" if full else "cheap", "available": False}
        self.send("stats", request_id, snapshot)

    def drain(self, request_id):
        drained = self.state.scheduler.drain()
        self.send("drained", request_id, {"drained": drained})

    def forget(self, request_id):
        with self.lock:
            self.calls.pop(request_id, None)

    def close(self):
        with self.write_lock:
            self.closed = True
        with self.lock:
            calls = list(self.calls.values())
        # A host that went away takes its calls with it.
        for call in calls:
            call.cancel(ack=False)
        for close in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
            try:
                close()
            except OSError:
                pass


class NativeCall:
    """One `generate`: run on its own thread through the scheduler, its
    events numbered in the order they go out, and exactly one terminal."""

    def __init__(self, connection, request_id, params, conversation, stream, accepted_ns, branch=None):
        self.connection = connection
        self.state = connection.state
        self.request_id = request_id
        self.params = params
        self.conversation = conversation
        self.stream = stream
        self.accepted_ns = accepted_ns
        # A `session.generate`'s working branch (exl3_session), which ends
        # with the call.
        self.branch = branch
        self.lock = threading.Lock()
        self.seq = 0
        self.terminal = False
        self.cancelled = threading.Event()
        self.req = None

    def _send_locked(self, op, body):
        seq = self.seq
        self.seq += 1
        return self.connection.send(op, self.request_id, body, seq)

    def emit(self, op, body):
        """One event before the terminal; nothing after it."""
        with self.lock:
            if not self.terminal:
                self._send_locked(op, body)

    def end(self, op, body):
        """The call's one terminal: `op`, or `released` when the host has
        cancelled it, with `body` either way."""
        with self.lock:
            if self.terminal:
                return
            self.terminal = True
            self._send_locked("released" if self.cancelled.is_set() else op, body)

    def cancel(self, ack):
        """Stops the call wherever it is. With `ack`, the host asked: it gets
        `cancel_ack`, and `released` follows once the call has ended."""
        with self.lock:
            live = not self.terminal
            if live:
                self.cancelled.set()
            if ack:
                self._send_locked("cancel_ack", {"found": live})
        req = self.req
        if live and req is not None:
            self.state.scheduler.cancel(req)

    def _ending(self, outcome, req, extra=None):
        body = {"outcome": outcome}
        if extra:
            body.update(extra)
        if req is not None:
            if req.partial_usage is not None:
                body["usage"] = req.partial_usage
            if req.final_stats is not None:
                body["stats"] = req.final_stats
        return body

    def _failure(self, error, kind, req):
        message = str(error) if kind == "invalid_request_error" else f"{type(error).__name__}: {error}"
        detail = {"message": message, "type": kind}
        if getattr(error, "code", None):
            detail["code"] = error.code
        return self._ending("error", req, {"error": detail})

    def run(self):
        state = self.state
        scheduler = state.scheduler
        req = None
        try:
            body = dict(self.params)
            body["messages"] = self.conversation["messages"]
            if "tools" in self.conversation:
                body["tools"] = self.conversation["tools"]
            model = body.get("model") or state.model_id
            req = state.prepare(body, "native-" + uuid.uuid4().hex, self.accepted_ns)
            if self.branch is not None:
                req.branch = self.branch
                req.shared = state.sessions.shared_pages(self.branch, req.ids)
            self.req = req
            if self.cancelled.is_set():
                self.end("released", {"outcome": "cancelled"})
                return
            splitter = exl3_tools.StreamSplitter(req.tools) if self.stream and req.tools else None
            reasoning, content = [], []

            def on_reasoning(piece):
                reasoning.append(piece)
                if self.stream:
                    self.emit("token", {"phase": "reasoning", "text": piece})

            def on_content(piece):
                content.append(piece)
                if self.stream:
                    out = piece if splitter is None else splitter.feed(piece)
                    if out:
                        self.emit("token", {"phase": "content", "text": out})

            def on_first_token(mark):
                self.emit("first_token", mark)

            scheduler.submit(req, self.cancelled.is_set)
            result = scheduler.wait(req, never, on_reasoning, on_content, on_first_token)
            finish = result["finish_reason"]
            final = {"outcome": "done", "model": model}
            if self.stream:
                tail, calls = splitter.finish(finish == "stop") if splitter is not None else ("", [])
                if tail:
                    final["tail"] = tail
                if calls:
                    final["tool_calls"] = exl3_tools.stream_deltas(calls)
                    finish = "tool_calls"
            else:
                final["message"], finish = exl3_tools.answer_message(reasoning, content, req.tools, finish)
            if finish == "tool_calls":
                # The receipt says so too (FIX 9300).
                cache_usage.mark_tool_calls(result["usage"])
            final["finish_reason"] = finish
            final["usage"] = result["usage"]
            final["timings"] = result["timings"]
            if req.final_stats is not None:
                final["stats"] = req.final_stats
            self.end("final", final)
        except Exception as error:
            # The scheduler's ClientGone is the cancel this call asked for,
            # or its connection's close.
            if isinstance(error, state.client_gone):
                self.end("released", self._ending("cancelled", req))
            elif isinstance(error, (ValueError, KeyError, TypeError)):
                self.end("final", self._failure(error, "invalid_request_error", req))
            else:
                print(f"NATIVE_CALL_ERROR {type(error).__name__}: {error}", flush=True)
                self.end("final", self._failure(error, "server_error", req))
        finally:
            if req is not None and not req.ended:
                scheduler.cancel(req)
            if self.branch is not None and (req is None or not req.queued):
                # The scheduler never had it, so never ends its branch.
                state.sessions.end_branch_later(self.branch)
            scheduler.settle()
            self.connection.forget(self.request_id)
