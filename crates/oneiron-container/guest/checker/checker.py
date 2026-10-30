#!/usr/bin/python3
"""The merge queue checker's trusted helper (FIX 6868).

Installed root-owned as /usr/local/bin/oneiron-queue-check in the checker
image, or run as a host child on the operator's explicit opt-in. It speaks
the engine's framed protocol on stdin/stdout
(crates/oneiron-server/src/server/merge_queue_checker/tree.rs):

  in:  H header (JSON), G Git objects, F file frames, E end
  out: per command R result (JSON), O stdout, X stderr, U declared outputs;
       then I digests, D done

A frame is a 4-byte big-endian length, a kind byte and its payload; the
length counts the kind byte. The helper materializes the pinned tree into a
private scratch copy, runs each phase command with exactly its argv and
environment (nothing inherited), stops the phase at the first nonzero exit,
then runs every contract-output command, and reports each child's actual
exit status or signal with its output on frames of their own, and each
output file the command declared that it left (FIX 7235). A child's stdout
is data, never protocol. Input digests are taken over the materialized
files before and after the commands. When the engine sends the pinned
commit's commit and tree objects, the files sit in a fresh local-only Git
object store whose HEAD is that commit, a shallow boundary with no remote,
hooks or index (FIX 7228). It installs nothing, fetches nothing and adds no
command. Its stdin closing ends it and its running child.
"""

import hashlib
import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import zlib

# The image's dependency store, preseeded from the baseline lockfile; copied
# into a command's scratch CARGO_HOME before it runs (README.md).
PRESEEDED_CARGO_HOME = "/opt/queue-check/cargo-home"

FRAME_HEADER = b"H"
FRAME_FILE = b"F"
FRAME_END = b"E"
FRAME_RESULT = b"R"
FRAME_STDOUT = b"O"
FRAME_STDERR = b"X"
FRAME_INPUTS = b"I"
FRAME_DONE = b"D"
FRAME_GIT = b"G"
FRAME_OUTPUT = b"U"

MODE_SYMLINK = 0o120000
MODE_EXECUTABLE = 0o100755
MODE_REGULAR = 0o100644

_out = sys.stdout.buffer
_in = sys.stdin.buffer
_out_lock = threading.Lock()
_running = {"child": None}


def read_exact(count):
    data = bytearray()
    while len(data) < count:
        chunk = _in.read(count - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def read_frame():
    head = read_exact(4)
    if head is None:
        return None
    (length,) = struct.unpack(">I", head)
    if length == 0:
        raise ValueError("a check frame has no kind")
    body = read_exact(length)
    if body is None:
        return None
    return body[:1], body[1:]


def write_frame(kind, payload):
    with _out_lock:
        _out.write(struct.pack(">I", len(payload) + 1))
        _out.write(kind)
        _out.write(payload)
        _out.flush()


def safe_join(root, path):
    """`path` under `root`, refusing absolute, `..` and `.git` components."""
    parts = path.split(b"/")
    if not path or any(part in (b"", b".", b"..") for part in parts):
        raise ValueError("a tree path is not a normal relative path")
    if any(part.lower() == b".git" for part in parts):
        raise ValueError("a tree path names git administration")
    return os.path.join(root, *parts)


def materialize(root, frame, git_dir):
    (path_length,) = struct.unpack(">I", frame[:4])
    path = frame[4 : 4 + path_length]
    (mode,) = struct.unpack(">I", frame[4 + path_length : 8 + path_length])
    content = frame[8 + path_length :]
    target = safe_join(root, path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if mode == MODE_SYMLINK:
        os.symlink(content, target)
    else:
        with open(target, "wb") as handle:
            handle.write(content)
        os.chmod(target, 0o755 if mode & 0o111 else 0o644)
    if git_dir is not None:
        write_object(git_dir, b"blob", content)
    return path


def write_object(git_dir, kind, content):
    """One loose object of the local-only store, named by its own id."""
    raw = kind + b" " + str(len(content)).encode() + b"\0" + content
    oid = hashlib.sha1(raw).hexdigest()
    folder = os.path.join(git_dir, "objects", oid[:2])
    os.makedirs(folder, exist_ok=True)
    target = os.path.join(folder, oid[2:])
    if not os.path.exists(target):
        with open(target, "wb") as handle:
            handle.write(zlib.compress(raw))
    return oid


def init_object_store(root, commit):
    """A fresh local-only object store beside the pinned files (FIX 7228):
    HEAD names the pinned commit on a branch of its own, behind a shallow
    boundary; no remote, hook or index."""
    git_dir = os.path.join(root, ".git")
    for folder in ("objects", os.path.join("refs", "heads"), os.path.join("refs", "tags")):
        os.makedirs(os.path.join(git_dir, folder), exist_ok=True)
    with open(os.path.join(git_dir, "HEAD"), "w") as handle:
        handle.write("ref: refs/heads/queue-check\n")
    with open(os.path.join(git_dir, "refs", "heads", "queue-check"), "w") as handle:
        handle.write(commit + "\n")
    with open(os.path.join(git_dir, "shallow"), "w") as handle:
        handle.write(commit + "\n")
    with open(os.path.join(git_dir, "config"), "w") as handle:
        handle.write("[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
    return git_dir


def report_outputs(root, command):
    """Each declared output file the command left, its path and bytes; a
    declared path it did not leave as a regular file is not reported."""
    for declared in command.get("declared_outputs", []):
        path = os.fsencode(declared)
        try:
            target = safe_join(root, path)
            info = os.lstat(target)
        except (ValueError, OSError):
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        with open(target, "rb") as handle:
            content = handle.read()
        write_frame(FRAME_OUTPUT, struct.pack(">I", len(path)) + path + content)


def observe(root, paths):
    """sha256 over every listed file in path order: its path length, path,
    mode and content sha256, the engine's own tree digest."""
    digest = hashlib.sha256()
    for path in sorted(paths):
        target = os.path.join(root, *path.split(b"/"))
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            mode, content = 0, b""
        else:
            if stat.S_ISLNK(info.st_mode):
                mode, content = MODE_SYMLINK, os.fsencode(os.readlink(target))
            elif stat.S_ISREG(info.st_mode):
                mode = MODE_EXECUTABLE if info.st_mode & stat.S_IXUSR else MODE_REGULAR
                with open(target, "rb") as handle:
                    content = handle.read()
            else:
                mode, content = 0, b""
        digest.update(struct.pack(">I", len(path)))
        digest.update(path)
        digest.update(struct.pack(">I", mode))
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def stage_scratch_dirs(scratch, env):
    """Creates the scratch directories a command's environment names under
    the scratch root, and seeds its CARGO_HOME from the image's store."""
    for key in ("HOME", "CARGO_HOME", "CARGO_TARGET_DIR", "TMPDIR"):
        value = env.get(key)
        if not value or not os.path.abspath(value).startswith(scratch + os.sep):
            continue
        if key == "CARGO_HOME" and not os.path.exists(value):
            if os.path.isdir(PRESEEDED_CARGO_HOME):
                shutil.copytree(PRESEEDED_CARGO_HOME, value, symlinks=True)
                continue
        os.makedirs(value, exist_ok=True)


def run(command, cwd, scratch):
    """One child with exactly its argv and environment: its terminal status
    and output, or the program the environment lacks."""
    env = {str(key): str(value) for key, value in command["env"].items()}
    stage_scratch_dirs(scratch, env)
    try:
        child = subprocess.Popen(
            command["argv"],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (FileNotFoundError, PermissionError, NotADirectoryError) as error:
        missing = "program {} is not available offline: {}".format(
            command["argv"][0], error.strerror or "not found"
        )
        return None, None, b"", b"", missing
    _running["child"] = child
    stdout, stderr = child.communicate()
    _running["child"] = None
    code = child.returncode
    if code < 0:
        return None, -code, stdout, stderr, None
    return code, None, stdout, stderr, None


def report(kind, index, name, result):
    status, sig, stdout, stderr, missing = result
    meta = {"kind": kind, "status": status, "signal": sig, "missing": missing}
    if index is not None:
        meta["index"] = index
    if name is not None:
        meta["name"] = name
    write_frame(FRAME_RESULT, json.dumps(meta).encode())
    write_frame(FRAME_STDOUT, stdout)
    write_frame(FRAME_STDERR, stderr)


def watch_input():
    """The engine closing this helper's input ends it and its child."""
    while _in.read(65536):
        pass
    child = _running["child"]
    if child is not None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except OSError:
            pass
    os._exit(3)


def main():
    first = read_frame()
    if first is None or first[0] != FRAME_HEADER:
        return 2
    header = json.loads(first[1])
    if header.get("version") != 1:
        return 2
    scratch = os.path.abspath(header["scratch"])
    shutil.rmtree(scratch, ignore_errors=True)
    source = os.path.join(scratch, "src")
    os.makedirs(source)
    commit = header.get("commit")
    git_dir = None
    paths = []
    while True:
        frame = read_frame()
        if frame is None:
            return 3
        kind, payload = frame
        if kind == FRAME_END:
            break
        if kind == FRAME_GIT and commit:
            if git_dir is None:
                git_dir = init_object_store(source, commit)
            object_kind, _, content = payload.partition(b" ")
            if object_kind not in (b"commit", b"tree"):
                return 2
            write_object(git_dir, object_kind, content)
            continue
        if kind != FRAME_FILE:
            return 2
        paths.append(materialize(source, payload, git_dir))
    threading.Thread(target=watch_input, daemon=True).start()
    before = observe(source, paths)
    red = False
    for index, command in enumerate(header["commands"]):
        result = run(command, source, scratch)
        report("phase", index, None, result)
        report_outputs(source, command)
        if result[0] != 0:
            red = True
            break
    for command in header["contract_outputs"]:
        report("contract", None, command["name"], run(command, source, scratch))
        report_outputs(source, command)
    after = observe(source, paths)
    write_frame(FRAME_INPUTS, json.dumps({"before": before, "after": after}).encode())
    write_frame(FRAME_DONE, json.dumps({"red": red}).encode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
