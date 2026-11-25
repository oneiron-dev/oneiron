"""The harness's one way into Oneiron: the built `oneiron api ... call <verb> --data -`.

The request body goes on stdin, never in argv, and nothing is evaluated as
shell text. The credential stays in the two environment variables the
issuer's configuration names (`oneiron api` reads them itself; see
crates/oneiron-server/src/commands/api.rs); no other variable of the caller
reaches the child, so no ssh agent, forward or proxy setting can carry the
call somewhere else. An issuer URL whose host connects to this box is refused
unless this box serves the issuer itself (`issuer.loopback_allowed`): on any
other box it would be a forward (rack.addresses judges the host).

curl's own lookup of the host could answer differently from the check's, so
the call holds curl to the addresses the check judged. `oneiron api` starts
`curl` from PATH; the harness puts a curl of its own first on that PATH, in
the call's private directory, which starts the real curl with `--resolve
<host>:<port>:<judged addresses>` (keeping `-q` first, where curl honours
it). It marks that it ran; a call that answered with no mark was not held to
the judged address, and fails. A host that is an address literal needs no
lookup and no pin.

The call runs in a process group of its own, with a private TMPDIR, where
`oneiron api` stages the request body. At the deadline the whole group is
killed (oneiron and its curl, which has no transfer deadline of its own),
and the directory goes with the staged body.
"""

from __future__ import annotations

import errno
import json
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from rack.addresses import AddressError, Target, resolve_target
from rack.commands import minimal_env
from rack.evidence import redact
from rack.rack_config import RackConfig


class ApiError(Exception):
    """A verb call that did not answer with its output.

    `code` is the facade error's code (`FORBIDDEN`, `CHECK_IN_PENDING`, ...)
    when the server answered one, and `error` its whole error object.
    """

    def __init__(self, verb: str, why: str, code: str = "", error: dict | None = None):
        super().__init__(f"{verb}: {why}")
        self.verb = verb
        self.why = why
        self.code = code
        self.error = error or {}


def _error_of(answer: Any) -> dict | None:
    """The facade error object of an answer, if it is one: `{"error": {"code": ...}}`."""
    if isinstance(answer, dict) and isinstance(answer.get("error"), dict) and "code" in answer["error"]:
        return answer["error"]
    return None


def _raise_for(verb: str, error: dict, status: str) -> None:
    code = str(error.get("code", ""))
    message = redact(str(error.get("message", "")))[:200]
    raise ApiError(verb, f"{status}{code}: {message}", code=code, error=error)


# After the deadline, how long the killed group may take to close its pipes.
REAP_SECS = 5


def _kill_group(leader: subprocess.Popen) -> None:
    """SIGKILL the leader's process group while the leader is unreaped (so its id is not reused)."""
    try:
        os.killpg(leader.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# The mark the harness's curl leaves in the call's directory when it ran.
PIN_MARK = "curl-pinned"


def _write_curl_pin(staging: Path, real_curl: str, target: Target) -> Path:
    """The call's own `curl`: the real one with `--resolve` to the judged addresses, `-q` still first."""
    bin_dir = staging / "bin"
    bin_dir.mkdir(mode=0o700)
    shim = bin_dir / "curl"
    shim.write_text(
        "#!/bin/sh\n"
        "# The rack harness's curl: it connects only to the addresses the harness judged.\n"
        '[ "$1" = "-q" ] || { echo "rack: curl was not started with -q first" >&2; exit 2; }\n'
        "shift\n"
        f": > {shlex.quote(str(staging / PIN_MARK))}\n"
        f'exec {shlex.quote(real_curl)} -q --resolve {shlex.quote(target.curl_resolve())} "$@"\n'
    )
    shim.chmod(0o700)
    return bin_dir


def _run_bounded(
    argv: list[str], data: bytes, timeout: int, env: dict[str, str], pin: Target | None
) -> tuple[int, bytes, bytes, bool]:
    """(exit, stdout, stderr, pinned) of `argv` in its own group with a private TMPDIR; TimeoutExpired past `timeout`.

    With `pin`, curl on the child's PATH is the harness's own (`pinned`: it ran).
    """
    staging = Path(tempfile.mkdtemp(prefix="oneiron-rack-api-"))
    try:
        child_env = {**env, "TMPDIR": str(staging)}
        if pin is not None:
            real_curl = shutil.which("curl", path=env.get("PATH", ""))
            if real_curl is None:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), "curl")
            bin_dir = _write_curl_pin(staging, os.path.abspath(real_curl), pin)
            child_env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
        child = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            start_new_session=True,
        )
        try:
            out, err = child.communicate(data, timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(child)
            try:
                child.communicate(timeout=REAP_SECS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            raise
        return child.returncode, out, err, (staging / PIN_MARK).exists()
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def call(config: RackConfig, host: str, verb: str, body: dict[str, Any], hold_secs: int = 0) -> Any:
    """The verb's answer as JSON. `hold_secs` is how long the server may hold the call."""
    issuer = config.issuer(host)
    url = issuer["base_url"]
    if not url:
        raise ApiError(verb, "no issuer.base_url for this host")
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ApiError(verb, "issuer.base_url is not http or https")
    pin: Target | None = None
    if not issuer["loopback_allowed"]:
        try:
            target = resolve_target(url)
        except AddressError as error:
            raise ApiError(verb, f"issuer.base_url: {error}") from None
        if target.local:
            raise ApiError(verb, "issuer.base_url is a loopback or local address on a box that does not serve the issuer")
        if not target.literal:
            pin = target
    passed = {
        name: os.environ[name]
        for name in (issuer["secret_env"], issuer["binding_key_env"])
        if name in os.environ
    }
    argv = [
        config.oneiron_bin,
        "api",
        "--base-url",
        url,
        "--secret-env",
        issuer["secret_env"],
        "--binding-key-env",
        issuer["binding_key_env"],
        "call",
        verb,
        "--data",
        "-",
    ]
    timeout = config.command_timeout_secs + hold_secs
    try:
        returncode, stdout, stderr, pinned = _run_bounded(argv, json.dumps(body).encode(), timeout, minimal_env(passed), pin)
    except FileNotFoundError as error:
        raise ApiError(verb, f"{error.filename or config.oneiron_bin} not installed") from None
    except subprocess.TimeoutExpired:
        raise ApiError(verb, f"no answer in {timeout} s") from None
    if pin is not None and returncode == 0 and not pinned:
        raise ApiError(verb, "the call did not go through the harness's curl, so it was not held to the checked address")
    # The facade answers the verb's output bare, or {"error": {...}}. curl fails a 4xx/5xx
    # with the body on stdout; a 202 (a pin that waits for a check-in) exits 0 with an error.
    text = stdout.decode("utf-8", errors="replace")
    try:
        answer = json.loads(text)
    except json.JSONDecodeError:
        answer = None
    error = _error_of(answer)
    if returncode != 0:
        if error is not None:
            _raise_for(verb, error, f"exit {returncode} ")
        detail = redact((text or stderr.decode("utf-8", errors="replace")).strip())[:300]
        raise ApiError(verb, f"exit {returncode}: {detail}")
    if error is not None:
        _raise_for(verb, error, "")
    if answer is None:
        raise ApiError(verb, "the answer is not JSON")
    return answer
