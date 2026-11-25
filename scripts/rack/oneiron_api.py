"""The harness's one way into Oneiron: the built `oneiron api ... call <verb> --data -`.

The request body goes on stdin, never in argv, and nothing is evaluated as
shell text. The credential stays in the two environment variables the
issuer's configuration names (`oneiron api` reads them itself; see
crates/oneiron-server/src/commands/api.rs); no other variable of the caller
reaches the child, so no ssh agent, forward or proxy setting can carry the
call somewhere else. An issuer URL whose host connects to this box (a
loopback or unspecified address in any spelling curl accepts, such as
`127.1`, or an address of the box's own) is refused unless this box serves
the issuer itself (`issuer.loopback_allowed`): on any other box it would be
a forward. The host is resolved as curl resolves it, and the URL is refused
when any of its addresses is local.

The call runs in a process group of its own, with a private TMPDIR, where
`oneiron api` stages the request body. At the deadline the whole group is
killed (oneiron and its curl, which has no transfer deadline of its own),
and the directory goes with the staged body.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import urllib.parse
from typing import Any

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


class AddressError(Exception):
    """A URL whose host cannot be resolved, or whose address cannot be judged."""


def _address_is_local(sockaddr: tuple) -> bool:
    """Whether a connect to this address reaches this box.

    Loopback and unspecified addresses do, in any spelling (an IPv4-mapped
    one too). Any other address is local when a socket can bind to it, which
    sends nothing; an answer other than "not an address here" counts as local.
    """
    ip = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return True
    family = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
    except OSError:
        return True
    with probe:
        try:
            probe.bind((sockaddr[0], 0, *sockaddr[2:]))
        except OSError as error:
            return error.errno != errno.EADDRNOTAVAIL
    return True


def local_target(url: str) -> bool:
    """Whether a request to `url` would connect to this box (AddressError when it cannot be told)."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if not host:
        raise AddressError("the URL names no host")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise AddressError("the URL's port is not a number") from None
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise AddressError("the URL's host does not resolve") from None
    if not answers:
        raise AddressError("the URL's host does not resolve")
    return any(_address_is_local(sockaddr) for *_, sockaddr in answers)


def _kill_group(leader: subprocess.Popen) -> None:
    """SIGKILL the leader's process group while the leader is unreaped (so its id is not reused)."""
    try:
        os.killpg(leader.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _run_bounded(argv: list[str], data: bytes, timeout: int, env: dict[str, str]) -> tuple[int, bytes, bytes]:
    """(exit, stdout, stderr) of `argv` in its own group with a private TMPDIR; TimeoutExpired past `timeout`."""
    staging = tempfile.mkdtemp(prefix="oneiron-rack-api-")
    try:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**env, "TMPDIR": staging},
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
        return child.returncode, out, err
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
    if not issuer["loopback_allowed"]:
        try:
            local = local_target(url)
        except AddressError as error:
            raise ApiError(verb, f"issuer.base_url: {error}") from None
        if local:
            raise ApiError(verb, "issuer.base_url is a loopback or local address on a box that does not serve the issuer")
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
        returncode, stdout, stderr = _run_bounded(argv, json.dumps(body).encode(), timeout, minimal_env(passed))
    except FileNotFoundError:
        raise ApiError(verb, f"{config.oneiron_bin} not installed") from None
    except subprocess.TimeoutExpired:
        raise ApiError(verb, f"no answer in {timeout} s") from None
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
