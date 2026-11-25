"""The harness's one way into Oneiron: the built `oneiron api ... call <verb> --data -`.

The request body goes on stdin, never in argv, and nothing is evaluated as
shell text. The credential stays in the two environment variables the
issuer's configuration names (`oneiron api` reads them itself; see
crates/oneiron-server/src/commands/api.rs); no other variable of the caller
reaches the child, so no ssh agent, forward or proxy setting can carry the
call somewhere else. A loopback issuer URL is refused unless this box serves
the issuer itself (`issuer.loopback_allowed`): on any other box it would be
a forward.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
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


def loopback(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def call(config: RackConfig, host: str, verb: str, body: dict[str, Any], hold_secs: int = 0) -> Any:
    """The verb's answer as JSON. `hold_secs` is how long the server may hold the call."""
    issuer = config.issuer(host)
    url = issuer["base_url"]
    if not url:
        raise ApiError(verb, "no issuer.base_url for this host")
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ApiError(verb, "issuer.base_url is not http or https")
    if loopback(url) and not issuer["loopback_allowed"]:
        raise ApiError(verb, "issuer.base_url is a loopback address on a box that does not serve the issuer")
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
        done = subprocess.run(
            argv,
            input=json.dumps(body).encode(),
            capture_output=True,
            timeout=timeout,
            env=minimal_env(passed),
        )
    except FileNotFoundError:
        raise ApiError(verb, f"{config.oneiron_bin} not installed") from None
    except subprocess.TimeoutExpired:
        raise ApiError(verb, f"no answer in {timeout} s") from None
    # The facade answers the verb's output bare, or {"error": {...}}. curl fails a 4xx/5xx
    # with the body on stdout; a 202 (a pin that waits for a check-in) exits 0 with an error.
    text = done.stdout.decode("utf-8", errors="replace")
    try:
        answer = json.loads(text)
    except json.JSONDecodeError:
        answer = None
    error = _error_of(answer)
    if done.returncode != 0:
        if error is not None:
            _raise_for(verb, error, f"exit {done.returncode} ")
        detail = redact((text or done.stderr.decode("utf-8", errors="replace")).strip())[:300]
        raise ApiError(verb, f"exit {done.returncode}: {detail}")
    if error is not None:
        _raise_for(verb, error, "")
    if answer is None:
        raise ApiError(verb, "the answer is not JSON")
    return answer
