"""Running the box's own read-only programs: fixed argument lists, no shell, a time bound.

Every program is found on PATH, so a test puts its stand-ins first on PATH.
The environment passed on is the minimum: PATH, HOME and LC_ALL=C, plus only
the variables one reader names (`systemctl --user` needs the user's bus). A
program that is missing, times out or fails is an error the calling check
turns into a FAIL; a readback never passes on output it could not read.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass
class CommandError(Exception):
    """A read-only program that did not answer."""

    program: str
    why: str

    def __str__(self) -> str:
        return f"{self.program}: {self.why}"


def minimal_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/"),
        "LC_ALL": "C",
    }
    if extra:
        env.update(extra)
    return env


def read_output(
    argv: list[str],
    timeout: int,
    ok_codes: tuple[int, ...] = (0,),
    extra_env: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> str:
    """The stdout of `argv`, or CommandError. `extra_env` adds to the minimal environment; `env`
    replaces it whole (for a program that must see another process's environment)."""
    return read_streams(argv, timeout, ok_codes, extra_env, env, cwd)[0]


def read_streams(
    argv: list[str],
    timeout: int,
    ok_codes: tuple[int, ...] = (0,),
    extra_env: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[str, str]:
    """(stdout, stderr) of `argv`, or CommandError, as `read_output` runs it."""
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=minimal_env(extra_env) if env is None else env,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise CommandError(argv[0], "not installed") from None
    except subprocess.TimeoutExpired:
        raise CommandError(argv[0], f"no answer in {timeout} s") from None
    except OSError as error:
        raise CommandError(argv[0], error.strerror or "not started") from None
    if done.returncode not in ok_codes:
        raise CommandError(argv[0], f"exit {done.returncode}")
    return done.stdout, done.stderr
