"""Running the box's own read-only programs: fixed argument lists, no shell, a time bound.

Every program is found on PATH, so a test puts its stand-ins first on PATH.
The environment passed on is the minimum: PATH, HOME and LC_ALL=C. A program
that is missing, times out or fails is an error the calling check turns into
a FAIL; a readback never passes on output it could not read.
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


def read_output(argv: list[str], timeout: int, ok_codes: tuple[int, ...] = (0,)) -> str:
    """The stdout of `argv`, or CommandError."""
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=minimal_env(),
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
    return done.stdout
