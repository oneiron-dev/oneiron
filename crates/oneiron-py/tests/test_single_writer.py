"""Single-writer ownership (ONE-1441 I8, §Test/Single-writer).

Exclusion is a property BETWEEN processes, so it is tested with real ones. A
same-process test could only prove the registry shares a handle, which is the
opposite behaviour.
"""

import json
import os
import subprocess
import sys
import textwrap
import time

import pytest

from oneiron import Oneiron, OneironError

OWNER = """
import sys, time
from oneiron import Oneiron
# Keep the client alive: dropping the last handle releases the writer lease.
memory = Oneiron.open(sys.argv[1])
open(sys.argv[2], "w").write("ready")
time.sleep(120)
"""

SECOND = """
import json, sys
from oneiron import Oneiron, OneironError
try:
    Oneiron.open(sys.argv[1])
    print(json.dumps({"code": "NO_ERROR", "suggestions": []}))
except OneironError as error:
    print(json.dumps({"code": error.code, "suggestions": list(error.suggestions)}))
"""


def run(source: str, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(source), *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return result.stdout


def test_second_process_is_refused_and_reopen_succeeds_after_exit(tmp_path) -> None:
    vault = str(tmp_path / "vault")
    marker = str(tmp_path / "ready")

    owner = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(OWNER), vault, marker]
    )
    try:
        deadline = time.time() + 60
        while not os.path.exists(marker) and time.time() < deadline:
            time.sleep(0.05)
        assert os.path.exists(marker), "the owning process never took the lease"

        payload = json.loads(run(SECOND, vault).strip().splitlines()[-1])
        assert payload["code"] == "VAULT_LOCKED_SINGLE_WRITER"
        assert "connect" in " ".join(payload["suggestions"])
    finally:
        owner.kill()
        owner.wait(timeout=30)

    # The pidfile is deliberately left in place: its contents carry no
    # authority, so a reopen after the owner exits must succeed anyway.
    assert os.path.exists(os.path.join(vault, "oneiron.writer.lock"))
    Oneiron.open(vault)


def test_two_opens_in_one_process_share_the_vault(tmp_path) -> None:
    vault = tmp_path / "vault"
    first = Oneiron.open(vault)
    second = Oneiron.open(vault)
    assert isinstance(first.receipts(1), list)
    assert isinstance(second.receipts(1), list)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is Unix-only")
def test_forked_child_fails_closed_while_parent_keeps_working(tmp_path) -> None:
    memory = Oneiron.open(tmp_path / "vault")

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: holds an INHERITED lease it never acquired
        os.close(read_fd)
        try:
            memory.receipts(1)
            os.write(write_fd, b"NO_ERROR")
        except OneironError as error:
            os.write(write_fd, error.code.encode())
        finally:
            os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    child_code = os.read(read_fd, 128).decode()
    os.close(read_fd)
    os.waitpid(pid, 0)

    assert child_code == "VAULT_LOCKED_SINGLE_WRITER"
    # The parent acquired the lease and must be unaffected by the child's
    # refusal.
    assert isinstance(memory.receipts(1), list)
