"""checker.py ends with its own status while the engine still holds its input
open (CHECKER-STDIN-FINALIZE-ABORT, Engine TASK 15 Nov 19:20).

The engine keeps the helper's stdin open until it has read the done frame, so
when main() returns the input watcher thread is still blocked in its read. A
watcher blocked inside the buffered stdin's read holds that buffer's lock, and
an interpreter that finalizes beside it aborts (SIGABRT, "could not acquire
lock for <_io.BufferedReader name='<stdin>'> at interpreter shutdown"): the
"Python quit unexpectedly" reports on the owner's Mac (Homebrew Python 3.15).

Run with each interpreter under test, never on the Mac:
    python3.15 crates/oneiron-container/guest/checker/test_checker_exit.py
    python3.13 crates/oneiron-container/guest/checker/test_checker_exit.py
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checker.py")


def frame(kind, payload):
    return struct.pack(">I", len(payload) + 1) + kind + payload


def read_frames(stream):
    """Every frame up to and including the done frame, or up to EOF."""
    frames = []
    while True:
        head = stream.read(4)
        if len(head) < 4:
            return frames
        (length,) = struct.unpack(">I", head)
        body = stream.read(length)
        frames.append((body[:1], body[1:]))
        if body[:1] == b"D":
            return frames


class CheckerExitWithInputOpen(unittest.TestCase):
    def run_checker(self, commands):
        """The helper's frames, exit status and stderr for one check of an
        empty tree, its input held open until it has exited."""
        with tempfile.TemporaryDirectory() as scratch:
            header = {
                "version": 1,
                "scratch": os.path.join(scratch, "work"),
                "commands": commands,
                "contract_outputs": [],
            }
            child = subprocess.Popen(
                [sys.executable, CHECKER],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                child.stdin.write(frame(b"H", json.dumps(header).encode()))
                child.stdin.write(frame(b"E", b""))
                child.stdin.flush()
                frames = read_frames(child.stdout)
                # The input stays open, as the engine holds it, until the
                # helper has exited by itself.
                status = child.wait(timeout=60)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdin.close()
            stderr = child.stderr.read()
            child.stdout.close()
            child.stderr.close()
        return frames, status, stderr

    def assert_clean_exit(self, frames, status, stderr):
        self.assertTrue(frames, "the helper wrote no frame")
        self.assertEqual(frames[-1][0], b"D", f"the helper never sent its done frame: {frames!r}")
        self.assertNotIn(b"Fatal Python error", stderr, stderr.decode(errors="replace"))
        self.assertEqual(
            status,
            0,
            f"the helper did not exit 0 with its input open (status {status}; "
            f"-6 is SIGABRT): {stderr.decode(errors='replace')}",
        )

    def test_a_check_with_no_commands_exits_zero_while_its_input_is_open(self):
        frames, status, stderr = self.run_checker([])
        self.assert_clean_exit(frames, status, stderr)
        self.assertEqual(json.loads(frames[-1][1]), {"red": False})

    def test_a_check_whose_command_ran_exits_zero_while_its_input_is_open(self):
        command = {"argv": [sys.executable, "-c", "print('owen')"], "env": {}}
        frames, status, stderr = self.run_checker([command])
        self.assert_clean_exit(frames, status, stderr)
        results = [json.loads(payload) for kind, payload in frames if kind == b"R"]
        self.assertEqual([result["status"] for result in results], [0], f"{results!r}")
        stdouts = [payload for kind, payload in frames if kind == b"O"]
        self.assertEqual(stdouts, [b"owen\n"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
