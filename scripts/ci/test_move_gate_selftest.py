"""Run the refactor move gate's synthetic self-test in CI, so a regression in
the move-equivalence checks fails the build (security fix H137: the gate takes
no string rewrite as a move)."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SELFTEST = Path(__file__).resolve().parents[1] / "refactor" / "tools" / "v2_selftest.py"


class MoveGateSelfTest(unittest.TestCase):
    def test_move_gate_selftest_passes(self):
        # The self-test writes its synthetic manifests with mkdtemp and never
        # removes them; a private TMPDIR keeps them off the runner.
        with tempfile.TemporaryDirectory(prefix="oneiron-move-gate-") as scratch:
            env = dict(os.environ, TMPDIR=scratch, PYTHONDONTWRITEBYTECODE="1")
            run = subprocess.run(
                [sys.executable, str(SELFTEST)],
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
            )
        report = run.stdout + run.stderr
        self.assertEqual(run.returncode, 0, report)
        self.assertIn("RESULT: PASS", run.stdout, report)


if __name__ == "__main__":
    unittest.main()
