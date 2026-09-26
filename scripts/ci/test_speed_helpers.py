"""Exercise the CI compiler wrapper and temp selection with disposable stubs."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


class SpeedHelperTests(unittest.TestCase):
    def test_wrapper_scopes_flag_opt_out_and_retries_exit_101(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            compiler = root / "fake-rustc"
            record = root / "calls.jsonl"
            compiler.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "with pathlib.Path(os.environ['RECORD']).open('a') as stream:\n"
                "    stream.write(json.dumps([args, os.environ.get('RUSTC_BOOTSTRAP')]) + '\\n')\n"
                "sys.exit(101 if '-Zthreads=8' in args and os.environ.get('FAIL_PARALLEL') else 0)\n"
            )
            compiler.chmod(0o755)
            env = os.environ | {"RECORD": str(record), "FAIL_PARALLEL": "1"}
            wrapper = ROOT / "rustc-threads.sh"
            for name, opt_out, expected in (("dependency", False, 1), ("oneiron", True, 1), ("oneiron", False, 2)):
                record.unlink(missing_ok=True)
                result = subprocess.run([str(wrapper), str(compiler), "--crate-name", name],
                                        env=env | ({"ONEIRON_PARALLEL_FRONTEND": "0"} if opt_out else {}),
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in record.read_text().splitlines()]
                self.assertEqual(len(calls), expected)
                self.assertNotIn("-Zthreads=8", calls[-1][0])
                if expected == 2:
                    self.assertIn("-Zthreads=8", calls[0][0])
                    self.assertEqual(calls[0][1], "oneiron")
                    self.assertIn("compiling it again", result.stderr)

    def test_tmpfs_threshold_fallback_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / "tools"
            tools.mkdir()
            for name, body in {
                "df": "print('Filesystem 1024-blocks Used Available Capacity Mounted on')\n"
                      "print('/dev/shm 20000000 0 ' + os.environ['FAKE_AVAILABLE'] + ' 0% /dev/shm')\n",
                "mktemp": "print(tempfile.mkdtemp(prefix='ci-test-', dir=os.environ['FAKE_ROOT']))\n",
            }.items():
                imports = "import os, tempfile\n"
                stub = tools / name
                stub.write_text(f"#!{sys.executable}\n" + imports + body)
                stub.chmod(0o755)
            disk = root / "disk"
            disk.mkdir()
            output = root / "observed.json"
            command = [sys.executable, "-c",
                       "import json,os,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(os.environ.get('TMPDIR'))); sys.exit(int(sys.argv[2]))",
                       str(output)]
            script = ROOT / "with-test-tmpdir.sh"
            for available, code in ((str(12 * 1024 * 1024 - 1), 0), (str(12 * 1024 * 1024), 7)):
                result = subprocess.run([str(script), *command, str(code)],
                    env=os.environ | {"PATH": f"{tools}:{os.environ['PATH']}",
                                      "FAKE_AVAILABLE": available, "FAKE_ROOT": str(root),
                                      "TMPDIR": str(disk), "RUNNER_NAME": "test runner"},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                used = Path(json.loads(output.read_text()))
                if code == 0:
                    self.assertEqual(used, disk)
                else:
                    self.assertNotEqual(used, disk)
                    self.assertFalse(used.exists(), "step temp must be removed on failure")


if __name__ == "__main__":
    unittest.main()
