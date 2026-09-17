"""Exercise verify CLI and gate contracts without compiling Rust.

Run with: python3 -m unittest discover -s scripts/tests -p test_verify.py -v
The scripts run in a fixture checkout with recording Cargo/codemap executables.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RECORDER = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

if Path(sys.argv[0]).name == "uname":
    print(os.environ["VERIFY_TEST_OS"])
    sys.exit(0)
log = Path(os.environ["VERIFY_TEST_LOG"])
command = ["codemap"] if Path(sys.argv[0]).name == "check.sh" else ["cargo", *sys.argv[1:]]
record = {
    "command": command,
    "rustdocflags": os.environ.get("RUSTDOCFLAGS"),
    "encoded_rustdocflags": os.environ.get("CARGO_ENCODED_RUSTDOCFLAGS"),
}
with log.open("a") as stream:
    stream.write(json.dumps(record) + "\n")
if len(log.read_text().splitlines()) == int(os.environ.get("VERIFY_TEST_FAIL_CALL", "0")):
    print(os.environ.get("VERIFY_TEST_OUTPUT", "fixture failure"), file=sys.stderr)
    sys.exit(int(os.environ.get("VERIFY_TEST_EXIT", "1")))
print("PASS error::tests::fixture")
"""


GATES = [
    ("codemap", ["scripts/codemap/check.sh"]),
    ("fmt", ["cargo", "fmt", "--check"]),
    ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
    ("clippy-featureless", ["cargo", "clippy", "-p", "oneiron", "--all-targets", "--no-default-features", "--", "-D", "warnings"]),
    ("clippy-server", ["cargo", "clippy", "-p", "oneiron-server", "--all-features", "--", "-D", "warnings"]),
    ("rustdoc", ["env", "-u", "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTDOCFLAGS=-D warnings", "cargo", "doc", "--workspace", "--all-features", "--no-deps"]),
    ("test", ["cargo", "nextest", "run", "--workspace", "--exclude", "oneiron-napi", "--all-features", "--profile", "full"]),
    ("test-featureless", ["cargo", "test", "-p", "oneiron", "--lib", "--no-default-features"]),
    ("doctest", ["cargo", "test", "--doc", "--workspace", "--exclude", "oneiron-bench", "--all-features"]),
]
# The recorder sees Cargo, not env's options/assignments or the fixture's path.
COMMANDS = [["codemap"], *[
    command[command.index("cargo"):] for _, command in GATES[1:]
]]
COMMAND_BY_STAGE = dict(zip((stage for stage, _ in GATES), COMMANDS))


class VerifyCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="verify-tests-")
        self.addCleanup(tmp.cleanup)
        self.cwd = Path(tmp.name)
        self.repo = self.cwd / "checkout with spaces"
        (self.repo / "scripts/codemap").mkdir(parents=True)
        for name in ("verify.sh", "verify-leg.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        self.bin = self.cwd / "bin"
        self.bin.mkdir()
        for path in (self.bin / "cargo", self.bin / "uname", self.repo / "scripts/codemap/check.sh"):
            path.write_text(RECORDER, encoding="utf-8")
            path.chmod(0o755)
        self.log = self.cwd / "commands.jsonl"
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("VERIFY_TEST_") and key != "LEG"
        }
        self.env.update(PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                        VERIFY_TEST_LOG=str(self.log), VERIFY_TEST_OS="Linux")

    def run_script(self, *args, script="verify.sh", env=None):
        self.log.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", str(self.repo / "scripts" / script), *args],
            cwd=self.cwd, env={**self.env, **(env or {})},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def records(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def commands(self):
        return [record["command"] for record in self.records()]

    def test_list_prints_stages_without_running_commands_or_claiming_success(self):
        result = self.run_script("--list")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.commands(), [])
        self.assertNotIn("VERIFY-OK", result.stdout)
        listed = []
        for line in result.stdout.splitlines():
            stage, command = line.split("\t", 1)
            listed.append((stage, shlex.split(command)))
        self.assertEqual(listed, GATES)

    def test_help_does_not_run_commands_or_claim_success(self):
        for option in ("--help", "-h"):
            with self.subTest(option=option):
                result = self.run_script(option)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.commands(), [])
                self.assertIn("--list", result.stdout)
                self.assertIn(f"run all {len(GATES)} scripted stages", result.stdout)
                self.assertNotIn("\nVERIFY-OK\n", result.stdout)

    def test_invalid_arguments_fail_before_any_command(self):
        for args in (("--unknown",), ("fmt",), ("--list", "--help"), ("",)):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(self.commands(), [])
                self.assertIn("VERIFY-FAIL-usage", result.stdout)
                self.assertNotIn("\nVERIFY-OK\n", result.stdout)

    def test_full_gate_executes_every_listed_command_in_order(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.commands(), COMMANDS)
        self.assertEqual(result.stdout.splitlines()[-1], "VERIFY-OK")

    def test_rustdoc_denies_warnings_without_changing_other_stage_environments(self):
        # Cargo gives encoded flags precedence even when their value is empty.
        for encoded in ("", "-A\x1fwarnings"):
            with self.subTest(encoded=encoded):
                result = self.run_script(env={
                    "RUSTDOCFLAGS": "-A warnings",
                    "CARGO_ENCODED_RUSTDOCFLAGS": encoded,
                })
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.commands(), COMMANDS)
                expected = ["-D warnings" if stage == "rustdoc" else "-A warnings" for stage, _ in GATES]
                self.assertEqual([record["rustdocflags"] for record in self.records()], expected)
                expected_encoded = [None if stage == "rustdoc" else encoded for stage, _ in GATES]
                self.assertEqual([record["encoded_rustdocflags"] for record in self.records()], expected_encoded)

    def test_each_failed_gate_stops_before_the_next_command(self):
        for index, (stage, _) in enumerate(GATES, start=1):
            with self.subTest(stage=stage):
                result = self.run_script(env={"VERIFY_TEST_FAIL_CALL": str(index), "VERIFY_TEST_EXIT": "7"})
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(self.commands(), COMMANDS[:index])
                self.assertEqual(result.stdout.splitlines()[-1], f"VERIFY-FAIL-{stage}")
                self.assertNotIn("VERIFY-OK", result.stdout)

    def test_compiler_errors_fail_even_when_command_exits_zero(self):
        for stage in ("clippy", "rustdoc"):
            index = next(index for index, (name, _) in enumerate(GATES, start=1) if name == stage)
            for message in ("error[E0308]: fixture error", "error: fixture error"):
                with self.subTest(stage=stage, message=message):
                    result = self.run_script(env={
                        "VERIFY_TEST_FAIL_CALL": str(index), "VERIFY_TEST_EXIT": "0", "VERIFY_TEST_OUTPUT": message,
                    })
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertEqual(self.commands(), COMMANDS[:index])
                    self.assertIn(message, result.stdout)
                    self.assertEqual(result.stdout.splitlines()[-1], f"VERIFY-FAIL-{stage}")

    def test_distributed_legs_keep_full_tier_and_host_specific_napi_coverage(self):
        for host in ("Linux", "Darwin"):
            nextest = COMMAND_BY_STAGE["test"]
            if host == "Darwin":
                nextest = [arg for arg in nextest if arg not in ("--exclude", "oneiron-napi")]
            legs = {
                "fmt-clippy": COMMANDS[:3],
                "tests:1/2": [nextest + ["--partition", "hash:1/2"], COMMAND_BY_STAGE["doctest"]],
                "tests:2/2": [nextest + ["--partition", "hash:2/2"]],
            }
            for leg, expected in legs.items():
                with self.subTest(host=host, leg=leg):
                    result = self.run_script(script="verify-leg.sh", env={"LEG": leg, "VERIFY_TEST_OS": host})
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(self.commands(), expected)
                    self.assertEqual(result.stdout.splitlines()[-1], f"VERIFY-LEG-OK {leg}")

    def test_missing_or_invalid_leg_fails_before_any_command(self):
        for env in ({}, {"LEG": "tests:3/3"}):
            with self.subTest(env=env):
                result = self.run_script(script="verify-leg.sh", env=env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.commands(), [])
                self.assertNotIn("VERIFY-LEG-OK", result.stdout)

    def test_distributed_failure_never_claims_success(self):
        for status, message in (("7", "fixture failure"), ("0", "error[E0308]: fixture error")):
            with self.subTest(status=status):
                result = self.run_script(script="verify-leg.sh", env={
                    "LEG": "fmt-clippy", "VERIFY_TEST_FAIL_CALL": "2",
                    "VERIFY_TEST_EXIT": status, "VERIFY_TEST_OUTPUT": message,
                })
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(self.commands(), COMMANDS[:2])
                self.assertEqual(result.stdout.splitlines()[-1], "VERIFY-LEG-FAIL-fmt fmt-clippy")
                self.assertNotIn("VERIFY-LEG-OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
