"""Exercise cache maintenance with fake tools and disposable target directories."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("cap-target-cache.sh")
GIB_KIB = 1024 * 1024


class CacheCapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oneiron cache test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target = self.root / "ci" / "target"
        self.target.mkdir(parents=True)
        self.dependency = self.target / "dependency.rlib"
        self.workspace = self.target / "workspace.rlib"
        self.dependency.touch()
        self.workspace.touch()
        self.state = self.root / "state.json"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        stub = self.tools / "stub"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, shutil, sys\n"
            "path = pathlib.Path(os.environ['STUB_STATE'])\n"
            "state = json.loads(path.read_text())\n"
            "tool = pathlib.Path(sys.argv[0]).name\n"
            "state['calls'].append([tool, *sys.argv[1:]])\n"
            "rc = state.get(tool + '_rc', 0)\n"
            "if tool == 'du' and state.get('du_calls', 0) == state.get('du_fail_at'):\n"
            "    rc = 1\n"
            "if tool == 'cargo':\n"
            "    i = state.get('cargo_calls', 0)\n"
            "    if i == state.get('cargo_fail_at'):\n"
            "        rc = 1\n"
            "    state['cargo_calls'] = i + 1\n"
            "if tool == 'du' and not rc:\n"
            "    i = state.get('du_calls', 0)\n"
            "    print(str(state['sizes'][min(i, len(state['sizes']) - 1)]) + '\t' + sys.argv[-1])\n"
            "    state['du_calls'] = i + 1\n"
            "if tool == 'cargo' and not rc:\n"
            "    pathlib.Path(os.environ['STUB_WORKSPACE']).unlink(missing_ok=True)\n"
            "if tool == 'rm' and not rc:\n"
            "    target = pathlib.Path(sys.argv[-1])\n"
            "    assert target == pathlib.Path(os.environ['STUB_TARGET'])\n"
            "    shutil.rmtree(target)\n"
            "path.write_text(json.dumps(state))\n"
            "sys.exit(rc)\n"
        )
        stub.chmod(0o755)
        for tool in ("du", "cargo", "rm"):
            (self.tools / tool).symlink_to(stub)
        self.env = os.environ | {
            "PATH": f"{self.tools}:{os.environ['PATH']}",
            "CARGO_TARGET_DIR": str(self.target),
            "STUB_STATE": str(self.state),
            "STUB_WORKSPACE": str(self.workspace),
            "STUB_TARGET": str(self.target),
        }

    def run_cap(self, sizes, cap="1", **state):
        self.state.write_text(json.dumps({"sizes": sizes, "calls": [], **state}))
        result = subprocess.run(
            ["/bin/bash", str(SCRIPT), cap],
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(self.state.read_text())["calls"]

    def test_workspace_cleanup_preserves_dependencies_when_it_reaches_the_cap(self):
        calls = self.run_cap([2 * GIB_KIB, GIB_KIB // 2])
        clean = next(call for call in calls if call[0] == "cargo")
        self.assertIn("--workspace", clean)
        self.assertIn("--target-dir", clean)
        self.assertEqual(clean[clean.index("--target-dir") + 1], str(self.target))
        self.assertTrue(self.dependency.exists())
        self.assertFalse(self.workspace.exists())

    def test_under_cap_does_not_clean_anything(self):
        calls = self.run_cap([GIB_KIB - 1])
        self.assertEqual([call[0] for call in calls], ["du"])
        self.assertTrue(self.workspace.exists())
        self.assertTrue(self.dependency.exists())

    def test_remaining_oversize_cache_uses_full_reset(self):
        calls = self.run_cap([2 * GIB_KIB, GIB_KIB])
        self.assertEqual([call[0] for call in calls], ["du", "cargo", "cargo", "du", "rm"])
        self.assertFalse(self.target.exists())

    def test_failed_cargo_clean_does_not_trigger_full_reset(self):
        calls = self.run_cap([2 * GIB_KIB], cargo_rc=1)
        self.assertEqual([call[0] for call in calls], ["du", "cargo"])
        self.assertTrue(self.dependency.exists())

    def test_failed_release_cleanup_does_not_trigger_full_reset(self):
        calls = self.run_cap([2 * GIB_KIB], cargo_fail_at=1)
        self.assertEqual([call[0] for call in calls], ["du", "cargo", "cargo"])
        self.assertTrue(self.dependency.exists())

    def test_failed_initial_measurement_keeps_everything(self):
        calls = self.run_cap([2 * GIB_KIB], du_rc=1)
        self.assertEqual([call[0] for call in calls], ["du"])
        self.assertTrue(self.workspace.exists())

    def test_failed_second_measurement_keeps_dependencies(self):
        calls = self.run_cap([2 * GIB_KIB], du_fail_at=1)
        self.assertEqual([call[0] for call in calls], ["du", "cargo", "cargo", "du"])
        self.assertTrue(self.dependency.exists())

    def test_malformed_measurement_keeps_everything(self):
        calls = self.run_cap(["not-a-size"])
        self.assertEqual([call[0] for call in calls], ["du"])
        self.assertTrue(self.workspace.exists())

    def test_failed_reset_does_not_change_job_verdict(self):
        calls = self.run_cap([2 * GIB_KIB], rm_rc=1)
        self.assertEqual([call[0] for call in calls], ["du", "cargo", "cargo", "du", "rm"])
        self.assertTrue(self.dependency.exists())

    def test_invalid_caps_never_measure_or_clean(self):
        for cap in ("", "no", "0", "-1", "1.5", "01", "9999999"):
            with self.subTest(cap=cap):
                self.assertEqual(self.run_cap([2 * GIB_KIB], cap=cap), [])
                self.assertTrue(self.workspace.exists())

    def test_unset_target_does_nothing(self):
        self.env.pop("CARGO_TARGET_DIR")
        self.assertEqual(self.run_cap([2 * GIB_KIB]), [])

    def test_missing_target_does_nothing(self):
        self.env["CARGO_TARGET_DIR"] = str(self.root / "missing" / "ci" / "target")
        self.assertEqual(self.run_cap([2 * GIB_KIB]), [])

    def test_non_ci_target_is_refused(self):
        other = self.root / "target"
        other.mkdir()
        self.env["CARGO_TARGET_DIR"] = str(other)
        self.assertEqual(self.run_cap([2 * GIB_KIB]), [])
        self.assertTrue(other.exists())

    def test_symlink_target_is_refused(self):
        link = self.root / "linked" / "ci" / "target"
        link.parent.mkdir(parents=True)
        link.symlink_to(self.target, target_is_directory=True)
        self.env["CARGO_TARGET_DIR"] = str(link)
        self.assertEqual(self.run_cap([2 * GIB_KIB]), [])
        self.assertTrue(self.workspace.exists())
        self.assertTrue(link.is_symlink())

    def test_symlink_ancestor_is_refused(self):
        link = self.root / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        self.env["CARGO_TARGET_DIR"] = str(link / "ci" / "target")
        self.assertEqual(self.run_cap([2 * GIB_KIB]), [])
        self.assertTrue(self.workspace.exists())

    def test_clean_covers_standard_profiles_offline(self):
        calls = self.run_cap([2 * GIB_KIB, 0])
        clean = next(call for call in calls if call[0] == "cargo")
        self.assertEqual(clean[:2], ["cargo", "clean"])
        self.assertIn("--locked", clean)
        self.assertIn("--offline", clean)
        profiles = [call[call.index("--profile") + 1] for call in calls if call[0] == "cargo"]
        self.assertEqual(profiles, ["dev", "release"])
        self.assertEqual(
            Path(clean[clean.index("--manifest-path") + 1]),
            SCRIPT.parents[2] / "Cargo.toml",
        )


if __name__ == "__main__":
    unittest.main()
