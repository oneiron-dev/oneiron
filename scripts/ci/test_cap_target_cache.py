"""Exercise cache maintenance with fake tools and disposable target directories."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys


SCRIPT = Path(__file__).resolve().with_name("cap-target-cache.sh")
GIB_KIB = 1024 * 1024


class CacheCapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='oneiron cache "test" \\ ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target = self.root / "ci" / "target"
        self.target.mkdir(parents=True)
        self.dependency = self.target / "dependency.rlib"
        self.workspace = self.target / "workspace.rlib"
        self.dependency.write_bytes(b"dependency\x00\xff")
        self.workspace.write_bytes(b"workspace\x00\xff")
        self.state = self.root / "state.json"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        stub = self.tools / "stub"
        stub.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, shutil, sys, tomllib\n"
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
            "    build_dir = os.environ.get('CARGO_BUILD_BUILD_DIR', state.get('configured_build_dir', os.environ['STUB_TARGET']))\n"
            "    for i, arg in enumerate(sys.argv[:-1]):\n"
            "        if arg == '--config':\n"
            "            build_dir = tomllib.loads(sys.argv[i + 1])['build']['build-dir']\n"
            "    state.setdefault('build_dirs', []).append(build_dir)\n"
            "    name = pathlib.Path(os.environ['STUB_WORKSPACE']).name\n"
            "    (pathlib.Path(build_dir) / name).unlink(missing_ok=True)\n"
            "    if state.get('symlink_after_dev') and state['cargo_calls'] == 1:\n"
            "        (pathlib.Path(os.environ['STUB_TARGET']) / 'release').symlink_to(state['symlink_after_dev'])\n"
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

    def test_descendant_symlinks_keep_the_cache_and_outside_bytes(self):
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.rlib"
        payload = b"outside sentinel\x00\xff"
        sentinel.write_bytes(payload)
        cache_before = (self.workspace.read_bytes(), self.dependency.read_bytes())
        cases = (
            ("debug", outside),
            ("debug/deps", outside),
            ("debug/build/probe/out/link", outside),
            ("release", outside),
            ("release/build/probe/out/link", outside),
            ("debug/deps/file.rlib", sentinel),
            ("release/deps/dangling", outside / "missing"),
        )
        for relative, destination in cases:
            with self.subTest(relative=relative):
                link = self.target / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(destination)
                try:
                    calls = self.run_cap([2 * GIB_KIB, 0])
                    self.assertEqual([call[0] for call in calls], ["du"])
                    self.assertTrue(link.is_symlink())
                    self.assertEqual(sentinel.read_bytes(), payload)
                    self.assertEqual(
                        (self.workspace.read_bytes(), self.dependency.read_bytes()),
                        cache_before,
                    )
                finally:
                    link.unlink()

    def test_internal_symlink_is_also_refused(self):
        link = self.target / "alias.rlib"
        link.symlink_to(self.workspace.name)
        calls = self.run_cap([2 * GIB_KIB, 0])
        self.assertEqual([call[0] for call in calls], ["du"])
        self.assertTrue(link.is_symlink())
        self.assertTrue(self.workspace.exists())

    def test_device_boundaries_keep_file_and_directory_artifacts(self):
        # Mock only filesystem metadata; no real mount operations are needed.
        mock_path = self.root / "device mock"
        mock_path.mkdir()
        (mock_path / "sitecustomize.py").write_text(
            "import contextlib, os\n"
            "original_scandir = os.scandir\n"
            "class Entry:\n"
            "    def __init__(self, entry): self.entry = entry\n"
            "    def __getattr__(self, name): return getattr(self.entry, name)\n"
            "    def stat(self, *args, **kwargs):\n"
            "        result = self.entry.stat(*args, **kwargs)\n"
            "        if self.entry.path == os.environ['STUB_DEVICE_PATH']:\n"
            "            values = list(result)\n"
            "            values[2] += int(os.environ['STUB_DEVICE_DELTA'])\n"
            "            return os.stat_result(values)\n"
            "        return result\n"
            "@contextlib.contextmanager\n"
            "def scandir(path):\n"
            "    with original_scandir(path) as entries:\n"
            "        yield (Entry(entry) for entry in entries)\n"
            "os.scandir = scandir\n"
        )
        self.env["PYTHONPATH"] = str(mock_path)
        directory = self.target / "debug" / "deps"
        directory.mkdir(parents=True)
        sentinel = directory / "sentinel.rlib"
        sentinel.write_bytes(b"device boundary artifact")
        for boundary in (directory, sentinel):
            for device_delta in (0, 1):
                with self.subTest(boundary=boundary.name, device_delta=device_delta):
                    self.env["STUB_DEVICE_PATH"] = str(boundary)
                    self.env["STUB_DEVICE_DELTA"] = str(device_delta)
                    self.workspace.write_bytes(b"workspace artifact")
                    calls = self.run_cap([2 * GIB_KIB, 0])
                    # The same-device control proves the mock does not itself fail.
                    expected = ["du"] if device_delta else ["du", "cargo", "cargo", "du"]
                    self.assertEqual([call[0] for call in calls], expected)
                    self.assertEqual(self.workspace.exists(), bool(device_delta))
                    self.assertEqual(sentinel.read_bytes(), b"device boundary artifact")
                    self.assertEqual(self.dependency.read_bytes(), b"dependency\x00\xff")

    def test_scan_process_failure_keeps_the_cache(self):
        # Stub the scanner's interpreter, not the fixture tools' interpreter.
        (self.tools / "python3").symlink_to(self.tools / "stub")
        before = (self.workspace.read_bytes(), self.dependency.read_bytes())
        calls = self.run_cap([2 * GIB_KIB, 0], python3_rc=1)
        self.assertEqual([call[0] for call in calls], ["du", "python3"])
        self.assertEqual(
            (self.workspace.read_bytes(), self.dependency.read_bytes()), before
        )

    @unittest.skipIf(os.geteuid() == 0, "root bypasses directory permission checks")
    def test_scan_read_or_stat_failure_keeps_the_cache(self):
        blocked = self.target / "debug" / "blocked"
        blocked.mkdir(parents=True)
        sentinel = blocked / "sentinel.rlib"
        sentinel.write_bytes(b"keep unreadable subtree")
        for mode in (0, 0o400):  # scandir denied, then lstat of entries denied
            with self.subTest(mode=mode):
                blocked.chmod(mode)
                try:
                    calls = self.run_cap([2 * GIB_KIB, 0])
                finally:
                    blocked.chmod(0o700)
                self.assertEqual([call[0] for call in calls], ["du"])
                self.assertEqual(sentinel.read_bytes(), b"keep unreadable subtree")
                self.assertTrue(self.workspace.exists())
                self.assertTrue(self.dependency.exists())

    def test_release_clean_rechecks_the_layout(self):
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.rlib"
        sentinel.write_bytes(b"keep after dev cleanup")
        calls = self.run_cap([2 * GIB_KIB, 0], symlink_after_dev=str(outside))
        self.assertEqual([call[0] for call in calls], ["du", "cargo"])
        self.assertEqual(sentinel.read_bytes(), b"keep after dev cleanup")
        self.assertTrue(self.dependency.exists())
        self.assertTrue((self.target / "release").is_symlink())

    def test_both_clean_passes_contain_env_and_config_build_dir_redirection(self):
        configured = self.root / "configured build"
        inherited = self.root / "inherited build"
        for outside in (configured, inherited):
            outside.mkdir()
            (outside / self.workspace.name).write_bytes(b"outside build artifact")
        for use_env in (False, True):
            with self.subTest(use_env=use_env):
                if use_env:
                    self.env["CARGO_BUILD_BUILD_DIR"] = str(inherited)
                else:
                    self.env.pop("CARGO_BUILD_BUILD_DIR", None)
                self.workspace.write_bytes(b"workspace artifact")
                calls = self.run_cap(
                    [2 * GIB_KIB, 0], configured_build_dir=str(configured)
                )
                clean = [call for call in calls if call[0] == "cargo"]
                self.assertEqual(
                    [call[call.index("--profile") + 1] for call in clean],
                    ["dev", "release"],
                )
                self.assertEqual(
                    json.loads(self.state.read_text())["build_dirs"],
                    [str(self.target), str(self.target)],
                )
                for outside in (configured, inherited):
                    self.assertEqual(
                        (outside / self.workspace.name).read_bytes(),
                        b"outside build artifact",
                    )
                self.assertFalse(self.workspace.exists())
                self.assertTrue(self.dependency.exists())

    def test_cargo_template_braces_in_target_path_are_refused(self):
        target = self.root / "{workspace-root}" / "ci" / "target"
        target.mkdir(parents=True)
        sentinel = target / "sentinel.rlib"
        sentinel.write_bytes(b"literal template path")
        self.env["CARGO_TARGET_DIR"] = str(target)
        calls = self.run_cap([2 * GIB_KIB, 0])
        self.assertEqual([call[0] for call in calls], ["du"])
        self.assertEqual(sentinel.read_bytes(), b"literal template path")

    def test_under_cap_needs_no_scan_even_with_symlinks(self):
        (self.tools / "python3").symlink_to(self.tools / "stub")
        link = self.target / "debug"
        link.symlink_to(self.root)
        calls = self.run_cap([GIB_KIB - 1], python3_rc=1)
        self.assertEqual([call[0] for call in calls], ["du"])
        self.assertTrue(link.is_symlink())
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
