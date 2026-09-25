"""Dependency-free QuickJS builder input validation, without compiling a guest."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("quickjs_build", ROOT / "components/code-run-quickjs/build.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class ToolVersionTests(unittest.TestCase):
    def test_release_commit_stamp_does_not_change_the_pin(self):
        self.assertTrue(BUILD.tool_version_matches("wit-bindgen", "0.46.0", "wit-bindgen-cli 0.46.0 (4c0e9a4ed 2025-09-10)"))
        self.assertTrue(BUILD.tool_version_matches("wasm-tools", "1.239.0", "wasm-tools 1.239.0"))
        for reported in ["wit-bindgen-cli 0.47.0", "wit-bindgen-cli 0.46.0-dev", "other 0.46.0", "0.46.0"]:
            with self.subTest(reported=reported):
                self.assertFalse(BUILD.tool_version_matches("wit-bindgen", "0.46.0", reported))


class ArtifactPinsTests(unittest.TestCase):
    def test_distributed_components_match_source_and_manifest(self):
        import hashlib
        import json
        directory = ROOT / "components/code-run-quickjs/artifacts"
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["world"], "oneiron:code-run/guest@1.0.0")
        self.assertEqual(manifest["component_name"], "oneiron.plain-js.quickjs-component")
        self.assertEqual(manifest["upstream_sha256"], BUILD.SOURCE_SHA256)
        self.assertEqual(set(manifest["artifacts"]), {"first-party", "foreign"})
        self.assertEqual(manifest["wit_sha256"], hashlib.sha256((ROOT / "crates/oneiron/wit/code-run.wit").read_bytes()).hexdigest())
        for name, digest in manifest["sources"].items():
            self.assertEqual(digest, hashlib.sha256((directory.parent / name).read_bytes()).hexdigest(), name)
        for row in manifest["artifacts"].values():
            data = (directory / row["file"]).read_bytes()
            self.assertEqual(data[:8], b"\x00asm\x0d\x00\x01\x00")
            self.assertEqual(len(data), row["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
        self.assertIn("Permission is hereby granted", (directory / "LICENSE").read_text())
