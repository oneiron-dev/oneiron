"""Dependency-free fixtures for the checked-in WIT artifact generator."""
import importlib.util
import shutil
import subprocess
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sandbox_wit_generator", ROOT / "scripts/code-sandbox/generate.py")
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class SandboxWitTests(unittest.TestCase):

    def test_bare_ask_declaration_compiles_as_typescript(self):
        declaration = GEN.OUT / "code-run.d.ts"
        self.assertIn("declare function ask(", declaration.read_text())
        tsc = shutil.which("tsc")
        if tsc is None:
            package_tsc = ROOT / "packages/oneiron/node_modules/.bin/tsc"
            if package_tsc.exists():
                tsc = str(package_tsc)
        if tsc is None:
            self.skipTest("TypeScript compiler is not installed on this host")
        result = subprocess.run(
            [tsc, "--noEmit", "--lib", "es2022", str(declaration)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
