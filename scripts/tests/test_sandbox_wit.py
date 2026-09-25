"""Dependency-free fixtures for the checked-in WIT artifact generator."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sandbox_wit_generator", ROOT / "scripts/code-sandbox/generate.py")
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class SandboxWitTests(unittest.TestCase):
    def test_regeneration_is_byte_identical(self):
        source = GEN.WIT.read_text()
        artifacts = GEN.generate(source)
        self.assertEqual(artifacts, GEN.generate(source))
        for name, content in artifacts.items():
            self.assertEqual(content, (GEN.OUT / name).read_text())

    def test_unknown_types_and_unannotated_imports_fail_closed(self):
        source = "package fixture:test; world guest { import clock: func() -> u64; }"
        with self.assertRaises(ValueError):
            GEN.generate(source)
        with self.assertRaises(ValueError):
            GEN.generate(source.replace("import clock:", "// @js fixture.clock\nimport clock:").replace("-> u64", "-> unknown-type"))

    def test_json_transport_fields_keep_public_object_types(self):
        artifacts = GEN.generate(GEN.WIT.read_text())
        self.assertIn("subject: unknown; value: unknown;", artifacts["code-run.d.ts"])
        self.assertIn("interface SearchOutput { results: unknown[]; }", artifacts["code-run.d.ts"])


if __name__ == "__main__":
    unittest.main()
