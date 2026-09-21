"""Test ONE-2201's const audit, including real source and hostile fixtures."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("burst_audit", ROOT / "scripts/check-federation-burst.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class FederationBurstAuditTests(unittest.TestCase):
    def test_live_policy_has_no_absolute_burst_constants(self):
        self.assertEqual(AUDIT.audit(ROOT), [])

    def test_absolute_constants_and_fixed_pauses_fail_regardless_of_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "crates/oneiron/src/sync/federation_burst"
            normalizer = root / "crates/oneiron/src/llm/burst_inputs.rs"
            policy.mkdir(parents=True)
            normalizer.parent.mkdir(parents=True)
            normalizer.write_text("")
            (policy / "observations.rs").write_text("")
            (policy / "mod.rs").write_text(
                '// const COMMENT: u64 = 10;\n'
                'const fn identity(n: u64) -> u64 { n }\n'
                'fn text() { let _ = r#"static STRING: u64 = 10;"#; }\n'
            )
            self.assertEqual(AUDIT.audit(root), [])
            for source in [policy / "mod.rs", policy / "new_policy.rs", normalizer]:
                for declaration, name in [
                    ("pub const MAX_WRITES: u64 = 100;", "MAX_WRITES"),
                    ("const PAUSE_SECS: u64 = 60;", "PAUSE_SECS"),
                    ("static renamed: f64 = 42.0;", "renamed"),
                    ("impl Policy { const X: usize = 100; }", "X"),
                ]:
                    with self.subTest(path=source, declaration=declaration):
                        source.write_text(declaration)
                        findings = AUDIT.audit(root)
                        self.assertEqual(len(findings), 1)
                        self.assertTrue(findings[0].endswith(": " + name))
                        source.write_text("")

    def test_missing_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                AUDIT.audit(Path(directory))
