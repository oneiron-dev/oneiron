"""Offline tests for cargo-deny advisory-ignore lock consistency."""

from pathlib import Path
import tempfile
import unittest

from scripts.ci.check_deny_policy import ROOT, find_stale_ignores, requirement_matches


class DenyPolicyTests(unittest.TestCase):
    def test_every_advisory_ignore_names_a_locked_crate(self):
        self.assertEqual(find_stale_ignores(ROOT / "deny.toml", ROOT / "Cargo.lock"), [])

    def test_a_stale_ignore_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2024-0370"
            advisory = root / "db" / "advisory-db-test" / "crates" / "proc-macro-error" / f"{advisory_id}.md"
            advisory.parent.mkdir(parents=True)
            advisory.write_text(
                '```toml\n[advisory]\nid = "RUSTSEC-2024-0370"\n'
                'package = "proc-macro-error"\n[versions]\npatched = []\n```\n'
            )
            deny = root / "deny.toml"
            deny.write_text(
                '[advisories]\ndb-path = "db"\nignore = '
                '[{id = "RUSTSEC-2024-0370", reason = "proc-macro-error@1.0.4 reviewed"}]\n'
            )
            lock = root / "Cargo.lock"
            lock.write_text('[[package]]\nname = "other-crate"\nversion = "1.0.4"\n')
            self.assertEqual(find_stale_ignores(deny, lock, root / "db"), [advisory_id])
            # A new lock version also makes the old acceptance stale.
            lock.write_text('[[package]]\nname = "proc-macro-error"\nversion = "1.0.5"\n')
            self.assertEqual(find_stale_ignores(deny, lock, root / "db"), [advisory_id])

    def test_locked_but_unaffected_version_is_stale(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2099-0001"
            advisory = root / "db" / "crates" / "example" / f"{advisory_id}.md"
            advisory.parent.mkdir(parents=True)
            deny = root / "deny.toml"
            deny.write_text(
                '[advisories]\ndb-path = "db"\nignore = '
                '[{id = "RUSTSEC-2099-0001", reason = "example@1.2.3 reviewed"}]\n'
            )
            lock = root / "Cargo.lock"
            lock.write_text('[[package]]\nname = "example"\nversion = "1.2.3"\n')
            for ranges in (
                'patched = [">= 1.2.3"]',
                'patched = []\nunaffected = [">= 1.2.3"]',
            ):
                with self.subTest(ranges=ranges):
                    advisory.write_text(
                        f'```toml\n[advisory]\nid = "{advisory_id}"\n'
                        f'package = "example"\n[versions]\n{ranges}\n```\n'
                    )
                    self.assertEqual(
                        find_stale_ignores(deny, lock, root / "db"), [advisory_id]
                    )
            advisory.write_text(
                f'```toml\n[advisory]\nid = "{advisory_id}"\n'
                'package = "example"\n[versions]\npatched = [">= 1.2.4"]\n```\n'
            )
            self.assertEqual(find_stale_ignores(deny, lock, root / "db"), [])

    def test_caret_zero_unaffected_locked_version_is_stale(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2099-0002"
            advisory = root / "db" / "crates" / "example" / f"{advisory_id}.md"
            advisory.parent.mkdir(parents=True)
            deny = root / "deny.toml"
            deny.write_text(
                '[advisories]\ndb-path = "db"\nignore = '
                f'[{{id = "{advisory_id}", reason = "example@0.9.10 reviewed"}}]\n'
            )
            lock = root / "Cargo.lock"
            lock.write_text('[[package]]\nname = "example"\nversion = "0.9.10"\n')
            for requirement in ("^0", "0"):
                with self.subTest(requirement=requirement):
                    advisory.write_text(
                        f'```toml\n[advisory]\nid = "{advisory_id}"\n'
                        'package = "example"\n[versions]\npatched = []\n'
                        f'unaffected = ["{requirement}"]\n```\n'
                    )
                    self.assertEqual(
                        find_stale_ignores(deny, lock, root / "db"), [advisory_id]
                    )

    def test_advisory_semver_ranges(self):
        self.assertTrue(requirement_matches("1.2.3", ">= 1.2.3, < 2.0.0"))
        self.assertFalse(requirement_matches("1.2.3", "> 1.2.3"))
        self.assertTrue(requirement_matches("0.9.10", "^0.9.9"))
        self.assertFalse(requirement_matches("0.10.0", "^0.9.9"))
        self.assertTrue(requirement_matches("0.9.10", "^0"))
        self.assertTrue(requirement_matches("0.9.10", "0"))
        self.assertFalse(requirement_matches("1.0.0", "^0"))
        self.assertFalse(requirement_matches("1.0.0", "0"))
        self.assertFalse(requirement_matches("0.9.10", "^0.0"))
        self.assertTrue(requirement_matches("1.2.3-beta", ">=1.2.3-alpha, <1.2.3"))
        self.assertFalse(requirement_matches("1.2.4-beta", ">=1.2.3-alpha"))
        with self.assertRaises(ValueError):
            requirement_matches("1.2.3", "unsupported syntax")


if __name__ == "__main__":
    unittest.main()
