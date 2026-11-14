"""Drive the suite census (scripts/ci/suite_census.py) over disposable git repositories (L4-23)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("suite_census.py")
GATE = Path(__file__).resolve().with_name("test_count.py")
ROOT = Path(__file__).resolve().parents[2]


def tests(*names, attrs="#[test]"):
    return "".join(f"{attrs}\nfn {name}() {{}}\n\n" for name in names)


BASELINE_HEADER = "id\tpackage\tfile\tkind\tmodule\titem\n"

# Out-of-line gated mod, inline gated mod, a self-gated test, a self-gated
# helper, a gated mod holding no test, and one live test.
LIB = """\
pub fn shipped() {}

// FIX [LIBTEST-QUARANTINE-A-TESTS]: port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;

#[cfg(any())]
mod inline_tests {
    #[test]
    fn inline_one() {
        let s = "}"; // a brace in a string does not end the module
        assert_eq!(s, "}");
    }

    #[test]
    fn inline_two() {}
}

#[cfg(test)]
mod live {
    // FIX [LIBTEST-QUARANTINE-SELF]: port it
    #[cfg(any())]
    #[test]
    fn self_gated() {}

    #[cfg(any())]
    fn gated_helper() {}

    #[test]
    fn still_runs() {}
}

#[cfg(any())]
mod dormant {
    pub fn no_tests_here() {}
}
"""


class SuiteCensusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="suite-census-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "repo"
        self.repo.mkdir()
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        out = subprocess.run(
            ["git", "-c", "user.name=owen", "-c", "user.email=owen@example.com", "-c", "commit.gpgsign=false", *args],
            cwd=self.repo, env=self.env, capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()

    def commit(self, files):
        for rel, text in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def census(self, *args, repo=None):
        argv = [sys.executable, str(SCRIPT), "--repo", str(repo or self.repo), "--json", *args]
        out = subprocess.run(argv, env=self.env, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_vendored_suites_are_reported_and_not_counted(self):
        self.commit({
            "crates/x/vendor/y/src/lib.rs": tests("v1", "v2", "v3"),
            "crates/x/src/lib.rs": tests("own1", "own2"),
        })
        c = self.census()
        self.assertEqual(c["vendored"], 3)
        self.assertEqual(c["total"], 2)
        self.assertEqual(c["rust"]["crates"], {"x": {"lib": 2, "integration": 0, "other": 0}})

    def test_quarantined_modules_count_apart_and_the_baseline_is_checked(self):
        self.commit({
            "crates/oneiron/src/a/mod.rs": LIB,
            "crates/oneiron/src/a/tests.rs": tests("q1", "q2", "q3") + "mod support;\n",
            "crates/oneiron/src/a/tests/support.rs": tests("q4"),
            "crates/oneiron/tests/door.rs": tests("door_one"),
            "scripts/nightly/libtest-quarantine-baseline.tsv": BASELINE_HEADER
            + "A-TESTS\toneiron\tcrates/oneiron/src/a/mod.rs\tmod\ta::tests\ttests\n"
            + "SELF\toneiron\tcrates/oneiron/src/a/mod.rs\tfn\ta::live\tself_gated\n"
            + "HELPER\toneiron\tcrates/oneiron/src/a/mod.rs\tfn\ta::live\tgated_helper\n"
            + "GONE\toneiron\tcrates/oneiron/src/b.rs\tmod\tb::tests\ttests\n"
            + "USE\toneiron\tcrates/oneiron/src/a/mod.rs\titem\ta\tpub(crate) use x::y;\n",
        })
        c = self.census("--files")
        self.assertEqual(c["quarantined"], 7)  # q1-q4, inline_one, inline_two, self_gated
        self.assertEqual(c["rust"]["lib"], 1)  # still_runs
        self.assertEqual(c["rust"]["integration"], 1)
        self.assertEqual(c["total"], 9)
        self.assertEqual(c["quarantine_ported"], ["crates/oneiron/src/b.rs::tests"])
        self.assertEqual(c["quarantine_unlisted"], ["crates/oneiron/src/a/mod.rs::inline_tests"])
        rows = {r["path"]: r for r in c["files"]}
        self.assertEqual(rows["crates/oneiron/src/a/mod.rs"], {"path": "crates/oneiron/src/a/mod.rs", "crate": "oneiron", "quarantined": 3, "rust_lib": 1})
        self.assertEqual(rows["crates/oneiron/src/a/tests/support.rs"]["quarantined"], 1)

    def test_office_counts_apart(self):
        self.commit({
            "crates/oneiron-seal/src/lib.rs": tests("seals"),
            "crates/oneiron-docedit/tests/edit.rs": tests("edits"),
            "crates/oneiron-docedit/vendor/stemma-engine/src/lib.rs": tests("upstream"),
            "crates/oneiron/src/edit_roundtrip/mod.rs": tests("round_trips"),
            "crates/oneiron/src/gate/tests/docx_zip_budget.rs": tests("budget"),
            "crates/oneiron/src/gate/mod.rs": tests("gate_test"),
            "packages/xlsx-viewer/tests/bridge.test.ts": 'test("bridges", () => {});\n',
            "packages/oneiron-client/src/api.test.ts": 'test("encodes", () => {});\n',
            "scripts/tests/test_excel_goldens.py": "def test_golden():\n    pass\n",
            "scripts/tests/test_split_check.py": "def test_split():\n    pass\n",
        })
        c = self.census()
        self.assertEqual(c["office"], 6)  # seal, docedit, edit_roundtrip, docx_zip_budget, xlsx-viewer, the Excel grader
        self.assertEqual((c["rust"]["total"], c["js"], c["python"], c["vendored"]), (1, 1, 1, 1))
        self.assertEqual(c["total"], 9)

    def test_e2e_cases_count_by_state(self):
        self.commit({"tests/e2e/boot.test.ts": (
            'suite.test(test, "BOOT-01", "boots", async () => {});\n'
            'suite.todo(test, "BOOT-02", "waits");\n'
            'suite.skip(test, "BOOT-03", "skipped");\n'
            'suite.pendingDoor(test, "BOOT-04", "a door to come");\n'
            '// suite.test(test, "BOOT-05", "commented out", async () => {});\n'
        )})
        c = self.census()
        self.assertEqual(c["e2e"], {"total": 4, "test": 1, "skip": 1, "todo": 1, "pendingDoor": 1})
        self.assertEqual(c["total"], 4)

    def test_ignored_tests_count_apart(self):
        self.commit({"crates/core/src/lib.rs": (
            tests("slow", attrs='#[test]\n#[ignore = "needs the fleet"]')
            + tests("live", attrs="#[test]\n// #[ignore]")
            + tests("plain")
        )})
        c = self.census()
        self.assertEqual(c["ignored"], 1)
        self.assertEqual(c["rust"]["lib"], 2)

    def test_an_empty_scan_or_unknown_revision_fails_closed(self):
        self.commit({"README.md": "no tests here\n"})
        for args in ([], ["--rev", "no-such-revision"]):
            out = subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo), *args], env=self.env, capture_output=True, text=True)
            self.assertEqual(out.returncode, 2)
            self.assertIn("suite_census=error", out.stderr)

    @unittest.skipUnless((ROOT / ".git").exists(), "needs the repository checkout")
    def test_real_checkout_total_equals_the_gate_total(self):
        c = self.census(repo=ROOT)
        gate = subprocess.run([sys.executable, str(GATE), "--repo", str(ROOT), "--head", c["rev"]], capture_output=True, text=True)
        self.assertEqual(gate.returncode, 0, gate.stderr)
        values = dict(line.split("=", 1) for line in gate.stdout.splitlines())
        self.assertEqual(c["total"], int(values["tests_total"]))
        self.assertGreaterEqual(c["vendored"], 6000)
        self.assertGreater(c["quarantined"], 0)


if __name__ == "__main__":
    unittest.main()
