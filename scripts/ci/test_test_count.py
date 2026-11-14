"""Drive the test-count gate (scripts/ci/test_count.py) over disposable git repositories (L8-01)."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("test_count.py")

TWO_TESTS = """\
#[test]
fn first() {}

#[tokio::test(flavor = "multi_thread")]
async fn second() {}

fn helper() {}
"""

THREE_TESTS = TWO_TESTS + """
#[test]
fn third() {}
"""

# One real test among look-alikes: comments, strings, raw strings, a char
# literal, a non-test attribute, and one fn under several test attributes.
MASKED = r'''
// #[test]
/// #[test] fn in_doc() {}
/* #[test] /* nested #[test] */ fn in_block() {} */
const S: &str = "#[test] fn in_string() {}";
const R: &str = r#"#[test] fn in_raw() {} "quoted""#;
const C: char = '"';
#[serde(rename = "test")]
struct NotATest<'a>(&'a str);
#[rstest]
#[case(1)]
#[case(2)]
fn parameterised(#[case] n: u8) {}
'''

E2E_CASES = """\
const suite = defineFile(import.meta, { profile: "deterministic" });
suite.test(test, "BOOT-01", "boots", async () => {});
suite.skip(test, "BOOT-02", "waits on a door");
suite.test(
  test,
  "BOOT-03",
  "multi-line call",
  async () => {},
);
// suite.test(test, "BOOT-04", "commented out", async () => {});
"""

PY_TESTS = """\
import unittest

class T(unittest.TestCase):
    def test_one(self):
        pass

    async def test_two(self):
        pass

    def helper(self):
        pass
"""


class TestCountGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test-count-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        out = subprocess.run(
            ["git", "-c", "user.name=owen", "-c", "user.email=owen@example.com", "-c", "commit.gpgsign=false", *args],
            cwd=self.repo, env=self.env, capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()

    def commit(self, files, message):
        for rel, text in files.items():
            path = self.repo / rel
            if text is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def run_gate(self, *args, body=None):
        argv = [sys.executable, str(SCRIPT), "--repo", str(self.repo), *args]
        if body is not None:
            body_file = self.root / "pr-body.txt"
            body_file.write_text(body)
            argv += ["--body-file", str(body_file)]
        out = subprocess.run(argv, env=self.env, capture_output=True, text=True)
        values = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
        return out.returncode, values, out.stderr

    def test_gate_prints_total_and_asks_reason_for_growth(self):
        base = self.commit({"crates/core/src/lib.rs": TWO_TESTS}, "base")
        head = self.commit({"crates/core/src/lib.rs": THREE_TESTS}, "head")

        rc, values, err = self.run_gate("--base", base, "--head", head, body="Adds a door test.\n")
        self.assertEqual(rc, 1, err)
        self.assertEqual(values["tests_total"], "3")
        self.assertEqual(values["tests_base"], "2")
        self.assertEqual(values["tests_growth"], "1")
        self.assertEqual(values["growth_reason"], "none")
        self.assertIn("Test growth: <reason>", err)

        rc, values, err = self.run_gate("--base", base, "--head", head, body="Summary.\n\n- Test growth: the BOOT-09 repro of FIX 4711.\n")
        self.assertEqual(rc, 0, err)
        self.assertEqual(values["tests_growth"], "1")
        self.assertEqual(values["growth_reason"], "the BOOT-09 repro of FIX 4711.")

        rc, values, err = self.run_gate("--base", base, "--head", head, "--report-only")
        self.assertEqual(rc, 0, err)
        self.assertEqual(values["tests_growth"], "1")

    def test_an_empty_reason_line_states_no_reason(self):
        base = self.commit({"crates/core/src/lib.rs": TWO_TESTS}, "base")
        head = self.commit({"crates/core/src/lib.rs": THREE_TESTS}, "head")
        rc, values, err = self.run_gate("--base", base, "--head", head, body="Test growth:   \n")
        self.assertEqual(rc, 1, err)
        self.assertEqual(values["growth_reason"], "none")

    def test_shrink_and_equal_counts_need_no_reason(self):
        base = self.commit({"crates/core/src/lib.rs": THREE_TESTS, "crates/core/tests/gone.rs": TWO_TESTS}, "base")
        head = self.commit({"crates/core/src/lib.rs": TWO_TESTS, "crates/core/tests/gone.rs": None}, "head")
        rc, values, err = self.run_gate("--base", base, "--head", head, body="")
        self.assertEqual(rc, 0, err)
        self.assertEqual(values["tests_total"], "2")
        self.assertEqual(values["tests_base"], "5")
        self.assertEqual(values["tests_growth"], "-3")

        same = self.commit({"README.md": "docs only\n"}, "docs")
        rc, values, err = self.run_gate("--base", head, "--head", same, body="")
        self.assertEqual(rc, 0, err)
        self.assertEqual(values["tests_growth"], "0")

    def test_comments_strings_and_repeated_attributes_are_not_counted(self):
        head = self.commit({"crates/core/src/masked.rs": MASKED}, "masked")
        rc, values, err = self.run_gate("--head", head)
        self.assertEqual(rc, 0, err)
        self.assertEqual(values["tests_rust"], "1")
        self.assertEqual(values["tests_total"], "1")
        self.assertNotIn("tests_growth", values)

    def test_counts_each_kind_and_skips_vendored_code(self):
        head = self.commit({
            "crates/core/src/lib.rs": TWO_TESTS,
            "crates/seal/vendor/upstream/src/lib.rs": THREE_TESTS,
            "tests/e2e/boot.test.ts": E2E_CASES,
            "packages/client/src/api.test.ts": 'test("encodes", () => {});\nit.skip("decodes", () => {});\n// test("old", () => {});\n',
            "scripts/ci/test_tool.py": PY_TESTS,
            "scripts/ci/tool.py": "def test_not_in_a_test_file():\n    pass\n",
        }, "kinds")
        rc, values, err = self.run_gate("--head", head)
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            {k: values[k] for k in ("tests_rust", "tests_e2e", "tests_js", "tests_py", "tests_total")},
            {"tests_rust": "2", "tests_e2e": "3", "tests_js": "2", "tests_py": "2", "tests_total": "9"},
        )

    def test_an_unreadable_revision_or_empty_scan_fails_closed(self):
        head = self.commit({"README.md": "no tests here\n"}, "docs")
        rc, _, err = self.run_gate("--head", head)
        self.assertEqual(rc, 2)
        self.assertIn("empty scan", err)

        rc, _, err = self.run_gate("--head", "no-such-revision")
        self.assertEqual(rc, 2)
        self.assertIn("test_count=error", err)


if __name__ == "__main__":
    unittest.main()
