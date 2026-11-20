"""Drive the test lint (scripts/ratchet/test_lint.py): it finds sleeps, wall-clock reads, network,
fixed ports and real models in test code, and nothing in comments, non-test code or lines allowed
with a reason. These are the cases of the Rust lint's tests (crates/oneiron-testkit/tests/lint_rules.rs)
it replaces, plus the command line that check.sh and ratchet_gate.py call."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ratchet/test_lint.py"


def load_lint():
    spec = importlib.util.spec_from_file_location("test_lint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LINT = load_lint()
TEST_FILE = "crates/oneiron/tests/sample.rs"


def rules(path, source):
    return [(line, rule) for _, line, rule, _ in LINT.scan_source(path, source)]


class Rules(unittest.TestCase):
    def test_sleeps_and_wall_clock_reads_in_test_code_are_found(self):
        source = (
            "fn a() {\n    std::thread::sleep(d);\n    tokio::time::sleep(d).await;\n"
            "    let t = std::time::SystemTime::now();\n    let i = Instant::now();\n}\n"
        )
        self.assertEqual(rules(TEST_FILE, source), [(2, "sleep"), (3, "sleep"), (4, "wall-clock"), (5, "wall-clock")])

    def test_comments_strings_methods_and_definitions_are_not_sleeps(self):
        source = (
            "// thread::sleep(d) in a comment\n/* Instant::now() */\nlet s = \"thread::sleep(d)\";\n"
            "clock.sleep(d);\nfn sleep(d: u64) {}\n"
        )
        self.assertEqual(rules(TEST_FILE, source), [])

    def test_urls_to_real_hosts_and_fixed_ports_are_found_but_loopback_and_reserved_names_are_not(self):
        source = (
            'let a = "https://github.com/x";\n'
            'let b = "http://127.0.0.1:0/";\n'
            'let c = "https://sub.example.com/a";\n'
            'let d = "http://api.test/x";\n'
            'let e = "127.0.0.1:8080";\n'
            'let f = format!("http://{addr}/v1");\n'
        )
        self.assertEqual(rules(TEST_FILE, source), [(1, "network"), (5, "fixed-port")])

    def test_xml_namespaces_and_schema_identifiers_are_not_network(self):
        source = (
            'const P: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";\n'
            "let s = \"{$schema:'http://json-schema.org/draft-07/schema#'}\";\n"
            'let x = "http://www.w3.org/2000/svg";\n'
            'let d = "https://schemas.openxmlformats.org.cdn.net/x";\n'
        )
        self.assertEqual(rules(TEST_FILE, source), [(4, "network")])

    def test_real_model_keys_hosts_and_files_are_found(self):
        source = 'env::var("OPENAI_API_KEY");\nlet u = "https://api.openai.com/v1";\nlet m = "model.gguf";\n'
        self.assertEqual(rules(TEST_FILE, source), [(1, "real-model"), (2, "real-model"), (3, "real-model")])

    def test_only_test_code_is_read_in_a_source_file(self):
        source = (
            "fn shipped() { std::thread::sleep(d); }\n#[cfg(test)]\nmod tests {\n    fn t() { std::thread::sleep(d); }\n}\n"
            "#[cfg(not(test))]\nfn other() { std::thread::sleep(d); }\n"
            '#[cfg(feature = "test-hooks")]\nfn hook() { std::thread::sleep(d); }\n'
        )
        self.assertEqual(rules("crates/oneiron/src/lib.rs", source), [(4, "sleep")])
        self.assertTrue(LINT.whole_file_is_test("crates/oneiron/src/gate/tests.rs"))
        self.assertTrue(LINT.whole_file_is_test("crates/oneiron/src/gate/policy_tests.rs"))
        self.assertTrue(LINT.whole_file_is_test("crates/oneiron-server/tests/it/main.rs"))
        self.assertFalse(LINT.whole_file_is_test("crates/oneiron/src/gate/mod.rs"))

    def test_a_file_gated_as_test_and_a_bodiless_test_item_are_read_too(self):
        gated = "#![cfg(test)]\nfn t() { std::thread::sleep(d); }\n"
        self.assertEqual(rules("crates/oneiron-seal/src/native/verify/review.rs", gated), [(2, "sleep")])
        item = '#[cfg(test)]\nconst URL: &str = "https://github.com/";\nconst SHIPPED: &str = "https://github.com/";\n'
        self.assertEqual(rules("crates/oneiron/src/lib.rs", item), [(2, "network")])

    def test_an_allow_with_a_reason_covers_its_line_or_the_next_and_one_without_covers_nothing(self):
        source = (
            "let a = Instant::now(); // testkit-lint: allow(wall-clock) a nightly budget test's bound\n"
            "// testkit-lint: allow(sleep) the sandbox's own timer under test\n"
            "std::thread::sleep(d);\n"
            "let b = Instant::now(); // testkit-lint: allow(wall-clock)\n"
        )
        self.assertEqual(rules(TEST_FILE, source), [(4, "wall-clock")])

    def test_an_allow_on_a_code_line_does_not_cover_the_next_line(self):
        source = (
            "let a = Instant::now(); // testkit-lint: allow(wall-clock, sleep) a budget test's bound\n"
            "std::thread::sleep(d);\n"
        )
        self.assertEqual(rules(TEST_FILE, source), [(2, "sleep")])

    def test_raw_strings_char_literals_and_nested_comments_are_classified(self):
        source = (
            'let a = r#"thread::sleep(d) "quoted" "#; let b = \'"\'; std::thread::sleep(d);\n'
            "/* outer /* inner */ Instant::now() */ let c = Instant::now();\n"
            "fn f<'a>(x: &'a str) { std::thread::sleep(d); }\n"
        )
        self.assertEqual(rules(TEST_FILE, source), [(1, "sleep"), (2, "wall-clock"), (3, "sleep")])

    def test_a_multibyte_character_in_a_string_keeps_the_rest_of_the_line_in_code(self):
        source = 'let s = "é ü"; let c = \'é\'; std::thread::sleep(d);\n'
        self.assertEqual(rules(TEST_FILE, source), [(1, "sleep")])

    def test_a_port_above_u32_or_zero_is_no_fixed_port(self):
        source = 'let a = "127.0.0.1:99999999999";\nlet b = "localhost:0";\nlet c = "x127.0.0.1:80";\n'
        self.assertEqual(rules(TEST_FILE, source), [])


class Totals(unittest.TestCase):
    def test_moving_a_finding_changes_no_total_and_a_new_one_raises_it(self):
        before = LINT.scan_source(TEST_FILE, "fn a() { std::thread::sleep(d); }\n")
        moved = LINT.scan_source("crates/oneiron/tests/moved.rs", "fn a() { std::thread::sleep(d); }\n")
        grown = LINT.scan_source(TEST_FILE, "fn a() { std::thread::sleep(d); }\nfn b() { std::thread::sleep(d); }\n")
        self.assertEqual(LINT.totals(before)["sleep"], 1)
        self.assertEqual(LINT.totals(moved), LINT.totals(before))
        self.assertEqual(LINT.totals(grown)["sleep"], 2)
        self.assertEqual(LINT.totals([])["sleep"], 0)

    def test_the_baseline_text_is_the_rust_lints_body(self):
        findings = LINT.scan_source(TEST_FILE, "fn a() { std::thread::sleep(d); let t = Instant::now(); }\n")
        findings += LINT.scan_source("crates/a/tests/b.rs", "fn a() { std::thread::sleep(d); }\n")
        body = [line for line in LINT.baseline_text(findings).splitlines() if not line.startswith("#")]
        self.assertEqual(
            body,
            [
                "sleep 2",
                "wall-clock 1",
                "network 0",
                "fixed-port 0",
                "real-model 0",
                "sleep crates/a/tests/b.rs 1",
                "sleep crates/oneiron/tests/sample.rs 1",
                "wall-clock crates/oneiron/tests/sample.rs 1",
            ],
        )


class CommandLine(unittest.TestCase):
    def run_lint(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    def test_count_and_list_read_the_tree_and_skip_vendored_and_target_dirs(self):
        with tempfile.TemporaryDirectory() as tree:
            files = {
                "crates/a/tests/t.rs": "fn t() { std::thread::sleep(d); let i = Instant::now(); }\n",
                "crates/a/src/lib.rs": "fn shipped() { std::thread::sleep(d); }\n",
                "crates/heed/tests/t.rs": "fn t() { std::thread::sleep(d); }\n",
                "crates/a/target/tests/t.rs": "fn t() { std::thread::sleep(d); }\n",
                "apps/b/tests/t.rs": 'let u = "https://github.com/";\n',
            }
            for path, text in files.items():
                full = Path(tree, path)
                full.parent.mkdir(parents=True, exist_ok=True)
                full.write_text(text)
            count = self.run_lint("--count", tree)
            self.assertEqual((count.returncode, count.stdout), (0, "1 1 1 0 0\n"))
            listed = self.run_lint("--list", "--rule", "sleep", tree)
            self.assertEqual((listed.returncode, listed.stdout), (0, "crates/a/tests/t.rs:1: sleep: " + files["crates/a/tests/t.rs"]))

    def test_a_tree_with_no_rust_file_is_an_error_not_a_zero(self):
        with tempfile.TemporaryDirectory() as tree:
            Path(tree, "crates").mkdir()
            result = self.run_lint("--count", tree)
            self.assertEqual(result.returncode, 2)
            self.assertIn("no .rs files found", result.stderr)


if __name__ == "__main__":
    unittest.main()
