"""The generated code map must be deterministic, fail closed, and follow the ratchet's definitions.

Runs under `python3 -m pytest scripts/tests/test_codemap.py -q` and, because the
cases are `unittest.TestCase`s, also under `python3 -m unittest` when pytest is
not installed. Every case builds its own fixture workspace in a temp dir; nothing
here depends on the real tree's numbers.
"""

import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/codemap/codemap.py"


def load_codemap():
    spec = importlib.util.spec_from_file_location("codemap", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


codemap = load_codemap()


def rust_lines(n, purpose=None):
    """A file of exactly `n` lines (LF-terminated), optionally with a `//!` head."""
    lines = []
    if purpose:
        lines.append(f"//! {purpose}")
    while len(lines) < n:
        lines.append(f"// line {len(lines) + 1}")
    return "\n".join(lines[:n]) + "\n"


class Fixture:
    """A temp workspace with one crate, `alpha`, in sibling (file+dir) style."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="codemap-"))
        self.root = self.dir / "repo"
        (self.root / "crates").mkdir(parents=True)
        self.crate("alpha", "Alpha is the fixture crate.")

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def crate(self, name, purpose=None, description=None):
        crate = self.root / "crates" / name
        (crate / "src").mkdir(parents=True)
        toml = ["[package]", f'name = "{name}"', 'version = "0.1.0"']
        if description:
            toml.append(f'description = "{description}"')
        (crate / "Cargo.toml").write_text("\n".join(toml) + "\n")
        (crate / "src/lib.rs").write_text(
            (f"//! {purpose}\n" if purpose else "") + "pub mod thing;\npub struct Root;\n"
        )
        return crate

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text)
        return path

    def run(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = codemap.main(["--root", str(self.root), *args])
        return code, out.getvalue()


class CodemapCase(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)


class TestNonTestDefinition(CodemapCase):
    def test_ratchet_definition(self):
        self.assertTrue(codemap.is_test_path("tests/it/flow.rs"))
        self.assertTrue(codemap.is_test_path("src/gate/tests/doors.rs"))
        self.assertTrue(codemap.is_test_path("src/gate/tests.rs"))
        self.assertTrue(codemap.is_test_path("src/gate/foo_tests.rs"))
        self.assertFalse(codemap.is_test_path("src/gate/doors.rs"))
        self.assertFalse(codemap.is_test_path("src/tests_helpers.rs"))
        self.assertFalse(codemap.is_test_path("src/contests.rs"))

    def test_kinds_and_counts_in_scan(self):
        self.fx.write("crates/alpha/src/thing.rs", rust_lines(5, "Thing"))
        self.fx.write("crates/alpha/src/thing/tests.rs", rust_lines(5))
        self.fx.write("crates/alpha/src/thing/unit_tests.rs", rust_lines(5))
        self.fx.write("crates/alpha/tests/it/flow.rs", rust_lines(5))
        data = codemap.scan_repo(self.fx.root)
        crate = data["crates"]["alpha"]
        kinds = {f["path"]: f["kind"] for f in crate["files"]}
        self.assertEqual(kinds["src/lib.rs"], "src")
        self.assertEqual(kinds["src/thing.rs"], "src")
        self.assertEqual(kinds["src/thing/tests.rs"], "test")
        self.assertEqual(kinds["src/thing/unit_tests.rs"], "test")
        self.assertEqual(kinds["tests/it/flow.rs"], "test")
        self.assertEqual(crate["source_files"], 2)
        self.assertEqual(crate["test_files"], 3)


class TestBuckets(CodemapCase):
    def test_boundaries(self):
        self.assertEqual(codemap.bucket(0), "s")
        self.assertEqual(codemap.bucket(299), "s")
        self.assertEqual(codemap.bucket(300), "m")
        self.assertEqual(codemap.bucket(799), "m")
        self.assertEqual(codemap.bucket(800), "L")
        self.assertEqual(codemap.bucket(1499), "L")
        self.assertEqual(codemap.bucket(1500), "XL")

    def test_boundaries_on_real_files(self):
        for n in (299, 300, 799, 800, 1499, 1500):
            self.fx.write(f"crates/alpha/src/f{n}.rs", rust_lines(n))
        self.fx.write("crates/alpha/src/f800_tests.rs", rust_lines(800))
        crate = codemap.scan_repo(self.fx.root)["crates"]["alpha"]
        buckets = {f["path"]: f["bucket"] for f in crate["files"]}
        self.assertEqual(buckets["src/f299.rs"], "s")
        self.assertEqual(buckets["src/f300.rs"], "m")
        self.assertEqual(buckets["src/f799.rs"], "m")
        self.assertEqual(buckets["src/f800.rs"], "L")
        self.assertEqual(buckets["src/f1499.rs"], "L")
        self.assertEqual(buckets["src/f1500.rs"], "XL")
        # Over-bar counts non-test files only: f800, f1499, f1500 (not the 800-line test file).
        self.assertEqual(crate["over_bar"], 3)

    def test_line_count_is_wc_style(self):
        self.assertEqual(codemap.count_lines(b""), 0)
        self.assertEqual(codemap.count_lines(b"a\n"), 1)
        self.assertEqual(codemap.count_lines(b"a\nb"), 2)
        self.assertEqual(codemap.count_lines(b"a\r\nb\r\n"), 2)


class TestPurpose(CodemapCase):
    def purpose(self, text):
        if isinstance(text, str):
            text = text.encode("utf-8")
        return codemap.extract_purpose(codemap.decode_lines(text))

    def test_first_doc_line_with_trailing_period_trimmed(self):
        self.assertEqual(self.purpose("//! Gate resolver.\n//! More detail.\nfn x() {}\n"), "Gate resolver")

    def test_wrapped_sentence_extends_to_its_end(self):
        text = "//! ARCH ledger: what the system\n//! learned. Second sentence here.\n"
        self.assertEqual(self.purpose(text), "ARCH ledger: what the system learned")

    def test_blank_doc_line_and_license_header_skipped(self):
        text = "// Copyright\n\n#![allow(dead_code)]\n//!\n//! Real purpose\n"
        self.assertEqual(self.purpose(text), "Real purpose")

    def test_code_stops_the_scan(self):
        text = "use std::fmt;\nmod inner {\n    //! Not the file purpose\n}\n"
        self.assertEqual(self.purpose(text), "—")

    def test_cap_at_110(self):
        long = "//! " + " ".join(["word"] * 60) + ".\n"
        got = self.purpose(long)
        self.assertLessEqual(len(got), 110)
        self.assertTrue(got.endswith("…"))
        exactly = "//! " + ("x" * 110) + ".\n"
        self.assertEqual(len(self.purpose(exactly)), 110)

    def test_odd_files_never_crash(self):
        self.assertEqual(self.purpose(b""), "—")
        self.assertEqual(self.purpose(b"\xff\xfe\x00//! bin\x00"), "—")
        self.assertEqual(self.purpose(b"//! CRLF purpose.\r\nfn x() {}\r\n"), "CRLF purpose")
        self.assertEqual(self.purpose(b"//! caf\xc3\xa9 \xff done\n"), "café � done")

    def test_pipe_is_escaped_in_markdown(self):
        self.fx.write("crates/alpha/src/thing.rs", "//! a | b\n")
        data = codemap.scan_repo(self.fx.root)
        page = codemap.render_crate("alpha", data["crates"]["alpha"])
        self.assertIn("a \\| b", page)

    def test_crate_purpose_falls_back_to_cargo_description(self):
        self.fx.crate("beta", description="Beta from Cargo.toml.")
        self.fx.crate("gamma")
        crates = codemap.scan_repo(self.fx.root)["crates"]
        self.assertEqual(crates["alpha"]["purpose"], "Alpha is the fixture crate")
        self.assertEqual(crates["beta"]["purpose"], "Beta from Cargo.toml")
        self.assertEqual(crates["gamma"]["purpose"], "—")


class TestLayout(CodemapCase):
    def test_file_dir_and_sibling(self):
        self.fx.write("crates/alpha/src/only_file.rs", "//! Only a file\n")
        self.fx.write("crates/alpha/src/only_dir/mod.rs", "//! Only a dir\n")
        self.fx.write("crates/alpha/src/only_dir/child.rs", rust_lines(300))
        self.fx.write("crates/alpha/src/both.rs", "//! Sibling style\n")
        self.fx.write("crates/alpha/src/both/child.rs", rust_lines(800))
        self.fx.write("crates/alpha/src/both/tests.rs", rust_lines(1500))
        self.fx.write("crates/alpha/src/bin/tool.rs", "fn main() {}\n")
        modules = codemap.scan_repo(self.fx.root)["crates"]["alpha"]["modules"]
        self.assertEqual(sorted(modules), ["both", "only_dir", "only_file"])
        self.assertEqual(modules["only_file"]["layout"], "file")
        self.assertEqual(modules["only_file"]["files"], 1)
        self.assertEqual(modules["only_dir"]["layout"], "dir")
        self.assertEqual(modules["only_dir"]["files"], 2)
        self.assertEqual(modules["only_dir"]["largest_src_bucket"], "m")
        self.assertEqual(modules["only_dir"]["purpose"], "Only a dir")
        self.assertEqual(modules["both"]["layout"], "file+dir")
        self.assertEqual(modules["both"]["files"], 3)
        # Largest NON-TEST bucket: the XL tests.rs does not count.
        self.assertEqual(modules["both"]["largest_src_bucket"], "L")
        self.assertEqual(modules["both"]["purpose"], "Sibling style")

    def test_root_only_crate_gets_one_row(self):
        crate = self.fx.crate("solo")
        (crate / "src/lib.rs").unlink()
        (crate / "src/main.rs").write_text("//! A binary.\nfn main() {}\n")
        modules = codemap.scan_repo(self.fx.root)["crates"]["solo"]["modules"]
        self.assertEqual(list(modules), ["main"])
        self.assertEqual(modules["main"]["layout"], "file")
        self.assertEqual(modules["main"]["purpose"], "A binary")


class TestPubSurface(CodemapCase):
    def test_counts_and_notable_types(self):
        self.fx.write(
            "crates/alpha/src/thing.rs",
            "\n".join(
                [
                    "pub struct A;",
                    "pub enum B {}",
                    "pub trait C {}",
                    "pub fn f() {}",
                    "pub async fn g() {}",
                    "pub const fn h() {}",
                    "pub const K: u8 = 1;",
                    "pub static S: u8 = 1;",
                    "pub type T = u8;",
                    "pub mod m {}",
                    "pub use crate::x::Y;",
                    "pub(crate) fn hidden() {}",
                    "pub(super) struct Hidden;",
                    "    pub struct Nested;",
                    "impl Vault {",
                    "}",
                    "",
                ]
            ),
        )
        crate = codemap.scan_repo(self.fx.root)["crates"]["alpha"]
        info = next(f for f in crate["files"] if f["path"] == "src/thing.rs")
        self.assertEqual(
            info["surface"],
            {
                "struct": 2,
                "enum": 1,
                "trait": 1,
                "fn": 3,
                "type": 1,
                "const": 1,
                "static": 1,
                "mod": 1,
                "re-export": 1,
                "crate-vis": 2,
            },
        )
        self.assertEqual(info["notable"], ["A", "B", "C", "Nested"])
        self.assertTrue(info["impl_vault"])
        self.assertTrue(crate["modules"]["thing"]["impl_vault"])
        self.assertTrue(crate["has_impl_vault"])
        self.assertEqual(codemap.notable_text([f"T{i}" for i in range(10)]), "T0, T1, T2, T3, T4, T5, T6, T7 +2")

    def test_impl_vault_column_only_where_present(self):
        self.fx.crate("beta")
        self.fx.write("crates/alpha/src/thing.rs", "impl Vault {}\n")
        top = codemap.render_top(codemap.scan_repo(self.fx.root))
        alpha = top.split("## alpha")[1].split("## beta")[0]
        beta = top.split("## beta")[1]
        self.assertIn("impl Vault", alpha)
        self.assertNotIn("impl Vault", beta)


class TestModes(CodemapCase):
    def artifact_bytes(self):
        return {
            rel: (self.fx.root / rel).read_bytes()
            for rel in sorted(p.relative_to(self.fx.root) for p in (self.fx.root / "docs").rglob("*") if p.is_file())
        }

    def test_generate_is_deterministic_and_check_passes(self):
        self.fx.write("crates/alpha/src/thing.rs", "//! Thing\npub struct Thing;\n")
        code, out = self.fx.run()
        self.assertEqual(code, 0, out)
        first = self.artifact_bytes()
        self.assertEqual(
            sorted(str(p) for p in first),
            ["docs/CODEMAP.md", "docs/codemap/alpha.md", "docs/codemap/codemap.json"],
        )
        code, _ = self.fx.run()
        self.assertEqual(code, 0)
        self.assertEqual(first, self.artifact_bytes())
        for content in first.values():
            self.assertNotIn(b"\r", content)
            self.assertNotIn(str(self.fx.root).encode(), content)
        code, out = self.fx.run("--check")
        self.assertEqual(code, 0, out)
        self.assertIn("CODEMAP-OK", out)
        data = json.loads(first[Path("docs/codemap/codemap.json")])
        self.assertEqual(list(data), ["crates"])
        self.assertNotIn("loc", json.dumps(data))

    def test_check_is_stale_after_a_new_file(self):
        self.fx.run()
        self.fx.write("crates/alpha/src/extra.rs", "//! Extra\n")
        code, out = self.fx.run("--check")
        self.assertEqual(code, 1)
        self.assertIn("docs/CODEMAP.md (differs)", out)
        self.assertIn("CODEMAP-STALE: run python3 scripts/codemap/codemap.py", out)
        code, _ = self.fx.run()
        self.assertEqual(code, 0)
        self.assertEqual(self.fx.run("--check")[0], 0)

    def test_check_fails_closed_on_missing_artifacts(self):
        code, out = self.fx.run("--check")
        self.assertEqual(code, 1)
        self.assertIn("(missing)", out)
        self.assertIn("CODEMAP-STALE", out)

    def test_orphan_crate_page_is_stale_then_removed(self):
        self.fx.run()
        self.fx.write("docs/codemap/gone.md", "# gone\n")
        code, out = self.fx.run("--check")
        self.assertEqual(code, 1)
        self.assertIn("docs/codemap/gone.md (orphan)", out)
        self.fx.run()
        self.assertFalse((self.fx.root / "docs/codemap/gone.md").exists())

    def test_empty_scan_is_an_error(self):
        shutil.rmtree(self.fx.root / "crates/alpha")
        code, out = self.fx.run()
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("CODEMAP-ERROR:"), out)

    def test_vendor_and_excluded_crates_are_skipped(self):
        self.fx.write("crates/alpha/vendor/dep/src/lib.rs", rust_lines(2000))
        self.fx.crate("heed")
        crates = codemap.scan_repo(self.fx.root)["crates"]
        self.assertNotIn("heed", crates)
        self.assertNotIn("vendor", " ".join(f["path"] for f in crates["alpha"]["files"]))

    def test_sizes_prints_exact_counts_sorted_desc(self):
        self.fx.write("crates/alpha/src/big.rs", rust_lines(42))
        self.fx.write("crates/alpha/src/big_tests.rs", rust_lines(7))
        code, out = self.fx.run("--sizes")
        self.assertEqual(code, 0)
        rows = [line.split() for line in out.splitlines()[1:-1]]
        self.assertEqual(rows[0][:3], ["alpha", "src/big.rs", "42"])
        self.assertEqual([r[2] for r in rows], sorted((r[2] for r in rows), key=int, reverse=True))
        self.assertEqual(next(r for r in rows if r[1] == "src/big_tests.rs")[3], "yes")
        self.assertFalse((self.fx.root / "docs").exists())


if __name__ == "__main__":
    unittest.main()
