#!/usr/bin/env python3
"""Tests for scripts/codemap/codemap.py: spec ids, the capability alias table, and the loud
failure when an alias path stops existing.

Each test builds a small fixture repo (one crate, one alias table) in a temporary directory and
runs the generator against it with --root, so no test reads or writes the real map.
"""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "codemap"))
import codemap  # noqa: E402

HEADER = "| phrase | synonyms | paths | spec_ids | note |\n| --- | --- | --- | --- | --- |\n"
RELAY_ROW = (
    "| Run work on another node | remote call; mesh call | crates/demo/src/relay.rs | OF-575 "
    "| Routes a call to another node; it is not a scheduler. |\n"
)
ROOT_ROW = "| Start the demo crate | crate root | crates/demo/src/lib.rs |  | The crate root. |\n"
UNPLACED = "\n## Phrases not placed\n\n- **Undo any verb.** Tried `global undo`.\n"
GOOD_ALIASES = "# Aliases\n\nReviewed.\n\n" + HEADER + RELAY_ROW + ROOT_ROW + UNPLACED


def make_repo(tmp: str, aliases: str = GOOD_ALIASES) -> Path:
    root = Path(tmp)
    src = root / "crates" / "demo" / "src"
    src.mkdir(parents=True)
    (root / "crates" / "demo" / "Cargo.toml").write_text(
        '[package]\nname = "demo"\ndescription = "Demo crate."\n'
    )
    (src / "lib.rs").write_text("//! Demo crate root.\n\npub mod relay;\n")
    (src / "relay.rs").write_text(
        "//! Relays a call to another node.\n//!\n//! OF-575, EIRI-ARCH-0002.\n\npub fn relay() {}\n"
    )
    (root / codemap.ALIASES_PATH).parent.mkdir(parents=True)
    (root / codemap.ALIASES_PATH).write_text(aliases)
    return root


def run(root: Path, *args: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = codemap.main(["--root", str(root), *args])
    return rc, out.getvalue()


class SpecIdTest(unittest.TestCase):
    def test_spec_ids_keep_part_suffixes_and_family_prefixes(self):
        block = [
            "Nightly things (OF-498c, OF-575), the browser library (EIRI-ARCH-0002),",
            "CROSS-ARCH-0002b, ONEIRON-ARCH-0063 and ARCH-0023b; ARCH-023b is ARCH-0023b.",
            "Not spec ids: RESEARCH-0366, REVIEW-9863, ONE-1385, DEC-0005, FIX 3374, XOF-123.",
        ]
        self.assertEqual(
            codemap.extract_spec_ids(block),
            [
                "ARCH-0023b",
                "CROSS-ARCH-0002b",
                "EIRI-ARCH-0002",
                "OF-498c",
                "OF-575",
                "ONEIRON-ARCH-0063",
            ],
        )

    def test_spec_index_lists_a_prefixed_id_and_a_suffixed_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo(tmp)
            (root / "crates" / "demo" / "src" / "things.rs").write_text("//! Things (OF-498c).\n")
            rc, out = run(root)
            self.assertEqual(rc, 0, out)
            page = (root / codemap.SPEC_PATH).read_text()
            self.assertIn("| EIRI-ARCH-0002 | `crates/demo/src/relay.rs` |", page)
            self.assertIn("| OF-498c | `crates/demo/src/things.rs` |", page)


class TestPathTest(unittest.TestCase):
    def test_test_paths_match_the_ratchet(self):
        for rel in ("src/tests.rs", "src/a/b_tests.rs", "src/a/tests_saver.rs", "tests/x.rs", "src/tests/x.rs"):
            with self.subTest(rel):
                self.assertTrue(codemap.is_test_path(rel))
        for rel in ("src/lib.rs", "src/contests.rs", "src/attests_x.rs", "src/tests_x/mod_x.rs"):
            with self.subTest(rel):
                self.assertFalse(codemap.is_test_path(rel))

    def test_spec_index_skips_a_tests_prefixed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo(tmp)
            src = root / "crates" / "demo" / "src"
            (src / "lib.rs").write_text(
                "//! Demo crate root.\n\npub mod relay;\n#[cfg(test)]\nmod tests_saver;\n"
            )
            (src / "tests_saver.rs").write_text("//! Saver tests (ARCH-0052).\n")
            rc, out = run(root)
            self.assertEqual(rc, 0, out)
            self.assertNotIn("ARCH-0052", (root / codemap.SPEC_PATH).read_text())
            self.assertIn("| `src/tests_saver.rs` | test |", (root / codemap.DIR_PATH / "demo.md").read_text())


class AliasPathTest(unittest.TestCase):
    def test_alias_path_that_stops_existing_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo(tmp)
            rc, out = run(root)
            self.assertEqual(rc, 0, out)
            page = (root / codemap.CAPABILITY_PATH).read_text()
            self.assertIn("`crates/demo/src/relay.rs` (s)", page)
            self.assertIn("- **Undo any verb.** Tried `global undo`.", page)

            (root / "crates" / "demo" / "src" / "relay.rs").unlink()
            rc, out = run(root)
            self.assertEqual(rc, codemap.EXIT_ALIAS_MISSING, out)
            self.assertIn(
                "CODEMAP-ALIAS-MISSING: scripts/codemap/capability_aliases.md:7: "
                "crates/demo/src/relay.rs is not a file in the repo",
                out,
            )
            self.assertNotIn("CODEMAP-OK", out)
            page = (root / codemap.CAPABILITY_PATH).read_text()
            self.assertIn("`crates/demo/src/relay.rs` (MISSING: fix it in", page)
            self.assertIn("`crates/demo/src/lib.rs` (s)", page)

            rc, out = run(root, "--check")
            self.assertEqual(rc, 1, out)
            self.assertIn("CODEMAP-ALIAS-MISSING", out)

    def test_alias_path_outside_the_map_that_exists_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = "| Read the pack | pack text | packs/demo/PACK.md |  | The pack's own text. |\n"
            root = make_repo(tmp, HEADER + RELAY_ROW + row)
            (root / "packs" / "demo").mkdir(parents=True)
            (root / "packs" / "demo" / "PACK.md").write_text("# Demo pack\n")
            rc, out = run(root)
            self.assertEqual(rc, 0, out)
            page = (root / codemap.CAPABILITY_PATH).read_text()
            self.assertIn("`packs/demo/PACK.md` (outside the map)", page)
            rc, out = run(root, "--check")
            self.assertEqual(rc, 0, out)


class MalformedAliasFileTest(unittest.TestCase):
    CASES = {
        "renamed column": GOOD_ALIASES.replace("| paths |", "| files |", 1),
        "extra column": GOOD_ALIASES.replace("| note |\n", "| note | owner |\n", 1),
        "no separator row": "# Aliases\n\n| phrase | synonyms | paths | spec_ids | note |\n"
        + RELAY_ROW,
        "extra cell": HEADER + RELAY_ROW.replace(" |\n", " | extra |\n"),
        "missing cell": HEADER + "| Run work | remote call | crates/demo/src/relay.rs | note |\n",
        "empty phrase": HEADER + RELAY_ROW.replace("| Run work on another node |", "|  |"),
        "empty note": HEADER + ROOT_ROW.replace("| The crate root. |", "|  |"),
        "empty paths": HEADER + ROOT_ROW.replace("crates/demo/src/lib.rs", ""),
        "empty list item": HEADER + RELAY_ROW.replace("remote call; mesh call", "remote call; ; x"),
        "absolute path": HEADER + ROOT_ROW.replace("crates/demo", "/crates/demo"),
        "parent path": HEADER + ROOT_ROW.replace("crates/demo", "crates/../demo"),
        "path twice": HEADER
        + ROOT_ROW.replace("crates/demo/src/lib.rs", "crates/demo/src/lib.rs; crates/demo/src/lib.rs"),
        "duplicate phrase": HEADER + ROOT_ROW + ROOT_ROW.replace("crate root", "root file"),
        "row after the table": HEADER + RELAY_ROW + "\n" + ROOT_ROW,
        "second table": HEADER + RELAY_ROW + "\n" + HEADER + ROOT_ROW,
        "no rows": "# Aliases\n\n" + HEADER,
        "no table": "# Aliases\n\nNothing here.\n",
        "prose under phrases not placed": HEADER + RELAY_ROW + UNPLACED + "Tried more terms.\n",
        "last row without its opening pipe": HEADER + RELAY_ROW + ROOT_ROW[1:],
        "last row without its closing pipe": HEADER + RELAY_ROW + ROOT_ROW.rstrip("|\n") + "\n",
        "pipe before the table": "# Aliases | draft\n\n" + HEADER + RELAY_ROW,
        "dot-slash path": HEADER + ROOT_ROW.replace("crates/demo", "./crates/demo"),
        "path twice in two spellings": HEADER
        + ROOT_ROW.replace("crates/demo/src/lib.rs", "crates/demo/src/lib.rs; ./crates/demo/src/lib.rs"),
        "doubled slash": HEADER + ROOT_ROW.replace("crates/demo", "crates//demo"),
        "trailing slash": HEADER + ROOT_ROW.replace("lib.rs", "lib.rs/"),
        "dot path": HEADER + ROOT_ROW.replace("crates/demo/src/lib.rs", "."),
        "non-heading under phrases not placed": GOOD_ALIASES + "\n#typo\nnot a bullet\n",
        "heading after phrases not placed": GOOD_ALIASES + "\n## More\n\nTried more terms.\n",
        "second phrases not placed": GOOD_ALIASES + UNPLACED,
        "phrases not placed before the table": "# Aliases\n" + UNPLACED + "\n" + HEADER + RELAY_ROW,
        "prose after the table": HEADER + RELAY_ROW + "\nA note.\n",
        "indented phrases not placed": HEADER + RELAY_ROW + UNPLACED.replace("## ", " ## "),
    }

    def test_malformed_alias_files_fail_closed(self):
        for name, text in self.CASES.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                root = make_repo(tmp, text)
                with self.assertRaises(codemap.CodemapError):
                    codemap.load_aliases(root)
                rc, out = run(root)
                self.assertEqual(rc, 1, out)
                self.assertTrue(out.startswith("CODEMAP-ERROR: "), out)
                self.assertFalse((root / codemap.CAPABILITY_PATH).exists())

    def test_unreadable_alias_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo(tmp)
            (root / codemap.ALIASES_PATH).unlink()
            rc, out = run(root)
            self.assertEqual(rc, 1, out)
            self.assertIn("CODEMAP-ERROR: unreadable alias file", out)

    def test_good_alias_file_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            aliases, unplaced = codemap.load_aliases(make_repo(tmp))
        self.assertEqual(
            aliases[0],
            {
                "line": 7,
                "phrase": "Run work on another node",
                "synonyms": ["remote call", "mesh call"],
                "paths": ["crates/demo/src/relay.rs"],
                "spec_ids": ["OF-575"],
                "note": "Routes a call to another node; it is not a scheduler.",
            },
        )
        self.assertEqual(aliases[1]["spec_ids"], [])
        self.assertEqual(unplaced, ["**Undo any verb.** Tried `global undo`."])


class CheckedInAliasFileTest(unittest.TestCase):
    """The checked-in alias table parses, and each one-line damage to it fails closed."""

    TEXT = (Path(__file__).resolve().parents[2] / codemap.ALIASES_PATH).read_text()

    def load(self, text: str) -> tuple[list[dict], list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            return codemap.load_aliases(make_repo(tmp, text))

    def edit_line(self, number: int, edit) -> str:
        lines = self.TEXT.split("\n")
        lines[number - 1] = edit(lines[number - 1])
        return "\n".join(lines)

    def test_checked_in_alias_file_parses(self):
        aliases, unplaced = self.load(self.TEXT)
        self.assertEqual(len(aliases), 100)
        self.assertEqual(len(unplaced), 3)

    def test_last_row_without_its_opening_pipe_fails(self):
        last_row = max(a["line"] for a in self.load(self.TEXT)[0])
        with self.assertRaisesRegex(codemap.CodemapError, rf":{last_row}: a table row outside"):
            self.load(self.edit_line(last_row, lambda line: line.replace("|", "", 1)))

    def test_one_path_in_two_spellings_fails(self):
        first = self.load(self.TEXT)[0][0]
        path = first["paths"][0]
        text = self.edit_line(first["line"], lambda line: line.replace(path, f"{path}; ./{path}", 1))
        with self.assertRaisesRegex(codemap.CodemapError, rf":{first['line']}: write the path"):
            self.load(text)

    def test_appended_non_heading_and_prose_fail(self):
        with self.assertRaisesRegex(codemap.CodemapError, "is one `- ` bullet"):
            self.load(self.TEXT + "\n#typo\nnot a bullet\n")


if __name__ == "__main__":
    unittest.main()
