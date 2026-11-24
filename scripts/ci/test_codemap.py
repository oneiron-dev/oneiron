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


if __name__ == "__main__":
    unittest.main()
