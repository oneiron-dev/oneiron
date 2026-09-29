"""Archived Office receipts are named by path and BLAKE3; their bytes never land in this repo.

Receipts are evidence of past oracle runs. They stay on the kept branch and in the offline
evidence archive; `archived-receipts.json` is the only trace of them here. Adding a receipt
back to the tree, or a pointer that escapes the archive root, fails this test.
"""

import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "crates/oneiron-docedit/tests/fixtures"
POINTER = FIXTURES / "archived-receipts.json"
ARCHIVE = "/Volumes/Cinema/archive/w7-evidence/W7-C14/"
BLAKE3 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")


class ArchivedReceiptPointers(unittest.TestCase):
    def test_every_archived_receipt_is_named_with_its_blake3(self):
        pointer = json.loads(POINTER.read_text())
        self.assertEqual(set(pointer), {"archive", "kept_branch", "kept_commit", "hash", "files"})
        self.assertEqual(pointer["archive"], ARCHIVE)
        archive = PurePosixPath(pointer["archive"])
        self.assertTrue(archive.is_absolute())
        self.assertEqual(archive.parts[-2:], ("w7-evidence", "W7-C14"))
        self.assertEqual(pointer["kept_branch"], "w7/W7-C14")
        self.assertIsNotNone(COMMIT.fullmatch(pointer["kept_commit"]), pointer["kept_commit"])
        self.assertEqual(pointer["hash"], "blake3")

        files = pointer["files"]
        self.assertTrue(files, "the pointer must name at least one archived receipt")
        paths = [entry["path"] for entry in files]
        self.assertEqual(paths, sorted(paths), "entries are sorted by path")
        self.assertEqual(len(paths), len(set(paths)), "duplicate archived path")
        for entry in files:
            with self.subTest(path=entry.get("path")):
                self.assertEqual(set(entry), {"path", "bytes", "blake3"})
                path = entry["path"]
                self.assertIsInstance(path, str)
                relative = PurePosixPath(path)
                self.assertFalse(relative.is_absolute(), "archived path must be relative")
                self.assertNotIn("\\", path)
                self.assertNotIn("..", relative.parts)
                self.assertNotIn(".", path.split("/"))
                self.assertNotIn("", path.split("/"))
                joined = PurePosixPath(posixpath.normpath(archive / relative))
                self.assertTrue(joined.is_relative_to(archive) and joined != archive,
                                f"{path} escapes {archive}")
                self.assertIsNotNone(BLAKE3.fullmatch(entry["blake3"]), entry["blake3"])
                self.assertIs(type(entry["bytes"]), int)
                self.assertGreater(entry["bytes"], 0)
                landed = FIXTURES / path
                self.assertFalse(landed.exists() or landed.is_symlink(),
                                 f"archived receipt {path} is in the working tree")


if __name__ == "__main__":
    unittest.main()
