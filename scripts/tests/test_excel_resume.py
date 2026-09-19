"""Observable custody and receipt laws for the Excel resume supervisor."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    "resume_excel", Path(__file__).parents[1] / "office/resume_real_excel_oracle.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExcelResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.args = SimpleNamespace(
            output=root / "oracle", manifest=root / "manifest.jsonl",
            driver=root / "driver.py", script=root / "driver.applescript",
            lock=root / "lock", container=root / "container",
            inventory=root / "inventory.applescript", close_owned=root / "close.applescript")
        for directory in [self.args.output, self.args.lock, self.args.container]:
            directory.mkdir()
        self.args.driver.write_text("immutable driver")
        self.args.script.write_text("immutable script")
        self.stage = self.args.container / "owned-123"
        self.stage.mkdir()
        input_bytes = b"hash-verified staged input"
        import hashlib
        self.key = hashlib.sha256(input_bytes).hexdigest()
        self.case = self.stage / self.key
        self.case.mkdir()
        self.input = self.case / "input.xlsx"
        self.input.write_bytes(input_bytes)
        prior = dict(sha256="a" * 64, path="prior.xlsx", status="completed",
                     app_version="16.112.4", calculation="calculate full rebuild", final_workbooks=0)
        output = self.args.output / (prior["sha256"] + ".xlsx")
        output.write_bytes(b"previous Excel output")
        prior["output_sha256"] = MODULE.sha(output)
        self.row = dict(sha256=self.key, path="nested/input.xlsx", status="timed-out", exit_code=-14)
        entries = [dict(sha256=r["sha256"], path=r["path"]) for r in [prior, self.row]]
        self.args.manifest.write_text("\n".join(map(json.dumps, entries)))
        self.rows = self.args.output / "rows.jsonl"
        self.rows.write_text("\n".join(map(json.dumps, [prior, self.row])))
        identity = dict(manifest_sha256=MODULE.sha(self.args.manifest),
                        driver_sha256=MODULE.sha(self.args.driver), script_sha256=MODULE.sha(self.args.script))
        (self.args.output / "identity.json").write_text(json.dumps(identity))
        self.owner = f"W7-C14 real workbook oracle {self.args.output}"
        (self.args.lock / "owner").write_text(self.owner)
        self.custody = dict(owner=self.owner, lock_retained=True, stage=str(self.stage))
        (self.args.output / "custody.json").write_text(json.dumps(self.custody))
        self.calls = []

    def runner(self, replies):
        replies = iter(replies)
        def run(command, **kwargs):
            self.calls.append(command)
            return subprocess.CompletedProcess(command, 0, next(replies), "")
        return run

    def owned(self):
        return f"1\ninput.xlsx\t{self.case}\ttrue\n"

    def test_owned_timeout_closes_only_owned_input_and_preserves_raw_evidence(self):
        before = self.rows.read_bytes()
        identity = (self.args.output / "identity.json").read_bytes()
        self.assertEqual(MODULE.recover(self.args, self.runner([self.owned(), "0\n", "0\n"])), 2)
        self.assertEqual(self.rows.read_bytes(), before)
        self.assertEqual((self.args.output / "identity.json").read_bytes(), identity)
        self.assertFalse(self.args.lock.exists())
        self.assertFalse(self.stage.exists())
        close = self.calls[1]
        self.assertEqual(close[-3:], [str(self.args.close_owned), "input.xlsx", str(self.case)])
        archive = next(self.args.output.glob("recovery-*"))
        receipt = json.loads((archive / "receipt.json").read_text())
        self.assertEqual(receipt["timeout_row_preserved"], self.row)
        self.assertEqual(receipt["completed_rows_reused"], 1)
        self.assertFalse(receipt["foreign_workbooks_touched"])
        self.assertEqual(json.loads((archive / "custody.json").read_text()), self.custody)

    def test_foreign_unsaved_recovered_and_extra_workbooks_refuse_without_close(self):
        for books in ["1\nBook1\t\tfalse\n", "1\ninput.xlsx\t/foreign\ttrue\n",
                      f"1\ninput.xlsx (Recovered)\t{self.case}\tfalse\n",
                      self.owned().replace("1\n", "2\n", 1) + "User.xlsx\t/foreign\ttrue\n"]:
            with self.subTest(books=books):
                self.calls.clear()
                with self.assertRaisesRegex(ValueError, "foreign or recovered"):
                    MODULE.recover(self.args, self.runner([books]))
                self.assertTrue(self.args.lock.exists())
                self.assertTrue(self.input.exists())
                self.assertEqual([call[-1] for call in self.calls], [str(self.args.inventory)])

    def test_changed_driver_or_input_refuses_before_any_office_call(self):
        for target in [self.args.driver, self.input]:
            with self.subTest(target=target):
                original = target.read_bytes()
                target.write_bytes(b"substituted")
                with self.assertRaises(ValueError):
                    MODULE.recover(self.args, self.runner([]))
                self.assertEqual(self.calls, [])
                self.assertTrue(self.args.lock.exists())
                target.write_bytes(original)

    def test_book_appearing_after_close_keeps_lock_and_staging(self):
        with self.assertRaisesRegex(ValueError, "appeared"):
            MODULE.recover(self.args, self.runner([self.owned(), "0\n", "1\nUser.xlsx\t/foreign\ttrue\n"]))
        self.assertTrue(self.args.lock.exists())
        self.assertTrue(self.input.exists())
        self.assertFalse(list(self.args.output.glob("recovery-*")))

    def test_completed_corpus_does_not_take_a_subsequent_owners_lock(self):
        (self.args.lock / "owner").unlink()
        self.args.lock.rmdir()
        self.args.corpus = self.input.parent
        def finished(command):
            self.assertIn(str(self.args.driver), command)
            self.args.lock.mkdir()
            (self.args.lock / "owner").write_text("another Office owner")
            custody = dict(self.custody, lock_retained=False)
            (self.args.output / "custody.json").write_text(json.dumps(custody))
            return subprocess.CompletedProcess(command, 0)
        with patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.subprocess, "run", finished):
            MODULE.run(self.args)
        self.assertEqual((self.args.lock / "owner").read_text(), "another Office owner")

    def test_duplicate_or_corrupt_prior_output_refuses(self):
        before = self.rows.read_text()
        self.rows.write_text(before + "\n" + json.dumps(self.row))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            MODULE.verify(self.args)
        self.rows.write_text(before)
        (self.args.output / ("a" * 64 + ".xlsx")).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "prior output hash"):
            MODULE.verify(self.args)


if __name__ == "__main__":
    unittest.main()
