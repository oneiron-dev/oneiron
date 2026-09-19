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
        self.args.inventory.write_text("indexed read-only inventory")
        self.args.close_owned.write_text("close only the exact owned workbook")
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

    def test_inventory_timeout_retries_once_and_retains_failed_read_receipt(self):
        prior_rows = self.rows.read_bytes()
        successful = self.runner([self.owned(), "0\n", "0\n"])
        first = True
        def busy_then_ready(command, **kwargs):
            nonlocal first
            if first:
                first = False
                self.calls.append(command)
                return subprocess.CompletedProcess(command, -14, "", "")
            return successful(command, **kwargs)
        self.assertEqual(MODULE.recover(self.args, busy_then_ready), 2)
        self.assertEqual(self.rows.read_bytes(), prior_rows)
        self.assertFalse(self.args.lock.exists())
        self.assertFalse(self.stage.exists())
        failures = list(self.args.output.glob("inventory-failure-*.json"))
        self.assertEqual(len(failures), 1)
        failure = json.loads(failures[0].read_text())
        self.assertEqual(failure["status"], "inventory-timeout")
        self.assertEqual(failure["exit_code"], -14)
        self.assertEqual(failure["script_sha256"], MODULE.sha(self.args.inventory))
        self.assertEqual(self.calls[2][-3:], [str(self.args.close_owned), "input.xlsx", str(self.case)])

    def test_inventory_failure_retry_is_bounded_and_preserves_foreign_custody(self):
        for mode, expected_calls, expected_failures in [
                ("error", 1, 1), ("timeout", 2, 2), ("outer-timeout", 2, 2),
                ("changed-owner", 1, 1), ("changed-owner-success", 1, 0),
                ("foreign-book", 2, 1)]:
            with self.subTest(mode=mode):
                self.calls.clear()
                (self.args.lock / "owner").write_text(self.owner)
                before = set(self.args.output.glob("inventory-failure-*.json"))
                prior_rows = self.rows.read_bytes()
                def failing(command, **kwargs):
                    self.calls.append(command)
                    self.assertEqual(command[-1], str(self.args.inventory))
                    if mode in ("changed-owner", "changed-owner-success"):
                        (self.args.lock / "owner").write_text("another Office owner")
                    if mode == "changed-owner-success":
                        return subprocess.CompletedProcess(command, 0, self.owned(), "")
                    if mode == "outer-timeout":
                        raise subprocess.TimeoutExpired(command, 130, output=b"partial inventory")
                    if mode == "foreign-book" and len(self.calls) == 2:
                        return subprocess.CompletedProcess(command, 0, "1\nUser.xlsx\t/foreign\ttrue\n", "")
                    return subprocess.CompletedProcess(command, 1 if mode == "error" else -14, "", "")
                with self.assertRaises((RuntimeError, ValueError)):
                    MODULE.recover(self.args, failing)
                self.assertEqual(len(self.calls), expected_calls)
                failures = set(self.args.output.glob("inventory-failure-*.json")) - before
                self.assertEqual(len(failures), expected_failures)
                if mode == "outer-timeout":
                    self.assertTrue(all(json.loads(path.read_text())["exit_code"] is None for path in failures))
                if mode in ("changed-owner", "changed-owner-success"):
                    self.assertEqual((self.args.lock / "owner").read_text(), "another Office owner")
                self.assertTrue(self.input.exists())
                self.assertTrue(self.args.lock.exists())
                self.assertEqual(self.rows.read_bytes(), prior_rows)
                self.assertFalse(list(self.args.output.glob("recovery-*")))

    def enable_activation(self):
        self.args.activate_existing = self.args.output / "activate-existing.js"
        self.args.activate_existing.write_text("activate explicitly identified existing process")
        self.args.activate_pid = 1234

    def activation_reply(self, **changes):
        value = dict(pid=1234, bundle="com.microsoft.Excel", activated=True)
        value.update(changes)
        return json.dumps(value)

    def test_existing_process_activation_still_requires_owned_inventory_before_close(self):
        self.enable_activation()
        remaining = self.runner([self.owned(), "0\n", "0\n"])
        def activate_then_ready(command, **kwargs):
            if not self.calls:
                self.calls.append(command)
                return subprocess.CompletedProcess(command, -14, "", "")
            if command[-2] == str(self.args.activate_existing):
                self.calls.append(command)
                self.assertEqual(command[-4:], ["-l", "JavaScript", str(self.args.activate_existing), "1234"])
                return subprocess.CompletedProcess(command, 0, self.activation_reply(), "")
            return remaining(command, **kwargs)
        before = self.rows.read_bytes()
        self.assertEqual(MODULE.recover(self.args, activate_then_ready), 2)
        self.assertEqual(self.rows.read_bytes(), before)
        receipt = json.loads(next(self.args.output.glob("activation-*.json")).read_text())
        self.assertEqual(receipt["status"], "activated-existing")
        self.assertEqual(self.calls[3][-3:], [str(self.args.close_owned), "input.xlsx", str(self.case)])
        self.assertFalse(self.args.lock.exists())

    def test_activation_refusal_or_owner_change_never_closes_a_workbook(self):
        self.enable_activation()
        for mode in ["false", "wrong-pid", "wrong-app", "invalid-json", "timeout", "exit",
                     "owner-before", "owner-during"]:
            with self.subTest(mode=mode):
                self.calls.clear()
                (self.args.lock / "owner").write_text(self.owner)
                before = self.rows.read_bytes()
                def refused(command, **kwargs):
                    self.calls.append(command)
                    if len(self.calls) == 1:
                        if mode == "owner-before":
                            (self.args.lock / "owner").write_text("another owner")
                        return subprocess.CompletedProcess(command, -14, "", "")
                    self.assertEqual(command[-2], str(self.args.activate_existing))
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired(command, 40)
                    if mode == "owner-during":
                        (self.args.lock / "owner").write_text("another owner")
                    reply = {"false": self.activation_reply(activated=False),
                             "wrong-pid": self.activation_reply(pid=9),
                             "wrong-app": self.activation_reply(bundle="other.app"),
                             "invalid-json": "not JSON"}.get(mode, self.activation_reply())
                    return subprocess.CompletedProcess(command, 1 if mode == "exit" else 0, reply, "")
                with self.assertRaises((RuntimeError, ValueError)):
                    MODULE.recover(self.args, refused)
                self.assertEqual(len(self.calls), 1 if mode == "owner-before" else 2)
                self.assertTrue(self.args.lock.exists())
                self.assertTrue(self.input.exists())
                self.assertEqual(self.rows.read_bytes(), before)
                self.assertFalse(list(self.args.output.glob("recovery-*")))

    def test_activation_does_not_authorize_closing_foreign_or_recovered_books(self):
        self.enable_activation()
        for book in ["Book1\t\tfalse", "User.xlsx\t/foreign\ttrue",
                     f"input.xlsx (Recovered)\t{self.case}\tfalse"]:
            with self.subTest(book=book):
                self.calls.clear()
                replies = iter([(-14, ""), (0, self.activation_reply()), (0, "1\n" + book + "\n")])
                def foreign(command, **kwargs):
                    self.calls.append(command)
                    code, output = next(replies)
                    return subprocess.CompletedProcess(command, code, output, "")
                with self.assertRaises(ValueError):
                    MODULE.recover(self.args, foreign)
                self.assertEqual(len(self.calls), 3)
                self.assertTrue(self.input.exists())
                self.assertTrue(self.args.lock.exists())

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

    def test_new_corpus_runs_driver_once_and_checks_complete_receipts(self):
        import shutil
        saved = {p.name: p.read_bytes() for p in self.args.output.iterdir()}
        shutil.rmtree(self.args.output)
        (self.args.lock / "owner").unlink()
        self.args.lock.rmdir()
        self.args.corpus = self.input.parent
        commands = []
        def finished(command):
            commands.append(command)
            self.args.output.mkdir()
            for name, data in saved.items():
                (self.args.output / name).write_bytes(data)
            (self.args.output / "custody.json").write_text(json.dumps(dict(self.custody, lock_retained=False)))
            return subprocess.CompletedProcess(command, 0)
        with patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.subprocess, "run", finished):
            MODULE.run(self.args)
        self.assertEqual(len(commands), 1)
        self.assertEqual(json.loads((self.args.output / "identity.json").read_text()), json.loads(saved["identity.json"]))

    def test_new_corpus_refuses_an_existing_office_owner(self):
        import shutil
        shutil.rmtree(self.args.output)
        (self.args.lock / "owner").write_text("foreign owner")
        with patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.subprocess, "run") as driver:
            with self.assertRaisesRegex(ValueError, "already owned"):
                MODULE.run(self.args)
            driver.assert_not_called()
        self.assertEqual((self.args.lock / "owner").read_text(), "foreign owner")

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
