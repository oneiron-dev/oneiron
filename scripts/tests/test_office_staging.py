"""Office runner contract tests using a fake app process; no Apple events."""
from argparse import Namespace
from pathlib import Path
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/office"))


def package(path, organ):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("_rels/.rels", "<Relationships/>")
        archive.writestr({"word": "word/document.xml", "ppt": "ppt/presentation.xml", "excel": "xl/workbook.xml"}[organ], "<root/>")


class OfficeStaging(unittest.TestCase):
    def exercise(self, name, organ, timeout):
        driver = importlib.import_module(name)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            extension = {"word": "docx", "ppt": "pptx", "excel": "xlsx"}[organ]
            source = base / ("source." + extension)
            package(source, organ)
            original = source.read_bytes()
            script = base / "driver.applescript"
            script.write_text("-- fake driver")
            stage = base / "container" / "run"
            stage.mkdir(parents=True)
            args = Namespace(input=source, output=base / "results", lock=base / "lock", script=script,
                             action="accept", expected=None if organ == "word" else 2.0,
                             sheet="Sheet1", cell="A1")
            def invoke(command, **kwargs):
                self.assertIn("alarm 120; exec @ARGV", command)
                self.assertEqual(kwargs["timeout"], 130)
                index = command.index(str(script))
                paths = command[index + 1:]
                self.assertTrue(Path(paths[0]).is_relative_to(stage))
                self.assertEqual(Path(paths[0]).read_bytes(), original)
                if name == "run_word_revision_oracle":
                    destinations = [Path(paths[2])]
                elif name == "run_excel_file_oracle":
                    destinations = [Path(paths[1])]
                else:
                    destinations = [Path(paths[1]), Path(paths[2])]
                for destination in destinations:
                    self.assertTrue(destination.is_relative_to(stage))
                if timeout:
                    raise subprocess.TimeoutExpired(command, 130)
                if name == "run_word_revision_oracle":
                    destinations[0].write_text("resolved")
                    result = "16.112.4\t2\t0\t1\t0\t0\n"
                else:
                    package(destinations[0], organ)
                    if len(destinations) > 1: destinations[1].write_bytes(b"%PDF-fake")
                    result = {"run_word_oracle": "16.112.4\t2\t0\t1\t0\t0\n",
                              "run_powerpoint_oracle": "16.112.4\t1\t0\t0\n",
                              "run_excel_file_oracle": "16.112.4\t2\t1\t1\t[user>saved]\t[user>saved]\n"}[name]
                return subprocess.CompletedProcess(command, 0, result, "")
            stage_fn = "word_stage" if name in ("run_word_oracle", "run_word_revision_oracle") else "app_stage"
            with patch.object(driver.sys, "platform", "darwin"), patch.object(driver, stage_fn, return_value=stage), patch.object(driver.subprocess, "run", side_effect=invoke):
                if timeout:
                    with self.assertRaises(subprocess.TimeoutExpired): driver.run(args)
                else:
                    driver.run(args)
            receipt = json.loads((args.output / "receipt.json").read_text())
            self.assertEqual(receipt["lock_retained"], timeout)
            self.assertEqual(args.lock.exists(), timeout)
            self.assertEqual(stage.exists(), timeout)
            self.assertEqual(source.read_bytes(), original)
            if timeout:
                self.assertEqual(Path(receipt["stage"]), stage)
                self.assertTrue((stage / source.name).is_file())
            else:
                self.assertEqual(receipt["status"], "completed")
                expected = "resolved.txt" if name == "run_word_revision_oracle" else "roundtrip." + extension
                self.assertTrue((args.output / expected).is_file())

    def test_all_app_paths_are_staged_and_outputs_return_after_cleanup(self):
        for name, organ in [("run_word_oracle", "word"), ("run_word_revision_oracle", "word"), ("run_powerpoint_oracle", "ppt"), ("run_excel_file_oracle", "excel")]:
            with self.subTest(driver=name): self.exercise(name, organ, False)

    def test_timeouts_keep_only_owned_staging_and_lock_for_recovery(self):
        for name, organ in [("run_word_oracle", "word"), ("run_word_revision_oracle", "word"), ("run_powerpoint_oracle", "ppt"), ("run_excel_file_oracle", "excel")]:
            with self.subTest(driver=name): self.exercise(name, organ, True)

    def test_container_names_include_case_sensitive_powerpoint_spelling(self):
        from run_word_oracle import app_stage
        with tempfile.TemporaryDirectory() as directory, patch("pathlib.Path.home", return_value=Path(directory)):
            for app, container in [("word", "com.microsoft.Word"), ("excel", "com.microsoft.Excel"), ("ppt", "com.microsoft.Powerpoint")]:
                stage = app_stage(app)
                self.assertTrue(stage.is_relative_to(Path(directory) / "Library/Containers" / container / "Data/tmp/w7-oracle"))
                self.assertTrue(stage.is_dir())


if __name__ == "__main__": unittest.main()
