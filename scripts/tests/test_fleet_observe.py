import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("fleet_observe", Path(__file__).resolve().parents[1] / "fleet-observe.py")
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class FleetProcessReceiptTests(unittest.TestCase):
    def test_success_and_failure_are_terminal_without_becoming_fleet_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            for code in [0, 7]:
                path = Path(directory) / f"{code}.json"
                self.assertEqual(OBSERVER.observe([sys.executable, "-c", f"raise SystemExit({code})"], path), code)
                row = json.loads(path.read_text())
                self.assertTrue(row["terminal"])
                self.assertEqual(row["exit_code"], code)
                self.assertIsNone(row["signal"])
                self.assertGreater(row["max_rss_bytes"], 0)
                self.assertNotIn("metrics", row)
                with self.assertRaises(FileExistsError):
                    OBSERVER.observe([sys.executable, "-c", "raise SystemExit(0)"], path)

    def test_signal_keeps_the_signal_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "signal.json"
            self.assertEqual(OBSERVER.observe([sys.executable, "-c", "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"], path), 143)
            row = json.loads(path.read_text())
            self.assertEqual(row["exit_code"], -15)
            self.assertEqual(row["signal"], 15)

    def test_missing_executable_is_not_reported_as_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            self.assertEqual(OBSERVER.observe([str(Path(directory) / "absent")], path), 127)
            self.assertIn("launch_error", json.loads(path.read_text()))

    def test_detached_measurement_has_independent_session_and_terminal_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"detached.json"
            log=Path(directory)/"child.log"
            identity=Path(directory)/"identity.json"
            probe="import os,json;from pathlib import Path;Path("+repr(str(identity))+").write_text(json.dumps({'session':os.getsid(0),'group':os.getpgrp()}));raise SystemExit(7)"
            self.assertEqual(OBSERVER.detach([sys.executable,"-c",probe],path,log),0)
            admission=json.loads(Path(str(path)+".admission.json").read_text())
            pid,status=os.waitpid(admission["observer_pid"],0)
            self.assertEqual(os.waitstatus_to_exitcode(status),7)
            self.assertNotEqual(pid,os.getsid(0))
            self.assertEqual(json.loads(identity.read_text()),{"session":pid,"group":pid})
            result=json.loads(path.read_text())
            self.assertTrue(result["terminal"])
            self.assertEqual(result["exit_code"],7)
