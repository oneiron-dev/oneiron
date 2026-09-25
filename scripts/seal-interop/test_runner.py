"""CLI contract smoke tests; all wrappers and PDFs are fixtures, no readers needed."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

RUNNER = Path(__file__).with_name("runner.py")

class RunnerTests(unittest.TestCase):
    def test_reader_emits_normalized_tsv_row(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); pdf=root/"sample.pdf"; pdf.write_bytes(b"%PDF-1.4\n")
            wrapper=root/"wrapper"; wrapper.write_text("#!/usr/bin/env python3\nimport json\nprint(json.dumps({'reader':'dss','version':'6.5','mode':'verify','status':'pass','detail':'fixture'}))\n")
            wrapper.chmod(0o755)
            env=os.environ.copy(); env["SEAL_DSS_BIN"]=str(wrapper)
            p=subprocess.run([sys.executable,str(RUNNER),"--reader","dss",str(pdf)],env=env,text=True,capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)
            row=p.stdout.strip().split("\t")
            self.assertEqual(row[:2],["dss","6.5"])
            self.assertIn("linux-x86_64/",row[2])
            self.assertEqual(row[3:5],["verify","pass"])
    def test_missing_wrapper_is_reported_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); pdf=root/"sample.pdf"; pdf.write_bytes(b"%PDF-1.4\n")
            env=os.environ.copy(); env["SEAL_DSS_BIN"]=str(root/"missing")
            p=subprocess.run([sys.executable,str(RUNNER),"--reader","dss",str(pdf)],env=env,text=True,capture_output=True)
            self.assertEqual(p.returncode,77)
            row=p.stdout.strip().split("\t")
            self.assertEqual(row[:2],["dss","unavailable"])
            self.assertEqual(row[4],"unavailable")

if __name__=="__main__": unittest.main()
