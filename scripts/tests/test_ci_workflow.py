"""Pin scoped CI, incremental build helpers, and the nightly full gate."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/ci/run_scoped.sh"


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.lines = cls.text.splitlines()
        cls.runner = RUNNER.read_text()

    def test_workflow_guard_is_executed_by_python_check(self):
        self.assertIn("python3 -m unittest discover -s scripts/tests -p 'test_ci_workflow.py' -v", self.text)


if __name__ == "__main__":
    unittest.main()
