"""Pin both featureless library process models in the CI test lanes."""

import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"


class CiWorkflowTests(unittest.TestCase):
    def test_featureless_tier_runs_under_cargo_test_and_nextest_on_both_lanes(self):
        lines = WORKFLOW.read_text().splitlines()
        for job in ("test", "test-linux"):
            start = lines.index(f"  {job}:") + 1
            end = next(
                (i for i in range(start, len(lines)) if lines[i].startswith("  ")
                 and not lines[i].startswith("    ") and lines[i].strip()),
                len(lines),
            )
            steps = []
            for line in lines[start:end]:
                if line.startswith("      - name: "):
                    steps.append({"name": line.removeprefix("      - name: ")})
                elif steps and line.startswith("        ") and not line.startswith("          "):
                    key, _, value = line.strip().partition(": ")
                    if key in ("run", "if"):
                        steps[-1][key] = value

            one_process = next(s for s in steps if s["name"] == "Featureless oneiron library tests")
            per_test = next(s for s in steps if s["name"] == "Featureless oneiron library tests (nextest, no retries)")
            self.assertEqual(one_process["run"], "cargo test -p oneiron --lib --no-default-features", job)
            self.assertEqual(
                per_test["run"],
                "cargo nextest run -p oneiron --lib --no-default-features "
                "--profile featureless --no-fail-fast --retries 0",
                job,
            )
            self.assertEqual(steps.index(per_test), steps.index(one_process) + 1, job)
            self.assertEqual(per_test.get("if"), one_process.get("if"), job)

    def test_workflow_guard_is_executed_by_python_check(self):
        lines = WORKFLOW.read_text()
        self.assertIn("python3 -m unittest discover -s scripts/tests -p 'test_ci_workflow.py' -v", lines)

    def test_build_guide_describes_both_ci_process_models(self):
        guide = (WORKFLOW.parents[2] / "docs/ops/build-performance.md").read_text()
        self.assertIn("shared-process", guide)
        self.assertIn("per-test-process", guide)
        self.assertNotIn("CI is unchanged", guide)
        self.assertNotIn("CI recipes, which remain unchanged", guide)
