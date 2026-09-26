"""Pin the split CI test jobs and both featureless process models."""

import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
FEATURELESS = (
    "Featureless oneiron library tests",
    "Featureless oneiron library tests (nextest, no retries)",
)


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = WORKFLOW.read_text().splitlines()

    def job_lines(self, job):
        start = self.lines.index(f"  {job}:") + 1
        end = next(
            (i for i in range(start, len(self.lines)) if self.lines[i].startswith("  ")
             and not self.lines[i].startswith("    ") and self.lines[i].strip()),
            len(self.lines),
        )
        return self.lines[start:end]

    def steps(self, job):
        steps = []
        for line in self.job_lines(job):
            if line.startswith("      - name: "):
                steps.append({"name": line.removeprefix("      - name: ")})
            elif line.startswith("      - uses: "):
                steps.append({"uses": line.removeprefix("      - uses: ")})
            elif steps and line.startswith("        ") and not line.startswith("          "):
                key, _, value = line.strip().partition(": ")
                if key in ("run", "if"):
                    steps[-1][key] = value
        return steps

    def test_linux_jobs_run_in_parallel_and_report_on_docs_only_prs(self):
        workspace = self.job_lines("test-linux")
        featureless = self.job_lines("test-linux-featureless")
        self.assertIn("    name: Test", workspace)
        self.assertIn("    name: Test (featureless)", featureless)
        for job in (workspace, featureless):
            self.assertIn("    runs-on: [self-hosted, linux, x64]", job)
            self.assertIn("    timeout-minutes: 90", job)
            self.assertIn("    needs: changes", job)
            self.assertNotIn("    needs: test-linux", job)
        # Compare the complete multiline job gate, not just the PR clause.
        def gate(lines):
            start = lines.index("    if: >-")
            return lines[start:lines.index("    steps:", start)]

        self.assertEqual(gate(workspace), gate(featureless))
        self.assertIn("        || github.event_name == 'pull_request'", gate(featureless))
        self.assertIn("      always()", gate(featureless))
        self.assertIn("      && vars.CI_PAUSED != 'true' && (github.event_name != 'pull_request' || github.event.pull_request.draft == false)", gate(featureless))

    def test_linux_jobs_have_the_same_needed_setup_and_cargo_step_gate(self):
        workspace, featureless = (self.steps(job) for job in ("test-linux", "test-linux-featureless"))
        self.assertEqual(workspace[:4], featureless[:4])
        self.assertEqual(workspace[0]["uses"], "actions/checkout@v4")
        self.assertEqual(
            [s["name"] for s in workspace[1:4]],
            ["Shared compiler cache (sccache 0.15.0)",
             "Toolchain (host rustup, pinned by rust-toolchain.toml)",
             "cargo-nextest (host copy, else a pinned install under ~/ci/tools)"],
        )
        cargo_gate = workspace[3]["if"]
        self.assertIn("needs.changes.outputs.rust == 'true'", cargo_gate)
        self.assertIn("needs.changes.result != 'success'", cargo_gate)
        self.assertIn("github.event_name == 'workflow_dispatch'", cargo_gate)
        for steps in (workspace, featureless):
            for step in steps[4:]:
                self.assertEqual(step.get("if"), cargo_gate, step["name"])

    def test_featureless_tier_runs_under_cargo_test_and_nextest_only_in_featureless_jobs(self):
        for job in ("test", "test-linux-featureless"):
            steps = self.steps(job)
            names = [s.get("name") for s in steps]
            one_process = steps[names.index(FEATURELESS[0])]
            per_test = steps[names.index(FEATURELESS[1])]
            self.assertEqual(one_process["run"], "cargo test -p oneiron --lib --no-default-features", job)
            self.assertEqual(
                per_test["run"],
                "cargo nextest run -p oneiron --lib --no-default-features "
                "--profile featureless --no-fail-fast --retries 0",
                job,
            )
            self.assertEqual(names.index(FEATURELESS[1]), names.index(FEATURELESS[0]) + 1, job)
            self.assertEqual(per_test.get("if"), one_process.get("if"), job)
        workspace = self.steps("test-linux")
        names = [s.get("name") for s in workspace]
        self.assertTrue(all(name not in names for name in FEATURELESS))
        self.assertEqual(names[-2:], ["Workspace tests (nextest, full tier, bench included)", "Doctests"])
        self.assertEqual(workspace[-2]["run"], "cargo nextest run --workspace --exclude oneiron-napi --all-features --profile full --no-fail-fast")
        self.assertEqual(workspace[-1]["run"], "cargo test --doc --workspace --exclude oneiron-bench --all-features")
        self.assertEqual([s.get("name") for s in self.steps("test-linux-featureless")][-2:], list(FEATURELESS))

    def test_workflow_guard_is_executed_by_python_check(self):
        lines = WORKFLOW.read_text()
        self.assertIn("python3 -m unittest discover -s scripts/tests -p 'test_ci_workflow.py' -v", lines)

    def test_build_guide_describes_split_ci_process_models(self):
        guide = (WORKFLOW.parents[2] / "docs/ops/build-performance.md").read_text()
        self.assertIn("shared-process", guide)
        self.assertIn("per-test-process", guide)
        self.assertIn("`Test (featureless)`", guide)
        self.assertNotIn("Both CI test jobs run", guide)
        self.assertNotIn("CI is unchanged", guide)
        self.assertNotIn("CI recipes, which remain unchanged", guide)
