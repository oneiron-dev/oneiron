"""Pin scoped CI: PRs and main pushes test what their diff touched; the full gate runs nightly."""

import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/ci/run_scoped.sh"
FEATURELESS_FULL = (
    "run cargo test -p oneiron --lib --no-default-features",
    "run cargo nextest run -p oneiron --lib --no-default-features --profile featureless --no-fail-fast --retries 0",
)
GUARD = (
    "      && vars.CI_PAUSED != 'true' && (github.event_name != 'pull_request' "
    "|| github.event.pull_request.draft == false)"
)


def load_scope():
    spec = importlib.util.spec_from_file_location("ci_scope", ROOT / "scripts/ci/ci_scope.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.lines = cls.text.splitlines()
        cls.runner = RUNNER.read_text()

    def job_lines(self, job):
        start = self.lines.index(f"  {job}:") + 1
        end = next(
            (i for i in range(start, len(self.lines)) if self.lines[i].startswith("  ")
             and not self.lines[i].startswith("    ") and self.lines[i].strip()),
            len(self.lines),
        )
        return self.lines[start:end]

    def test_required_contexts_always_report_and_honour_pause_and_drafts(self):
        for job, name in (("checks", "Checks"), ("test-linux", "Test"), ("test-linux-featureless", "Test (featureless)")):
            lines = self.job_lines(job)
            self.assertIn(f"    name: {name}", lines)
            self.assertIn("    needs: changes", lines)
            self.assertIn("      always()", lines)
            self.assertIn(GUARD, lines)

    def test_jobs_run_the_scoped_runner(self):
        self.assertIn("        run: scripts/ci/run_scoped.sh clippy", self.job_lines("checks"))
        self.assertIn("        run: scripts/ci/run_scoped.sh test", self.job_lines("test-linux"))
        self.assertIn("        run: scripts/ci/run_scoped.sh featureless", self.job_lines("test-linux-featureless"))

    def test_full_gate_runs_nightly_and_keeps_both_featureless_process_models(self):
        self.assertIn("    - cron: '0 18 * * *'", self.lines)
        first, second = (self.runner.index(c) for c in FEATURELESS_FULL)
        self.assertLess(first, second)
        self.assertIn("run cargo test --doc --workspace --exclude oneiron-bench --all-features", self.runner)
        self.assertIn("schedule | workflow_dispatch) python3 scripts/ci/ci_scope.py --full ;;", self.text)

    def test_atom_fuzz_runs_on_lens_changes_and_the_nightly_gate(self):
        job = "\n".join(self.job_lines("test-linux"))
        self.assertIn("Fuzz atom codec and render (golden corpus)", job)
        self.assertIn("timeout 1200s cargo test -j 8 -p oneiron --lib --all-features lens::tests::atom_fuzz::sustained_atom_codec_render_fuzz -- --ignored --exact", job)
        guard = job.split("Fuzz atom codec and render (golden corpus)", 1)[1].split("        run:", 1)[0]
        expression = guard.split("${{", 1)[1].split("}}", 1)[0]

        def runs(*, cancelled=False, scope_result="success", full="false", oneiron="false", modules=""):
            # Evaluate only the small boolean grammar of this GitHub Actions guard.
            substitutions = {
                "contains(format(' {0} ', needs.changes.outputs.modules), ' lens ')": "lens" in modules.split(),
                "needs.changes.outputs.modules == 'ALL'": modules == "ALL",
                "needs.changes.outputs.oneiron == 'true'": oneiron == "true",
                "needs.changes.outputs.full == 'true'": full == "true",
                "needs.changes.result != 'success'": scope_result != "success",
                "!cancelled()": not cancelled,
            }
            value = expression
            for term, result in substitutions.items():
                value = value.replace(term, str(result))
            tree = ast.parse(value.replace("&&", " and ").replace("||", " or ").strip(), mode="eval")
            self.assertTrue(all(isinstance(node, (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Constant)) for node in ast.walk(tree)))
            return eval(compile(tree, "<fuzz-guard>", "eval"), {"__builtins__": {}})

        self.assertTrue(runs(scope_result="failure"))  # Failed scope; all outputs empty.
        self.assertTrue(runs(scope_result="cancelled"))  # Same fail-safe as the Test job.
        self.assertTrue(runs(modules="lens", oneiron="true"))
        self.assertTrue(runs(full="true"))
        self.assertFalse(runs(modules="gate", oneiron="true"))  # Unrelated scoped change.
        self.assertFalse(runs(cancelled=True, scope_result="failure"))

    def test_macos_recipe_and_mutation_audit_are_dispatch_only(self):
        for job in ("test", "mutation-audit"):
            gate = next(l for l in self.job_lines(job) if l.startswith("    if: "))
            self.assertIn("github.event_name == 'workflow_dispatch'", gate)
            self.assertNotIn("pull_request", gate)

    def test_workflow_guard_is_executed_by_python_check(self):
        self.assertIn("python3 -m unittest discover -s scripts/tests -p 'test_ci_workflow.py' -v", self.text)

    def test_build_guide_describes_scoped_ci_and_process_models(self):
        guide = (ROOT / "docs/ops/build-performance.md").read_text()
        for phrase in ("shared-process", "per-test-process", "`Test (featureless)`", "scripts/ci/ci_scope.py"):
            self.assertIn(phrase, guide)
        self.assertNotIn("Both CI test jobs run", guide)


class ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = staticmethod(load_scope().scope)

    def test_docs_only_touches_no_rust(self):
        s = self.scope(["docs/README.md"], False)
        self.assertFalse(s["rust"])
        self.assertFalse(s["full"])
        self.assertEqual(s["packages"], [])

    def test_module_change_scopes_to_that_module(self):
        s = self.scope(["crates/oneiron/src/authority/fold_engine.rs", "crates/oneiron/src/memory.rs"], False)
        self.assertTrue(s["rust"] and s["oneiron"])
        self.assertEqual(s["packages"], ["oneiron"])
        self.assertEqual(s["modules"], {"authority", "memory"})
        self.assertFalse(s["full"])

    def test_crate_root_or_many_modules_means_the_whole_crate(self):
        self.assertEqual(self.scope(["crates/oneiron/src/lib.rs"], False)["modules"], {"ALL"})
        many = [f"crates/oneiron/src/m{i}/x.rs" for i in range(13)]
        self.assertEqual(self.scope(many, False)["modules"], {"ALL"})

    def test_build_files_force_the_full_gate(self):
        for f in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml"):
            self.assertTrue(self.scope([f], False)["full"], f)

    def test_other_crates_and_integration_tests(self):
        s = self.scope(["crates/oneiron-server/src/lib.rs", "crates/oneiron/tests/it/main.rs"], False)
        self.assertEqual(sorted(s["packages"]), ["oneiron", "oneiron-server"])
        self.assertTrue(s["it"])


if __name__ == "__main__":
    unittest.main()
