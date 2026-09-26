"""Pin scoped CI: PRs and main pushes test what their diff touched; the full gate runs nightly."""

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

    def test_only_clippy_receives_reverse_dependents(self):
        self.assertIn("      dependents: ${{ steps.scope.outputs.dependents }}", self.job_lines("changes"))
        self.assertIn("      SCOPE_DEPENDENTS: ${{ needs.changes.outputs.dependents }}", self.job_lines("checks"))
        self.assertNotIn("SCOPE_DEPENDENTS", "\n".join(self.job_lines("test-linux")))
        self.assertNotIn("SCOPE_DEPENDENTS", "\n".join(self.job_lines("test-linux-featureless")))
        self.assertIn('for p in $packages $dependents; do pk+=(-p "$p"); done', self.runner)
        self.assertIn('cargo clippy "${pk[@]}" --all-targets --all-features', self.runner)

    def test_full_gate_runs_nightly_and_keeps_both_featureless_process_models(self):
        self.assertIn("    - cron: '0 18 * * *'", self.lines)
        first, second = (self.runner.index(c) for c in FEATURELESS_FULL)
        self.assertLess(first, second)
        self.assertIn("run cargo test --doc --workspace --exclude oneiron-bench --all-features", self.runner)
        self.assertIn("schedule | workflow_dispatch) python3 scripts/ci/ci_scope.py --full ;;", self.text)

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
        self.assertEqual(s["dependents"], [])

    def test_module_change_scopes_to_that_module(self):
        s = self.scope(["crates/oneiron/src/authority/fold_engine.rs", "crates/oneiron/src/memory.rs"], False)
        self.assertTrue(s["rust"] and s["oneiron"])
        self.assertEqual(s["packages"], ["oneiron"])
        self.assertIn("oneiron-server", s["dependents"])
        self.assertIn("oneiron-remote", s["dependents"])
        self.assertIn("oneiron-bench", s["dependents"])
        self.assertNotIn("oneiron", s["dependents"])
        self.assertEqual(s["modules"], {"authority", "memory"})
        self.assertFalse(s["full"])

    def test_reverse_dependents_include_dev_dependencies_and_are_transitive(self):
        s = self.scope(["crates/oneiron-remote/src/lib.rs"], False)
        self.assertEqual(s["packages"], ["oneiron-remote"])
        self.assertIn("oneiron-server", s["dependents"])  # server uses remote as a dev-dependency
        self.assertIn("oneiron-bench", s["dependents"])  # bench depends on server

    def test_leaf_crate_has_no_reverse_dependents(self):
        s = self.scope(["crates/oneiron-android/src/lib.rs"], False)
        self.assertEqual(s["packages"], ["oneiron-android"])
        self.assertEqual(s["dependents"], [])

    def test_crate_root_or_many_modules_means_the_whole_crate(self):
        self.assertEqual(self.scope(["crates/oneiron/src/lib.rs"], False)["modules"], {"ALL"})
        many = [f"crates/oneiron/src/m{i}/x.rs" for i in range(13)]
        self.assertEqual(self.scope(many, False)["modules"], {"ALL"})

    def test_build_files_force_the_full_gate(self):
        for f in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml"):
            s = self.scope([f], False)
            self.assertTrue(s["full"], f)
            self.assertEqual(s["dependents"], [])

    def test_other_crates_and_integration_tests(self):
        s = self.scope(["crates/oneiron-server/src/lib.rs", "crates/oneiron/tests/it/main.rs"], False)
        self.assertEqual(sorted(s["packages"]), ["oneiron", "oneiron-server"])
        self.assertTrue(s["it"])


if __name__ == "__main__":
    unittest.main()
