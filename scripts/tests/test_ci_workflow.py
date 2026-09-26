"""Pin scoped CI, incremental build helpers, and the nightly full gate."""

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
    "      && vars.CI_PAUSED != 'true' && !inputs.cache_proof && (github.event_name != 'pull_request' "
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
        self.assertIn("        run: env -u CARGO_INCREMENTAL scripts/ci/run_scoped.sh clippy", self.job_lines("checks"))
        self.assertIn("        run: env -u CARGO_INCREMENTAL scripts/ci/run_scoped.sh test", self.job_lines("test-linux"))
        self.assertIn("        run: env -u CARGO_INCREMENTAL scripts/ci/run_scoped.sh featureless", self.job_lines("test-linux-featureless"))

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

    def test_shared_compiler_cache_is_pinned_and_reported_in_each_compiler_job(self):
        self.assertIn("  SCCACHE_GHA_ENABLED: 'on'", self.lines)
        self.assertIn(
            "SCCACHE_GHA_VERSION=ci-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('rust-toolchain.toml', 'Cargo.lock') }}",
            self.text,
        )
        for job in ("checks", "test", "test-linux", "test-linux-featureless"):
            lines = self.job_lines(job)
            self.assertIn(
                "        uses: mozilla-actions/sccache-action@7d986dd989559c6ecdb630a3fd2557667be217ad # v0.0.9",
                lines,
                job,
            )
            self.assertIn("      - name: Shared compiler cache key", lines, job)
            self.assertIn("        id: sccache", lines, job)
            self.assertIn('          version: "v0.15.0"', lines, job)
            self.assertIn("        if: always() && steps.sccache.outcome == 'success'", lines, job)
            self.assertIn("          RUSTC_WRAPPER: sccache", lines, job)
            self.assertIn("        run: sccache --show-stats", lines, job)
        # Tool installers stay unwrapped. Check the owning step, not a global line count.
        expected = {
            "checks": {"Clippy (touched packages and dependents; the full gate nightly)"},
            "test": {"Workspace tests (nextest, full tier, macOS recipe)",
                     "Featureless oneiron library tests",
                     "Featureless oneiron library tests (nextest, no retries)"},
            "test-linux": {"Tests (touched packages and modules; everything nightly)"},
            "test-linux-featureless": {"Featureless oneiron library tests (touched modules; both process models nightly)"},
        }
        for job, names in expected.items():
            lines = self.job_lines(job)
            steps = [i for i, line in enumerate(lines) if line.startswith("      - name: ")]
            wrapped = {lines[i].removeprefix("      - name: ") for i, end in zip(steps, steps[1:] + [len(lines)])
                       if "          RUSTC_WRAPPER: sccache" in lines[i:end]}
            self.assertEqual(wrapped, names, job)

    def test_full_tier_nextest_commands_are_not_replaced_by_cache_setup(self):
        self.assertIn(
            "run: cargo nextest run --workspace --exclude oneiron-napi --exclude oneiron-bench --all-features --profile full --no-fail-fast",
            self.text,
        )
        self.assertIn(
            "run cargo nextest run --workspace --exclude oneiron-napi --all-features --profile full --no-fail-fast",
            self.runner,
        )

    def test_cache_proof_dispatch_runs_two_separate_clean_artifact_jobs(self):
        self.assertIn("      cache_proof:", self.lines)
        self.assertIn("  group: ${{ inputs.cache_proof && format('ci-proof-{0}', github.run_id) || format('ci-{0}-{1}', github.workflow, github.event.pull_request.number || github.sha) }}", self.lines)
        for job, phase in (("cache-proof-populate", "populate"), ("cache-proof-repeat", "repeat")):
            lines = self.job_lines(job)
            self.assertIn("    runs-on: [self-hosted, macos, arm64, mini]", lines)
            self.assertIn("    if: vars.CI_PAUSED != 'true' && github.event_name == 'workflow_dispatch' && inputs.cache_proof", lines)
            self.assertTrue(any("proof-${{ github.run_id }}" in line for line in lines))
            self.assertTrue(any(f"ci_cache_proof.py {phase}" in line for line in lines))
            self.assertIn('          version: "v0.15.0"', lines)
            self.assertIn("        uses: actions/upload-artifact@v4", lines)
        self.assertIn("    needs: cache-proof-populate", self.job_lines("cache-proof-repeat"))
        self.assertIn("        uses: actions/download-artifact@v4", self.job_lines("cache-proof-repeat"))
        for job in ("changes", "checks", "test", "test-linux", "test-linux-featureless", "mutation-audit"):
            self.assertTrue(any("!inputs.cache_proof" in line for line in self.job_lines(job)), job)

    def test_pr_incremental_keeps_the_existing_shared_sccache_action(self):
        selector = "${{ github.event_name == 'pull_request' && 'true' || 'false' }}"
        for job in ("checks", "test-linux", "test-linux-featureless"):
            lines = self.job_lines(job)
            for profile in ("DEV", "TEST"):
                self.assertIn(f"      CARGO_PROFILE_{profile}_INCREMENTAL: {selector}", lines)
            self.assertIn("          RUSTC_WRAPPER: sccache", lines)
            self.assertIn("      - name: sccache 0.15.0 (GitHub Actions shared cache)", lines)
        self.assertNotIn("CARGO_INCREMENTAL: '1'", self.text)
        self.assertNotIn("CARGO_INCREMENTAL=1", self.runner)

    def test_scoped_runner_wraps_test_builds_and_rustdoc_not_clippy(self):
        self.assertIn('if [ "$mode" = test ] || [ "$mode" = featureless ]; then', self.runner)
        self.assertIn('RUSTC_WORKSPACE_WRAPPER="$PWD/scripts/ci/rustc-threads.sh" scripts/ci/with-test-tmpdir.sh "$@"', self.runner)
        self.assertIn('RUSTC_WORKSPACE_WRAPPER="$PWD/scripts/ci/rustc-threads.sh" RUSTDOCFLAGS="-D warnings" cargo doc', self.runner)
        self.assertNotIn("RUSTC_WORKSPACE_WRAPPER: ", "\n".join(self.job_lines("checks")))
        self.assertTrue((ROOT / "scripts/ci/rustc-threads.sh").stat().st_mode & 0o111)
        self.assertTrue((ROOT / "scripts/ci/with-test-tmpdir.sh").stat().st_mode & 0o111)

    def test_workflow_guard_is_executed_by_python_check(self):
        self.assertIn("python3 -m unittest discover -s scripts/tests -p 'test_ci_workflow.py' -v", self.text)

    def test_build_guide_describes_scoped_ci_and_process_models(self):
        guide = (ROOT / "docs/ops/build-performance.md").read_text()
        for phrase in ("shared-process", "per-test-process", "`Test (featureless)`", "scripts/ci/ci_scope.py", "RUSTC_WORKSPACE_WRAPPER", "CARGO_PROFILE_DEV_INCREMENTAL"):
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
