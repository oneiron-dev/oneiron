"""Tests for mutant_screen.py (L8-02). The door is the script's CLI; the restore is a pure function.

Run: python3 -m unittest discover -s scripts/audit -p 'test_mutant_screen.py' -v
The full-screen case needs cargo, cargo-nextest and cargo-mutants 27.1.0 on PATH; it skips otherwise.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "mutant_screen.py"
_spec = importlib.util.spec_from_file_location("mutant_screen", SCRIPT)
ms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ms)

CRATE = "crates/screen_fixture"
LIB = CRATE + "/src/lib.rs"
DELETED_ID = LIB + "::tests::adult_at_eighteen"

PRODUCTION = """\
pub fn is_adult(age: u32) -> bool {
    age >= 18
}

pub fn double(x: u32) -> u32 {
    x * 2
}
"""
TEST_MOD = """
#[cfg(test)]
mod tests {
    use super::*;

    /// Eighteen is the first adult age.
    #[test]
    fn adult_at_eighteen() {
        assert!(is_adult(18));
    }

    #[test]
    fn minor_at_seventeen() {
        assert!(!is_adult(17));
    }

    #[test]
    fn double_three() {
        assert_eq!(double(3), 6);
    }
}
"""
OLD_LIB = PRODUCTION + TEST_MOD
DELETED_BLOCK = """
    /// Eighteen is the first adult age.
    #[test]
    fn adult_at_eighteen() {
        assert!(is_adult(18));
    }
"""
PRUNED_LIB = OLD_LIB.replace(DELETED_BLOCK, "")


def run_git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=owen", "-c", "user.email=owen@example.com",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def write(repo, path, text):
    p = Path(repo) / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def manifest(name):
    return f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n'


def fixture(tmp, second):
    """A git repo with the toy crate: commit 1 = the old suite; `second(repo)` makes commit 2."""
    repo = Path(tmp) / "repo"
    run_git(tmp, "init", "-q", "-b", "main", str(repo))
    write(repo, "Cargo.toml", '[workspace]\nmembers = ["crates/screen_fixture"]\nresolver = "2"\n')
    write(repo, ".gitignore", "target/\nCargo.lock\n")
    write(repo, CRATE + "/Cargo.toml", manifest("screen_fixture"))
    write(repo, LIB, OLD_LIB)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "old suite")
    old = run_git(repo, "rev-parse", "HEAD")
    second(repo)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "pruned suite")
    return repo, old, run_git(repo, "rev-parse", "HEAD")


def delete_one_test(repo):
    write(repo, LIB, PRUNED_LIB)


def move_crate(repo):
    run_git(repo, "mv", CRATE, "crates/screen_fixture_core")
    write(repo, "Cargo.toml", '[workspace]\nmembers = ["crates/screen_fixture_core"]\nresolver = "2"\n')


def run_cli(*args, env=None):
    p = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr


def mutant(name_line, function, genre, replacement, change):
    file = LIB
    return {"name": f"{file}:{name_line}:5: {change}", "package": "screen_fixture", "file": file,
            "function": {"function_name": function, "return_type": "-> bool",
                         "span": {"start": {"line": 1, "column": 1}, "end": {"line": 3, "column": 2}}},
            "span": {"start": {"line": name_line, "column": 5}, "end": {"line": name_line, "column": 14}},
            "replacement": replacement, "genre": genre}


def outcomes_file(folder, results, fail_lines=None):
    """A cargo-mutants 27.1.0 outcomes.json (as mutation.py's score() reads it) with one log per mutant."""
    folder = Path(folder)
    (folder / "log").mkdir(parents=True, exist_ok=True)
    outs = [{"scenario": "Baseline", "summary": "Success", "log_path": "log/baseline.log", "diff_path": None,
             "phase_results": [{"phase": "Test", "duration": 0.4, "process_status": "Success", "argv": ["cargo"]}]}]
    for n, (m, summary) in enumerate(results):
        log = f"log/mutant-{n}.log"
        (folder / log).write_text("\n".join((fail_lines or {}).get(m["name"], [])) + "\n")
        status = {"CaughtMutant": {"Failure": 100}, "MissedMutant": "Success", "Timeout": "Timeout"}[summary]
        outs.append({"scenario": {"Mutant": m}, "summary": summary, "log_path": log, "diff_path": None,
                     "phase_results": [{"phase": "Build", "duration": 0.5, "process_status": "Success", "argv": []},
                                       {"phase": "Test", "duration": 30.0 if summary == "Timeout" else 0.3,
                                        "process_status": status, "argv": []}]})
    doc = {"outcomes": outs, "total_mutants": len(results),
           "missed": sum(1 for _, s in results if s == "MissedMutant"),
           "caught": sum(1 for _, s in results if s == "CaughtMutant"),
           "timeout": sum(1 for _, s in results if s == "Timeout"), "unviable": 0, "success": 0,
           "start_time": "2026-11-15T00:00:00Z", "end_time": "2026-11-15T00:01:00Z",
           "cargo_mutants_version": "27.1.0"}
    path = folder / "outcomes.json"
    path.write_text(json.dumps(doc))
    return path


FALSE = ("replace is_adult -> bool with false", "is_adult", "FnValue", "false")
LESS = ("replace >= with < in is_adult", "is_adult", "BinaryOperator", "<")


def pair(change, old_line, pruned_line):
    text, function, genre, replacement = change
    return (mutant(old_line, function, genre, replacement, text),
            mutant(pruned_line, function, genre, replacement, text))


class MutantScreenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mutant-screen-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def no_cargo_env(self):
        """PATH with a cargo that leaves a mark when called, so a no-cargo claim is checked."""
        bin_dir = Path(self.tmp) / "bin"
        bin_dir.mkdir()
        mark = Path(self.tmp) / "cargo-was-called"
        (bin_dir / "cargo").write_text(f"#!/bin/sh\ntouch {mark}\nexit 99\n")
        (bin_dir / "cargo").chmod(0o755)
        return dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}"), mark

    def test_plan_only_names_the_deleted_test_and_its_file(self):
        repo, old, pruned = fixture(self.tmp, delete_one_test)
        env, mark = self.no_cargo_env()
        rc, out, err = run_cli("--repo", str(repo), "--old", old, "--pruned", pruned, "--plan-only", env=env)
        self.assertEqual(rc, 0, err)
        plan = json.loads(out)
        self.assertEqual([c["crate"] for c in plan["crates"]], ["screen_fixture"])
        self.assertEqual(plan["crates"][0]["deleted"], [DELETED_ID])
        self.assertEqual(plan["crates"][0]["candidate_files"], [LIB])
        self.assertEqual(plan["screened_first"], ["screen_fixture"])
        self.assertEqual(plan["followed_moves"], [])
        self.assertFalse(mark.exists(), "--plan-only ran cargo")

    def test_a_moved_test_is_not_deleted(self):
        repo, old, pruned = fixture(self.tmp, move_crate)
        env, mark = self.no_cargo_env()
        rc, out, err = run_cli("--repo", str(repo), "--old", old, "--pruned", pruned, "--plan-only", env=env)
        self.assertEqual(rc, 0, err)
        plan = json.loads(out)
        self.assertEqual(plan["deleted_total"], 0)
        self.assertEqual(plan["crates"], [])
        self.assertEqual(plan["followed_moves"],
                         [{"old": LIB, "pruned": "crates/screen_fixture_core/src/lib.rs", "tests": 3}])
        self.assertFalse(mark.exists())

    def test_restore_puts_a_deleted_test_back_into_its_module(self):
        text, pieces = ms.restore_file(OLD_LIB, PRUNED_LIB, {(("tests",), "adult_at_eighteen"): DELETED_ID})
        tests = ms.Source(text).levels()[("tests",)][0]
        self.assertEqual([i.name for i in tests if i.is_test],
                         ["minor_at_seventeen", "double_three", "adult_at_eighteen"])
        self.assertIn("/// Eighteen is the first adult age.\n    #[test]\n    fn adult_at_eighteen()", text)
        self.assertEqual(ms.blank(text, pieces), PRUNED_LIB)
        self.assertEqual({u for _, _, us in pieces for u in us}, {DELETED_ID})

    def test_restore_recreates_a_removed_module_with_its_use_lines_and_helpers(self):
        old = PRODUCTION + TEST_MOD.replace("    use super::*;\n", "    use super::*;\n\n    fn age() -> u32 {\n        18\n    }\n")
        old = old.replace("assert!(is_adult(18))", "assert!(is_adult(age()))")
        wanted = {(("tests",), "adult_at_eighteen"): DELETED_ID}
        text, pieces = ms.restore_file(old, PRODUCTION, wanted, label=LIB)
        level = ms.Source(text).levels()[("tests",)]
        self.assertTrue(level[1].test_gated)
        self.assertEqual([(i.kind, i.name) for i in level[0]], [("use", None), ("fn", "age"), ("fn", "adult_at_eighteen")])
        self.assertEqual(ms.blank(text, pieces), PRODUCTION)
        units = {u for _, _, us in pieces for u in us}
        self.assertEqual(units, {DELETED_ID, LIB + "::tests::use #0", LIB + "::tests::fn age"})
        skipped, _ = ms.restore_file(old, PRODUCTION, wanted, label=LIB, skip={DELETED_ID})
        self.assertEqual(skipped, PRODUCTION, "with its only test left out, the module is not re-created")

    def compare(self, old_sets, pruned_sets):
        args = ["--old-outcomes"]
        for n, results in enumerate(old_sets):
            args.append(str(outcomes_file(Path(self.tmp) / f"old-{n}", *results)))
        args.append("--pruned-outcomes")
        for n, results in enumerate(pruned_sets):
            args.append(str(outcomes_file(Path(self.tmp) / f"pruned-{n}", *results)))
        rc, out, err = run_cli(*args)
        return rc, json.loads(out) if out.strip() else None, err

    def test_compare_names_a_mutant_only_the_old_suite_catches(self):
        lost_old, lost_new = pair(FALSE, 20, 2)
        both_old, both_new = pair(LESS, 21, 2)
        fail = {lost_old["name"]: ["        FAIL [   0.004s] (1/3) screen_fixture tests::adult_at_eighteen"]}
        rc, doc, err = self.compare([([(lost_old, "CaughtMutant"), (both_old, "CaughtMutant")], fail)],
                                    [([(lost_new, "MissedMutant"), (both_new, "CaughtMutant")],)])
        self.assertEqual(rc, 1, err)
        self.assertEqual(doc["verdict"], "lost")
        self.assertEqual([m["name_pruned"] for m in doc["lost"]], [lost_new["name"]])
        self.assertEqual(doc["lost"][0]["name_old"], lost_old["name"])
        self.assertEqual(doc["lost"][0]["old_failed_tests"], ["screen_fixture tests::adult_at_eighteen"])
        self.assertEqual(doc["undecided"], [])

    def test_compare_passes_when_the_pruned_suite_catches_all_the_old_did(self):
        a_old, a_new = pair(FALSE, 20, 2)
        b_old, b_new = pair(LESS, 21, 2)
        rc, doc, err = self.compare([([(a_old, "CaughtMutant"), (b_old, "MissedMutant")],)],
                                    [([(a_new, "CaughtMutant"), (b_new, "CaughtMutant")],)])
        self.assertEqual(rc, 0, err)
        self.assertEqual(doc["verdict"], "loses_nothing")
        self.assertEqual((doc["lost"], doc["undecided"]), ([], []))

    def test_a_pair_that_times_out_twice_is_undecided_and_fails(self):
        t_old, t_new = pair(LESS, 21, 2)
        rc, doc, err = self.compare([([(t_old, "Timeout")],), ([(t_old, "Timeout")],)],
                                    [([(t_new, "CaughtMutant")],), ([(t_new, "Timeout")],)])
        self.assertEqual(rc, 1, err)
        self.assertEqual(doc["verdict"], "lost")
        self.assertEqual([m["name_pruned"] for m in doc["undecided"]], [t_new["name"]])
        self.assertEqual(doc["lost"], [])
        settled, _, _ = self.compare([([(t_old, "Timeout")],), ([(t_old, "CaughtMutant")],)],
                                     [([(t_new, "Timeout")],), ([(t_new, "CaughtMutant")],)])
        self.assertEqual(settled, 0, "a rerun that settles both sides decides the pair")

    def test_report_rejudges_a_saved_report(self):
        report = Path(self.tmp) / "report.json"
        report.write_text(json.dumps({"schema": 1, "crates": [{"crate": "screen_fixture", "mutants": [
            {"name_pruned": "a", "name_old": "a", "old": "CaughtMutant", "pruned": "MissedMutant"},
            {"name_pruned": "b", "name_old": "b", "old": "CaughtMutant", "pruned": "CaughtMutant"}]}]}))
        rc, out, err = run_cli("--report", str(report))
        self.assertEqual(rc, 1, err)
        self.assertEqual([m["name_pruned"] for m in json.loads(out)["lost"]], ["a"])

    @unittest.skipUnless(
        shutil.which("cargo")
        and subprocess.run(["cargo", "nextest", "--version"], capture_output=True).returncode == 0
        and subprocess.run(["cargo", "mutants", "--version"], capture_output=True, text=True).stdout.strip()
        == ms.RUNNER,
        "needs cargo, cargo-nextest and " + ms.RUNNER)
    def test_full_screen_on_the_fixture_finds_the_lost_mutant(self):
        repo, old, pruned = fixture(self.tmp, delete_one_test)
        rc, out, err = run_cli("--repo", str(repo), "--old", old, "--pruned", pruned, "--crates", "screen_fixture")
        self.assertEqual(rc, 1, err + out)
        summary = json.loads(out)
        report = json.loads(Path(summary["report"]).read_text())
        self.assertEqual(report["verdict"], "lost")
        crate = report["crates"][0]
        self.assertIsNone(crate["skipped"])
        self.assertEqual((crate["restored_compiled"], crate["restored_did_not_compile"]), (1, []))
        lost = {m["name_pruned"].split(": ", 1)[1]: m for m in report["lost"]}
        self.assertEqual(set(lost), {"replace is_adult -> bool with false"})
        self.assertEqual(lost["replace is_adult -> bool with false"]["caught_by_restored"], [DELETED_ID])
        doubles = [m for m in crate["mutants"] if "double" in m["name_pruned"]]
        self.assertEqual(len(doubles), 4)
        self.assertTrue(all(m["old"] == m["pruned"] == "CaughtMutant" for m in doubles), doubles)
        self.assertEqual(len(crate["mutants"]), 7, "all 7 mutants of the toy crate are screened")


if __name__ == "__main__":
    unittest.main()
