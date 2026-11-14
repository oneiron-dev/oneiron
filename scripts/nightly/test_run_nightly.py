"""Tests of scripts/nightly/run_nightly.sh against a stub `cargo` (no real build).

The stub answers `cargo nextest --version`, `cargo metadata` and `cargo nextest
run` (with and without --no-run) from a fixture workspace, logs each call with
its CARGO_BUILD_JOBS, and writes the JUnit nextest would write. It fails to
compile the test targets named in STUB_FAIL_TESTS, and cannot list the tests of
a run that selects a target named in STUB_LIST_ERROR_TESTS (exit 104, no JUnit).
A budget verdict run (its filter starts with the budget set's first row) gives
the timed cases of STUB_BUDGET_CASES, or cannot list its tests when
STUB_LIST_ERROR_BUDGET is set.

Run: python3 -m unittest discover -s scripts/nightly -p 'test_*.py' -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

STUB_CARGO = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path

    args = sys.argv[1:]
    target = Path(os.environ["STUB_TARGET"])
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write(os.environ.get("CARGO_BUILD_JOBS", "-") + " " + " ".join(args) + "\\n")
    if args[:2] == ["nextest", "--version"]:
        if os.environ.get("STUB_NO_NEXTEST"):
            print("error: no such command: `nextest`", file=sys.stderr)
            sys.exit(101)
        print("cargo-nextest 0.9.137 (stub)")
        sys.exit(0)
    if args[0] == "metadata":
        metadata = json.loads(Path(os.environ["STUB_METADATA"]).read_text())
        metadata["target_directory"] = str(target)
        print(json.dumps(metadata))
        sys.exit(0)
    assert args[:2] == ["nextest", "run"], args
    tests = [args[i + 1] for i, arg in enumerate(args) if arg == "--test"]
    deps = target / "debug" / "deps"
    deps.mkdir(parents=True, exist_ok=True)
    if "--no-run" in args:
        if any(t in os.environ.get("STUB_SETUP_ERROR_TESTS", "").split(",") for t in tests):
            print("error: the stub's setup error (no unit named)")
            sys.exit(96)
        broken = [t for t in tests if t in os.environ.get("STUB_FAIL_TESTS", "").split(",")]
        for t in broken:
            print(f'error: could not compile `oneiron` (test "{t}") due to 1 previous error')
        if broken:
            sys.exit(101)
        for t in tests:
            (deps / f"{t}-0123456789abcdef").write_text("test binary")
        if "--lib" in args:
            door = target / "debug" / "oneiron-testkit-pending-door"
            door.write_text(
                "#!/bin/sh\\necho '{\\"pending\\": 0, \\"expired\\": 0, \\"pending_filter\\": \\"none()\\", "
                "\\"expired_filter\\": \\"none()\\"}'\\n"
            )
            door.chmod(0o755)
        sys.exit(0)
    for t in tests:
        if not (deps / f"{t}-0123456789abcdef").exists():
            print(f"stub: the {t} test binary is gone before its run", file=sys.stderr)
            sys.exit(102)
    if any(t in os.environ.get("STUB_LIST_ERROR_TESTS", "").split(",") for t in tests):
        print("error: creating test list failed (stub)", file=sys.stderr)
        sys.exit(104)
    profile = args[args.index("--profile") + 1]
    expression = args[args.index("-E") + 1]
    cases = []
    if profile == "nightly" and expression.startswith("(kind(lib)"):
        if "--lib" in args:
            cases.append(("oneiron", "tests::a_row_is_kept", 0.5))
    elif profile == "nightly" and expression.startswith("((package("):
        if os.environ.get("STUB_LIST_ERROR_BUDGET"):
            print("error: creating test list failed (stub)", file=sys.stderr)
            sys.exit(104)
        budget = json.loads(os.environ.get("STUB_BUDGET_CASES", "{}"))
        cases += [(f"oneiron::{t}", name, seconds) for t in tests for name, seconds in budget.get(t, [])]
    elif profile == "nightly":
        cases += [(f"oneiron::{t}", "a_case_runs", 0.5) for t in tests]
    junit = target / "nextest" / profile / "junit.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        f'<testsuite name="{binary}"><testcase name="{name}" classname="{binary}" time="{seconds}"/></testsuite>'
        for binary, name, seconds in cases
    )
    junit.write_text(f'<?xml version="1.0"?><testsuites name="nextest-run">{body}</testsuites>')
    """
)


def target(name: str, kind: str) -> dict:
    return {"name": name, "kind": [kind], "test": True}


METADATA = {
    "workspace_members": ["oneiron 0.1.0", "oneiron-testkit 0.1.0"],
    "packages": [
        {
            "id": "oneiron 0.1.0",
            "name": "oneiron",
            "targets": [
                target("oneiron", "lib"),
                target("alpha", "test"),
                target("beta", "test"),
                target("shared", "test"),
            ],
        },
        {
            "id": "oneiron-testkit 0.1.0",
            "name": "oneiron-testkit",
            "targets": [target("oneiron_testkit", "lib"), target("kit", "test"), target("pending_door", "test")],
        },
    ],
}

LIB_RS = """\
// FIX [LIBTEST-QUARANTINE-ROOT-TESTS]: the lib test target's type check fails here; port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;
"""


class RunNightlyTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.repo = base / "repo"
        (self.repo / "scripts/nightly").mkdir(parents=True)
        for name in ("run_nightly.sh", "nightly_report.py"):
            shutil.copy(HERE / name, self.repo / "scripts/nightly" / name)
        (self.repo / "crates/core/src").mkdir(parents=True)
        (self.repo / "crates/core/Cargo.toml").write_text('[package]\nname = "oneiron"\n')
        (self.repo / "crates/core/src/lib.rs").write_text(LIB_RS)
        baseline = subprocess.run(
            ["python3", str(self.repo / "scripts/nightly/nightly_report.py"), "census", str(self.repo)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        (self.repo / "scripts/nightly/libtest-quarantine-baseline.tsv").write_text(baseline)
        git = [
            "git",
            "-C",
            str(self.repo),
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
        ]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "fixture"], check=True)
        stub_dir = base / "bin"
        stub_dir.mkdir()
        (stub_dir / "cargo").write_text(STUB_CARGO)
        (stub_dir / "cargo").chmod(0o755)
        (base / "metadata.json").write_text(json.dumps(METADATA))
        self.target = base / "target"
        self.calls = base / "cargo-calls.log"
        self.out = base / "out"
        self.env = {
            **os.environ,
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "STUB_TARGET": str(self.target),
            "STUB_LOG": str(self.calls),
            "STUB_METADATA": str(base / "metadata.json"),
        }
        self.env.pop("CARGO_BUILD_JOBS", None)
        self.env.pop("NIGHTLY_LIB_JOBS", None)

    def run_nightly(self, *args: str, out: Path | None = None, **env: str) -> subprocess.CompletedProcess[str]:
        command = ["bash", str(self.repo / "scripts/nightly/run_nightly.sh"), "--out", str(out or self.out), *args]
        if "--date" not in args:
            command += ["--date", "2026-11-15"]
        return subprocess.run(command, env={**self.env, **env}, capture_output=True, text=True, timeout=120)

    def summary_line(self, result: subprocess.CompletedProcess[str]) -> str:
        lines = [line for line in result.stdout.splitlines() if line.startswith("## NIGHTLY SUMMARY ")]
        self.assertEqual(len(lines), 1, result.stdout + result.stderr)
        return lines[0].removeprefix("## NIGHTLY SUMMARY ")

    def builds(self) -> list[str]:
        return [line for line in self.calls.read_text().splitlines() if " --no-run " in line]

    def runs(self, profile: str) -> list[str]:
        """The -E filter of each `cargo nextest run` under the profile, in order."""
        lines = [line for line in self.calls.read_text().splitlines() if f" --profile {profile} " in line]
        return [line.split(" -E ", 1)[1] for line in lines]

    def write_budget_set(self) -> str:
        row = ("alpha-props", "oneiron", "test", "alpha", "^", "props::", "crates/core/tests/alpha.rs", "30 min")
        header = ("id", "package", "kind", "binary", "match", "test", "source", "bound")
        (self.repo / "scripts/nightly/budget-set.tsv").write_text("\t".join(header) + "\n" + "\t".join(row) + "\n")
        return "(package(oneiron) & kind(test) & binary(=alpha) & test(/^props::/))"

    def test_the_budget_tests_run_every_night_before_the_shards_and_no_other_verdict_runs_them(self) -> None:
        budget = self.write_budget_set()
        cursor = self.out.parent / "cursor.json"
        result = self.run_nightly(
            "--shard-files", "2", "--max-shards", "1", "--cursor", str(cursor),
            STUB_BUDGET_CASES=json.dumps({"alpha": [["props::a_merge_converges", 3.5]]}),
        )  # fmt: skip
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            [line.split(" --all-features ")[1] for line in self.builds()],
            [
                "--workspace --exclude oneiron-bench --lib --bins --test pending_door",
                "--workspace --exclude oneiron-bench --test alpha",
                "--workspace --exclude oneiron-bench --test alpha --test beta",
            ],
        )
        verdicts = self.runs("nightly")
        self.assertEqual(len(verdicts), 4, "libs, libtest, budget, tests-01")
        self.assertTrue(verdicts[0].endswith(f"& not ({budget})"), verdicts[0])
        self.assertEqual(verdicts[2], f"({budget}) & not (none() | none())")
        self.assertTrue(verdicts[3].endswith(f"& not ({budget})"), verdicts[3])
        self.assertEqual(len(self.runs("quarantine")), 2, "the budget binaries' quarantine runs in their shards")
        self.assertIn("## NIGHTLY stop reason=max-shards next=tests-02", result.stdout)
        self.assertIn("## NIGHTLY measure after=budget minutes=0 ", result.stdout)
        line = self.summary_line(result)
        self.assertIn(" cycle=1 shards_run=1/2 next=kit passed=4 failed=0 ", line)
        self.assertIn(" budget_in=0 budget_out=0 budget_pending=1 budget_not_run=0", line)
        samples = json.loads((self.out / "budget-samples.json").read_text())
        (host_samples,) = samples.values()
        self.assertEqual(
            [s["seconds"] for s in host_samples["oneiron::alpha props::a_merge_converges"]], [3.5], "one sample a night"
        )
        left = sorted(path.name for path in (self.target / "debug/deps").iterdir())
        self.assertEqual(left, ["pending_door-0123456789abcdef"], "the budget and shard binaries are deleted")

    def test_a_deadline_already_passed_still_runs_the_budget_tests(self) -> None:
        self.write_budget_set()
        result = self.run_nightly(
            "--shard-files", "2", "--deadline-epoch", "1",
            STUB_BUDGET_CASES=json.dumps({"alpha": [["props::a_merge_converges", 3.5]]}),
        )  # fmt: skip
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("## NIGHTLY verdict-budget rc=0 ", result.stdout)
        self.assertIn("## NIGHTLY stop reason=deadline next=tests-01", result.stdout)
        self.assertIn(" shards_run=0/2 next=alpha passed=2 ", self.summary_line(result))

    def test_budget_tests_that_could_not_be_listed_make_the_night_red_and_the_shards_still_run(self) -> None:
        self.write_budget_set()
        result = self.run_nightly("--shard-files", "2", STUB_LIST_ERROR_BUDGET="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("## NIGHTLY verdict-budget rc=104 ", result.stdout)
        self.assertNotIn("stop reason=", result.stdout)
        line = self.summary_line(result)
        self.assertIn(
            " RED build=ok cycle=1 shards_run=2/2 next=alpha passed=5 failed=0 skipped=0 verdict_not_run=1 ", line
        )
        self.assertIn(
            "the verdict stage of budget did not run (exit 104, no JUnit)",
            json.loads((self.out / "summary.json").read_text())["reasons"],
        )

    def test_a_sharded_green_night_runs_every_shard_and_deletes_its_test_binaries(self) -> None:
        result = self.run_nightly("--shard-files", "2")
        line = self.summary_line(result)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(line.startswith("NIGHTLY 2026-11-15 head="), line)
        # the four integration tests in two shards, plus the pending-door tool's own test in libs
        self.assertIn(" GREEN build=ok cycle=1 shards_run=2/2 next=alpha passed=5 failed=0 ", line)
        self.assertIn(" libtest_passed=1 libtest_failed=0 quarantine_gated=1 ", line)
        self.assertEqual(
            [line.split(" --all-features ")[1] for line in self.builds()],
            [
                "--workspace --exclude oneiron-bench --lib --bins --test pending_door",
                "--workspace --exclude oneiron-bench --test alpha --test beta",
                "--workspace --exclude oneiron-bench --test kit --test shared",
            ],
        )
        left = sorted(path.name for path in (self.target / "debug/deps").iterdir())
        self.assertEqual(left, ["pending_door-0123456789abcdef"])
        for name in ("summary.json", "summary.txt", "results-store.json", "flake-row.json"):
            self.assertTrue((self.out / name).is_file(), name)

    def test_a_test_file_that_does_not_compile_is_left_out_and_the_night_is_red(self) -> None:
        result = self.run_nightly(STUB_FAIL_TESTS="beta")
        line = self.summary_line(result)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(" RED build=partial cycle=1 shards_run=1/1 next=alpha passed=4 failed=0 ", line)
        self.assertIn('## NIGHTLY failed-unit `oneiron` (test "beta") due to 1 previous error', result.stdout)
        self.assertEqual(
            [line.split(" --all-features ")[1] for line in self.builds()[1:]],
            [
                "--workspace --exclude oneiron-bench --test alpha --test beta --test kit --test shared",
                "--workspace --exclude oneiron-bench --test alpha --test kit --test shared",
            ],
        )
        self.assertIn(
            "unselected: tests-01 oneiron test beta (did not compile)", (self.out / "summary.txt").read_text()
        )
        self.assertTrue(
            (self.target / "debug/deps/alpha-0123456789abcdef").exists(), "an unsharded night keeps its binaries"
        )

    def test_a_night_stopped_after_max_shards_resumes_at_the_cursor_the_next_night(self) -> None:
        cursor = self.out.parent / "cursor.json"
        first = self.run_nightly("--shard-files", "1", "--max-shards", "2", "--cursor", str(cursor))
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("## NIGHTLY stop reason=max-shards next=tests-03", first.stdout)
        self.assertIn(" cycle=1 shards_run=2/4 next=kit ", self.summary_line(first))
        self.assertEqual(json.loads(cursor.read_text()), {"next": "kit", "cycle": 1})
        self.assertIn("## NIGHTLY measured shards=2 ", first.stdout)

        second_out = self.out.parent / "out-2"
        second = self.run_nightly(
            "--shard-files", "1", "--max-shards", "2", "--cursor", str(cursor),
            "--previous", str(self.out / "results-store.json"), "--date", "2026-11-16", out=second_out,
        )  # fmt: skip
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn(" cycle=1 shards_run=2/4 next=alpha ", self.summary_line(second))
        self.assertEqual(json.loads(cursor.read_text()), {"next": "alpha", "cycle": 2})
        store = json.loads((second_out / "results-store.json").read_text())
        self.assertEqual(store["oneiron::alpha a_case_runs"], {"outcome": "pass", "date": "2026-11-15"})
        self.assertEqual(store["oneiron::kit a_case_runs"], {"outcome": "pass", "date": "2026-11-16"})

    def test_a_deadline_already_passed_runs_the_libs_and_no_shard(self) -> None:
        result = self.run_nightly("--shard-files", "2", "--deadline-epoch", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("## NIGHTLY stop reason=deadline next=tests-01", result.stdout)
        self.assertIn(" GREEN build=ok cycle=1 shards_run=0/2 next=alpha passed=1 ", self.summary_line(result))
        self.assertIn("## NIGHTLY measure after=libs minutes=0 target_kb=", result.stdout)

    def test_the_lib_job_count_applies_to_the_lib_selection_build_only(self) -> None:
        result = self.run_nightly(NIGHTLY_LIB_JOBS="1", CARGO_BUILD_JOBS="4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([line.split(" ")[0] for line in self.builds()], ["1", "4"])

    def test_a_shard_whose_build_fails_beyond_pruning_stops_the_night_and_keeps_the_cursor_on_it(self) -> None:
        cursor = self.out.parent / "cursor.json"
        result = self.run_nightly("--shard-files", "1", "--cursor", str(cursor), STUB_SETUP_ERROR_TESTS="beta")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("## NIGHTLY stop reason=build-dropped next=tests-02", result.stdout)
        self.assertIn(" RED build=partial cycle=1 shards_run=1/4 next=beta ", self.summary_line(result))
        self.assertEqual(json.loads(cursor.read_text()), {"next": "beta", "cycle": 1})
        self.assertEqual(len(self.builds()), 3, "libs, tests-01, and tests-02 once (no unit to leave out)")

    def test_a_shard_whose_tests_could_not_be_listed_stops_the_night_red_and_keeps_the_cursor_on_it(self) -> None:
        cursor = self.out.parent / "cursor.json"
        result = self.run_nightly("--shard-files", "1", "--cursor", str(cursor), STUB_LIST_ERROR_TESTS="beta")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("## NIGHTLY verdict-tests-02 rc=104 ", result.stdout)
        self.assertIn("## NIGHTLY stop reason=verdict-not-run next=tests-02", result.stdout)
        line = self.summary_line(result)
        self.assertIn(
            " RED build=ok cycle=1 shards_run=1/4 next=beta passed=2 failed=0 skipped=0 verdict_not_run=1 ", line
        )
        self.assertEqual(json.loads(cursor.read_text()), {"next": "beta", "cycle": 1})
        self.assertIn(
            "the verdict stage of tests-02 did not run (exit 104, no JUnit)",
            json.loads((self.out / "summary.json").read_text())["reasons"],
        )
        self.assertFalse((self.target / "debug/deps/beta-0123456789abcdef").exists(), "the stopped shard's binaries")

    def test_a_reused_out_dir_lends_no_older_nights_build_errors_to_the_pruning(self) -> None:
        self.out.mkdir()
        # an older night's lib error in a later round's log name, and its stage ends
        (self.out / "build-tests-01-2.log").write_text(
            "error: could not compile `oneiron` (lib) due to 1 previous error\n"
        )
        (self.out / "stages.tsv").write_text("verdict\ttests-01\t104\tno\tno\n")
        result = self.run_nightly(STUB_FAIL_TESTS="beta")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        line = self.summary_line(result)
        self.assertIn(
            " RED build=partial cycle=1 shards_run=1/1 next=alpha passed=4 failed=0 skipped=0 verdict_not_run=0 ", line
        )
        text = (self.out / "summary.txt").read_text()
        self.assertIn("unselected: tests-01 oneiron test beta (did not compile)", text)
        self.assertNotIn("dropped:", text)

    def test_a_host_without_cargo_nextest_cannot_start_the_night(self) -> None:
        result = self.run_nightly(STUB_NO_NEXTEST="1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("## NIGHTLY nextest rc=missing", result.stdout)


if __name__ == "__main__":
    unittest.main()
