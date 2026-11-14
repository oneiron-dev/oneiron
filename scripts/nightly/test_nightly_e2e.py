"""Tests of scripts/nightly/nightly_e2e.py (the nightly E2E stage).

Run: python3 -m unittest discover -s scripts/nightly -p 'test_*.py' -v

The night tests drive the stage against a stub runner: a `bun` asset that
writes the runner's report.json shapes (tests/e2e/support/run.ts: a finished
run, deadline rows, a refused preflight) from a scenario file beside it.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nightly_e2e  # noqa: E402

SUITE_PLAN = {
    "version": 1,
    "files": [
        {
            "file": "a.test.ts",
            "area": "A",
            "slots": 1,
            "estimatedSeconds": 60,
            "tests": [
                {"id": "A-01", "name": "a one", "estimatedSeconds": 20},
                {"id": "A-02", "name": "a two"},
                {"id": "A-03", "name": "a three"},
            ],
        },
        {
            "file": "b.test.ts",
            "area": "B",
            "slots": 2,
            "estimatedSeconds": 100,
            "tests": [{"id": "B-01", "name": "b one"}, {"id": "B-02", "name": "b two"}],
        },
        {
            "file": "c.test.ts",
            "area": "C",
            "slots": 1,
            "estimatedSeconds": 300,
            "tests": [
                {"id": "C-01", "name": "c one"},
                {"id": "C-02", "name": "c two"},
                {"id": "C-03", "name": "c three"},
            ],
        },
    ],
}

STUB_RUNNER = """\
import json, os, sys
from pathlib import Path
here = Path(__file__).resolve().parent
scenario = json.loads((here / "scenario.json").read_text())
args = sys.argv[1:]
files = args[args.index("--files") + 1].split(",")
plan = json.loads(Path("tests/e2e/fixtures/suite-plan.json").read_text())
ids = [t["id"] for f in plan["files"] if f["file"] in files for t in f["tests"]]
with (here / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps({"files": files, "workers": args[args.index("--workers") + 1], "script": args[0],
                            "cwd": os.getcwd(), "env": dict(os.environ)}) + "\\n")
call = scenario.get("calls", {}).get(",".join(files), {})
report = Path(os.environ["E2E_REPORT_DIR"]) / "report.json"
if call.get("no_report"):
    sys.exit(1)
if call.get("preflight"):
    rows = [{"id": i, "outcome": "BLOCKED", "durationMs": 0, "reason": "FixturePinError: digest"} for i in ids]
    report.write_text(json.dumps({"profile": "deterministic", "success": False, "results": rows}))
    sys.exit(1)
rows = []
for i in ids:
    if i in scenario.get("drop", []):
        continue
    outcome, ms, reason = scenario.get("cases", {}).get(i, ["PASS", 1000, ""])
    rows.append({"id": i, "outcome": outcome, "durationMs": ms, **({"reason": reason} if reason else {})})
value = {"profile": "deterministic", "success": all(r["outcome"] in ("PASS", "SKIPPED") for r in rows),
         "durationMs": 1234.5, "schedulerFailure": call.get("scheduler", ""), "results": rows}
report.write_text(json.dumps(value))
sys.exit(0 if value["success"] else 1)
"""


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Fixture:
    """A checkout with a suite plan, and a READY set built from its commit whose `bun` is the stub runner."""

    def __init__(self, root: Path) -> None:
        self.checkout, self.set, self.out = root / "checkout", root / "set", root / "out"
        plan_dir = self.checkout / "tests/e2e/fixtures"
        plan_dir.mkdir(parents=True)
        (plan_dir / "suite-plan.json").write_text(json.dumps(SUITE_PLAN))
        (self.checkout / "tests/e2e/support").mkdir()
        (self.checkout / "tests/e2e/support/run.ts").write_text("// the runner\n")
        git(self.checkout, "init", "-q")
        git(self.checkout, "add", ".")
        git(
            self.checkout,
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "suite",
        )
        self.head = git(self.checkout, "rev-parse", "HEAD")
        self.bin = self.set / "bin"
        self.bin.mkdir(parents=True)
        bun = self.bin / "bun"
        bun.write_text("#!" + sys.executable + "\n" + STUB_RUNNER)
        bun.chmod(0o755)
        self.scenario({})
        (self.set / "src/tests/e2e/node_modules").mkdir(parents=True)
        self.manifest(
            {
                "version": 1,
                "head": self.head,
                "profile": "deterministic",
                "assets": {"bun": {"path": str(bun)}, "node": {"path": str(self.bin / "node")}},
            }
        )

    def manifest(self, value: dict) -> None:
        text = json.dumps(value)
        (self.set / "manifest.json").write_text(text)
        digest = hashlib.sha256(text.encode()).hexdigest()
        (self.set / "manifest.sha256").write_text(digest + "\n")
        (self.set / "READY").write_text(json.dumps({"format": 1, "manifestSha256": digest}))
        self.digest = digest

    def scenario(self, value: dict) -> None:
        (self.bin / "scenario.json").write_text(json.dumps(value))

    def calls(self) -> list[dict]:
        path = self.bin / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []

    def night(self, *extra: str) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = nightly_e2e.main(
                [
                    "night",
                    "--set",
                    str(self.set),
                    "--out",
                    str(self.out),
                    "--checkout",
                    str(self.checkout),
                    "--date",
                    "2026-11-15",
                    *extra,
                ]
            )
        return code, output.getvalue()

    def summary(self) -> dict:
        return json.loads((self.out / "summary.json").read_text())

    def state(self) -> dict:
        return json.loads((self.out / "e2e-state.json").read_text())

    def write_state(self, value: dict) -> str:
        path = self.out.parent / "state-in.json"
        path.write_text(json.dumps(value))
        return str(path)


def outcomes(summary: dict) -> dict[str, str]:
    return {row["id"]: row["outcome"] for row in summary["cases"]}


class PlanTest(unittest.TestCase):
    def files(self) -> list[dict]:
        return json.loads(json.dumps(SUITE_PLAN))["files"]

    def test_a_case_is_planned_at_its_longest_recent_wall_else_its_estimate_times_the_factor(self) -> None:
        a, _, c = self.files()
        state = {"cases": {"C-01": {"walls": [10000, 30000, 20000]}}, "files": {}}
        self.assertEqual(nightly_e2e.case_seconds(c, c["tests"][0], state, 2.0), 30.0)
        self.assertEqual(nightly_e2e.case_seconds(c, c["tests"][1], state, 2.0), 200.0)  # 300 / 3 cases x 2
        self.assertEqual(nightly_e2e.case_seconds(a, a["tests"][0], state, 2.0), 40.0)  # its own 20 x 2

    def test_a_file_load_counts_its_slots(self) -> None:
        _, b, _ = self.files()
        self.assertEqual(nightly_e2e.file_load(b, nightly_e2e.empty_state(), 2.0), 400.0)  # (50 + 50) x 2 x 2 slots

    def test_files_pack_first_fit_by_decreasing_load_under_the_bound(self) -> None:
        runs = nightly_e2e.plan_runs(self.files(), nightly_e2e.empty_state(), 2, 400, 2.0)
        # loads a 120, b 400, c 600; a run is load / 2 workers + 30 s
        self.assertEqual(
            [(run["name"], run["files"], run["seconds"]) for run in runs],
            [("e2e-01", ["a.test.ts", "c.test.ts"], 390), ("e2e-02", ["b.test.ts"], 230)],
        )
        self.assertTrue(all(run["seconds"] <= 400 for run in runs))

    def test_a_file_over_the_bound_runs_alone(self) -> None:
        runs = nightly_e2e.plan_runs(self.files(), nightly_e2e.empty_state(), 2, 200, 2.0)
        self.assertEqual(sorted(run["files"] for run in runs), [["a.test.ts"], ["b.test.ts"], ["c.test.ts"]])

    def test_the_runs_whose_files_ran_longest_ago_go_first(self) -> None:
        state = {"cases": {}, "files": {"a.test.ts": "2026-11-13", "c.test.ts": "2026-11-13"}}
        runs = nightly_e2e.plan_runs(self.files(), state, 2, 400, 2.0)
        self.assertEqual([run["files"] for run in runs], [["b.test.ts"], ["a.test.ts", "c.test.ts"]])
        state = {
            "cases": {},
            "files": {"a.test.ts": "2026-11-14", "c.test.ts": "2026-11-12", "b.test.ts": "2026-11-13"},
        }
        runs = nightly_e2e.plan_runs(self.files(), state, 2, 400, 2.0)
        self.assertEqual([run["files"] for run in runs], [["a.test.ts", "c.test.ts"], ["b.test.ts"]])

    def test_measured_walls_repack_the_runs(self) -> None:
        walls = {case: {"walls": [5000]} for case in ("A-01", "A-02", "A-03", "B-01", "B-02", "C-01", "C-02", "C-03")}
        runs = nightly_e2e.plan_runs(self.files(), {"cases": walls, "files": {}}, 2, 400, 2.0)
        self.assertEqual([run["files"] for run in runs], [["a.test.ts", "b.test.ts", "c.test.ts"]])
        self.assertEqual(runs[0]["seconds"], 55)  # (15 + 20 + 15) / 2 + 30

    def test_the_plan_command_prints_the_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "suite-plan.json"
            path.write_text(json.dumps(SUITE_PLAN))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(nightly_e2e.main(["plan", str(path)]), 0)
            self.assertEqual(
                [run["files"] for run in json.loads(output.getvalue())], [["a.test.ts", "c.test.ts"], ["b.test.ts"]]
            )


class NightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_a_green_night_runs_every_file_against_the_set_with_only_the_runner_env(self) -> None:
        self.fixture.scenario(
            {"cases": {"A-02": ["BLOCKED", 0, "waits on a door"], "C-03": ["SKIPPED", 0, "owner-deferred"]}}
        )
        os.environ["NIGHTLY_E2E_TEST_SENTINEL"] = "leak"
        try:
            code, output = self.fixture.night()
        finally:
            del os.environ["NIGHTLY_E2E_TEST_SENTINEL"]
        self.assertEqual(code, 0, output)
        summary = self.fixture.summary()
        self.assertIn(
            " GREEN runs=2/2 pass=6 fail=0 blocked=1 skipped=1 deadline=0 not_run=0 missing=0 flipped=0 workers=2 ",
            summary["line"],
        )
        self.assertTrue(
            summary["line"].startswith(
                "NIGHTLY-E2E 2026-11-15 head=%s set=%s " % (self.fixture.head[:12], self.fixture.digest[:12])
            )
        )
        self.assertIn("## NIGHTLY-E2E SUMMARY " + summary["line"], output)
        calls = self.fixture.calls()
        self.assertEqual([call["files"] for call in calls], [["a.test.ts", "c.test.ts"], ["b.test.ts"]])
        env = calls[0]["env"]
        self.assertNotIn("NIGHTLY_E2E_TEST_SENTINEL", env)
        self.assertEqual(env["E2E_BUILD_MANIFEST"], str((self.fixture.set / "manifest.json").resolve()))
        self.assertEqual(env["E2E_BUILD_MANIFEST_SHA256"], self.fixture.digest)
        self.assertTrue(env["E2E_REPORT_DIR"].endswith("/runs/e2e-01/report"))
        self.assertEqual(calls[0]["workers"], "2")
        self.assertEqual(calls[0]["script"], str(self.fixture.checkout.resolve() / "tests/e2e/support/run.ts"))
        modules = self.fixture.checkout / "tests/e2e/node_modules"
        self.assertTrue(modules.is_symlink())
        self.assertEqual(modules.resolve(), (self.fixture.set / "src/tests/e2e/node_modules").resolve())
        self.assertFalse((self.fixture.out / "runs/e2e-01/tmp").exists())  # the cases' temp root goes
        state = self.fixture.state()
        self.assertEqual(state["files"], {name: "2026-11-15" for name in ("a.test.ts", "b.test.ts", "c.test.ts")})
        self.assertEqual(state["cases"]["A-01"], {"walls": [1000], "outcome": "PASS", "date": "2026-11-15"})
        self.assertEqual(state["cases"]["A-02"], {"walls": [0]})  # a BLOCKED case plans at its wall, holds no outcome

    def test_a_fail_reddens_the_night_and_a_flip_compares_with_the_case_s_own_last_run(self) -> None:
        self.fixture.scenario({"cases": {"B-02": ["FAIL", 4000, "expected 2 rows"], "C-01": ["PASS", 2000, ""]}})
        previous = self.fixture.write_state(
            {
                "cases": {
                    "B-02": {"outcome": "PASS", "date": "2026-11-12", "walls": [1, 2, 3]},
                    "C-01": {"outcome": "FAIL", "date": "2026-11-14"},
                },
                "files": {},
            }
        )
        code, output = self.fixture.night("--state", previous)
        self.assertEqual(code, 1, output)
        summary = self.fixture.summary()
        self.assertIn(" RED runs=2/2 pass=7 fail=1 ", summary["line"])
        self.assertIn("flipped=2", summary["line"])
        self.assertEqual(
            summary["flips"],
            [
                {"id": "C-01", "from": "FAIL", "to": "PASS", "since": "2026-11-14"},
                {"id": "B-02", "from": "PASS", "to": "FAIL", "since": "2026-11-12"},
            ],
        )
        self.assertIn("## NIGHTLY-E2E FAIL B-02 4000ms expected 2 rows", output)
        text = (self.fixture.out / "summary.txt").read_text()
        self.assertIn("FAIL B-02 b.test.ts 4000ms run=e2e-02 expected 2 rows", text)
        self.assertIn("FLIP B-02 PASS->FAIL since 2026-11-12", text)
        self.assertEqual(
            self.fixture.state()["cases"]["B-02"], {"outcome": "FAIL", "date": "2026-11-15", "walls": [2, 3, 4000]}
        )

    def test_deadline_rows_are_counted_apart_and_leave_no_wall(self) -> None:
        reason = nightly_e2e.DEADLINE_REASON
        self.fixture.scenario({"cases": {"C-02": ["FAIL", 0, reason], "C-03": ["FAIL", 0, reason]}})
        code, output = self.fixture.night()
        self.assertEqual(code, 0, output)
        summary = self.fixture.summary()
        self.assertIn(" GREEN runs=2/2 pass=6 fail=0 blocked=0 skipped=0 deadline=2 ", summary["line"])
        self.assertNotIn("C-02", self.fixture.state()["cases"])
        self.assertIn("DEADLINE C-02 c.test.ts 0ms run=e2e-01", (self.fixture.out / "summary.txt").read_text())

    def test_a_refused_preflight_is_a_run_that_did_not_run(self) -> None:
        self.fixture.scenario({"calls": {"b.test.ts": {"preflight": True}}})
        code, output = self.fixture.night()
        self.assertEqual(code, 1, output)
        summary = self.fixture.summary()
        self.assertEqual(outcomes(summary)["B-01"], "NOT-RUN")
        self.assertIn(" RED runs=1/2 pass=6 fail=0 blocked=0 skipped=0 deadline=0 not_run=2 ", summary["line"])
        self.assertIn("state=preflight", output)
        self.assertIn("preflight refused: FixturePinError: digest", output)
        self.assertNotIn("b.test.ts", self.fixture.state()["files"])  # the next night starts with it

    def test_a_runner_without_a_report_reddens_the_night(self) -> None:
        self.fixture.scenario({"calls": {"a.test.ts,c.test.ts": {"no_report": True}}})
        code, output = self.fixture.night()
        self.assertEqual(code, 1, output)
        self.assertIn("state=no-report rc=1", output)
        self.assertEqual(outcomes(self.fixture.summary())["C-01"], "NOT-RUN")

    def test_a_scheduler_failure_reddens_the_night_and_keeps_its_rows(self) -> None:
        self.fixture.scenario({"calls": {"b.test.ts": {"scheduler": "Error: slot accounting"}}})
        code, output = self.fixture.night()
        self.assertEqual(code, 1, output)
        self.assertIn("state=scheduler", output)
        self.assertEqual(outcomes(self.fixture.summary())["B-01"], "PASS")

    def test_a_planned_case_with_no_report_row_is_missing(self) -> None:
        self.fixture.scenario({"drop": ["A-03"]})
        code, output = self.fixture.night()
        self.assertEqual(code, 1, output)
        self.assertIn("missing=1", self.fixture.summary()["line"])
        self.assertIn("## NIGHTLY-E2E MISSING A-03 0ms no row in the run's report", output)

    def test_the_night_stops_before_a_run_that_would_end_past_the_deadline(self) -> None:
        code, output = self.fixture.night("--deadline-epoch", str(int(time.time()) + 300))
        self.assertEqual(code, 0, output)
        summary = self.fixture.summary()
        self.assertEqual([call["files"] for call in self.fixture.calls()], [])  # e2e-01 plans 390 s
        self.assertIn(" GREEN runs=0/2 pass=0 fail=0 blocked=0 skipped=0 deadline=0 not_run=8 ", summary["line"])
        self.assertIn("## NIGHTLY-E2E stop before e2e-01 (deadline)", output)
        # bound 250: a (90 s), b (230 s) and c (330 s) each run alone; with 300 s left, c does not start
        code, output = self.fixture.night("--deadline-epoch", str(int(time.time()) + 300), "--bound", "250")
        self.assertEqual(code, 0, output)
        self.assertEqual([call["files"] for call in self.fixture.calls()], [["a.test.ts"], ["b.test.ts"]])
        self.assertIn(
            " GREEN runs=2/3 pass=5 fail=0 blocked=0 skipped=0 deadline=0 not_run=3 ", self.fixture.summary()["line"]
        )
        self.assertIn(
            "RUN e2e-03 state=stopped rc=- seconds=- planned=330 files=c.test.ts reason=stop-at",
            (self.fixture.out / "summary.txt").read_text(),
        )

    def test_a_set_from_another_commit_does_not_start_and_hands_the_state_on(self) -> None:
        self.fixture.manifest(
            {"version": 1, "head": "0" * 40, "assets": {"bun": {"path": "/x"}, "node": {"path": "/y"}}}
        )
        previous = self.fixture.write_state({"cases": {"A-01": {"walls": [7]}}, "files": {"a.test.ts": "2026-11-14"}})
        code, output = self.fixture.night("--state", previous)
        self.assertEqual(code, 2, output)
        self.assertIn(
            "NOT-STARTED reason=the set was built from 000000000000, the checkout is " + self.fixture.head[:12], output
        )
        self.assertEqual(
            self.fixture.state(), {"cases": {"A-01": {"walls": [7]}}, "files": {"a.test.ts": "2026-11-14"}}
        )
        self.assertEqual(self.fixture.calls(), [])

    def test_a_state_kept_in_the_out_dir_is_read_before_the_night_clears_it(self) -> None:
        self.fixture.scenario({"cases": {"B-02": ["FAIL", 4000, "expected 2 rows"]}})
        self.fixture.out.mkdir(parents=True, exist_ok=True)
        own = self.fixture.out / "e2e-state.json"
        own.write_text(
            json.dumps({"cases": {"B-02": {"outcome": "PASS", "date": "2026-11-12", "walls": [1, 2, 3]}}, "files": {}})
        )
        code, output = self.fixture.night("--state", str(own))
        self.assertEqual(code, 1, output)
        self.assertEqual(
            self.fixture.summary()["flips"], [{"id": "B-02", "from": "PASS", "to": "FAIL", "since": "2026-11-12"}]
        )
        self.assertEqual(
            self.fixture.state()["cases"]["B-02"], {"outcome": "FAIL", "date": "2026-11-15", "walls": [2, 3, 4000]}
        )

    def test_a_night_that_cannot_start_hands_on_a_state_kept_in_the_out_dir(self) -> None:
        self.fixture.manifest(
            {"version": 1, "head": "0" * 40, "assets": {"bun": {"path": "/x"}, "node": {"path": "/y"}}}
        )
        self.fixture.out.mkdir(parents=True, exist_ok=True)
        own = self.fixture.out / "e2e-state.json"
        kept = {"cases": {"A-01": {"walls": [7]}}, "files": {"a.test.ts": "2026-11-14"}}
        own.write_text(json.dumps(kept))
        code, output = self.fixture.night("--state", str(own))
        self.assertEqual(code, 2, output)
        self.assertIn("NOT-STARTED", output)
        self.assertEqual(self.fixture.state(), kept)

    def test_a_set_whose_digests_disagree_does_not_start(self) -> None:
        (self.fixture.set / "manifest.sha256").write_text("f" * 64 + "\n")
        code, output = self.fixture.night()
        self.assertEqual(code, 2, output)
        self.assertIn("the set is not READY", output)

    def test_a_checkout_with_its_own_node_modules_does_not_start(self) -> None:
        (self.fixture.checkout / "tests/e2e/node_modules").mkdir()
        code, output = self.fixture.night()
        self.assertEqual(code, 2, output)
        self.assertIn("the checkout has its own tests/e2e/node_modules", output)

    def test_fewer_workers_than_a_file_s_slots_does_not_start(self) -> None:
        code, output = self.fixture.night("--workers", "1")
        self.assertEqual(code, 2, output)
        self.assertIn("a file needs 2 slots, more than --workers 1", output)


if __name__ == "__main__":
    unittest.main()
