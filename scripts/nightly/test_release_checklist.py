"""Tests of scripts/nightly/release_checklist.py (the release checklist, PR 10d).

Run: python3 -m unittest discover -s scripts/nightly -p 'test_*.py' -v
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_checklist  # noqa: E402

TODAY = "2026-11-20"
REVISIONS = "oneiron-docedit::revisions archive_preflight_refuses_entry_part_and_cumulative_inflation"
STEMMA = "oneiron-docedit::stemma_reader start_tag_with_many_attributes_parses_in_bounded_time"
STATE_LINE = re.compile(r"^(\d)\. \[(MET|NOT MET|UNKNOWN)\] ")


def cargo_line(night: str, state: str = "GREEN", **fields: int) -> str:
    counts = {"skipped": 0, "quarantined": 0, "pending": 0, "expired": 0, "quarantine_gated": 0, "new_gates": 0}
    counts.update(fields)
    words = " ".join(f"{key}={value}" for key, value in counts.items())
    return f"NIGHTLY {night} head=aaaaaaaaaaaa1111 {state} build=ok cycle=1 {words} red_nights=0"


def e2e_line(night: str, state: str = "GREEN", **fields: int) -> str:
    counts = {"pass": 259, "fail": 0, "blocked": 0, "skipped": 0, "deadline": 0}
    counts.update(fields)
    words = " ".join(f"{key}={value}" for key, value in counts.items())
    return f"NIGHTLY-E2E {night} head=bbbbbbbbbbbb set=cccccccccccc {state} runs=5/5 {words} workers=2"


GREEN_HISTORY = [
    line for night in ("2026-11-17", "2026-11-18", "2026-11-19") for line in (cargo_line(night), e2e_line(night))
]


def summary(*tests: tuple[str, str], not_run: tuple[str, ...] = ()) -> dict:
    return {
        "date": "2026-11-19",
        "head": "aaaaaaaaaaaa1111",
        "budget": {
            "host": "<host>",
            "tests": [{"id": name, "test": f"pkg::bin {name}", "band": band} for name, band in tests],
            "not_run": [{"id": name, "reason": "quarantined"} for name in not_run],
        },
    }


GREEN_SUMMARY = summary(("vault-open", "in"), ("stemma", "in"))
GREEN_STORE = {
    REVISIONS: {"outcome": "pass", "date": "2026-11-18"},
    STEMMA: {"outcome": "pass", "date": "2026-11-19"},
    "oneiron::it sync_ok": {"outcome": "pass", "date": "2026-11-19"},
}


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def make_tree(root: Path, *, todo: int = 0, skip: int = 0, pending_door: int = 0, ignore: int = 0) -> Path:
    """A workspace like the engine's: members crates/*, one excluded vendor, one nested vendored package."""
    write(root / "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/heed"]\n')
    package = '[package]\nname = "{}"\nversion = "0.1.0"\n'
    write(root / "crates/core/Cargo.toml", package.format("core"))
    ignored = "".join(f'#[test]\n#[ignore = "slow"]\nfn slow_{n}() {{}}\n' for n in range(ignore))
    write(root / "crates/core/src/lib.rs", f"// a comment naming #[ignore] is not a test\n{ignored}")
    # Never run by cargo: an excluded member, a package nested in a member, and a build output.
    write(root / "crates/heed/Cargo.toml", package.format("heed"))
    write(root / "crates/heed/src/lib.rs", "#[test]\n#[ignore]\nfn upstream() {}\n")
    write(root / "crates/core/vendor/stemma/Cargo.toml", package.format("stemma"))
    write(root / "crates/core/vendor/stemma/tests/suite.rs", "#[test]\n#[ignore]\nfn upstream() {}\n")
    write(root / "crates/core/target/debug/build/out.rs", "#[ignore]\n")
    write(root / "crates/oneiron-docedit/Cargo.toml", package.format("oneiron-docedit"))
    write(
        root / "crates/oneiron-docedit/tests/revisions.rs",
        "#[test]\nfn archive_preflight_refuses_entry_part_and_cumulative_inflation() {}\n",
    )
    write(
        root / "crates/oneiron-docedit/tests/stemma_reader.rs",
        "#[test]\nfn start_tag_with_many_attributes_parses_in_bounded_time() {}\n",
    )
    cases = (
        [f'suite.todo(test, "A-{n:02}", "waits on a door");' for n in range(todo)]
        + [f'suite.skip(test, "B-{n:02}", "waits on a host");' for n in range(skip)]
        + [f'suite.pendingDoor(test, "C-{n:02}", "waits on a door", pending);' for n in range(pending_door)]
    )
    write(root / "tests/e2e/memory.test.ts", "\n".join(['suite.test(test, "M-01", async () => {});', *cases]) + "\n")
    # The runner's own definitions are not cases.
    write(root / "tests/e2e/support/run.ts", "todo(test, id, reason) { test.todo(id); }\nsuite.todo(\n")
    write(root / "tests/e2e/node_modules/pkg/x.test.ts", 'suite.todo(test, "X-01", "vendored");\n')
    write(root / ".config/test-quarantine.toml", "# Quarantined tests. Empty today.\n")
    return root


class ChecklistCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.tree = make_tree(self.dir / "tree")
        self.register = write(self.dir / "register.jsonl", "")
        patcher = mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(self.dir)})
        patcher.start()
        os.environ.pop(release_checklist.REGISTER_ENV, None)
        self.addCleanup(patcher.stop)

    def run_checklist(
        self,
        *,
        history: list[str] | None = GREEN_HISTORY,
        summary_json: dict | None = GREEN_SUMMARY,
        store: dict | None = GREEN_STORE,
        register: bool = True,
        extra: tuple[str, ...] = (),
    ) -> tuple[int, dict[int, str], str]:
        argv = ["--tree", str(self.tree), "--today", TODAY, *extra]
        if history is not None:
            argv += ["--history", str(write(self.dir / "history.txt", "\n".join(history) + "\n"))]
        if summary_json is not None:
            argv += ["--summary", str(write(self.dir / "summary.json", json.dumps(summary_json)))]
        if store is not None:
            argv += ["--results-store", str(write(self.dir / "results-store.json", json.dumps(store)))]
        if register:
            argv += ["--register", str(self.register)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = release_checklist.main(argv)
        text = out.getvalue() + err.getvalue()
        states = {int(m.group(1)): m.group(2) for line in text.splitlines() if (m := STATE_LINE.match(line))}
        return code, states, text

    def condition_text(self, text: str, number: int) -> str:
        """The condition's own line and its evidence lines."""
        lines = text.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith(f"{number}. ["))
        end = next((i for i in range(start + 1, len(lines)) if not lines[i].startswith("   ")), len(lines))
        return "\n".join(lines[start:end])


class CleanReleaseTest(ChecklistCase):
    def test_a_clean_release_meets_every_sourced_condition_and_leaves_quality_and_upgrade_unknown(self) -> None:
        code, states, text = self.run_checklist()
        self.assertEqual(states, {1: "MET", 2: "MET", 3: "UNKNOWN", 4: "MET", 5: "UNKNOWN", 6: "MET", 7: "MET"}, text)
        self.assertEqual(code, 1)
        self.assertIn(f"## RELEASE {TODAY} head=unknown NOT-MET met=5/7 not_met=0 unknown=2", text)
        self.assertIn("RELEASE-CHECK-QUALITY-NO-SOURCE", self.condition_text(text, 3))
        self.assertIn("previous tag: none found", self.condition_text(text, 5))

    def test_the_checklist_passes_only_when_all_seven_are_met(self) -> None:
        def met(_inputs: release_checklist.Inputs) -> tuple[str, list[str]]:
            return release_checklist.MET, []

        unsourced = (release_checklist.quality, release_checklist.upgrade)
        checks = tuple(met if check in unsourced else check for check in release_checklist.CHECKS)
        with mock.patch.object(release_checklist, "CHECKS", checks):
            code, states, text = self.run_checklist()
        self.assertEqual(set(states.values()), {"MET"}, text)
        self.assertEqual(code, 0)
        self.assertIn("MET met=7/7 not_met=0 unknown=0", text)


class ThreeNightsTest(ChecklistCase):
    def test_a_red_night_among_the_last_three_is_not_met(self) -> None:
        history = [*GREEN_HISTORY[:2], cargo_line("2026-11-18", "RED"), *GREEN_HISTORY[3:]]
        _, states, text = self.run_checklist(history=history)
        self.assertEqual(states[1], "NOT MET", text)
        self.assertIn("2026-11-18 NIGHTLY: RED", text)

    def test_a_red_e2e_night_is_not_met(self) -> None:
        _, states, text = self.run_checklist(history=[*GREEN_HISTORY, e2e_line("2026-11-19", "RED", fail=2)])
        self.assertEqual(states[1], "NOT MET", text)

    def test_an_e2e_night_that_did_not_start_is_not_green(self) -> None:
        not_started = "NIGHTLY-E2E 2026-11-19 head=bbbbbbbbbbbb set=none NOT-STARTED reason=no READY set"
        _, states, text = self.run_checklist(history=[*GREEN_HISTORY, not_started])
        self.assertEqual(states[1], "NOT MET", text)
        self.assertIn("2026-11-19 NIGHTLY-E2E: NOT-STARTED", text)

    def test_a_night_without_its_e2e_line_is_not_met(self) -> None:
        history = [line for line in GREEN_HISTORY if not line.startswith("NIGHTLY-E2E 2026-11-18")]
        _, states, text = self.run_checklist(history=history)
        self.assertEqual(states[1], "NOT MET", text)
        self.assertIn("2026-11-18 NIGHTLY-E2E: no line", text)

    def test_fewer_than_three_nights_is_not_met(self) -> None:
        _, states, text = self.run_checklist(history=GREEN_HISTORY[2:])
        self.assertEqual(states[1], "NOT MET", text)
        self.assertIn("2 night(s) in the history, 3 needed", text)

    def test_only_the_last_three_nights_count(self) -> None:
        older_red = [cargo_line("2026-11-10", "RED"), e2e_line("2026-11-10", "RED")]
        _, states, text = self.run_checklist(history=[*older_red, *GREEN_HISTORY])
        self.assertEqual(states[1], "MET", text)
        self.assertNotIn("2026-11-10", self.condition_text(text, 1))

    def test_a_later_line_on_the_same_night_wins(self) -> None:
        rerun = [cargo_line("2026-11-19", "RED"), *GREEN_HISTORY]
        _, states, text = self.run_checklist(history=rerun)
        self.assertEqual(states[1], "MET", text)

    def test_nights_after_today_are_left_out(self) -> None:
        future = [cargo_line("2026-11-21", "RED"), e2e_line("2026-11-21", "RED")]
        _, states, text = self.run_checklist(history=[*GREEN_HISTORY, *future])
        self.assertEqual(states[1], "MET", text)

    def test_events_log_prefixes_and_summary_echoes_are_read(self) -> None:
        history = [
            f"11-20 06:01 ## NIGHTLY SUMMARY {line}"
            if line.startswith("NIGHTLY ")
            else f"## NIGHTLY-E2E SUMMARY {line}"
            for line in GREEN_HISTORY
        ]
        history += ["11-19 15:37 INBOX 15:37 JST OPUS-TESTKIT NOTE NIGHTLY-MEASURED 2026-11-19 head=x RED"]
        _, states, text = self.run_checklist(history=history)
        self.assertEqual(states[1], "MET", text)
        self.assertEqual(self.condition_text(text, 1).count(": GREEN"), 6, text)

    def test_the_results_store_failures_are_shown_beside_the_three_nights(self) -> None:
        store = {**GREEN_STORE, "oneiron::it a_shard_test": {"outcome": "fail", "date": "2026-11-12"}}
        _, states, text = self.run_checklist(store=store)
        self.assertEqual(states[1], "MET", text)
        self.assertIn("results store: 1 of 4 test(s) failed at their last run", text)

    def test_no_history_is_unknown(self) -> None:
        _, states, text = self.run_checklist(history=None)
        self.assertEqual(states[1], "UNKNOWN", text)
        self.assertEqual(states[2], "UNKNOWN", text)
        self.assertIn("no NIGHTLY line", self.condition_text(text, 2))


class NothingLeftOutTest(ChecklistCase):
    def test_e2e_todo_and_skip_cases_are_counted(self) -> None:
        self.tree = make_tree(self.dir / "tree", todo=3, skip=1)
        _, states, text = self.run_checklist()
        self.assertEqual(states[2], "NOT MET", text)
        self.assertIn("e2e suite.todo cases (BLOCKED): 3", text)
        self.assertIn("e2e suite.skip cases: 1", text)

    def test_ignored_tests_count_in_members_only(self) -> None:
        self.tree = make_tree(self.dir / "tree", ignore=2)
        _, states, text = self.run_checklist()
        self.assertEqual(states[2], "NOT MET", text)
        self.assertIn("#[ignore] tests in workspace members: 2", text)

    def test_vendored_nested_and_build_output_ignores_are_not_counted(self) -> None:
        _, states, text = self.run_checklist()
        self.assertIn("#[ignore] tests in workspace members: 0", text)
        self.assertIn("e2e suite.todo cases (BLOCKED): 0", text)
        self.assertEqual(states[2], "MET", text)

    def test_a_quarantine_row_is_not_met(self) -> None:
        row = '[[test]]\nfilter = "test(=flaky)"\nissue = "FIX [X]"\nadded = "2026-11-18"\nexpires = "2026-11-25"\n'
        write(self.tree / ".config/test-quarantine.toml", row)
        _, states, text = self.run_checklist()
        self.assertEqual(states[2], "NOT MET", text)
        self.assertIn(".config/test-quarantine.toml rows: 1", text)

    def test_the_last_nights_counts_are_read(self) -> None:
        history = [*GREEN_HISTORY, cargo_line("2026-11-19", quarantine_gated=401), e2e_line("2026-11-19", blocked=3)]
        _, states, text = self.run_checklist(history=history)
        self.assertEqual(states[2], "NOT MET", text)
        self.assertIn("NIGHTLY 2026-11-19 quarantine_gated: 401", text)
        self.assertIn("NIGHTLY-E2E 2026-11-19 blocked: 3", text)

    def test_a_night_line_without_a_count_is_unknown(self) -> None:
        history = [line.replace(" skipped=0", "") if line.startswith("NIGHTLY-E2E") else line for line in GREEN_HISTORY]
        _, states, text = self.run_checklist(history=history)
        self.assertEqual(states[2], "UNKNOWN", text)
        self.assertIn("NIGHTLY-E2E 2026-11-19: no skipped=", text)


class BudgetTest(ChecklistCase):
    def test_a_budget_out_of_band_either_way_is_not_met(self) -> None:
        for band in ("over", "under"):
            with self.subTest(band=band):
                _, states, text = self.run_checklist(summary_json=summary(("a", "in"), ("b", band)))
                self.assertEqual(states[4], "NOT MET", text)
                self.assertIn(f"pkg::bin b: {band}", text)

    def test_a_pending_baseline_or_a_missing_sample_is_not_met(self) -> None:
        for band in ("pending", "no-sample"):
            with self.subTest(band=band):
                _, states, text = self.run_checklist(summary_json=summary(("a", "in"), ("b", band)))
                self.assertEqual(states[4], "NOT MET", text)

    def test_a_budget_row_not_run_is_not_met(self) -> None:
        _, states, text = self.run_checklist(summary_json=summary(("a", "in"), not_run=("ready-parent",)))
        self.assertEqual(states[4], "NOT MET", text)
        self.assertIn("not run: ready-parent (quarantined)", text)

    def test_no_budget_measured_is_not_met(self) -> None:
        _, states, text = self.run_checklist(summary_json=summary())
        self.assertEqual(states[4], "NOT MET", text)
        self.assertIn("no budget test measured", text)

    def test_no_summary_or_no_budget_report_is_unknown(self) -> None:
        _, states, _ = self.run_checklist(summary_json=None)
        self.assertEqual(states[4], "UNKNOWN")
        _, states, text = self.run_checklist(summary_json={"date": "2026-11-19"})
        self.assertEqual(states[4], "UNKNOWN", text)


class PendingDoorTest(ChecklistCase):
    ROWS = [
        {
            "row": "ND-001",
            "crate": "oneiron",
            "file": "crates/oneiron/src/a.rs",
            "test": "t1",
            "deadline": "2026-12-01",
        },
        {"row": "ND-002", "crate": "e2e", "file": "tests/e2e/x.test.ts", "test": "X-01", "deadline": "2026-11-19"},
        {"row": "ND-003", "crate": "oneiron", "module": "crates/oneiron/src/b", "door": "a door", "status": "DOOR-ROW"},
    ]

    def test_waiting_tests_and_e2e_cases_are_not_met_and_expired_rows_are_named(self) -> None:
        write(self.register, "\n".join(json.dumps(row) for row in self.ROWS) + "\n")
        _, states, text = self.run_checklist()
        self.assertEqual(states[6], "NOT MET", text)
        self.assertIn("register: 1 Rust test(s), 1 E2E case(s), 1 past their deadline", text)
        self.assertIn("door or delete: ND-002 tests/e2e/x.test.ts::X-01 (deadline 2026-11-19)", text)

    def test_a_door_row_naming_no_test_does_not_count(self) -> None:
        write(self.register, json.dumps(self.ROWS[2]) + "\n")
        _, states, text = self.run_checklist()
        self.assertEqual(states[6], "MET", text)

    def test_a_pending_door_case_in_the_tree_is_not_met(self) -> None:
        self.tree = make_tree(self.dir / "tree", pending_door=2)
        _, states, text = self.run_checklist()
        self.assertEqual(states[6], "NOT MET", text)
        self.assertIn("e2e suite.pendingDoor cases: 2", text)

    def test_the_last_nights_pending_count_is_read(self) -> None:
        _, states, text = self.run_checklist(history=[*GREEN_HISTORY, cargo_line("2026-11-19", pending=230)])
        self.assertEqual(states[6], "NOT MET", text)

    def test_no_register_is_unknown_and_the_environment_names_one(self) -> None:
        _, states, text = self.run_checklist(register=False)
        self.assertEqual(states[6], "UNKNOWN", text)
        write(self.register, json.dumps(self.ROWS[0]) + "\n")
        with mock.patch.dict(os.environ, {release_checklist.REGISTER_ENV: str(self.register)}):
            _, states, text = self.run_checklist(register=False)
        self.assertEqual(states[6], "NOT MET", text)


class OfficeTest(ChecklistCase):
    def test_a_failed_office_test_is_not_met(self) -> None:
        store = {**GREEN_STORE, STEMMA: {"outcome": "fail", "date": "2026-11-19"}}
        _, states, text = self.run_checklist(store=store)
        self.assertEqual(states[7], "NOT MET", text)
        self.assertIn(f"{STEMMA}: fail on 2026-11-19 (fixed by #6907)", text)

    def test_an_office_test_not_yet_run_is_unknown(self) -> None:
        store = {key: value for key, value in GREEN_STORE.items() if key != REVISIONS}
        _, states, text = self.run_checklist(store=store)
        self.assertEqual(states[7], "UNKNOWN", text)
        self.assertIn(f"{REVISIONS}: not in the results store", text)

    def test_an_office_test_gone_from_the_tree_is_unknown(self) -> None:
        write(self.tree / "crates/oneiron-docedit/tests/revisions.rs", "#[test]\nfn renamed() {}\n")
        _, states, text = self.run_checklist()
        self.assertEqual(states[7], "UNKNOWN", text)
        self.assertIn("not in the tree", text)


class InputTest(ChecklistCase):
    def test_a_malformed_input_exits_2(self) -> None:
        bad = write(self.dir / "bad.json", "{not json")
        for flag in ("--summary", "--results-store"):
            with self.subTest(flag=flag):
                code, _, text = self.run_checklist(summary_json=None, store=None, extra=(flag, str(bad)))
                self.assertEqual(code, 2, text)
        write(self.register, '{"row": "ND-001"}\nnot json\n')
        code, _, text = self.run_checklist()
        self.assertEqual(code, 2, text)
        self.assertIn("line 2", text)

    def test_a_missing_input_file_exits_2(self) -> None:
        code, _, text = self.run_checklist(register=False, extra=("--register", str(self.dir / "absent.jsonl")))
        self.assertEqual(code, 2, text)

    def test_a_tree_without_cargo_toml_exits_2(self) -> None:
        self.tree = self.dir / "empty"
        self.tree.mkdir()
        code, _, text = self.run_checklist()
        self.assertEqual(code, 2, text)


if __name__ == "__main__":
    unittest.main()
