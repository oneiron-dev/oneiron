"""Tests of scripts/nightly/nightly_report.py (the nightly test job's report tool).

Run: python3 -m unittest discover -s scripts/nightly -p 'test_*.py' -v
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nightly_report  # noqa: E402

BUILD_LOG = """\
   Compiling oneiron v0.1.0
warning: unused import: `std::fmt`
error: could not compile `oneiron` (lib test) due to 3 previous errors; 9 warnings emitted
error: could not compile `oneiron` (test "beta") due to 1 previous error
error: could not compile `oneiron-server` (bin "oneiron-server" test) due to 2 previous errors
error: could not compile `oneiron-server` (bin "oneiron-server" test) due to 2 previous errors
error: could not compile `oneiron-docedit` (lib) due to 1 previous error
error: could not compile `oneiron-bench` (build script) due to 1 previous error
error: could not compile `oneiron-cli` (example "quickstart") due to 1 previous error
"""


def target(name: str, kind: str) -> dict:
    return {"name": name, "kind": [kind], "test": True}


METADATA = {
    "workspace_members": ["oneiron 0.1.0", "oneiron-server 0.1.0", "oneiron-testkit 0.1.0", "oneiron-bench 0.1.0"],
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
            "id": "oneiron-server 0.1.0",
            "name": "oneiron-server",
            "targets": [
                target("oneiron_server", "lib"),
                target("oneiron-server", "bin"),
                target("gamma", "test"),
                target("shared", "test"),
            ],
        },
        {
            "id": "oneiron-testkit 0.1.0",
            "name": "oneiron-testkit",
            "targets": [target("oneiron_testkit", "lib"), target("kit", "test"), target("pending_door", "test")],
        },
        {
            "id": "oneiron-bench 0.1.0",
            "name": "oneiron-bench",
            "targets": [target("oneiron_bench", "lib"), target("bench_smoke", "test")],
        },
        {"id": "serde 1.0.0", "name": "serde", "targets": [target("serde", "lib")]},
    ],
}


def unit(package: str, kind: str, name: str = "") -> dict:
    return {"package": package, "kind": kind, "name": name}


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def junit(path: Path, suites: dict[str, dict[str, str]]) -> None:
    bodies = {"pass": "", "fail": '<failure type="test failure">assertion failed</failure>', "skip": "<skipped/>"}
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<testsuites name="nextest-run">']
    for binary, tests in suites.items():
        parts.append(f'<testsuite name="{binary}" tests="{len(tests)}">')
        parts += [
            f'<testcase name="{name}" classname="{binary}">{bodies[outcome]}</testcase>'
            for name, outcome in tests.items()
        ]
        parts.append("</testsuite>")
    parts.append("</testsuites>")
    write(path, "\n".join(parts) + "\n")


ROOT_GATE = """\
pub mod access;

// FIX [LIBTEST-QUARANTINE-ROOT-TESTS]: the lib test target's type check fails here (2 errors: E0063 x2); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;
"""

ACCESS_MOD = """\
pub mod grant;

// FIX [LIBTEST-QUARANTINE-ACCESS-TESTS]: the lib test target's type check fails here (1 error: E0308 x1); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests {
    #[test]
    fn a_grant_is_read() {}
}

// FIX [LIBTEST-QUARANTINE-NOT-A-GATE]: a comment whose item carries no cfg(any())
#[cfg(test)]
mod other;
"""

GRANT_ITEMS = """\
#[cfg(test)]
mod tests {
    // FIX [LIBTEST-QUARANTINE-ACCESS-GRANT-ITEMS]: the lib test target's type check fails here (1 error: E0061 x1); port it, then drop this gate
    #[cfg(any())]
    #[test]
    fn a_revoked_grant_reads_nothing() {}

    #[test]
    fn a_grant_reads_its_rows() {}
}
"""

MANIFEST = """\
[package]
name = "oneiron"
version = "0.1.0"

[dependencies.serde]
version = "1"
"""


def tree(root: Path, root_gate: bool = True, extra_gate: bool = False) -> Path:
    write(root / "crates/core/Cargo.toml", MANIFEST)
    lib = ROOT_GATE if root_gate else "pub mod access;\n\n#[cfg(test)]\nmod tests;\n"
    if extra_gate:
        lib += "\n// FIX [LIBTEST-QUARANTINE-ROOT-NEW]: new\n#[cfg(any())]\n#[cfg(test)]\nmod fresh;\n"
    write(root / "crates/core/src/lib.rs", lib)
    write(root / "crates/core/src/access/mod.rs", ACCESS_MOD)
    write(root / "crates/core/src/access/grant.rs", GRANT_ITEMS)
    return root


class FailedUnitsTest(unittest.TestCase):
    def test_each_could_not_compile_line_becomes_one_unit_with_its_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = write(Path(tmp) / "build.log", BUILD_LOG)
            units = nightly_report.failed_units([log])
        self.assertEqual(
            units,
            [
                unit("oneiron", "lib-test"),
                unit("oneiron", "test", "beta"),
                unit("oneiron-bench", "build-script"),
                unit("oneiron-cli", "example", "quickstart"),
                unit("oneiron-docedit", "lib"),
                unit("oneiron-server", "bin-test", "oneiron-server"),
            ],
        )

    def test_units_named_in_two_logs_are_merged_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = write(
                Path(tmp) / "build.log", 'error: could not compile `oneiron` (test "beta") due to 1 previous error\n'
            )
            second = write(
                Path(tmp) / "build-1-tests.log",
                'error: could not compile `oneiron` (test "beta") due to 1 previous error\n',
            )
            self.assertEqual(nightly_report.failed_units([first, second]), [unit("oneiron", "test", "beta")])


class PlanTest(unittest.TestCase):
    def test_an_unsharded_plan_selects_the_lib_tests_then_every_integration_test_by_name(self) -> None:
        chosen = nightly_report.plan(METADATA)
        self.assertEqual(
            [nightly_report.selection_args(chosen, entry) for entry in chosen["selections"]],
            [
                ["--workspace", "--exclude", "oneiron-bench", "--lib", "--bins", "--test", "pending_door"],
                ["--workspace", "--exclude", "oneiron-bench"]
                + [a for n in ("alpha", "beta", "gamma", "kit", "shared") for a in ("--test", n)],
            ],
        )
        self.assertEqual([entry["name"] for entry in chosen["selections"]], ["libs", "tests-01"])

    def test_shards_split_the_integration_tests_into_runs_of_n_names(self) -> None:
        chosen = nightly_report.plan(METADATA, shard_files=2)
        self.assertEqual(
            [(entry["name"], entry["tests"]) for entry in chosen["selections"][1:]],
            [("tests-01", ["alpha", "beta"]), ("tests-02", ["gamma", "kit"]), ("tests-03", ["shared"])],
        )

    def test_a_cursor_starts_the_shards_at_its_name_and_wraps_past_the_end(self) -> None:
        chosen = nightly_report.plan(METADATA, shard_files=2, cursor={"next": "gamma", "cycle": 3})
        self.assertEqual(
            [(entry["name"], entry["first"], entry["last"], entry["ends_cycle"]) for entry in chosen["order"]],
            [
                ("tests-01", "gamma", "kit", False),
                ("tests-02", "shared", "alpha", True),
                ("tests-03", "beta", "beta", False),
            ],
        )
        self.assertEqual(chosen["cursor_in"], {"next": "gamma", "cycle": 3})

    def test_advancing_past_the_shard_that_ends_the_cycle_counts_a_new_cycle(self) -> None:
        chosen = nightly_report.plan(METADATA, shard_files=2, cursor={"next": "gamma", "cycle": 3})
        self.assertEqual(nightly_report.advance(chosen, "tests-01"), {"next": "shared", "cycle": 3})
        self.assertEqual(nightly_report.advance(chosen, "tests-02"), {"next": "beta", "cycle": 4})
        self.assertEqual(nightly_report.advance(chosen, "tests-03"), {"next": "gamma", "cycle": 4})
        self.assertEqual(chosen["shards_run"], ["tests-01", "tests-02", "tests-03"])

    def test_a_cursor_name_that_left_the_list_starts_at_the_next_name_or_wraps_to_the_first(self) -> None:
        self.assertEqual(nightly_report.plan(METADATA, 2, {"next": "delta"})["order"][0]["first"], "gamma")
        self.assertEqual(nightly_report.plan(METADATA, 2, {"next": "zeta"})["order"][0]["first"], "alpha")

    def test_the_deadline_is_the_next_hh_mm_in_japan_time(self) -> None:
        japan = timezone(timedelta(hours=9))
        at_0130 = datetime(2026, 11, 15, 1, 30, tzinfo=japan).timestamp()
        at_0700 = datetime(2026, 11, 15, 7, 0, tzinfo=japan).timestamp()
        self.assertEqual(
            nightly_report.deadline_epoch("06:00", at_0130), datetime(2026, 11, 15, 6, 0, tzinfo=japan).timestamp()
        )
        self.assertEqual(
            nightly_report.deadline_epoch("06:00", at_0700), datetime(2026, 11, 16, 6, 0, tzinfo=japan).timestamp()
        )

    def test_the_plan_and_advance_commands_read_and_write_the_cursor_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = write(Path(tmp) / "metadata.json", json.dumps(METADATA))
            cursor = write(Path(tmp) / "cursor.json", json.dumps({"next": "kit", "cycle": 2}))
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                nightly_report.main(["plan", str(metadata), "--shard-files", "2", "--cursor", str(cursor)])
            plan_file = write(Path(tmp) / "plan.json", printed.getvalue())
            self.assertEqual(json.loads(plan_file.read_text())["order"][0]["first"], "kit")
            nightly_report.main(["advance", str(plan_file), "tests-01", str(cursor)])
            self.assertEqual(json.loads(cursor.read_text()), {"next": "alpha", "cycle": 3})


class PruneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.chosen = nightly_report.plan(METADATA)

    def args(self, name: str) -> list[str]:
        return nightly_report.selection_args(self.chosen, nightly_report.find_selection(self.chosen, name))

    def test_a_failed_lib_test_excludes_its_package_from_the_lib_selection_only(self) -> None:
        self.assertTrue(nightly_report.prune(self.chosen, "libs", [unit("oneiron", "lib-test")], METADATA))
        self.assertEqual(self.args("libs")[:5], ["--workspace", "--exclude", "oneiron-bench", "--exclude", "oneiron"])
        self.assertNotIn("oneiron", self.chosen["selections"][1]["excluded"])
        self.assertEqual(
            self.chosen["unselected"],
            [{"selection": "libs", "package": "oneiron", "kind": "lib-test", "name": "", "reason": "did not compile"}],
        )

    def test_a_failed_testkit_lib_test_also_drops_the_door_tools_test(self) -> None:
        self.assertTrue(nightly_report.prune(self.chosen, "libs", [unit("oneiron-testkit", "lib-test")], METADATA))
        self.assertNotIn("--test", self.args("libs"))

    def test_a_failed_test_file_drops_its_name_in_every_package_that_shares_it(self) -> None:
        self.assertTrue(nightly_report.prune(self.chosen, "tests-01", [unit("oneiron", "test", "shared")], METADATA))
        self.assertEqual(self.chosen["selections"][1]["tests"], ["alpha", "beta", "gamma", "kit"])
        reasons = {(u["package"], u["name"]): u["reason"] for u in self.chosen["unselected"]}
        self.assertEqual(reasons[("oneiron", "shared")], "did not compile")
        self.assertEqual(
            reasons[("oneiron-server", "shared")], "shares its name with a test target that did not compile"
        )

    def test_a_failed_bin_excludes_its_package_and_the_names_only_it_has(self) -> None:
        self.assertTrue(
            nightly_report.prune(self.chosen, "tests-01", [unit("oneiron-server", "bin", "oneiron-server")], METADATA)
        )
        entry = self.chosen["selections"][1]
        self.assertEqual(entry["excluded"], ["oneiron-server"])
        self.assertEqual(entry["tests"], ["alpha", "beta", "kit", "shared"])

    def test_a_failed_bin_test_drops_the_bins_flag(self) -> None:
        self.assertTrue(
            nightly_report.prune(self.chosen, "libs", [unit("oneiron-server", "bin-test", "oneiron-server")], METADATA)
        )
        self.assertNotIn("--bins", self.args("libs"))

    def test_a_failed_lib_or_build_script_drops_the_selection(self) -> None:
        for failed in ([unit("oneiron", "lib")], [unit("oneiron-bench", "build-script")]):
            chosen = nightly_report.plan(METADATA)
            self.assertFalse(nightly_report.prune(chosen, "tests-01", failed, METADATA))
            self.assertEqual([entry["name"] for entry in chosen["selections"]], ["libs"])
            self.assertIn(failed[0]["package"], chosen["dropped"][0]["reason"])

    def test_a_build_that_fails_again_with_no_new_unit_drops_the_selection(self) -> None:
        failed = [unit("oneiron", "test", "beta")]
        self.assertTrue(nightly_report.prune(self.chosen, "tests-01", failed, METADATA))
        self.assertFalse(nightly_report.prune(self.chosen, "tests-01", failed, METADATA))
        self.assertEqual(
            self.chosen["dropped"],
            [{"selection": "tests-01", "reason": "the build failed again and named no new failed unit"}],
        )

    def test_the_commands_rewrite_the_plan_and_print_a_selections_args_and_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = write(Path(tmp) / "metadata.json", json.dumps(METADATA))
            plan_file = write(Path(tmp) / "plan.json", json.dumps(self.chosen))
            failed = write(Path(tmp) / "failed.json", json.dumps([unit("oneiron", "test", "beta")]))
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                self.assertEqual(
                    nightly_report.main(["prune", str(plan_file), "tests-01", str(failed), str(metadata)]), 0
                )
                nightly_report.main(["binaries", str(plan_file), "tests-01"])
                nightly_report.main(["args", str(plan_file), "--name", "libs"])
                nightly_report.main(["args", str(plan_file)])
                self.assertEqual(nightly_report.main(["drop", str(plan_file), "libs", "a reason"]), 3)
            lines = printed.getvalue().splitlines()
            self.assertEqual(lines[:4], ["alpha", "gamma", "kit", "shared"])
            self.assertEqual(lines[4], "--workspace --exclude oneiron-bench --lib --bins --test pending_door")
            self.assertEqual(lines[5].split()[0], "libs")
            self.assertEqual(lines[6].split()[:2], ["tests-01", "--workspace"])
            self.assertEqual([entry["name"] for entry in json.loads(plan_file.read_text())["selections"]], ["tests-01"])


class CensusTest(unittest.TestCase):
    def test_a_gate_is_a_fix_comment_whose_item_carries_cfg_any(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rows = nightly_report.census(tree(Path(tmp)))
        self.assertEqual(
            [(row["id"], row["package"], row["kind"], row["module"], row["item"]) for row in rows],
            [
                (
                    "LIBTEST-QUARANTINE-ACCESS-GRANT-ITEMS",
                    "oneiron",
                    "fn",
                    "access::grant",
                    "a_revoked_grant_reads_nothing",
                ),
                ("LIBTEST-QUARANTINE-ACCESS-TESTS", "oneiron", "mod", "access::tests", "tests"),
                ("LIBTEST-QUARANTINE-ROOT-TESTS", "oneiron", "mod", "tests", "tests"),
            ],
        )
        self.assertEqual(rows[1]["file"], "crates/core/src/access/mod.rs")

    def test_a_gated_item_after_long_doc_comments_and_a_multi_line_attribute_is_found(self) -> None:
        doc = "".join(f"/// line {n} of a long bug repro note.\n" for n in range(30))
        source = (
            "// FIX [LIBTEST-QUARANTINE-LONG-DOC-ITEMS]: the lib test target's type check fails here\n"
            "#[cfg(any())]\n"
            + doc
            + '#[cfg(all(\n    feature = "sync",\n    test\n))]\n#[test]\nfn a_tie_settles_for_the_last_link() {}\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "crates/core/Cargo.toml", MANIFEST)
            write(root / "crates/core/src/lib.rs", "mod roster;\n")
            write(root / "crates/core/src/roster.rs", source)
            rows = nightly_report.census(root)
        self.assertEqual(
            [(row["kind"], row["module"], row["item"]) for row in rows],
            [("fn", "roster", "a_tie_settles_for_the_last_link")],
        )

    def test_the_census_tsv_reads_back_the_same_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rows = nightly_report.census(tree(Path(tmp)))
            path = write(Path(tmp) / "baseline.tsv", nightly_report.census_tsv(rows))
            self.assertEqual(nightly_report.read_census_tsv(path), rows)


class SummaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.out = base / "out"
        self.out.mkdir()
        baseline_rows = nightly_report.census(tree(base / "baseline"))
        self.baseline = write(base / "baseline.tsv", nightly_report.census_tsv(baseline_rows))
        self.tonight = tree(base / "tonight")
        self.plan = write(self.out / "plan.json", json.dumps(nightly_report.plan(METADATA)))
        self.pending_door = write(
            self.out / "pending-door.json",
            json.dumps({"pending": 0, "expired": 0, "pending_filter": "none()", "expired_filter": "none()"}),
        )
        junit(
            self.out / "junit-verdict-workspace.xml",
            {"oneiron::alpha": {"a_claim_is_read": "pass", "a_claim_is_kept": "pass"}},
        )

    def run_summary(self, **extra: str) -> tuple[int, str]:
        args = Namespace(
            out=str(self.out),
            date="2026-11-15",
            head="0123456789abcdef0123456789abcdef01234567",
            host="nelly",
            plan=str(self.plan),
            pending_door=str(self.pending_door),
            baseline=str(self.baseline),
            census_root=str(self.tonight),
            previous=None,
            history=None,
            budget_set=None,
            budget_baseline=None,
            budget_samples=None,
        )
        for key, value in extra.items():
            setattr(args, key, value)
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = nightly_report.summary(args)
        return code, printed.getvalue().strip()

    def test_a_night_with_every_test_passing_is_green(self) -> None:
        code, line = self.run_summary()
        self.assertEqual(code, 0)
        self.assertTrue(
            line.startswith(
                "NIGHTLY 2026-11-15 head=0123456789ab GREEN build=ok cycle=1 shards_run=0/1 next=alpha passed=2 failed=0 skipped=0"
            ),
            line,
        )
        self.assertIn(" quarantine_gated=3 ported_green=0 ported_red=0 new_gates=0 red_nights=0", line)
        record = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(record["verdict"], "green")
        self.assertEqual(json.loads((self.out / "flake-row.json").read_text())["host"], "nelly")

    def test_one_failed_test_makes_the_night_red_and_names_the_test(self) -> None:
        junit(
            self.out / "junit-verdict-workspace.xml",
            {"oneiron::alpha": {"a_claim_is_read": "fail", "a_claim_is_kept": "pass"}},
        )
        code, line = self.run_summary()
        self.assertEqual(code, 1)
        self.assertIn(" RED build=ok cycle=1 shards_run=0/1 next=alpha passed=1 failed=1 ", line)
        self.assertIn("failed: oneiron::alpha a_claim_is_read", (self.out / "summary.txt").read_text())

    def test_a_ported_module_is_named_with_its_tests_pass_or_fail(self) -> None:
        self.tonight = tree(Path(self.tmp.name) / "ported", root_gate=False)
        junit(
            self.out / "junit-libtest-workspace.xml",
            {"oneiron": {"tests::a_row_is_kept": "pass", "tests::a_row_is_read": "fail"}},
        )
        code, line = self.run_summary()
        self.assertEqual(code, 0, "the lib test stage is report only")
        self.assertIn(" libtest_passed=1 libtest_failed=1 quarantine_gated=2 ported_green=0 ported_red=1 ", line)
        self.assertTrue(line.endswith(" ported_red_ids=LIBTEST-QUARANTINE-ROOT-TESTS"), line)
        text = (self.out / "summary.txt").read_text()
        self.assertIn("ported LIBTEST-QUARANTINE-ROOT-TESTS: red 2 test(s), failed: tests::a_row_is_read", text)
        state = json.loads((self.out / "summary.json").read_text())["quarantine"]["ids"]
        self.assertEqual(state["LIBTEST-QUARANTINE-ACCESS-TESTS"]["state"], "gated")

    def test_a_ported_test_fn_is_found_inside_its_files_module(self) -> None:
        tonight = Path(self.tmp.name) / "ported-fn"
        tree(tonight)
        write(tonight / "crates/core/src/access/grant.rs", GRANT_ITEMS.replace("    #[cfg(any())]\n", "", 1))
        self.tonight = tonight
        junit(
            self.out / "junit-libtest-workspace.xml",
            {"oneiron": {"access::grant::tests::a_revoked_grant_reads_nothing": "pass"}},
        )
        _, line = self.run_summary()
        self.assertIn(" quarantine_gated=2 ported_green=1 ported_red=0 ", line)

    def test_a_gate_not_in_the_baseline_is_counted_as_new(self) -> None:
        self.tonight = tree(Path(self.tmp.name) / "new-gate", extra_gate=True)
        _, line = self.run_summary()
        self.assertIn(" new_gates=1 ", line)
        self.assertIn("new quarantine gate: LIBTEST-QUARANTINE-ROOT-NEW", (self.out / "summary.txt").read_text())

    def test_a_flip_compares_a_test_with_its_own_last_run_and_the_store_keeps_tests_not_run(self) -> None:
        store = {
            "oneiron::alpha a_claim_is_read": {"outcome": "pass", "date": "2026-11-12"},
            "oneiron::kit a_kit_case": {"outcome": "fail", "date": "2026-11-10"},
        }
        previous = write(Path(self.tmp.name) / "store.json", json.dumps(store))
        junit(self.out / "junit-verdict-workspace.xml", {"oneiron::alpha": {"a_claim_is_read": "fail"}})
        _, line = self.run_summary(previous=str(previous))
        self.assertIn(" flipped=1 ", line)
        row = json.loads((self.out / "flake-row.json").read_text())
        self.assertEqual(
            row["flipped_tests"],
            [{"test": "oneiron::alpha a_claim_is_read", "from": "pass", "to": "fail", "since": "2026-11-12"}],
        )
        self.assertEqual(
            json.loads((self.out / "results-store.json").read_text()),
            {
                "oneiron::alpha a_claim_is_read": {"outcome": "fail", "date": "2026-11-15"},
                "oneiron::kit a_kit_case": {"outcome": "fail", "date": "2026-11-10"},
            },
        )

    def test_the_third_red_night_in_a_row_says_so(self) -> None:
        history = write(
            Path(self.tmp.name) / "history.txt",
            "NIGHTLY 2026-11-12 head=aaaaaaaaaaaa GREEN build=ok\n"
            "NIGHTLY 2026-11-13 head=bbbbbbbbbbbb RED build=ok\n"
            "NIGHTLY 2026-11-14 head=cccccccccccc RED build=fallback\n",
        )
        junit(self.out / "junit-verdict-workspace.xml", {"oneiron::alpha": {"a_claim_is_read": "fail"}})
        _, line = self.run_summary(history=str(history))
        self.assertIn(" red_nights=3", line)

    def test_an_expired_pending_door_test_makes_the_night_red(self) -> None:
        write(
            self.pending_door,
            json.dumps({"pending": 1, "expired": 1, "pending_filter": "none()", "expired_filter": "test(=x)"}),
        )
        code, line = self.run_summary()
        self.assertEqual(code, 1)
        self.assertIn(" pending=1 expired=1 ", line)

    def test_a_night_whose_pending_door_tool_did_not_run_is_red(self) -> None:
        code, line = self.run_summary(pending_door=str(self.out / "absent.json"))
        self.assertEqual(code, 1)
        self.assertIn(" pending=? expired=? ", line)
        self.assertIn(
            "the pending-door tool did not run", json.loads((self.out / "summary.json").read_text())["reasons"]
        )

    def test_a_unit_left_out_of_the_build_makes_the_night_red_and_is_listed(self) -> None:
        chosen = nightly_report.plan(METADATA)
        nightly_report.prune(chosen, "tests-01", [unit("oneiron", "test", "beta")], METADATA)
        write(self.plan, json.dumps(chosen))
        code, line = self.run_summary()
        self.assertEqual(code, 1)
        self.assertIn(" RED build=partial cycle=1 shards_run=0/1 ", line)
        self.assertIn(
            "unselected: tests-01 oneiron test beta (did not compile)", (self.out / "summary.txt").read_text()
        )

    def test_the_report_names_the_cycle_the_shards_run_and_a_dropped_selection(self) -> None:
        chosen = nightly_report.plan(METADATA, shard_files=2, cursor={"next": "gamma", "cycle": 2})
        nightly_report.advance(chosen, "tests-01")
        nightly_report.drop(chosen, "tests-02", "the build failed in 3 rounds")
        nightly_report.advance(chosen, "tests-02")
        write(self.plan, json.dumps(chosen))
        _, line = self.run_summary()
        self.assertIn(" RED build=partial cycle=2 shards_run=2/3 next=beta passed=2 ", line)
        text = (self.out / "summary.txt").read_text()
        self.assertIn("shard tests-01: gamma .. kit (2 files)\n", text)
        self.assertIn("shard tests-02: shared .. alpha (2 files), ends cycle\n", text)
        self.assertIn("not run tonight: 1 shard(s); the cursor resumes at beta", text)
        self.assertIn("dropped: tests-02 (the build failed in 3 rounds)", text)

    def test_a_verdict_stage_that_did_not_run_makes_the_night_red_beside_a_passing_one(self) -> None:
        write(
            self.out / "stages.tsv",
            "verdict\tlibs\t0\tyes\tyes\nverdict\ttests-01\t104\tno\tno\nquarantine\tlibs\t96\tyes\tno\n",
        )
        code, line = self.run_summary()
        self.assertEqual(code, 1)
        self.assertIn(
            " RED build=ok cycle=1 shards_run=0/1 next=alpha passed=2 failed=0 skipped=0 verdict_not_run=1 ", line
        )
        record = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(record["reasons"], ["the verdict stage of tests-01 did not run (exit 104, no JUnit)"])
        self.assertEqual([end["selection"] for end in record["stages_not_run"]], ["tests-01", "libs"])
        text = (self.out / "summary.txt").read_text()
        self.assertIn("not run: the verdict stage of tests-01 did not run (exit 104, no JUnit)\n", text)
        self.assertIn("not run: the quarantine stage of libs did not run (exit 96) (report only)\n", text)

    def test_a_verdict_run_that_wrote_no_junit_makes_the_night_red(self) -> None:
        (self.out / "junit-verdict-workspace.xml").unlink()
        code, _ = self.run_summary()
        self.assertEqual(code, 1)
        self.assertIn(
            "the verdict run reported no test", json.loads((self.out / "summary.json").read_text())["reasons"]
        )


REPO = Path(__file__).resolve().parent.parent.parent

BUDGET_SET = "".join(
    "\t".join(row) + "\n"
    for row in (
        ("id", "package", "kind", "binary", "match", "test", "source", "bound"),
        ("grant-rows", "oneiron", "lib", "oneiron", "=", "access::grant::tests::a_grant_reads_its_rows",
         "crates/core/src/access/grant.rs", "nightly override: 30 min"),
        ("long-replay", "oneiron", "lib", "oneiron", "=", "tests::replay::a_long_replay",
         "crates/core/src/tests/replay.rs", "60 min"),
        ("alpha-props", "oneiron", "test", "alpha", "^", "props::", "crates/core/tests/alpha.rs", "30 min"),
        ("kit-bounded", "oneiron-testkit", "test", "kit", "~", "_in_bounded_time", "crates/kit/tests/kit.rs", "5 s"),
        ("bench-smoke", "oneiron-bench", "test", "bench_smoke", "=", "a_smoke_run", "crates/bench/tests/s.rs", "30 min"),
    )
)  # fmt: skip


def timed_junit(path: Path, suites: dict[str, dict[str, tuple[str, float]]]) -> None:
    bodies = {"pass": "", "fail": '<failure type="test failure">assertion failed</failure>'}
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<testsuites name="nextest-run">']
    for binary, tests in suites.items():
        parts.append(f'<testsuite name="{binary}" tests="{len(tests)}">')
        parts += [
            f'<testcase name="{name}" classname="{binary}" time="{seconds}">{bodies[outcome]}</testcase>'
            for name, (outcome, seconds) in tests.items()
        ]
        parts.append("</testsuite>")
    parts.append("</testsuites>")
    write(path, "\n".join(parts) + "\n")


class BudgetSetTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.rows = nightly_report.read_budget_set(write(self.base / "budget-set.tsv", BUDGET_SET))

    def test_the_budget_filter_names_each_row_by_package_kind_binary_and_its_match(self) -> None:
        self.assertEqual(
            nightly_report.budget_filter(self.rows),
            "(package(oneiron) & kind(lib) & test(=access::grant::tests::a_grant_reads_its_rows))"
            " | (package(oneiron) & kind(lib) & test(=tests::replay::a_long_replay))"
            " | (package(oneiron) & kind(test) & binary(=alpha) & test(/^props::/))"
            " | (package(oneiron-testkit) & kind(test) & binary(=kit) & test(~_in_bounded_time))"
            " | (package(oneiron-bench) & kind(test) & binary(=bench_smoke) & test(=a_smoke_run))",
        )
        self.assertEqual(nightly_report.budget_filter([]), "none()")

    def test_the_filter_keeps_only_rows_a_selection_can_run(self) -> None:
        # nextest refuses a package() or binary() that matches nothing (toy night job 1114-133136-ec54: exit 94,
        # "operator didn't match any binary names")
        def ids(metadata: dict) -> list[str]:
            kept = nightly_report.budget_filter(self.rows, metadata)
            return [row["id"] for row in self.rows if nightly_report.budget_filter([row]) in kept]

        self.assertEqual(ids(METADATA), ["grant-rows", "long-replay", "alpha-props", "kit-bounded"], "bench left out")
        no_testkit = {**METADATA, "workspace_members": ["oneiron 0.1.0", "oneiron-server 0.1.0"]}
        self.assertEqual(ids(no_testkit), ["grant-rows", "long-replay", "alpha-props"], "not a member")
        no_alpha = json.loads(json.dumps(METADATA))
        no_alpha["packages"][0]["targets"] = [t for t in no_alpha["packages"][0]["targets"] if t["name"] != "alpha"]
        self.assertEqual(ids(no_alpha), ["grant-rows", "long-replay", "kit-bounded"], "no such test target")
        no_lib = json.loads(json.dumps(METADATA))
        no_lib["packages"][0]["targets"] = [t for t in no_lib["packages"][0]["targets"] if t["kind"] != ["lib"]]
        self.assertEqual(ids(no_lib), ["alpha-props", "kit-bounded"], "no lib")
        empty = {**METADATA, "workspace_members": ["oneiron-bench 0.1.0"]}
        self.assertEqual(nightly_report.budget_filter(self.rows, empty), "none()")
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            nightly_report.main(
                [
                    "budget-filter",
                    str(self.base / "budget-set.tsv"),
                    "--metadata",
                    str(write(self.base / "m.json", json.dumps(METADATA))),
                ]
            )
        self.assertEqual(printed.getvalue().strip(), nightly_report.budget_filter(self.rows, METADATA))

    def test_a_budget_set_with_an_unknown_match_a_missing_column_or_a_repeated_id_is_refused(self) -> None:
        header, first = BUDGET_SET.splitlines()[:2]
        for broken in (
            first.replace("\t=\t", "\t*\t"),
            first.replace("\tlib\t", "\tbench\t"),
            first.replace("\tnightly override: 30 min", "\t"),
        ):
            with self.subTest(broken=broken), self.assertRaises(SystemExit):
                nightly_report.read_budget_set(write(self.base / "broken.tsv", f"{header}\n{broken}\n"))
        with self.assertRaises(SystemExit):
            nightly_report.read_budget_set(write(self.base / "twice.tsv", f"{header}\n{first}\n{first}\n"))

    def test_the_budget_tests_run_every_night_after_the_libs_with_a_shards_args(self) -> None:
        cursor = {"next": "kit", "cycle": 2}
        chosen = nightly_report.plan(METADATA, shard_files=2, cursor=cursor, budget=self.rows)
        self.assertEqual(
            [entry["name"] for entry in chosen["selections"]], ["libs", "budget", "tests-01", "tests-02", "tests-03"]
        )
        budget = nightly_report.find_selection(chosen, "budget")
        self.assertEqual(
            nightly_report.selection_args(chosen, budget),
            ["--workspace", "--exclude", "oneiron-bench", "--test", "alpha", "--test", "kit"],
        )
        self.assertEqual([entry["first"] for entry in chosen["order"]], ["kit", "alpha", "gamma"], "shards unchanged")
        self.assertNotIn("budget", [entry["name"] for entry in nightly_report.plan(METADATA)["selections"]])

    def test_a_budget_selection_whose_every_test_failed_to_compile_is_dropped(self) -> None:
        chosen = nightly_report.plan(METADATA, budget=self.rows)
        failed = [unit("oneiron", "test", "alpha"), unit("oneiron-testkit", "test", "kit")]
        self.assertFalse(nightly_report.prune(chosen, "budget", failed, METADATA))
        self.assertEqual(chosen["dropped"], [{"selection": "budget", "reason": "every unit is left out"}])

    def test_the_committed_budget_set_names_test_targets_and_tests_that_exist(self) -> None:
        rows = nightly_report.read_budget_set(REPO / "scripts/nightly/budget-set.tsv")
        self.assertGreaterEqual(len(rows), 6)
        for row in rows:
            with self.subTest(row=row["id"]):
                source = REPO / row["source"]
                crate = REPO / Path(row["source"]).parts[0] / Path(row["source"]).parts[1]
                self.assertIn(f'name = "{row["package"]}"', (crate / "Cargo.toml").read_text())
                text = source.read_text()
                if row["kind"] == "job":  # a bench job's metric (PR 10b2)
                    import nightly_bench  # noqa: PLC0415 (the bench module came with the job rows)

                    self.assertIn(row["binary"], [job[0] for job in nightly_bench.BENCH_JOBS])
                    continue
                if row["match"] == "=":
                    self.assertIn(f"fn {row['test'].rsplit('::', 1)[-1]}(", text)
                elif row["match"] == "~":
                    self.assertRegex(text, rf"fn \w*{row['test']}\w*\(")
                else:
                    self.assertEqual(source.stem, row["test"].split("::")[0])
                if row["kind"] == "test":
                    targets = (crate / "tests" / f"{row['binary']}.rs", crate / "tests" / row["binary"] / "main.rs")
                    self.assertTrue(any(path.is_file() for path in targets), targets)

    def test_every_test_the_nightly_profile_bounds_is_in_the_committed_budget_set(self) -> None:
        config = (REPO / ".config/nextest.toml").read_text()
        block = config.split("[[profile.nightly.overrides]]", 1)[1].split("slow-timeout", 1)[0]
        names = [name.rstrip(":") for name in re.findall(r"test\([=~/^]*([A-Za-z0-9_:]+)", block)]
        self.assertEqual(len(names), 4, block)
        tests = [row["test"] for row in nightly_report.read_budget_set(REPO / "scripts/nightly/budget-set.tsv")]
        for name in names:
            self.assertTrue(any(name in test for test in tests), name)


class BudgetSummaryTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.budget_set = write(self.base / "budget-set.tsv", BUDGET_SET)
        rows = nightly_report.read_budget_set(self.budget_set)
        self.baseline = write(
            self.base / "baseline.tsv", nightly_report.census_tsv(nightly_report.census(tree(self.base / "b")))
        )
        self.tonight = tree(self.base / "tonight")
        self.plan = json.dumps(nightly_report.plan(METADATA, budget=rows))
        self.samples: str | None = None

    def night(
        self, date: str, alpha: float, alpha_outcome: str = "pass", committed: str | None = None
    ) -> tuple[int, str, Path]:
        """One night: the budget verdict times props::a_merge_converges, libtest times the grant row test."""
        out = self.base / f"out-{date}"
        plan = write(out / "plan.json", self.plan)
        pending_door = write(
            out / "pending-door.json",
            json.dumps({"pending": 0, "expired": 0, "pending_filter": "none()", "expired_filter": "none()"}),
        )
        timed_junit(
            out / "junit-verdict-budget.xml", {"oneiron::alpha": {"props::a_merge_converges": (alpha_outcome, alpha)}}
        )
        timed_junit(out / "junit-verdict-tests-01.xml", {"oneiron::alpha": {"a_claim_is_read": ("pass", 0.25)}})
        timed_junit(
            out / "junit-libtest-libs.xml", {"oneiron": {"access::grant::tests::a_grant_reads_its_rows": ("pass", 2.0)}}
        )
        args = Namespace(
            out=str(out),
            date=date,
            head="0123456789abcdef0123456789abcdef01234567",
            host="nelly",
            plan=str(plan),
            pending_door=str(pending_door),
            baseline=str(self.baseline),
            census_root=str(self.tonight),
            previous=None,
            history=None,
            budget_set=str(self.budget_set),
            budget_baseline=committed,
            budget_samples=self.samples,
        )
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = nightly_report.summary(args)
        self.samples = str(out / "budget-samples.json")
        return code, printed.getvalue().strip(), out

    def test_a_budget_test_is_pending_until_its_hosts_fifth_night_whose_median_becomes_the_proposed_baseline(
        self,
    ) -> None:
        for day, seconds in zip(range(10, 14), (10.0, 12.0, 11.0, 30.0)):
            code, line, out = self.night(f"2026-11-{day}", seconds)
            self.assertEqual(code, 0, line)
            self.assertIn(" red_nights=0 budget_in=0 budget_out=0 budget_pending=2 budget_not_run=3", line)
            self.assertFalse((out / "budget-baseline-proposal.tsv").exists())
        self.assertIn(
            "budget oneiron::alpha props::a_merge_converges: 30.00 s, baseline pending (4/5 nights on nelly)",
            (out / "summary.txt").read_text(),
        )
        code, line, out = self.night("2026-11-14", 9.0)
        self.assertIn(" budget_in=2 budget_out=0 budget_pending=0 budget_not_run=3", line)
        text = (out / "summary.txt").read_text()
        self.assertIn(
            "budget oneiron::alpha props::a_merge_converges: 9.00 s, baseline 11.00 s (samples), in band (-18%)", text
        )
        self.assertIn("budget baseline proposal: 2 new row(s) in budget-baseline-proposal.tsv", text)
        self.assertEqual(
            (out / "budget-baseline-proposal.tsv").read_text().splitlines(),
            [
                "host\ttest\tseconds\tnights\tfirst\tlast",
                "nelly\toneiron access::grant::tests::a_grant_reads_its_rows\t2.000\t5\t2026-11-10\t2026-11-14",
                "nelly\toneiron::alpha props::a_merge_converges\t11.000\t5\t2026-11-10\t2026-11-14",
            ],
        )
        samples = json.loads((out / "budget-samples.json").read_text())
        self.assertEqual(
            [s["seconds"] for s in samples["nelly"]["oneiron::alpha props::a_merge_converges"]],
            [10.0, 12.0, 11.0, 30.0, 9.0],
        )

    def test_a_time_out_of_the_band_is_reported_and_a_committed_baseline_wins_over_the_samples(self) -> None:
        for day in range(10, 15):
            self.night(f"2026-11-{day}", 10.0)
        code, line, out = self.night("2026-11-15", 12.5)
        self.assertEqual(code, 0, "the band is report only")
        self.assertIn(" budget_in=1 budget_out=1 budget_pending=0 ", line)
        self.assertIn("baseline 10.00 s (samples), over band (+25%)", (out / "summary.txt").read_text())
        row = json.loads((out / "budget-row.json").read_text())
        self.assertEqual(
            row["out_tests"],
            [{"test": "oneiron::alpha props::a_merge_converges", "seconds": 12.5, "baseline": 10.0, "band": "over"}],
        )
        committed = write(
            self.base / "budget-baseline.tsv",
            "host\ttest\tseconds\tnights\tfirst\tlast\n"
            "nelly\toneiron::alpha props::a_merge_converges\t20.000\t5\t2026-10-01\t2026-10-05\n",
        )
        _, line, out = self.night("2026-11-16", 12.5, committed=str(committed))
        text = (out / "summary.txt").read_text()
        self.assertIn("12.50 s, baseline 20.00 s (committed), under band (-38%)", text)
        self.assertEqual(
            (out / "budget-baseline-proposal.tsv").read_text().splitlines()[1:],
            [
                "nelly\toneiron access::grant::tests::a_grant_reads_its_rows\t2.000\t5\t2026-11-10\t2026-11-14",
                "nelly\toneiron::alpha props::a_merge_converges\t20.000\t5\t2026-10-01\t2026-10-05",
            ],
            "the proposal is the whole file: the committed rows and the new one",
        )

    def test_each_budget_row_without_a_result_says_why_and_a_failed_budget_test_gives_no_sample(self) -> None:
        code, line, out = self.night("2026-11-10", 10.0, alpha_outcome="fail")
        self.assertEqual(code, 1, "a failed budget test is a failed test")
        self.assertIn(" failed=1 ", line)
        self.assertIn(" budget_in=0 budget_out=0 budget_pending=1 budget_not_run=3", line)
        text = (out / "summary.txt").read_text()
        self.assertIn("budget oneiron::alpha props::a_merge_converges: fail tonight, no sample", text)
        self.assertIn("budget not run: long-replay (quarantined (LIBTEST-QUARANTINE-ROOT-TESTS))", text)
        self.assertIn("budget not run: kit-bounded (no result tonight)", text)
        self.assertIn("budget not run: bench-smoke (oneiron-bench is left out of the nightly)", text)
        samples = json.loads((out / "budget-samples.json").read_text())
        self.assertEqual(list(samples["nelly"]), ["oneiron access::grant::tests::a_grant_reads_its_rows"])

    def test_a_rerun_of_a_night_replaces_its_sample(self) -> None:
        self.night("2026-11-10", 10.0)
        _, _, out = self.night("2026-11-10", 14.0)
        series = json.loads((out / "budget-samples.json").read_text())["nelly"][
            "oneiron::alpha props::a_merge_converges"
        ]
        self.assertEqual([(s["date"], s["seconds"]) for s in series], [("2026-11-10", 14.0)])


if __name__ == "__main__":
    unittest.main()
