"""Tests of scripts/nightly/nightly_report.py (the nightly test job's report tool).

Run: python3 -m unittest discover -s scripts/nightly -p 'test_*.py' -v
"""

from __future__ import annotations

import contextlib
import io
import json
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
                nightly_report.main(["tests", str(plan_file), "tests-01"])
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

    def test_a_verdict_run_that_wrote_no_junit_makes_the_night_red(self) -> None:
        (self.out / "junit-verdict-workspace.xml").unlink()
        code, _ = self.run_summary()
        self.assertEqual(code, 1)
        self.assertIn(
            "the verdict run reported no test", json.loads((self.out / "summary.json").read_text())["reasons"]
        )


if __name__ == "__main__":
    unittest.main()
