//! The nightly pending-door filter (Engine ruling 03:32, 10 Nov; Fable's
//! verdict, section 1, "Door waits"): promise tests that wait on a product
//! door run nightly, are reported, and fail nothing until their deadline.
//! Past it they fail the nightly: door or delete, no third option.
//!
//! The tests come from OPUS-NODOOR's register, a JSONL file kept outside the
//! engine repo whose path is in [`REGISTER_ENV`] (no variable: no pending
//! tests). Each line names a waiting test by crate, file and function, with
//! its deadline. E2E cases (crate `e2e`) and lines that name no test are
//! skipped: they are not nextest tests.
//!
//! A nightly job asks [`PendingDoors::load`] for today's split and runs:
//! - `cargo nextest run --profile nightly -E 'not (<pending> | <expired>)'`:
//!   the nightly proper, without the waiting tests;
//! - `cargo nextest run --profile pending-door -E '<pending>'`: the waiting
//!   tests, reported, its exit code ignored;
//! - and fails the night when [`PendingDoors::expired`] is not empty, naming
//!   each row: door or delete.
//!
//! A test is matched by its function name inside its package, its test
//! binary (an integration test file) or its top-level module (a source
//! file), as plan-classes-v2.jsonl matches tests by file and name.
//!
//! The register names files as they were on 10 Nov, and fold waves move
//! integration test files into a harness (`tests/<stem>.rs` to
//! `tests/it/<area>/<stem>.rs`). nextest refuses a whole filterset that
//! names a test binary the build does not have, so one stale row leaves every
//! stage of the night without a test (18 Nov, row ND-105). The tool
//! therefore checks the register's files against the tree first
//! ([`PendingDoors::locate`]).

use std::fs;
use std::path::Path;

use crate::quarantine::Date;

/// The environment variable that holds the register's path.
pub const REGISTER_ENV: &str = "ONEIRON_TESTKIT_NO_DOOR_REGISTER";

/// One waiting test from the register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingTest {
    /// The register row (`ND-001`).
    pub row: String,
    /// The package the test is in.
    pub package: String,
    /// The file, relative to the workspace root.
    pub file: String,
    /// The test function's name.
    pub test: String,
    pub deadline: Date,
    /// The register status (`WAIT`, `LAPSE`, `DELETE-UNLESS`, ...).
    pub status: String,
}

impl WaitingTest {
    /// The nextest filterset that selects this test.
    #[must_use]
    pub fn filter(&self) -> String {
        let name = format!("{}$", self.test);
        let tail = self
            .file
            .strip_prefix("crates/")
            .and_then(|rest| rest.split_once('/'))
            .map(|(_, inside)| inside);
        match tail.and_then(|inside| inside.split_once('/')) {
            // crates/<c>/tests/<stem>.rs or crates/<c>/tests/<binary>/...
            Some(("tests", rest)) => {
                let binary = rest
                    .split('/')
                    .next()
                    .unwrap_or(rest)
                    .trim_end_matches(".rs");
                format!(
                    "(package(={}) & binary(={binary}) & test(/(^|::){name}/))",
                    self.package
                )
            }
            // crates/<c>/src/<module>[/...]: the test sits under its top module.
            Some(("src", rest)) if rest.contains('/') || !matches!(rest, "lib.rs" | "main.rs") => {
                let module = rest
                    .split('/')
                    .next()
                    .unwrap_or(rest)
                    .trim_end_matches(".rs");
                format!(
                    "(package(={}) & test(/^{module}::(.+::)?{name}/))",
                    self.package
                )
            }
            _ => format!("(package(={}) & test(/(^|::){name}/))", self.package),
        }
    }
}

/// The waiting tests, split by today's date.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingDoors {
    /// Still before (or on) their deadline: run, reported, never failing.
    pub pending: Vec<WaitingTest>,
    /// Past their deadline: the nightly fails on each, door or delete.
    pub expired: Vec<WaitingTest>,
    /// Still waiting, but the register's integration test file is gone from
    /// the tree ([`PendingDoors::locate`]). In no filter, so a test of that
    /// name that still exists runs as a live one.
    pub pending_unlocated: Vec<WaitingTest>,
    /// Past their deadline, with the register's integration test file gone
    /// from the tree. In no filter, but still in
    /// [`PendingDoors::expired_report`]: the night fails on each until the
    /// register drops its row.
    pub expired_unlocated: Vec<WaitingTest>,
}

fn union(tests: &[WaitingTest]) -> String {
    if tests.is_empty() {
        return "none()".to_owned();
    }
    tests
        .iter()
        .map(WaitingTest::filter)
        .collect::<Vec<_>>()
        .join(" | ")
}

impl PendingDoors {
    /// The register at [`REGISTER_ENV`], split at `today`; empty when the
    /// variable is unset.
    ///
    /// # Errors
    /// The register cannot be read, or a line is malformed.
    pub fn load(today: Date) -> Result<Self, String> {
        match std::env::var_os(REGISTER_ENV) {
            Some(path) => Self::read(Path::new(&path), today),
            None => Ok(Self::default()),
        }
    }

    /// The register at `path`, split at `today`.
    ///
    /// # Errors
    /// The register cannot be read, or a line is malformed.
    pub fn read(path: &Path, today: Date) -> Result<Self, String> {
        let text =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text, today)
    }

    /// The register's text, split at `today`.
    ///
    /// # Errors
    /// A line is not JSON, or a test line lacks its row, package, file or
    /// deadline.
    pub fn parse(text: &str, today: Date) -> Result<Self, String> {
        let mut doors = Self::default();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let at = index + 1;
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|error| format!("register line {at}: {error}"))?;
            let text_of = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
            let (Some(test), Some(file)) = (text_of("test"), text_of("file")) else {
                continue; // a door row with no waiting test of its own
            };
            let package =
                text_of("crate").ok_or_else(|| format!("register line {at}: no crate"))?;
            if package == "e2e" {
                continue; // an E2E case: the E2E runner's to skip, not nextest's
            }
            let deadline = text_of("deadline")
                .and_then(Date::parse)
                .ok_or_else(|| format!("register line {at}: no deadline YYYY-MM-DD"))?;
            let waiting = WaitingTest {
                row: text_of("row").unwrap_or_default().to_owned(),
                package: package.to_owned(),
                file: file.to_owned(),
                test: test.to_owned(),
                deadline,
                status: text_of("status").unwrap_or_default().to_owned(),
            };
            if today > deadline {
                doors.expired.push(waiting);
            } else {
                doors.pending.push(waiting);
            }
        }
        Ok(doors)
    }

    /// Checks each waiting test's integration test file against the tree at
    /// `root`, the workspace root (FIX
    /// NIGHTLY-PENDING-DOOR-FILTER-MOVED-TEST-FILE).
    ///
    /// A file `crates/<c>/tests/...` that is absent is looked up by its file
    /// name below `crates/<c>/tests`. Found exactly once, the test is selected
    /// at that file, so in that file's binary (the `it` harness after a fold
    /// wave). Found nowhere, or more than once, the test leaves the filters
    /// for [`PendingDoors::pending_unlocated`] or
    /// [`PendingDoors::expired_unlocated`]. A source-file row is selected by
    /// its module and name, which nextest never refuses, so it stays as it
    /// is. Returns one line per moved test: `<row> <from>::<test> -> <to>`.
    pub fn locate(&mut self, root: &Path) -> Vec<String> {
        let mut moved = Vec::new();
        let (pending, pending_unlocated) = locate_each(&mut self.pending, root, &mut moved);
        let (expired, expired_unlocated) = locate_each(&mut self.expired, root, &mut moved);
        self.pending = pending;
        self.expired = expired;
        self.pending_unlocated.extend(pending_unlocated);
        self.expired_unlocated.extend(expired_unlocated);
        moved
    }

    /// One line per test whose register file is gone from the tree,
    /// `<row> <file>::<test>`, still waiting first.
    #[must_use]
    pub fn unlocated_report(&self) -> Vec<String> {
        self.pending_unlocated
            .iter()
            .chain(&self.expired_unlocated)
            .map(|test| format!("{} {}::{}", test.row, test.file, test.test))
            .collect()
    }

    /// The filterset of the tests still waiting (`none()` for none).
    #[must_use]
    pub fn pending_filter(&self) -> String {
        union(&self.pending)
    }

    /// The filterset of the tests past their deadline (`none()` for none).
    #[must_use]
    pub fn expired_filter(&self) -> String {
        union(&self.expired)
    }

    /// One line per expired test, saying what the nightly fails on.
    #[must_use]
    pub fn expired_report(&self) -> Vec<String> {
        self.expired
            .iter()
            .map(|test| (test, ""))
            .chain(
                self.expired_unlocated
                    .iter()
                    .map(|test| (test, ", file gone from the tree")),
            )
            .map(|(test, gone)| {
                format!(
                    "door or delete: {} {}::{} ({}, deadline {:04}-{:02}-{:02}{gone})",
                    test.row,
                    test.file,
                    test.test,
                    test.status,
                    test.deadline.year,
                    test.deadline.month,
                    test.deadline.day
                )
            })
            .collect()
    }
}

/// Splits `tests` into the located (moved where needed) and the unlocated,
/// appending a line to `moved` for each move.
fn locate_each(
    tests: &mut Vec<WaitingTest>,
    root: &Path,
    moved: &mut Vec<String>,
) -> (Vec<WaitingTest>, Vec<WaitingTest>) {
    let mut located = Vec::with_capacity(tests.len());
    let mut unlocated = Vec::new();
    for mut test in tests.drain(..) {
        let dir = integration_tests_dir(&test.file).map(str::to_owned);
        let Some(dir) = dir.filter(|_| !root.join(&test.file).is_file()) else {
            located.push(test);
            continue;
        };
        let name = test.file.rsplit('/').next().unwrap_or_default().to_owned();
        match files_named(root, &dir, &name).as_slice() {
            [to] => {
                moved.push(format!("{} {}::{} -> {to}", test.row, test.file, test.test));
                test.file.clone_from(to);
                located.push(test);
            }
            _ => unlocated.push(test),
        }
    }
    (located, unlocated)
}

/// `crates/<c>/tests` when `file` is under it, else `None`.
fn integration_tests_dir(file: &str) -> Option<&str> {
    let (krate, inside) = file.strip_prefix("crates/")?.split_once('/')?;
    if !inside.starts_with("tests/") {
        return None;
    }
    file.get(.."crates/".len() + krate.len() + "/tests".len())
}

/// Every file called `name` at or below `dir` (relative to `root`), as paths
/// relative to `root`, sorted.
fn files_named(root: &Path, dir: &str, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_owned()];
    while let Some(at) = dirs.pop() {
        let Ok(entries) = fs::read_dir(root.join(&at)) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(entry_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let path = format!("{at}/{entry_name}");
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => dirs.push(path),
                Ok(_) if entry_name == name => found.push(path),
                _ => {}
            }
        }
    }
    found.sort();
    found
}
