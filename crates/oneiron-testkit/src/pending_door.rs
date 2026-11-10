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
            .map(|test| {
                format!(
                    "door or delete: {} {}::{} ({}, deadline {:04}-{:02}-{:02})",
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
