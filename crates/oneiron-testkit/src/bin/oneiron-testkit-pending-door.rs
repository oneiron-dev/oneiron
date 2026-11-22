//! The nightly pending-door filter for a nightly job: `oneiron-testkit-pending-door
//! <YYYY-MM-DD>` reads the NO-DOOR register named by
//! `ONEIRON_TESTKIT_NO_DOOR_REGISTER` (none set: nothing waits) and prints
//! `{"register", "pending", "expired", "pending_filter", "expired_filter",
//! "expired_report", "moved", "unlocated"}`. The job runs the nightly with
//! `-E 'not (<pending_filter> | <expired_filter>)'` and the `pending-door`
//! profile with `-E '<pending_filter>'`, ignoring that run's exit code. The exit code here is 1
//! when any test is past its deadline (door or delete), else 0. The date is
//! an argument: no tool of the test tiers reads the wall clock.
//!
//! It runs from the workspace root (run_nightly.sh changes there first) and
//! checks the register's integration test files against that tree
//! ([`PendingDoors::locate`]): `moved` lists the tests it selects at a file a
//! fold wave moved them to, `unlocated` the tests whose file is gone, which
//! no filter names (nextest refuses a filterset that names a test binary the
//! build lacks).

use std::path::Path;
use std::process::ExitCode;

use oneiron_testkit::pending_door::{PendingDoors, REGISTER_ENV};
use oneiron_testkit::quarantine::Date;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(today), None) = (args.next(), args.next()) else {
        eprintln!("usage: oneiron-testkit-pending-door <YYYY-MM-DD>");
        return ExitCode::from(2);
    };
    let Some(today) = Date::parse(&today) else {
        eprintln!("oneiron-testkit-pending-door: {today:?} is not YYYY-MM-DD");
        return ExitCode::from(2);
    };
    let mut doors = match PendingDoors::load(today) {
        Ok(doors) => doors,
        Err(error) => {
            eprintln!("oneiron-testkit-pending-door: {error}");
            return ExitCode::from(2);
        }
    };
    let moved = doors.locate(Path::new("."));
    let unlocated = doors.unlocated_report();
    let report = doors.expired_report();
    println!(
        "{}",
        serde_json::json!({
            "register": std::env::var(REGISTER_ENV).ok(),
            "pending": doors.pending.len(),
            "expired": doors.expired.len() + doors.expired_unlocated.len(),
            "pending_filter": doors.pending_filter(),
            "expired_filter": doors.expired_filter(),
            "expired_report": report,
            "moved": moved,
            "unlocated": unlocated,
        })
    );
    let stderr_lines = moved
        .iter()
        .map(|line| format!("moved: {line}"))
        .chain(
            unlocated
                .iter()
                .map(|line| format!("file gone from the tree, in no filter: {line}")),
        )
        .chain(report.iter().cloned());
    for line in stderr_lines {
        eprintln!("{line}");
    }
    if report.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
