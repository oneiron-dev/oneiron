//! The nightly pending-door filter for a nightly job: `oneiron-testkit-pending-door
//! <YYYY-MM-DD>` reads the NO-DOOR register named by
//! `ONEIRON_TESTKIT_NO_DOOR_REGISTER` (none set: nothing waits) and prints
//! `{"register", "pending", "expired", "pending_filter", "expired_filter",
//! "expired_report"}`. The job runs the nightly with `-E 'not (<pending_filter>
//! | <expired_filter>)'` and the `pending-door` profile with `-E
//! '<pending_filter>'`, ignoring that run's exit code. The exit code here is 1
//! when any test is past its deadline (door or delete), else 0. The date is
//! an argument: no tool of the test tiers reads the wall clock.

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
    let doors = match PendingDoors::load(today) {
        Ok(doors) => doors,
        Err(error) => {
            eprintln!("oneiron-testkit-pending-door: {error}");
            return ExitCode::from(2);
        }
    };
    let report = doors.expired_report();
    println!(
        "{}",
        serde_json::json!({
            "register": std::env::var(REGISTER_ENV).ok(),
            "pending": doors.pending.len(),
            "expired": doors.expired.len(),
            "pending_filter": doors.pending_filter(),
            "expired_filter": doors.expired_filter(),
            "expired_report": report,
        })
    );
    for line in &report {
        eprintln!("{line}");
    }
    if report.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
