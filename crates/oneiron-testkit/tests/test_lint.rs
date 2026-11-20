//! The quarantine agrees with the nextest tiers. The test lint this file
//! also ran is the ratchet's test_lint_* metrics now
//! (scripts/ratchet/test_lint.py).
//!
//! The nightly sets `ONEIRON_TESTKIT_TODAY=YYYY-MM-DD` so an expired
//! quarantine entry fails it.

use std::path::Path;

use oneiron_testkit::quarantine::{self, Date};

/// The workspace root, two levels above this crate's manifest.
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[test]
fn the_quarantine_and_the_pr_nightly_and_quarantine_profiles_agree() {
    let today = std::env::var("ONEIRON_TESTKIT_TODAY")
        .ok()
        .map(|text| Date::parse(&text).expect("ONEIRON_TESTKIT_TODAY is YYYY-MM-DD"));
    let problems = quarantine::check(Path::new(WORKSPACE_ROOT), today);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn a_quarantine_entry_may_stay_at_most_seven_days() {
    let added = Date::parse("2026-11-10").expect("a date");
    let expires = Date::parse("2026-11-17").expect("a date");
    assert_eq!(
        expires.days() - added.days(),
        quarantine::MAX_QUARANTINE_DAYS
    );
    assert_eq!(Date::parse("1970-01-01").map(Date::days), Some(0));
    assert_eq!(Date::parse("2026-13-01"), None);
    assert_eq!(quarantine::union(&[]), "none()");
}
