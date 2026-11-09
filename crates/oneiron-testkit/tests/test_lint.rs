//! The workspace's tests keep the testkit rules, and the quarantine agrees
//! with the nextest tiers.
//!
//! `ONEIRON_TESTKIT_LINT=write` rewrites the baseline from the tree instead
//! of checking it (fleet only; never cargo on a laptop). The nightly sets
//! `ONEIRON_TESTKIT_TODAY=YYYY-MM-DD` so an expired quarantine entry fails it.

use std::fs;
use std::path::Path;

use oneiron_testkit::lint::{Baseline, LintReport, scan_workspace, workspace_root};
use oneiron_testkit::quarantine::{self, Date};

#[test]
fn no_new_test_sleeps_reads_the_wall_clock_dials_the_network_or_calls_a_real_model() {
    let root = workspace_root();
    let findings = scan_workspace(&root).expect("scan the workspace's tests");
    let baseline_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("lint-baseline.txt");
    if std::env::var("ONEIRON_TESTKIT_LINT").as_deref() == Ok("write") {
        let text = Baseline::of(&findings).render();
        fs::write(&baseline_path, &text).expect("write the baseline");
        println!("## LINT-BASELINE BEGIN\n{text}## LINT-BASELINE END");
        return;
    }
    let text = fs::read_to_string(&baseline_path).expect("read lint-baseline.txt");
    let baseline = Baseline::parse(&text).expect("parse lint-baseline.txt");
    let report = LintReport::compare(&findings, &baseline);
    print!("{report}");
    assert!(report.passed(), "{report}");
}

#[test]
fn the_quarantine_and_the_pr_nightly_and_quarantine_profiles_agree() {
    let today = std::env::var("ONEIRON_TESTKIT_TODAY")
        .ok()
        .map(|text| Date::parse(&text).expect("ONEIRON_TESTKIT_TODAY is YYYY-MM-DD"));
    let problems = quarantine::check(&workspace_root(), today);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn a_quarantine_entry_may_stay_at_most_seven_days() {
    let added = Date::parse("2026-11-10").expect("a date");
    let expires = Date::parse("2026-11-17").expect("a date");
    assert_eq!(expires.days() - added.days(), quarantine::MAX_QUARANTINE_DAYS);
    assert_eq!(Date::parse("1970-01-01").map(Date::days), Some(0));
    assert_eq!(Date::parse("2026-13-01"), None);
    assert_eq!(quarantine::union(&[]), "none()");
}
