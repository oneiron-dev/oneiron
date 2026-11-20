//! A large copy lineage brought to an unrelated copy is refused within the whole-text diff
//! budget.

use super::{BODY, LoroDoc, bring_current};
use std::time::{Duration, Instant};

/// Before the diff budget this ran for many minutes. Past the budget the
/// lineage keeps its text and gains no edit, so a peer's concurrent edits
/// still merge with it.
#[test]
fn bringing_a_large_lineage_to_an_unrelated_copy_is_refused_within_the_budget() {
    let lineage = LoroDoc::new();
    let old = format!("{} tail \u{2713}", "x".repeat(1 << 20));
    lineage.get_text(BODY).insert(0, &old).unwrap();
    lineage.commit();
    let held_version = lineage.oplog_vv();
    let copy = "\u{e9}dited tail \u{2713}";
    // testkit-lint: allow(wall-clock) the elapsed time is the budget under test
    let started = Instant::now();
    let result = bring_current(&lineage, copy, || Ok(42_u64));
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "bringing the lineage current took {elapsed:?}"
    );
    assert!(result.is_err(), "bringing the lineage current is refused");
    assert_eq!(lineage.get_text(BODY).to_string(), old);
    assert_eq!(
        lineage.oplog_vv(),
        held_version,
        "the lineage gains no edit"
    );
}
