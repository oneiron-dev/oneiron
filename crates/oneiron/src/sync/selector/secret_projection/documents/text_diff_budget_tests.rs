//! A large copy lineage brought to an unrelated copy holds to the whole-text diff budget.

use super::{BODY, LoroDoc, bring_current};
use std::time::{Duration, Instant};

/// Before the diff budget this ran for many minutes.
#[test]
fn bringing_a_large_lineage_to_an_unrelated_copy_ends_within_the_budget() {
    let lineage = LoroDoc::new();
    let old = format!("{} tail \u{2713}", "x".repeat(1 << 20));
    lineage.get_text(BODY).insert(0, &old).unwrap();
    lineage.commit();
    let copy = "\u{e9}dited tail \u{2713}";
    let started = Instant::now();
    let result = bring_current(&lineage, copy, || Ok(42_u64));
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "bringing the lineage current took {elapsed:?}"
    );
    assert!(result.unwrap());
    assert_eq!(lineage.get_text(BODY).to_string(), copy);
}
