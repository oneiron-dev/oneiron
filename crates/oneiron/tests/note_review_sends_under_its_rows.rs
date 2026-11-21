//! The Dreamer's NOTE review sends its model call under the rows its text was
//! read from: the NOTE and each entity its listing names
//! ([DREAMER-UNSOURCED-ROLE-CALLS-SEND-UNFENCED]). Before the fix the call
//! went out on the extraction role's own route with no source rows, so a
//! host's source fence never saw what it read.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test note_review_sends_under_its_rows`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::note_review_sources::note_review_bound_rows;

#[test]
fn a_note_review_call_is_sent_bound_to_the_note_it_read() {
    let dir = tempfile::tempdir().expect("FIXTURE: tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("FIXTURE: vault");
    let review = note_review_bound_rows(&vault, "The kitchen kettle leaks whenever it boils.")
        .expect("FIXTURE: the NOTE review runs");
    assert_eq!(
        review.calls, 1,
        "FIXTURE: the review asks the model once for its one NOTE"
    );
    assert_eq!(
        review.bound.len(),
        1,
        "the review's one call is sent bound to its source rows: {:?}",
        review.bound
    );
    assert!(
        review.bound[0].contains(&review.note),
        "the bound rows name the NOTE {:?}: {:?}",
        review.note,
        review.bound
    );
}
