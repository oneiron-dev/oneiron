//! UC-07 PR 6, HEX-CASE-POLICY = A: stored and wire forms read lowercase-only;
//! typed or foreign input reads either case; no door trims.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test hex_input_policy`
#![cfg(oneiron_test_support)]

use oneiron::dreamer_runner::ConsolidationHomePickReceipt;
use oneiron::test_doors::hex_input_policy::{
    compaction_snapshot_reads, craft_verdict_reads, extraction_subject_id_reads,
    fanout_plan_digest_reads, projection_digest_reads, turn_span_fingerprint_reads,
};

fn lower64() -> String {
    "0123456789abcdef".repeat(4)
}

fn lower32() -> String {
    "0123456789abcdef".repeat(2)
}

fn sign64(lower: &str) -> String {
    format!("+a{}", &lower[2..])
}

#[test]
fn a_pinned_turn_fingerprint_reads_only_lowercase() {
    let lower = lower64();
    let upper = lower.to_ascii_uppercase();
    let sign = sign64(&lower);
    assert!(
        turn_span_fingerprint_reads(&lower),
        "a lowercase pinned fingerprint reads"
    );
    assert!(
        !turn_span_fingerprint_reads(&upper),
        "an uppercase pinned fingerprint is no pin"
    );
    assert!(
        !turn_span_fingerprint_reads(&sign),
        "a sign-led pinned fingerprint is no pin"
    );
}

#[test]
fn a_compaction_snapshot_hash_reads_only_lowercase() {
    let lower = lower64();
    let upper = lower.to_ascii_uppercase();
    let sign = sign64(&lower);
    assert!(
        compaction_snapshot_reads(&lower),
        "a lowercase snapshot hash reads"
    );
    assert!(
        !compaction_snapshot_reads(&upper),
        "an uppercase snapshot hash is no snapshot"
    );
    assert!(
        !compaction_snapshot_reads(&sign),
        "a sign-led snapshot hash is no snapshot"
    );
}

#[test]
fn a_craft_verdict_with_an_uppercase_candidate_hash_is_no_verdict() {
    let lower = lower64();
    let upper = lower.to_ascii_uppercase();
    assert!(
        craft_verdict_reads(&lower),
        "a lowercase candidate hash reads as a verdict"
    );
    assert!(
        !craft_verdict_reads(&upper),
        "an uppercase candidate hash is no verdict"
    );
}

#[test]
fn a_model_subject_id_reads_either_case_untrimmed() {
    let lower = lower32();
    let upper = lower.to_ascii_uppercase();
    let padded = format!(" {lower} ");
    assert!(
        extraction_subject_id_reads(&lower),
        "a lowercase model subject id reads"
    );
    assert!(
        extraction_subject_id_reads(&upper),
        "an uppercase model subject id reads"
    );
    assert!(
        !extraction_subject_id_reads(&padded),
        "a padded model subject id is no id"
    );
}

#[test]
fn a_stored_projection_digest_reads_only_lowercase() {
    let lower = lower64();
    let upper = lower.to_ascii_uppercase();
    let sign = sign64(&lower);
    assert!(
        projection_digest_reads(&lower),
        "a lowercase stored digest reads"
    );
    assert!(
        !projection_digest_reads(&upper),
        "an uppercase stored digest is no digest"
    );
    assert!(
        !projection_digest_reads(&sign),
        "a sign-led stored digest is no digest"
    );
}

#[test]
fn a_fanout_plan_digest_argument_takes_either_case() {
    let lower = lower64();
    let upper = lower.to_ascii_uppercase();
    let short = lower[..63].to_owned();
    assert!(
        fanout_plan_digest_reads(&lower),
        "a lowercase plan digest argument reads"
    );
    assert!(
        fanout_plan_digest_reads(&upper),
        "an uppercase plan digest argument reads"
    );
    assert!(
        !fanout_plan_digest_reads(&short),
        "a 63-digit plan digest argument is no digest"
    );
}

#[test]
fn a_home_pick_receipt_act_ref_reads_only_lowercase() {
    let lower = lower64();
    let upper = lower.to_ascii_uppercase();
    let receipt = |act_ref: String| ConsolidationHomePickReceipt {
        pick: None,
        act_ref,
        revision: "0".repeat(64),
        heads: Vec::new(),
        conflict: Vec::new(),
        home: None,
    };
    assert!(
        receipt(lower).act_row().is_some(),
        "a lowercase act ref names its row"
    );
    assert!(
        receipt(upper).act_row().is_none(),
        "an uppercase act ref names no row"
    );
}
