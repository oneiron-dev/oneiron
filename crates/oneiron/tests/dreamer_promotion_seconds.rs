//! UC-03 PR 0a (FIX GATE-ROW-CREATED-AT-MILLISECONDS, DREAMER-RUN-NOW-MS-INTO-SECONDS-PARAMS): a Dreamer
//! run's clock is milliseconds (`DreamerRunContext::now_ms`, the recording clock times 1,000 in the attempt
//! sink), and the rows it stamps through a seconds parameter carry seconds. On main the promotion writer
//! passed `now_ms` itself, so a parked replacement's pending Gate row and tray row, and a landed claim's
//! Finding notice, were dated about 1,000 times the recording clock (some 56,000 years ahead): the
//! retention sweep never aged such a Gate row and the burst window skipped it.
//!
//! Red on main: each stamp is the clock times 1,000. Green on the head: each is within a minute of the
//! recording clock.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! dreamer_promotion_seconds`.

use oneiron::dreamer_promotion::promote_consolidated_claims;
use oneiron::test_doors::dreamer_promotion_seconds::{
    PromotionRun, candidate, finding_notice_created_at, open_auto_promotion_vault, pending_stamps,
    promotion_run,
};
use oneiron::{EntityId, Vault};

/// How far a seconds stamp may sit from the recording clock read around the run.
const SLACK_SECS: u64 = 60;

fn assert_recording_seconds(what: &str, stamp: u64, before: u64, after: u64) {
    assert!(
        stamp + SLACK_SECS >= before && stamp <= after + SLACK_SECS,
        "{what} is {stamp}; the recording clock read {before}..={after} seconds around the run \
         (a millisecond stamp is about 1,000 times that)"
    );
}

/// Lands one Generated `profile.name` claim through the promotion writer and returns it.
fn land_first(vault: &Vault, run: &PromotionRun) -> EntityId {
    let first = candidate(run, "profile.name", "Ada", None);
    let id = first.claim_id;
    let outcome =
        promote_consolidated_claims(vault, &run.run, vec![first]).expect("promotion pass");
    assert_eq!(
        outcome.landed,
        vec![id],
        "the first claim lands Auto: {outcome:?}"
    );
    id
}

#[test]
fn a_parked_dreamer_replacement_is_stamped_in_recording_seconds() {
    let directory = tempfile::tempdir().expect("vault dir");
    let vault = open_auto_promotion_vault(directory.path()).expect("open the vault");
    let run = promotion_run(&vault).expect("queue a Dreamer run");
    let before = vault.now_recorded_at();
    let old = land_first(&vault, &run);

    // A replacement of a landed claim stages Proposed behind a pending Gate row and a tray row.
    let second = candidate(&run, "profile.name", "Ada Lovelace", Some(old));
    let new = second.claim_id;
    let outcome =
        promote_consolidated_claims(&vault, &run.run, vec![second]).expect("promotion pass");
    let after = vault.now_recorded_at();
    assert_eq!(
        outcome.pended,
        vec![new],
        "the replacement parks: {outcome:?}"
    );
    assert_eq!(
        vault
            .pending_claim_supersession(&new)
            .expect("read the staging"),
        Some(old)
    );

    let stamps = pending_stamps(&vault, &new)
        .expect("read the pending rows")
        .expect("a tray row parks the replacement");
    assert_recording_seconds(
        "the pending Gate row's created_at",
        stamps.gate_row_created_at,
        before,
        after,
    );
    assert_recording_seconds(
        "the tray row's created_at",
        stamps.tray_row_created_at,
        before,
        after,
    );
}

#[test]
fn a_landed_dreamer_finding_notice_is_stamped_in_recording_seconds() {
    let directory = tempfile::tempdir().expect("vault dir");
    let vault = open_auto_promotion_vault(directory.path()).expect("open the vault");
    let run = promotion_run(&vault).expect("queue a Dreamer run");
    let before = vault.now_recorded_at();
    let landed = land_first(&vault, &run);
    let after = vault.now_recorded_at();

    let created_at = finding_notice_created_at(&vault, &landed)
        .expect("read the Finding notice")
        .expect("a landed claim about an entity raises a Finding notice");
    assert_recording_seconds("the Finding notice's created_at", created_at, before, after);
}
