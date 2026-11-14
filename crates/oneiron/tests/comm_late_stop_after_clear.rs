//! A STOP that occurred at or after an opt-out-clear request makes that
//! request stale whenever it arrives (COMM-STOP-LATE-ARRIVAL; restrictive
//! wins). FIX 22384 made the approval refuse the clear when such a STOP is
//! already recorded. One that is recorded only after the approval (a delayed
//! provider webhook, a peer's copy by sync) used to be retracted at the
//! clear's ruling, so the outcome depended on the order of arrival.
//!
//! Sync imports the head a clear closed and the clear's receipt as separate
//! rows. A late STOP that finds the closed head here before the receipt
//! stands: no receipt says the clear answers it (review round 1).
//!
//! A peer's copy of a STOP its peer already projected mints nothing here. It
//! holds sends until the peer's state arrives, and any move of its slot after
//! it settles it: nothing here says whether the peer minted the STOP's own
//! opt-out or folded the STOP into a head that already stood. Waiting for an
//! opt-out the peer never minted would hold sends for good (review round 2).
//!
//! The vault is unseeded, as in `comm_unprojected_stop_clear.rs`, so the
//! unseeded opener needs the test-support feature. The peer and in-flight
//! receipt legs reach crate-private doors, so they also need
//! `--cfg oneiron_test_support`.
#![cfg(feature = "test-support")]

use oneiron::comm::{
    CommClearOptOutOutcome, PREDICATE_COMM_OPT_OUT, approve_pending_opt_out_clear,
    count_active_comm_claims, record_comm_inbound_stop, request_opt_out_clear,
    resolve_or_create_comm_party, run_comm_projector,
};
use oneiron::{EdgeActorClass, Vault, VaultConfig, WriteActor};

const PARTY: &str = "late-stop@example.com";
const CHANNEL: &str = "email";

/// An unseeded vault: the shipped default manifest pends the human approval
/// at the criticality floor before the clear rule is read.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("vault dir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(directory.path(), config).expect("open vault");
    (directory, vault)
}

/// STOP@10 projected; a clear requested at 20 and approved by a human at 40,
/// with no other STOP here yet.
fn clear_an_opt_out_requested_at_20_and_approved_at_40(vault: &Vault) {
    record_comm_inbound_stop(vault, PARTY, CHANNEL, 10).expect("record STOP@10");
    run_comm_projector(vault).expect("project STOP@10");
    assert_eq!(
        request_opt_out_clear(vault, PARTY, CHANNEL, 20).expect("request the clear"),
        CommClearOptOutOutcome::PendingHumanRuling
    );
    let party_ref = resolve_or_create_comm_party(vault, PARTY).expect("resolve the party");
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    approve_pending_opt_out_clear(vault, PARTY, CHANNEL, human, 40).expect("approve the clear");
    assert_eq!(
        standing_opt_outs(vault),
        0,
        "the approved clear retracts STOP@10"
    );
}

fn standing_opt_outs(vault: &Vault) -> usize {
    count_active_comm_claims(vault, PREDICATE_COMM_OPT_OUT, PARTY, CHANNEL)
        .expect("count the standing opt-outs")
}

#[test]
fn late_stop_after_the_request_stands_past_the_approved_clear() {
    let (_directory, vault) = open_vault();
    clear_an_opt_out_requested_at_20_and_approved_at_40(&vault);

    record_comm_inbound_stop(&vault, PARTY, CHANNEL, 30).expect("record STOP@30 late");
    run_comm_projector(&vault).expect("project STOP@30");

    assert_eq!(
        standing_opt_outs(&vault),
        1,
        "STOP@30 came after the request@20, so the clear approved at 40 does not answer it"
    );
}

#[test]
fn late_stop_before_the_request_is_cleared_by_the_approval() {
    let (_directory, vault) = open_vault();
    clear_an_opt_out_requested_at_20_and_approved_at_40(&vault);

    record_comm_inbound_stop(&vault, PARTY, CHANNEL, 15).expect("record STOP@15 late");
    run_comm_projector(&vault).expect("project STOP@15");

    assert_eq!(
        standing_opt_outs(&vault),
        0,
        "STOP@15 came before the request@20, so the clear approved at 40 answers it"
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn peer_stop_folded_into_a_retracted_head_stops_holding() {
    use oneiron::test_doors::comm_late_stop::{
        mark_recorded_stop_peer_projected, recorded_stop_holds, retract_standing_opt_outs,
    };

    let (_directory, vault) = open_vault();
    record_comm_inbound_stop(&vault, PARTY, CHANNEL, 10).expect("record STOP@10");
    run_comm_projector(&vault).expect("project STOP@10");
    // A peer projected STOP@15 while STOP@10's head stood there, so it minted
    // no opt-out of STOP@15's own. The STOP row has arrived here.
    record_comm_inbound_stop(&vault, PARTY, CHANNEL, 15).expect("record STOP@15");
    let stop =
        mark_recorded_stop_peer_projected(&vault, PARTY, CHANNEL, 15).expect("peer's STOP@15");
    run_comm_projector(&vault).expect("run the pass while STOP@10's head stands");
    assert!(
        recorded_stop_holds(&vault, &stop).expect("read the hold"),
        "STOP@10's head started before the peer's STOP@15: no move after it is here yet"
    );

    // The owner retracts that head at 40 through the generic claim door: no
    // clear request, no receipt.
    assert_eq!(
        retract_standing_opt_outs(&vault, PARTY, CHANNEL, 40).expect("retract STOP@10's head"),
        1
    );
    assert_eq!(
        standing_opt_outs(&vault),
        0,
        "the retract at 40 closes STOP@10's head"
    );
    run_comm_projector(&vault).expect("run the pass over the closed head");

    assert!(
        !recorded_stop_holds(&vault, &stop).expect("read the hold"),
        "the retract at 40 moved the slot after the peer's STOP@15, and no opt-out of the \
         peer's own is coming: the STOP holds sends no more"
    );
    assert_eq!(
        standing_opt_outs(&vault),
        0,
        "nothing is minted here for the peer's STOP@15"
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn late_stop_before_the_clear_receipt_arrives_stands() {
    use oneiron::test_doors::comm_late_stop::{
        deliver_withheld_clear_receipts, withhold_clear_receipts,
    };

    let (_directory, vault) = open_vault();
    clear_an_opt_out_requested_at_20_and_approved_at_40(&vault);
    // Sync has imported STOP@10's head, closed at 40, and not yet the
    // clear's receipt, which says the clear was requested at 20.
    assert_eq!(
        withhold_clear_receipts(&vault, PARTY, CHANNEL).expect("withhold the receipt"),
        1
    );
    record_comm_inbound_stop(&vault, PARTY, CHANNEL, 30).expect("record STOP@30 late");
    run_comm_projector(&vault).expect("project STOP@30 before the receipt");

    assert_eq!(
        standing_opt_outs(&vault),
        1,
        "no receipt says the close at 40 answers STOP@30: STOP@30 stands"
    );

    assert_eq!(
        deliver_withheld_clear_receipts(&vault, PARTY, CHANNEL).expect("deliver the receipt"),
        1
    );
    run_comm_projector(&vault).expect("run the pass with the receipt");

    assert_eq!(
        standing_opt_outs(&vault),
        1,
        "the receipt says the clear was requested at 20, before STOP@30: STOP@30 still stands"
    );
}
