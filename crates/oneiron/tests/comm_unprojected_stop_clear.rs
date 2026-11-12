//! A STOP recorded after an opt-out-clear request supersedes that request
//! whether or not the projector has reached it yet (FIX 22384; restrictive
//! wins). The approval read only projected STOPs: it cleared the slot at the
//! ruling, and the recorded STOP's own projection then landed behind that
//! boundary and was retracted for good.
//!
//! The vault is unseeded, as the effect-spine oracle's comm legs open it
//! (`tests/it/effect_spine_oracle.rs` `open_comm_vault`), so the
//! unseeded opener needs the test-support feature.
#![cfg(feature = "test-support")]

use oneiron::comm::{
    CommClearOptOutOutcome, CommError, PREDICATE_COMM_OPT_OUT, approve_pending_opt_out_clear,
    count_active_comm_claims, record_comm_inbound_stop, request_opt_out_clear,
    resolve_or_create_comm_party, run_comm_projector,
};
use oneiron::{EdgeActorClass, Vault, VaultConfig, WriteActor};

const PARTY: &str = "unprojected-stop@example.com";
const CHANNEL: &str = "email";

/// An unseeded vault. The shipped default manifest has no `comm.` rule, so
/// there the human approval pends at the criticality floor
/// (`gate.pending.criticality_floor`) before the STOP rule is ever read, on
/// main and on the fix alike, and the pair proves nothing about the rule.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("vault dir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(directory.path(), config).expect("open vault");
    (directory, vault)
}

/// STOP@10 projected; a clear requested at 20; STOP@30 recorded and not
/// projected. Answers the human approval of the clear at 40.
fn approve_an_older_clear_past_an_unprojected_stop(vault: &Vault) -> Result<(), CommError> {
    record_comm_inbound_stop(vault, PARTY, CHANNEL, 10).expect("record STOP@10");
    run_comm_projector(vault).expect("project STOP@10");
    assert_eq!(
        request_opt_out_clear(vault, PARTY, CHANNEL, 20).expect("request the clear"),
        CommClearOptOutOutcome::PendingHumanRuling
    );
    record_comm_inbound_stop(vault, PARTY, CHANNEL, 30).expect("record STOP@30");
    let party_ref = resolve_or_create_comm_party(vault, PARTY).expect("resolve the party");
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    approve_pending_opt_out_clear(vault, PARTY, CHANNEL, human, 40)
}

#[test]
fn unprojected_stop_invalidates_an_older_clear_request() {
    let (_directory, vault) = open_vault();

    let approval = approve_an_older_clear_past_an_unprojected_stop(&vault);

    assert!(
        matches!(approval, Err(CommError::PendingClearSupersededByStop)),
        "the STOP@30 recorded after the request@20 refuses its approval; got {approval:?}"
    );
}

#[test]
fn unprojected_stop_still_holds_once_projected_after_the_refused_clear() {
    let (_directory, vault) = open_vault();
    let approval = approve_an_older_clear_past_an_unprojected_stop(&vault);

    run_comm_projector(&vault).expect("project STOP@30");

    let standing = count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, PARTY, CHANNEL)
        .expect("count the standing opt-outs");
    assert_eq!(
        standing, 1,
        "the party's opt-out still stands after STOP@30 projects; the approval answered {approval:?}"
    );
}
