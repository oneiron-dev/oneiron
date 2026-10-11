//! An owner proof acts only while it still holds, checked in the transaction
//! that writes the act (engine-core-07, engine-prs-14).

use super::*;
use crate::error::{Error, GateError, Result};

fn refused<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(
        result,
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    )
}

#[test]
fn a_proof_from_another_vault_mints_no_consent_here() {
    let (_home_dir, _home, owner) = owner_vault();
    // The other vault holds a PERSON with the same id, so only the proof's
    // vault binding tells them apart.
    let (_dir, vault, _its_owner) = owner_vault();
    let before = vault.store.gate_decisions(100).unwrap().len();
    let effect = ComposedEffect::new(irreversible_send_facts());
    assert!(refused(vault.create_standing_grant(
        &owner,
        action_bound("agent-a", "send", &["channel:email"])
    )));
    assert!(refused(vault.approve_once(&owner, effect.digest())));
    assert!(refused(vault.deny_consent(&owner, effect.digest())));
    assert_eq!(vault.store.gate_decisions(100).unwrap().len(), before);
}

#[test]
fn a_deleted_owner_mints_nothing_and_cleans_up_nothing() {
    let (_dir, vault, owner) = owner_vault();
    // A plain delete keeps the PERSON shell and its Active lifecycle.
    assert!(vault.delete_entity(&owner.actor()).unwrap());
    let before = vault.store.gate_decisions(100).unwrap().len();
    assert!(refused(vault.create_standing_grant(
        &owner,
        action_bound("agent-a", "send", &["channel:email"])
    )));
    assert!(refused(vault.authenticate_owner(
        owner.actor(),
        "principal:owner",
        true,
        GateDecisionId::now()
    )));
    assert!(refused(
        vault.accept_cleanup_proposal_as(&owner, &EntityId::now())
    ));
    assert_eq!(vault.store.gate_decisions(100).unwrap().len(), before);
}
