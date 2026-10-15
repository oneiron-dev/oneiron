//! A native host's proof shows a live person, not whose vault this is, so an
//! owner door asks for both (F18 tier flip, Engine design (a)). A person-tier
//! door takes a non-owner's proof for that person's own rows only.

use super::*;
use crate::error::{Error, GateError};

fn refused<T: std::fmt::Debug>(result: crate::error::Result<T>) -> bool {
    matches!(
        result,
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    )
}

/// The vault owner's proof, and a live non-owner person's on the same vault.
fn owner_and_person() -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    AuthenticatedOwner,
) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let person = crate::test_util::non_owner_proof(&vault);
    (dir, vault, owner, person)
}

/// Sample owner doors in consent, dreamer maintenance and the gate: each
/// refuses a live non-owner person's credential-less proof and takes the
/// owner's.
#[test]
fn a_non_owner_persons_proof_opens_no_owner_door() {
    let (_dir, vault, owner, person) = owner_and_person();
    let now = vault.store.clock.now_recorded_at();
    let cadence = crate::dreamer_runner::maintenance::digest::ProactivityCadence {
        period_secs: 100,
        group_by_facet: true,
        urgent_breakthrough: true,
    };
    let doors: [(
        &str,
        &dyn Fn(&AuthenticatedOwner) -> crate::error::Result<()>,
    ); 3] = [
        ("consent: create_standing_grant", &|proof| {
            vault
                .create_standing_grant(proof, action_bound("agent-a", "send", &["channel:email"]))
                .map(drop)
        }),
        ("dreamer maintenance: set_proactivity_cadence", &|proof| {
            vault.set_proactivity_cadence(proof, &cadence)
        }),
        ("gate: grant_dreamer_weave", &|proof| {
            vault.grant_dreamer_weave(proof, now).map(drop)
        }),
    ];
    let mut failures = Vec::new();
    for (door, call) in doors {
        let decisions = vault.store.gate_decisions(1_000).unwrap().len();
        if !refused(call(&person)) {
            failures.push(format!("{door}: took a non-owner person's proof"));
        } else if vault.store.gate_decisions(1_000).unwrap().len() != decisions {
            failures.push(format!("{door}: refused but left a gate decision"));
        }
        if let Err(error) = call(&owner) {
            failures.push(format!("{door}: refused the owner ({:?})", error.kind()));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A non-owner's own refusal and a self-scoped read take the person tier:
/// the person declines what was asked of them and reads whether they own
/// the vault (false, never an error). Positive control: the owner reads true.
#[test]
fn a_non_owner_person_refuses_for_themselves_and_reads_that_they_own_nothing() {
    let (_dir, vault, owner, person) = owner_and_person();
    let digest = ComposedEffect::new(irreversible_send_facts()).digest();
    let receipt = vault
        .deny_consent(&person, digest)
        .expect("a person's own refusal");
    assert!(matches!(receipt, ConsentReceipt::Denied { .. }));
    assert!(
        !vault
            .is_live_vault_owner(&person)
            .expect("a read, not an error")
    );
    assert!(vault.is_live_vault_owner(&owner).unwrap());
}
