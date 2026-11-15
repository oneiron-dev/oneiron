//! The owner takes back what the Dreamer landed (owner ruling 18 Oct:
//! "autoapply + revert rather than holdout"; FIX 8655). The Dreamer lands a
//! claim at Auto under its own `generated` permit. The owner's revert
//! retracts that claim through the lifecycle door, and the Gate decides the
//! close as its verified closer, the owner. The owner holds no `generated`
//! permit and needs none: a close admits nothing new.
//!
//! The owner's revert row is the vault's: its `created_at` is whole seconds on the vault's
//! recording clock, read by the mint (UC-03 PR 4-1b; FIX
//! GATE-ROW-DREAMER-REVERT-MILLISECONDS). The door's own `now` stays milliseconds for the
//! retract it drives.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_reverts_dreamer_claim`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_support::{bind_host_owner, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, Vault};

const READER: &str = "reader";

/// The model's reply: one new person, named in T1, and its name.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

/// The Dreamer lands one claim at Auto, and the embedded owner, bound as the vault's root,
/// holds a fresh proof: `(claim, owner id, proof)`.
fn a_landed_claim_and_its_owner(vault: &Vault) -> (EntityId, EntityId, AuthenticatedOwner) {
    let pass = consolidate_unbound_turn(vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let landed = vault.get_claim(claim).expect("read").expect("the claim");
    assert_eq!(
        (landed.approval.as_str(), landed.lifecycle.as_str()),
        ("auto", "active"),
        "the Dreamer's claim stands at Auto"
    );

    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    bind_host_owner(vault, &test_host_issuer(), owner_id).expect("the owner's root binding");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    (*claim, owner_id, owner)
}

#[test]
fn the_owner_reverts_a_claim_the_dreamer_landed_at_auto() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let (claim, owner_id, owner) = a_landed_claim_and_its_owner(&vault);
    let receipt = vault
        .memory(owner_id, EdgeActorClass::Human)
        .revert_dreamer_change(&owner, claim, vault.now_recorded_ms())
        .expect("the owner reverts the Dreamer's claim");
    assert_eq!(receipt.reverted.retracted, vec![claim]);
    let reverted = vault.get_claim(&claim).expect("read").expect("the claim");
    assert_eq!(reverted.lifecycle.as_str(), "retracted");
}

#[test]
fn the_owners_revert_row_reads_the_recording_second() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let (claim, owner_id, owner) = a_landed_claim_and_its_owner(&vault);
    let before = vault.now_recorded_at();
    let receipt = vault
        .memory(owner_id, EdgeActorClass::Human)
        .revert_dreamer_change(&owner, claim, vault.now_recorded_ms())
        .expect("the owner reverts the Dreamer's claim");
    let after = vault.now_recorded_at();
    assert_eq!(receipt.reverted.retracted, vec![claim]);

    let id = receipt
        .receipt_ref
        .strip_prefix("gate:")
        .expect("the revert names its Gate row");
    let rows: Vec<_> = vault
        .gate_decisions(256)
        .expect("gate decisions")
        .into_iter()
        .filter(|row| row.decision_id.to_hex() == id)
        .collect();
    let [row] = rows.as_slice() else {
        panic!("one revert row, found {}", rows.len());
    };
    assert_eq!(row.content_kind, "dreamer_change_revert");
    assert!(
        (before..=after).contains(&row.created_at),
        "the revert row's created_at {} is a second of the vault's recording clock in {before}..={after}",
        row.created_at
    );
}
