//! ROLES-CHECKIN P2.5, row 2k5a (ARCH-0082 #act-table "Delete items" and
//! #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39):
//! `vault.embedding_spaces.probes.delete`, an Owner-proof door, takes the 2j
//! apply shape.
//!
//! - The Owner's delete of a stored probe is never gated: it goes on their
//!   own proof, and the answer records that decision.
//! - The Owner applies another asker's approved check-in for deleting that
//!   probe on their own proof: the delete's writer spends it, and the answer
//!   names it and its asker. An approval for another probe deletes nothing
//!   and stays unspent.
//!
//! On its base, 2k5a's head, this file does not build: the delete's input
//! has no `check_in_ref`, and its answer no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_probe_delete_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::{ActClass, embedding_space_probe_delete_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::{
    EmbeddingSpaceProbeDeleteRequest, EmbeddingSpaceProbePutRequest,
    delete_embedding_space_probe_as, put_embedding_space_probe_as,
};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};
use serde_json::json;

const VERB: &str = "vault.embedding_spaces.probes.delete";

/// A text probe whose query `query` was written from a live record: its id,
/// 32 hex, and its 16 bytes.
fn probe(vault: &Vault, owner: &AuthenticatedOwner, query: &str) -> (String, [u8; 16]) {
    let family = EntityId::now();
    vault
        .put_entity(
            &family,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a record the query was written from",
        )
        .expect("a live record");
    let request: EmbeddingSpaceProbePutRequest = serde_json::from_value(json!({
        "kind": "text",
        "query": query,
        "family": family.to_hex(),
        "author": "owen",
    }))
    .expect("a probe put request");
    let id = put_embedding_space_probe_as(vault, owner, request)
        .expect("the Owner stores a probe")
        .id;
    let bytes = *EntityId::from_hex(&id).expect("a probe id").as_bytes();
    (id, bytes)
}

fn stored(vault: &Vault, id: &[u8; 16]) -> bool {
    vault
        .space_probes()
        .expect("read the probes")
        .iter()
        .any(|(stored, _)| stored == id)
}

fn delete(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    id: &str,
    check_in_ref: Option<EntityId>,
) -> oneiron::memory::MemoryResult<oneiron::task_verb::sdk::EmbeddingSpaceProbeDeleted> {
    delete_embedding_space_probe_as(
        vault,
        owner,
        EmbeddingSpaceProbeDeleteRequest {
            id: id.to_owned(),
            check_in_ref: check_in_ref.map(|id| id.to_hex()),
        },
    )
}

#[test]
fn the_owners_probe_delete_goes_on_their_own_proof_and_records_it() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    let (id, bytes) = probe(&vault, &owner_proof, "what the owner asked");
    let deleted = delete(&vault, &owner_proof, &id, None).expect("the Owner deletes the probe");
    assert!(deleted.ok, "the probe was stored");
    assert!(!stored(&vault, &bytes), "the probe is gone");
    assert_eq!(
        deleted.check_in,
        Some(owner_decision(ActClass::Delete, None, None)),
        "the Owner's delete records their own proof"
    );
}

#[test]
fn the_owner_applies_an_approved_ask_to_delete_that_probe_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let (id, bytes) = probe(&vault, &owner_proof, "the probe asked for");
    let (other_id, other_bytes) = probe(&vault, &owner_proof, "another probe");
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        VERB,
        ActClass::Delete,
        &embedding_space_probe_delete_effect_digest(&bytes),
    );

    assert!(
        delete(&vault, &owner_proof, &other_id, Some(check_in)).is_err(),
        "the approval covers the probe it was asked for only"
    );
    assert!(stored(&vault, &other_bytes), "the other probe stays");
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    let deleted = delete(&vault, &owner_proof, &id, Some(check_in))
        .expect("the Owner applies the approved ask");
    assert!(deleted.ok);
    assert!(!stored(&vault, &bytes), "the asked-for probe is gone");
    assert!(spent(&vault, &check_in), "the delete spent the check-in");
    assert_eq!(
        deleted.check_in,
        Some(owner_decision(
            ActClass::Delete,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the check-in and its asker"
    );
}
