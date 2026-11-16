//! A MESSAGE's `rel` names a live RELATIONSHIP row (MESSAGE-REL-NAMES = A;
//! ARCH-0003:43, a scope names "all" or a set of relationship ids), and a
//! consolidation step refused for a relationship that names no row parks
//! where no later pass resumes it, never as a Retry that meets the same
//! refusal on every pass (FIX MESSAGE-REL-NOT-RELATIONSHIP-ROW).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test message_rel_relationship_row`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_RELATIONSHIP;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{invalid_relationship_error, recipe_park_cause};
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{DreamerParkCause, EntityId, Error, Vault, VaultConfig};

/// A vault and its embedded owner.
fn owned_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[]).expect("fixture vault");
    let (owner, _) = embedded_owner(&vault).expect("the owner");
    (dir, vault, owner)
}

/// One owner turn whose one MESSAGE, `message`, names `rel` as its `rel`.
fn turn(message: EntityId, rel: EntityId) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: "We moved the lease call to Thursday.".to_owned(),
            parts: None,
            metadata: Some(serde_json::json!({"rel": rel.to_hex()})),
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: 10,
        assertions: WitnessAssertions::default(),
    }
}

/// Whether the owner reads `id`.
fn owner_reads(vault: &Vault, owner: EntityId, id: EntityId) -> bool {
    vault
        .memory(owner, EdgeActorClass::Human)
        .get_entity(&id.to_hex())
        .expect("owner read")
        .value
        .is_some()
}

/// Red on main: the witness takes the rel and lands the MESSAGE.
#[test]
fn witness_refuses_a_rel_that_names_no_relationship_row() {
    let (_dir, vault, owner) = owned_vault();
    let message = EntityId::now();
    let space = EntityId::now();
    let Err(error) = vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&turn(message, space))
    else {
        panic!("the witness took a rel that names no RELATIONSHIP row");
    };
    assert!(
        error.message.contains("invalid active relationship"),
        "the refusal names the relationship rule: {error:?}"
    );
    assert!(!owner_reads(&vault, owner, message), "no MESSAGE landed");
}

/// The control: a rel naming a live RELATIONSHIP row lands. Green on both.
#[test]
fn witness_takes_a_rel_that_names_a_live_relationship_row() {
    let (_dir, vault, owner) = owned_vault();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            b"relationship",
        )
        .expect("a relationship");
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&turn(message, relationship))
        .expect("the owner's turn");
    assert!(owner_reads(&vault, owner, message), "the MESSAGE landed");
}

/// A stored MESSAGE from before the rule can still carry a rel that names
/// no RELATIONSHIP row; its consolidation step meets the claim write's
/// refusal on every pass, so the step parks privately (red on main: Retry).
/// A plain engine error still parks for a Retry.
#[test]
fn a_step_refused_for_a_relationship_with_no_row_parks_where_no_pass_resumes_it() {
    assert_eq!(
        recipe_park_cause(&invalid_relationship_error(EntityId::now())),
        DreamerParkCause::Other
    );
    assert_eq!(
        recipe_park_cause(&Error::InvalidConfig("a moved scope".to_owned())),
        DreamerParkCause::Retry
    );
}
