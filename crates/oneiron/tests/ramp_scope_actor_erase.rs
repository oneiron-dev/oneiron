//! A hard erase takes the erased actor out of every ramp scope it is the
//! actor of (RAMP-SCOPE-ACTOR-ERASE; Engine RULING NEXT-ROW-18 = A1, Sat 14
//! Nov 10:27 JST): the scope's stats row and streak-floor override go, and
//! its threshold override with them; its demotions, door-recorded outcomes
//! and offer answers stay as acts, and their receipts carry
//! `ERASED_CALL_IDENTITY` in `actor`. Nothing names the erased actor
//! afterwards (the erased-member rule, 13 Nov 21:09), and a rebuild folds
//! their history into no shared "erased" scope. An offer answer a former
//! owner gave keeps its row in a scope that is not theirs, and its
//! `answerer` reads `ERASED_CALL_IDENTITY` once that owner is erased
//! (review of #7834).
//!
//! The scope's actor is a PERSON, the entity type #7514's erase test already
//! hard-erases; the scrub matches the id whatever its type. Every ramp table
//! is read raw through the hidden door
//! `oneiron::test_doors::consent_graduation_ramp_rows`, built only under
//! `--cfg oneiron_test_support`; every assertion is here. Without that cfg
//! this target is empty. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test ramp_scope_actor_erase`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::consent_graduation::{
    DemotionReason, RampScope, is_ramp_demotion_receipt, is_ramp_outcome_receipt,
};
use oneiron::edit_distance::graduation::{
    DEFAULT_POSTERIOR_GUARD, ThresholdRow, exact_pattern, is_graduation_answer_receipt,
    set_graduation_policy_as_owner, unpin_scope_as_owner,
};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::identity_topology::ProposalOutcome;
use oneiron::receipt::{ERASED_CALL_IDENTITY, ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consent_graduation_ramp_rows::{RampTableRows, ramp_rows_spelling};
use oneiron::{DeleteReason, EntityId, Vault, VaultConfig};

const OP_KIND: &str = "send_email";
const TARGET_CLASS: &str = "client_followup";
const SHARED: u64 = 42;

/// The owner's proof on a fresh vault.
fn owner(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    proof(vault, owner)
}

/// `person`'s own proof.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: a person's proof")
}

/// A live PERSON the hard erase accepts.
fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("FIXTURE: a live person");
    id
}

/// The ramp tables that spell `text` in some row, by name.
fn spelling(vault: &Vault, text: &str) -> Vec<RampTableRows> {
    ramp_rows_spelling(vault, text)
        .expect("ramp table read")
        .into_iter()
        .filter(|table| table.spelling > 0)
        .collect()
}

/// The ramp's three receipt families: demotions, door-recorded outcomes and
/// offer answers.
fn ramp_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::default().with_kind(ReceiptKind::Gate))
        .expect("Gate receipts")
        .into_iter()
        .filter(|record| {
            is_ramp_demotion_receipt(record)
                || is_ramp_outcome_receipt(record)
                || is_graduation_answer_receipt(record)
        })
        .collect()
}

/// Each receipt's id, its `actor`, and its scope's actor field.
fn receipt_actors(receipts: &[ReceiptRecord]) -> Vec<(String, Option<String>, Option<String>)> {
    receipts
        .iter()
        .map(|record| {
            (
                record.receipt_id.clone(),
                record.actor.clone(),
                record.fields.get("actor").cloned(),
            )
        })
        .collect()
}

#[test]
fn a_hard_erase_leaves_no_ramp_row_or_receipt_naming_the_scope_actor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = owner(&vault);
    let actor = person(&vault);
    let hex = actor.to_hex();
    let scope = RampScope::new(OP_KIND, TARGET_CLASS, hex.clone()).expect("FIXTURE: the scope");
    // A scope of the same op and class that no override names: the streak
    // the erased actor's scope falls back to once its overrides are gone.
    let untouched = RampScope::new(OP_KIND, TARGET_CLASS, EntityId::now().to_hex())
        .expect("FIXTURE: an untouched scope");

    // Every ramp row the scope can have: two door-recorded rulings and the
    // stats they fold, a floor override, a demotion, an offer answer, and a
    // threshold override naming the scope exactly.
    for _ in 0..2 {
        vault
            .record_proposal_outcome_for_ramp(&owner, &scope, ProposalOutcome::ApprovedUntouched)
            .expect("FIXTURE: the owner rules in the scope");
    }
    vault
        .set_ramp_streak_floor(&scope, 3)
        .expect("FIXTURE: the floor override");
    assert_eq!(
        vault.ramp_streak_floor(&scope).expect("floor read"),
        3,
        "FIXTURE: the floor override is in force"
    );
    vault
        .demote_scope_to_propose(&owner, &scope, DemotionReason::Rejected)
        .expect("FIXTURE: the owner demotes the scope");
    unpin_scope_as_owner(&vault, &owner, &scope).expect("FIXTURE: an offer answer");
    set_graduation_policy_as_owner(
        &vault,
        &owner,
        &ThresholdRow::new(exact_pattern(&scope), 5, DEFAULT_POSTERIOR_GUARD)
            .expect("FIXTURE: a threshold row"),
    )
    .expect("FIXTURE: the threshold override");
    // The owner's exact row outranks the dial of equal specificity.
    assert_eq!(
        vault.ramp_streak_floor(&scope).expect("floor read"),
        5,
        "FIXTURE: the threshold override is in force"
    );

    let named: Vec<&str> = spelling(&vault, &hex)
        .iter()
        .map(|table| table.table)
        .collect();
    assert_eq!(
        named,
        vec![
            "ramp_demotion",
            "ramp_outcome",
            "ramp_stats",
            "graduation_answer",
            "graduation_threshold",
        ],
        "FIXTURE: every ramp table that spells an actor names this one"
    );
    let before = ramp_receipts(&vault);
    assert_eq!(
        before.len(),
        4,
        "FIXTURE: two outcomes, one demotion and one answer"
    );
    assert!(
        receipt_actors(&before)
            .iter()
            .all(|(_, actor, field)| actor.as_deref() == Some(hex.as_str())
                && field.as_deref() == Some(hex.as_str())),
        "FIXTURE: each receipt names the scope's actor"
    );

    // Every delete signs as this install first.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .delete_entity_with_reason(&actor, DeleteReason::UserHardDelete)
        .expect("FIXTURE: the scope's actor is hard-erased");

    assert_eq!(
        spelling(&vault, &hex),
        Vec::new(),
        "no ramp table row spells the erased actor's id"
    );
    let after = ramp_receipts(&vault);
    assert_eq!(
        receipt_actors(&after),
        receipt_actors(&before)
            .into_iter()
            .map(|(id, _, _)| (
                id,
                Some(ERASED_CALL_IDENTITY.to_owned()),
                Some(ERASED_CALL_IDENTITY.to_owned()),
            ))
            .collect::<Vec<_>>(),
        "each act keeps its receipt, and the receipt's actor reads erased"
    );
    assert!(
        after
            .iter()
            .all(|record| !format!("{record:?}").contains(&hex)),
        "no ramp receipt names the erased actor anywhere"
    );
    assert!(
        vault.scope_stats(&scope).expect("stats read").is_none(),
        "the scope's stats row is gone"
    );
    assert_eq!(
        vault.ramp_streak_floor(&scope).expect("floor read"),
        vault.ramp_streak_floor(&untouched).expect("floor read"),
        "the scope's floor and threshold overrides are gone"
    );

    // A rebuild folds the erased actor's history into no shared scope.
    vault
        .rebuild_ramp_stats_from_receipts()
        .expect("the stats rebuild");
    let erased = RampScope::new(OP_KIND, TARGET_CLASS, ERASED_CALL_IDENTITY).expect("erased scope");
    assert!(
        vault.scope_stats(&erased).expect("stats read").is_none(),
        "no stats row folds the erased actor's rulings under a shared key"
    );
    assert!(
        vault.scope_stats(&scope).expect("stats read").is_none(),
        "the rebuild brings back no row for the erased actor"
    );
    assert_eq!(
        ramp_rows_spelling(&vault, &hex)
            .expect("ramp table read")
            .into_iter()
            .find(|table| table.table == "ramp_stats")
            .map(|table| table.rows),
        Some(0),
        "the stats table holds no row at all"
    );
}

/// A shared vault whose roster holds its embedded owner and a second Owner,
/// who has accepted the founding invitation; the second Owner's id.
fn co_owner(vault: &Vault) -> EntityId {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    let co_owner = person(vault);
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: co_owner,
                    role: Some(Role::Owner),
                },
            ],
            1,
        )
        .expect("FIXTURE: a shared vault with two owners");
    let own = proof(vault, co_owner);
    let invitation = vault
        .shared_invitations(&own, SHARED)
        .expect("FIXTURE: the co-owner's invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("FIXTURE: the co-owner's founding invitation");
    vault
        .accept_shared_invitation(&own, SHARED, &invitation.id)
        .expect("FIXTURE: the co-owner accepts");
    co_owner
}

/// Each answer receipt's id, its scope actor, and its `answerer` field.
fn answer_receipts(vault: &Vault) -> Vec<(String, Option<String>, Option<String>)> {
    ramp_receipts(vault)
        .iter()
        .filter(|record| is_graduation_answer_receipt(record))
        .map(|record| {
            (
                record.receipt_id.clone(),
                record.actor.clone(),
                record.fields.get("answerer").cloned(),
            )
        })
        .collect()
}

/// The answer row's first head rewrote only the scope actor, so an owner
/// who answered an offer in an agent's scope and was later erased stayed
/// named in the row's `answerer` and on its receipt.
#[test]
fn a_hard_erase_takes_a_former_owner_out_of_the_answers_they_gave() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let co_owner = co_owner(&vault);
    let co_owner_hex = co_owner.to_hex();
    let agent = EntityId::now().to_hex();
    let scope =
        RampScope::new(OP_KIND, TARGET_CLASS, agent.clone()).expect("FIXTURE: an agent's scope");
    unpin_scope_as_owner(&vault, &proof(&vault, co_owner), &scope)
        .expect("FIXTURE: the co-owner answers an offer");

    let named: Vec<&str> = spelling(&vault, &co_owner_hex)
        .iter()
        .map(|table| table.table)
        .collect();
    assert_eq!(
        named,
        vec!["graduation_answer"],
        "FIXTURE: only the answer names the co-owner"
    );
    let before = answer_receipts(&vault);
    assert_eq!(
        before
            .iter()
            .map(|(_, actor, answerer)| (actor.clone(), answerer.clone()))
            .collect::<Vec<_>>(),
        vec![(Some(agent.clone()), Some(co_owner_hex.clone()))],
        "FIXTURE: the answer receipt names the agent's scope and the co-owner"
    );

    // Every delete signs as this install first.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .delete_entity_with_reason(&co_owner, DeleteReason::UserHardDelete)
        .expect("FIXTURE: the co-owner is hard-erased");

    assert_eq!(
        spelling(&vault, &co_owner_hex),
        Vec::new(),
        "no ramp table row spells the erased co-owner's id"
    );
    assert_eq!(
        answer_receipts(&vault),
        before
            .into_iter()
            .map(|(id, actor, _)| (id, actor, Some(ERASED_CALL_IDENTITY.to_owned())))
            .collect::<Vec<_>>(),
        "the answer stays in the agent's scope, and its answerer reads erased"
    );
}
