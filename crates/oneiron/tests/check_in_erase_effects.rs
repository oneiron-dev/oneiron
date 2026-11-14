//! ROLES-CHECKIN P2.5, row 2k2a (ARCH-0082 #act-table "Erase (C)" and
//! #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39): two erase
//! doors 2j left, in the 2j apply shape.
//!
//! - `vault.outbound_calls.request.erase` and
//!   `vault.legal_holds.lift_and_erase` take `check_in_ref`. An Owner's own
//!   erase is never gated: its answer records the Owner's own-proof decision.
//! - With `check_in_ref` the Owner applies another asker's approved check-in
//!   for that exact erase on their own proof: it is spent in the erase's
//!   writer, the answer names the asker as requester, and it applies once. A
//!   check-in for another effect erases nothing and stays unspent; so does a
//!   lift-and-erase whose shown state changed.
//!
//! The ask is opened here through the check-in test doors on a chain whose
//! Owner rung is the vault owner; `check_in_destructive_effects` drives the
//! same apply shape from a Deputy house's `vault.check_in.open`.
//!
//! On the base (14d48cd3e3b) this file does not build: the two requests have
//! no `check_in_ref`, their answers no `check_in`, and the two effect
//! digests do not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_erase_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::{
    ActClass, legal_hold_erase_effect_digest, outbound_call_request_erase_effect_digest,
};
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::BlobArtifactInput;
use oneiron::verbs::{
    LegalHoldEraseState, LegalHoldLiftAndEraseRequest, LegalHoldLiftAndErased,
    LegalHoldPlaceRequest, OutboundCallRequestEraseRequest, erase_outbound_call_request_as_owner,
    lift_legal_hold_and_erase_as, place_legal_hold_as,
};
use oneiron::{EdgeActorClass, EntityId};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const OUTBOUND_ERASE: &str = "vault.outbound_calls.request.erase";
const LIFT_AND_ERASE: &str = "vault.legal_holds.lift_and_erase";

#[test]
fn the_owner_applies_an_approved_outbound_request_erase_once() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let attempt = EntityId::now();
    let erase = |call_seq, check_in_ref: Option<EntityId>| {
        erase_outbound_call_request_as_owner(
            &vault,
            &owner_proof,
            OutboundCallRequestEraseRequest {
                attempt,
                call_seq,
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };

    let own = erase(1, None).expect("the owner erases on their own proof");
    assert!(!own.erased, "no row here: nothing to erase");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::Erase, None, None)),
        "the Owner's own erase records their own proof"
    );

    let digest = outbound_call_request_erase_effect_digest(&attempt, 7);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        OUTBOUND_ERASE,
        ActClass::Erase,
        &digest,
    );
    let other_call = erase(8, Some(asked));
    assert!(
        other_call.is_err(),
        "an ask for another call erases nothing: {other_call:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");

    let applied = erase(7, Some(asked)).expect("the owner applies the approved erase");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(ActClass::Erase, Some(asked), Some(asker))),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&vault, &asked),
        "the erase's writer spent the check-in"
    );
    let again = erase(7, Some(asked));
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}

#[test]
fn the_owner_applies_an_approved_lift_and_erase_on_the_state_shown() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let artifact = || {
        let put = memory
            .put_blob_artifact(&BlobArtifactInput {
                id: None,
                name: "erase fixture".to_owned(),
                media_type: "text/plain".to_owned(),
                occurred_at: 1,
                learned_at: None,
            })
            .expect("the owner writes an artifact");
        EntityId::from_hex(&put.id_hex).expect("an artifact id")
    };
    let confirm = |record: EntityId, check_in_ref: Option<EntityId>| -> LegalHoldLiftAndErased {
        let shown_state = vault
            .lift_and_erase_shown_state(&owner_proof, &[record], false)
            .expect("the confirm's shown state");
        lift_legal_hold_and_erase_as(
            &vault,
            &owner_proof,
            LegalHoldLiftAndEraseRequest {
                records: vec![record],
                claim_free_partition: false,
                shown_state,
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
        .expect("the owner confirms")
    };
    let ran = |erased: &LegalHoldLiftAndErased| {
        erased.records.len() == 1
            && matches!(
                erased.records[0].status,
                LegalHoldEraseState::Erased { .. } | LegalHoldEraseState::CompletionPending { .. }
            )
    };

    let own = confirm(artifact(), None);
    assert!(ran(&own), "the owner's confirm erases: {own:?}");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::Erase, None, None)),
        "the Owner's own confirm records their own proof"
    );

    let record = artifact();
    let digest = legal_hold_erase_effect_digest(&[record], false);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        LIFT_AND_ERASE,
        ActClass::Erase,
        &digest,
    );
    // A hold placed after the state was read: the confirm changes nothing.
    let stale_shown = vault
        .lift_and_erase_shown_state(&owner_proof, &[record], false)
        .expect("the shown state");
    let hold = place_legal_hold_as(
        &vault,
        &owner_proof,
        LegalHoldPlaceRequest {
            targets: vec![LegalHoldTarget::Record(record)],
            matter_ref: None,
        },
    )
    .expect("the owner holds the record");
    let stale = lift_legal_hold_and_erase_as(
        &vault,
        &owner_proof,
        LegalHoldLiftAndEraseRequest {
            records: vec![record],
            claim_free_partition: false,
            shown_state: stale_shown,
            check_in_ref: Some(asked.to_hex()),
        },
    )
    .expect("a stale confirm answers");
    assert!(
        stale.changed.is_some() && stale.check_in.is_none(),
        "a changed shown state lifts and erases nothing: {stale:?}"
    );
    assert!(!spent(&vault, &asked), "a stale confirm spends nothing");

    let applied = confirm(record, Some(asked));
    assert!(ran(&applied), "the applied confirm erases: {applied:?}");
    assert_eq!(applied.holds, vec![hold.hold_id], "it lifts the hold");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(ActClass::Erase, Some(asked), Some(asker))),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&vault, &asked),
        "the confirm's writer spent the check-in"
    );
}
