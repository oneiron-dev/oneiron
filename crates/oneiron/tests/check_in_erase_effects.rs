//! ROLES-CHECKIN P2.5, row 2k2a (ARCH-0082 #act-table "Erase (C)" and
//! #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39): the erase
//! door 2j left, in the 2j apply shape. The second door, the legal hold's
//! lift-and-erase confirm, is retired by L10-21 (a hold never blocks an
//! erase), so it has no check-in here.
//!
//! - `vault.outbound_calls.request.erase` takes `check_in_ref`. An Owner's
//!   own erase is never gated: its answer records the Owner's own-proof
//!   decision.
//! - With `check_in_ref` the Owner applies another asker's approved check-in
//!   for that exact erase on their own proof: it is spent in the erase's
//!   writer, the answer names the asker as requester, and it applies once. A
//!   check-in for another effect erases nothing and stays unspent.
//!
//! The ask is opened here through the check-in test doors on a chain whose
//! Owner rung is the vault owner; `check_in_destructive_effects` drives the
//! same apply shape from a Deputy house's `vault.check_in.open`.
//!
//! On the base (14d48cd3e3b) this file does not build: the request has no
//! `check_in_ref`, its answer no `check_in`, and the effect digest does not
//! exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_erase_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::EntityId;
use oneiron::check_in::{ActClass, outbound_call_request_erase_effect_digest};
use oneiron::verbs::{OutboundCallRequestEraseRequest, erase_outbound_call_request_as_owner};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const OUTBOUND_ERASE: &str = "vault.outbound_calls.request.erase";

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
