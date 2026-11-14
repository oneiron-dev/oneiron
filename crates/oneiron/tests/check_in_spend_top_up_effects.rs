//! ROLES-CHECKIN P2.5, row 2k10a (ARCH-0082 #act-table "Spend above the
//! cap": "Raising the cap is the act that checks in"; Engine rulings
//! P25-SHAPE Q1 = A and Q4 = A, 14 Nov 13:39): `vault.budgets.lease.top_up`
//! in the 2j apply shape, the door naming the typed class `spend_over_cap`
//! while the verb row stays `unstated`.
//!
//! - The Owner's own top-up is never gated: its answer records the Owner's
//!   own-proof decision. A read of the lease, and a replay that finds the
//!   cap already set, answer none.
//! - With `check_in_ref` the Owner applies another asker's approved
//!   check-in for exactly that raise (scope, unit, cap expected, cap set)
//!   on their own proof: it is spent in the top-up's writer, the answer
//!   names the asker as requester, and it applies once. The moment the
//!   maximum was shown is the applying Owner's own.
//! - A check-in that does not apply (another raise, another verb, a stale
//!   cap, a ref that is no id) raises nothing and stays unspent; a replay
//!   spends nothing.
//!
//! On the base (52efa723fa2) this file does not build: the request has no
//! `check_in_ref`, the answer no `check_in`, and the effect digest does not
//! exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_spend_top_up_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::Vault;
use oneiron::agent_dispatch::budget_doors::{
    OpenSpendLeaseRequest, SpendLeaseView, SpendScopeRequest, TopUpSpendLeaseRequest,
    open_spend_lease_as_owner, spend_lease_as_owner, top_up_spend_lease_as_owner,
};
use oneiron::check_in::{ActClass, spend_lease_top_up_effect_digest};
use oneiron::consent::AuthenticatedOwner;

use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const VERB: &str = "vault.budgets.lease.top_up";
const LAUNCH: &str = "launch-owen-notes";
const UNIT: &str = "units";

/// Opens the launch lease at a cap of 100, shown at 1.
fn open_lease(vault: &Vault, owner_proof: &AuthenticatedOwner) {
    open_spend_lease_as_owner(
        vault,
        owner_proof,
        &OpenSpendLeaseRequest {
            launch: LAUNCH.to_owned(),
            cap_units: 100,
            unit: UNIT.to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )
    .expect("the owner opens the lease");
}

fn top_up(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    expected_cap_units: u64,
    cap_units: u64,
    shown_at_ms: u64,
    check_in_ref: Option<String>,
) -> oneiron::Result<SpendLeaseView> {
    top_up_spend_lease_as_owner(
        vault,
        owner_proof,
        &TopUpSpendLeaseRequest {
            scope: LAUNCH.to_owned(),
            expected_cap_units,
            cap_units,
            unit: UNIT.to_owned(),
            shown_at_ms,
            check_in_ref,
        },
    )
}

fn read(vault: &Vault, owner_proof: &AuthenticatedOwner) -> SpendLeaseView {
    spend_lease_as_owner(
        vault,
        owner_proof,
        &SpendScopeRequest {
            scope: LAUNCH.to_owned(),
        },
    )
    .expect("the owner reads the lease")
}

fn digest(expected_cap_units: u64, cap_units: u64) -> [u8; 32] {
    spend_lease_top_up_effect_digest(LAUNCH, UNIT, expected_cap_units, cap_units)
}

/// The Owner's own raise checks in on their own proof; the lease read and a
/// replay of the same raise answer no decision.
#[test]
fn an_owners_own_top_up_answers_own_proof() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    open_lease(&vault, &owner_proof);
    assert_eq!(read(&vault, &owner_proof).check_in, None);

    let raised = top_up(&vault, &owner_proof, 100, 200, 2, None).expect("the owner raises");
    assert_eq!(raised.lease.cap_units, 200);
    assert_eq!(
        raised.check_in,
        Some(owner_decision(ActClass::SpendOverCap, None, None))
    );

    let read_back = read(&vault, &owner_proof);
    assert_eq!(read_back.lease.cap_units, 200);
    assert_eq!(read_back.check_in, None, "a read answers no decision");

    let replay = top_up(&vault, &owner_proof, 100, 200, 3, None).expect("a replay answers");
    assert_eq!(replay.lease.cap_units, 200);
    assert_eq!(replay.check_in, None, "a replay raised nothing");
}

/// The Owner applies an asker's approved raise: spent in the top-up's
/// writer, the asker named as requester, the Owner's own shown moment kept,
/// and the ask applies once.
#[test]
fn an_owner_applies_an_askers_approved_raise() {
    let (_dir, vault, owner, owner_proof) = rooted();
    open_lease(&vault, &owner_proof);
    let (id, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        VERB,
        ActClass::SpendOverCap,
        &digest(100, 200),
    );

    let raised = top_up(&vault, &owner_proof, 100, 200, 7, Some(id.to_hex()))
        .expect("the owner applies the approved raise");
    assert_eq!(raised.lease.cap_units, 200);
    assert_eq!(
        raised.lease.shown_at_ms,
        Some(7),
        "the applying Owner's shown moment"
    );
    assert_eq!(
        raised.check_in,
        Some(owner_decision(
            ActClass::SpendOverCap,
            Some(id),
            Some(asker)
        ))
    );
    assert!(spent(&vault, &id), "the raise spent the ask");

    assert!(
        top_up(&vault, &owner_proof, 200, 300, 8, Some(id.to_hex())).is_err(),
        "a spent ask applies once"
    );
    assert_eq!(read(&vault, &owner_proof).lease.cap_units, 200);
}

/// A check-in that does not apply raises nothing and stays unspent: an ask
/// for another raise, an ask for another verb, an ask whose cap went stale,
/// and a ref that is no id.
#[test]
fn an_ask_that_does_not_apply_raises_nothing_and_stays_unspent() {
    let (_dir, vault, owner, owner_proof) = rooted();
    open_lease(&vault, &owner_proof);

    let (other_raise, _) = approved(
        &vault,
        owner,
        &owner_proof,
        VERB,
        ActClass::SpendOverCap,
        &digest(100, 300),
    );
    assert!(
        top_up(
            &vault,
            &owner_proof,
            100,
            200,
            2,
            Some(other_raise.to_hex())
        )
        .is_err()
    );
    assert!(!spent(&vault, &other_raise), "another raise's ask");

    let (other_verb, _) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.budgets.rsi.top_up",
        ActClass::SpendOverCap,
        &digest(100, 200),
    );
    assert!(top_up(&vault, &owner_proof, 100, 200, 2, Some(other_verb.to_hex())).is_err());
    assert!(!spent(&vault, &other_verb), "another verb's ask");

    let (stale, _) = approved(
        &vault,
        owner,
        &owner_proof,
        VERB,
        ActClass::SpendOverCap,
        &digest(50, 200),
    );
    let refused = top_up(&vault, &owner_proof, 50, 200, 2, Some(stale.to_hex()))
        .expect_err("the cap is no longer 50");
    assert!(
        refused.to_string().contains("spend cap changed"),
        "the stale cap refuses first: {refused}"
    );
    assert!(!spent(&vault, &stale), "a stale cap's ask");

    let malformed = top_up(
        &vault,
        &owner_proof,
        100,
        200,
        2,
        Some("not-a-check-in".to_owned()),
    )
    .expect_err("a ref that is no id");
    assert!(
        malformed
            .to_string()
            .contains("check_in_ref is not a check-in id"),
        "{malformed}"
    );

    let lease = read(&vault, &owner_proof).lease;
    assert_eq!(lease.cap_units, 100, "nothing was raised");
    assert_eq!(lease.shown_at_ms, Some(1));
}

/// A replay that finds the cap already set raises nothing and spends no
/// ask, even one approved for that very raise.
#[test]
fn a_replay_spends_no_ask() {
    let (_dir, vault, owner, owner_proof) = rooted();
    open_lease(&vault, &owner_proof);
    let (id, _) = approved(
        &vault,
        owner,
        &owner_proof,
        VERB,
        ActClass::SpendOverCap,
        &digest(100, 200),
    );
    top_up(&vault, &owner_proof, 100, 200, 2, None).expect("the owner's own raise");

    let replay =
        top_up(&vault, &owner_proof, 100, 200, 3, Some(id.to_hex())).expect("a replay answers");
    assert_eq!(replay.lease.cap_units, 200);
    assert_eq!(replay.check_in, None);
    assert!(!spent(&vault, &id), "a replay spends nothing");
}
