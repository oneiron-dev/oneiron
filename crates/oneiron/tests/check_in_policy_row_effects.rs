//! ROLES-CHECKIN P2.5, row 2k4a (ARCH-0082 #act-table "Disable a security
//! control (C)" and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov
//! 13:39): the Owner policy row change and the bypass grant, both Owner
//! doors on a security_control_disable row.
//!
//! - `vault.policy.owner.row.change` takes `check_in_ref`. The Owner's own
//!   change is never gated: its receipt records the Owner's own-proof
//!   decision, in the change ledger too.
//! - With `check_in_ref` the Owner applies another asker's approved
//!   check-in for that exact change on their own proof: it is spent in the
//!   change's writer, the receipt names the asker as requester, and it
//!   applies once. A check-in for another change does nothing and stays
//!   unspent.
//! - `vault.consent.create_bypass_grant` is the Owner's own act, receipt
//!   only: each receipt records the own-proof decision, and the warning
//!   must still be acknowledged unchanged.
//!
//! The ask is opened here through the check-in test doors on a chain whose
//! Owner rung is the vault owner, as in `check_in_erase_effects`.
//!
//! On the base (55ab61dc0c9) this file does not build: the policy row
//! request has no `check_in_ref`, the policy row and consent receipts no
//! `check_in`, and the policy row effect digest does not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_policy_row_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::{ActClass, policy_row_change_effect_digest};
use oneiron::consent::bypass_lifecycle::{
    BypassActionEnvelopeRequest, BypassGrantBoundRequest, BypassGrantWarningRequest,
    CreateBypassGrantRequest, bypass_grant_warning, create_bypass_grant,
};
use oneiron::consent::{BypassScope, CatastropheClass};
use oneiron::gate::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
use oneiron::policy_model::doors::{PolicyRowChangeRequest, change_owner_policy_row};
use oneiron::registry::ENTITY_TYPE_CONVERSATION;
use oneiron::{EntityId, TimeRange};

use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const ROW_CHANGE: &str = "vault.policy.owner.row.change";
const ACT: ActClass = ActClass::SecurityControlDisable;

/// An add of vault row `row_ref`.
fn add(row_ref: &str) -> PolicyRowChange {
    PolicyRowChange::Add {
        row_ref: row_ref.to_owned(),
        text: "Keep this private".to_owned(),
        action: PolicyRowAction::Warn,
        scope: PolicyRowScope::Vault,
    }
}

fn request(change: PolicyRowChange, check_in_ref: Option<EntityId>) -> PolicyRowChangeRequest {
    PolicyRowChangeRequest {
        change,
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owners_policy_row_change_records_their_own_decision() {
    let (_dir, vault, _owner, owner_proof) = rooted();

    let receipt = change_owner_policy_row(&vault, &owner_proof, request(add("quiet"), None))
        .expect("the Owner changes a row");

    assert_eq!(
        receipt.check_in,
        Some(owner_decision(ACT, None, None)),
        "the Owner's own change goes on their own proof"
    );
    let log = vault.policy_row_change_log().expect("the change log");
    assert_eq!(
        log.last().map(|kept| (&kept.receipt_id, &kept.check_in)),
        Some((&receipt.receipt_id, &receipt.check_in)),
        "the change ledger keeps the decision"
    );
}

#[test]
fn the_owner_applies_an_approved_policy_row_change_once() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let change = add("asked");
    let digest = policy_row_change_effect_digest(&change).expect("the change's digest");
    let (ask, asker) = approved(&vault, owner, &owner_proof, ROW_CHANGE, ACT, &digest);

    assert!(
        change_owner_policy_row(&vault, &owner_proof, request(add("other"), Some(ask))).is_err(),
        "the ask names another change"
    );
    assert!(
        !spent(&vault, &ask),
        "a refused change leaves the ask unspent"
    );
    assert!(
        vault
            .policy_row_change_log()
            .expect("the change log")
            .is_empty(),
        "the refused change landed nothing"
    );

    let receipt = change_owner_policy_row(&vault, &owner_proof, request(change.clone(), Some(ask)))
        .expect("the Owner applies the approved ask");
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(ACT, Some(ask), Some(asker))),
        "the receipt names the ask it spent and its asker"
    );
    assert!(spent(&vault, &ask), "the change spent the ask");

    assert!(
        change_owner_policy_row(&vault, &owner_proof, request(change, Some(ask))).is_err(),
        "a spent ask applies once"
    );
    assert_eq!(
        vault.policy_row_change_log().expect("the change log").len(),
        1,
        "the replay landed nothing"
    );
}

#[test]
fn the_owners_bypass_grant_records_their_own_decision() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let thread = EntityId::now();
    vault
        .put_entity(
            &thread,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            b"\x80",
        )
        .expect("a thread to scope the bypass to");
    let bound = BypassGrantBoundRequest {
        actor: owner.to_hex(),
        actor_class: None,
        classes: vec![CatastropheClass::VaultWideDestruction],
        scope: BypassScope::Thread(thread),
        envelope: BypassActionEnvelopeRequest {
            selectors: vec!["act:delete_vault".to_owned()],
            target: None,
            budget: None,
            receipt_required: false,
        },
    };
    let warning = bypass_grant_warning(&vault, &owner_proof, BypassGrantWarningRequest { bound })
        .expect("the Owner reads the warning");

    let mut changed = warning.clone();
    changed.bound_digests.clear();
    assert!(
        create_bypass_grant(
            &vault,
            &owner_proof,
            CreateBypassGrantRequest { warning: changed }
        )
        .is_err(),
        "a changed warning is still refused"
    );

    let receipts = create_bypass_grant(&vault, &owner_proof, CreateBypassGrantRequest { warning })
        .expect("the Owner creates the bypass grant");
    assert!(!receipts.is_empty(), "one receipt per class");
    for receipt in &receipts {
        assert_eq!(
            receipt.check_in,
            Some(owner_decision(ACT, None, None)),
            "the Owner's own bypass grant goes on their own proof"
        );
    }
}
