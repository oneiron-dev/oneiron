//! ROLES-CHECKIN P2.5, row 2k10b (ARCH-0082 #act-table "Spend above the
//! cap": "Raising the cap is the act that checks in"; Engine rulings
//! P25-SHAPE Q1 = A and Q4 = A, 14 Nov 13:39): `vault.budgets.rsi.top_up`
//! in the 2j apply shape, the door naming the typed class `spend_over_cap`
//! while the verb row stays `unstated`.
//!
//! - The owner's own raise of an RSI line is never gated: its answer
//!   records the owner's own-proof decision. A read of the line answers
//!   none.
//! - With the line's `check_in_ref` the owner applies another asker's
//!   approved check-in for exactly that raise (line, share, units) on their
//!   own proof: it is spent in the top-up's writer, the answer names the
//!   asker as requester, and it applies once.
//! - A check-in that does not apply (another line, other units, another
//!   verb), a raise the line refuses, and a ref that is no id raise nothing
//!   and leave the ask unspent.
//!
//! On the base (0d49bd4831d) this file does not build: the top-up lines have
//! no `check_in_ref`, the answer no `check_in`, and the effect digest does
//! not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_rsi_top_up_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::collections::BTreeMap;

use oneiron::Vault;
use oneiron::check_in::{ActClass, rsi_top_up_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::rsi_doors::{
    RsiLineRequest, RsiLineView, configure_rsi_budget_as_owner, rsi_line_as_owner,
    top_up_rsi_budget_as_owner,
};
use oneiron::llm::{RsiBudgetConfig, RsiBudgetShare, RsiTopUp};

use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const VERB: &str = "vault.budgets.rsi.top_up";

/// Configures the line: 100 tokens, 10 exposures, one soft share `notes` of
/// 40 tokens.
fn configure(vault: &Vault, owner_proof: &AuthenticatedOwner) {
    let mut shares = BTreeMap::new();
    shares.insert(
        "notes".to_owned(),
        RsiBudgetShare {
            units: 40,
            pinned: false,
        },
    );
    configure_rsi_budget_as_owner(
        vault,
        owner_proof,
        &RsiBudgetConfig {
            limit: 100,
            exploration_exposure_limit: 10,
            shares,
        },
    )
    .expect("the owner configures the RSI line");
}

fn tokens(units: u64, check_in_ref: Option<String>) -> RsiTopUp {
    RsiTopUp::Tokens {
        units,
        check_in_ref,
    }
}

fn read(vault: &Vault, owner_proof: &AuthenticatedOwner) -> RsiLineView {
    rsi_line_as_owner(vault, owner_proof, &RsiLineRequest {}).expect("the owner reads the line")
}

/// The owner's own raise checks in on their own proof; a read of the line
/// answers no decision.
#[test]
fn an_owners_own_raise_answers_own_proof() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    configure(&vault, &owner_proof);
    assert!(read(&vault, &owner_proof).check_in.is_none());

    let raised = top_up_rsi_budget_as_owner(&vault, &owner_proof, &tokens(10, None))
        .expect("the owner raises the token line");
    assert_eq!(raised.work_line.limit, 110);
    assert_eq!(
        raised.check_in,
        Some(owner_decision(ActClass::SpendOverCap, None, None))
    );

    let shared = top_up_rsi_budget_as_owner(
        &vault,
        &owner_proof,
        &RsiTopUp::Share {
            share: "notes".to_owned(),
            units: 5,
            check_in_ref: None,
        },
    )
    .expect("the owner raises the share");
    assert_eq!(
        shared
            .shares
            .iter()
            .find(|share| share.label == "notes")
            .map(|share| share.units),
        Some(45)
    );
    assert_eq!(
        shared.check_in,
        Some(owner_decision(ActClass::SpendOverCap, None, None))
    );

    let read_back = read(&vault, &owner_proof);
    assert_eq!(read_back.work_line.limit, 110);
    assert!(read_back.check_in.is_none(), "a read answers no decision");
}

/// The owner applies an asker's approved raise: spent in the top-up's
/// writer, the asker named as requester, and the ask applies once.
#[test]
fn an_owner_applies_an_askers_approved_raise() {
    let (_dir, vault, owner, owner_proof) = rooted();
    configure(&vault, &owner_proof);
    let (id, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        VERB,
        ActClass::SpendOverCap,
        &rsi_top_up_effect_digest(&tokens(10, None)),
    );

    let raised = top_up_rsi_budget_as_owner(&vault, &owner_proof, &tokens(10, Some(id.to_hex())))
        .expect("the owner applies the approved raise");
    assert_eq!(raised.work_line.limit, 110);
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
        top_up_rsi_budget_as_owner(&vault, &owner_proof, &tokens(10, Some(id.to_hex()))).is_err(),
        "a spent ask applies once"
    );
    assert_eq!(read(&vault, &owner_proof).work_line.limit, 110);
}

/// A check-in that does not apply raises nothing and stays unspent: an ask
/// for another line, for other units, for another verb; an ask for a raise
/// the line refuses; and a ref that is no id.
#[test]
fn an_ask_that_does_not_apply_raises_nothing_and_stays_unspent() {
    let (_dir, vault, owner, owner_proof) = rooted();
    configure(&vault, &owner_proof);
    let ask = |verb: &str, top_up: &RsiTopUp| {
        approved(
            &vault,
            owner,
            &owner_proof,
            verb,
            ActClass::SpendOverCap,
            &rsi_top_up_effect_digest(top_up),
        )
        .0
    };

    let other_line = ask(
        VERB,
        &RsiTopUp::Exploration {
            units: 10,
            check_in_ref: None,
        },
    );
    let other_units = ask(VERB, &tokens(20, None));
    let other_verb = ask("vault.budgets.lease.top_up", &tokens(10, None));
    for id in [other_line, other_units, other_verb] {
        assert!(
            top_up_rsi_budget_as_owner(&vault, &owner_proof, &tokens(10, Some(id.to_hex())))
                .is_err()
        );
        assert!(!spent(&vault, &id), "an ask for another raise");
    }

    let unknown_share = RsiTopUp::Share {
        share: "absent".to_owned(),
        units: 5,
        check_in_ref: None,
    };
    let refused_raise = ask(VERB, &unknown_share);
    let refused = top_up_rsi_budget_as_owner(
        &vault,
        &owner_proof,
        &RsiTopUp::Share {
            share: "absent".to_owned(),
            units: 5,
            check_in_ref: Some(refused_raise.to_hex()),
        },
    )
    .expect_err("the line has no such share");
    assert!(
        refused.to_string().contains("invalid"),
        "the line refuses first: {refused}"
    );
    assert!(!spent(&vault, &refused_raise), "a refused raise's ask");

    let malformed = top_up_rsi_budget_as_owner(
        &vault,
        &owner_proof,
        &tokens(10, Some("not-a-check-in".to_owned())),
    )
    .expect_err("a ref that is no id");
    assert!(
        malformed
            .to_string()
            .contains("check_in_ref is not a check-in id"),
        "{malformed}"
    );

    let line = read(&vault, &owner_proof);
    assert_eq!(line.work_line.limit, 100, "nothing was raised");
    assert_eq!(line.exposure_line.limit, 10);
}

/// The wire is unchanged for a caller that names no check-in: a line
/// without `check_in_ref` reads as before and writes without it.
#[test]
fn a_top_up_without_a_check_in_keeps_its_wire() {
    let old: RsiTopUp =
        serde_json::from_str(r#"{"line":"tokens","units":7}"#).expect("the old shape still reads");
    assert_eq!(old, tokens(7, None));
    assert_eq!(
        serde_json::to_string(&old).expect("encode"),
        r#"{"line":"tokens","units":7}"#
    );
}
