//! ROLES-CHECKIN P2.5, row 2k7a (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov
//! 13:39): `vault.agents.grants.mint`, an Owner-proof door, takes the 2j
//! apply shape.
//!
//! - The Owner's mint is never gated: it goes on their own proof, and the
//!   answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   mint on their own proof: the mint's writer spends it, and the answer
//!   names it and its asker. An approval for another mint stands no Grant
//!   and stays unspent.
//!
//! On its base, 2k6b's head, this file does not build: the mint's input
//! has no `check_in_ref`, and its answer no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_agent_grant_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::check_in::ActClass;
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::MemoryResult;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantMinted, agent_grant_mint_effect_digest, mint_agent_grant_as,
};
use oneiron::{EntityId, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const MINT_VERB: &str = "vault.agents.grants.mint";

/// The Owner's Grant for `agent` listing `verbs`, with no bounds.
fn mint_request(agent: EntityId, verbs: &[&str]) -> AgentGrantMintRequest {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    AgentGrantMintRequest {
        agent,
        authority_scope,
        expires_at: None,
        repo_bounds: None,
        verb_classes: BTreeSet::new(),
        wallet_ref: None,
        working_view_bounds: None,
        check_in_ref: None,
    }
}

fn mint(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: AgentGrantMintRequest,
    check_in_ref: Option<EntityId>,
) -> MemoryResult<AgentGrantMinted> {
    mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            check_in_ref: check_in_ref.map(|id| id.to_hex()),
            ..request
        },
    )
}

/// How many of the Owner's agent Grants name `agent`, as the consent
/// registry lists them.
fn grants_naming(vault: &Vault, agent: EntityId) -> usize {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("the owner's consent registry")
        .rows
        .iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == agent)
        })
        .count()
}

#[test]
fn the_owners_mint_goes_on_their_own_proof_and_records_it() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    let agent = vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let minted = mint(&vault, &owner_proof, mint_request(agent, &["read"]), None)
        .expect("the Owner mints the Grant");
    assert!(minted.grant.confers, "the Grant confers");
    assert_eq!(
        minted.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's mint records their own proof"
    );
}

#[test]
fn the_owner_applies_an_approved_ask_to_mint_that_grant_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let agent = vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let asked = mint_request(agent, &["read"]);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        MINT_VERB,
        ActClass::GrantWiden,
        &agent_grant_mint_effect_digest(&asked).expect("the mint's digest"),
    );

    let wider = mint(
        &vault,
        &owner_proof,
        mint_request(agent, &["read", "write"]),
        Some(check_in),
    );
    assert!(
        wider.is_err(),
        "the approval covers the Grant it was asked for only; seen {wider:?}"
    );
    assert_eq!(
        grants_naming(&vault, agent),
        0,
        "the refused mint stands no Grant"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    let minted = mint(&vault, &owner_proof, asked, Some(check_in))
        .expect("the Owner applies the approved ask");
    assert_eq!(
        grants_naming(&vault, agent),
        1,
        "the asked-for Grant stands"
    );
    assert!(spent(&vault, &check_in), "the mint spent the check-in");
    assert_eq!(
        minted.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the check-in and its asker"
    );
}
