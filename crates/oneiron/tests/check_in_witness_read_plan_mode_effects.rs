//! ROLES-CHECKIN P2.5, row 2k8c (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine rulings P25-SHAPE Q1 = A, 14 Nov
//! 13:39, and P25-2K8-SCOPE Q1 = A, 19:32): two Owner-proof doors take the
//! 2j apply shape, `vault.connectors.read_grants.grant` and
//! `vault.agents.plan_mode.set`.
//!
//! - The Owner's act is never gated: it goes on their own proof, and the
//!   answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   change: the act's writer spends it, and the answer names it and its
//!   asker. An approval for another change changes nothing and stays
//!   unspent.
//! - A witness-read grant that already stands, and a plan mode set to the
//!   mode the agent has, change nothing: they record no decision (ruling
//!   P25-2K8-SCOPE Q1: plan_mode.set spends on every changed set).
//!
//! On its base, 2k8b's head, this file does not build: neither request has
//! a `check_in_ref`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_witness_read_plan_mode_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::agent_def::{
    AgentPlanMode, AgentPlanModeSetRequest, agent_plan_mode_set_effect_digest,
    set_agent_plan_mode_from_request_as,
};
use oneiron::authority::ActSurface;
use oneiron::check_in::ActClass;
use oneiron::registry::ENTITY_TYPE_CONVERSATION;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{
    ConnectorWitnessReadGrantRequest, connector_witness_read_grant_effect_digest,
    grant_connector_witness_read_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

/// A live connector conversation: a CONVERSATION minted under the
/// connector's import source, as a connector's inbound witness mints one.
fn connector_conversation(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("import_source"),
            rmpv::Value::from("connector"),
        ),
        (rmpv::Value::from("import_kind"), rmpv::Value::from("slack")),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body).expect("the body encodes");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .expect("a live connector conversation");
    id
}

fn witness_request(
    agent: EntityId,
    conversation: EntityId,
    check_in_ref: Option<EntityId>,
) -> ConnectorWitnessReadGrantRequest {
    ConnectorWitnessReadGrantRequest {
        agent,
        conversation,
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_witness_read_grant_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let agent = define_agent(&vault, "witness-reader").expect("an agent definition");
    let (own_conversation, asked_conversation, other_conversation) = (
        connector_conversation(&vault),
        connector_conversation(&vault),
        connector_conversation(&vault),
    );

    let own = grant_connector_witness_read_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        witness_request(agent, own_conversation, None),
    )
    .expect("the Owner grants the agent its read");
    assert!(own.changed, "the grant stands anew");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own grant records their own proof"
    );
    let repeat = grant_connector_witness_read_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        witness_request(agent, own_conversation, None),
    )
    .expect("the Owner repeats the grant");
    assert!(!repeat.changed, "the repeat changes nothing");
    assert_eq!(repeat.check_in, None, "an unchanged grant records none");

    let asked = witness_request(agent, asked_conversation, None);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.connectors.read_grants.grant",
        ActClass::GrantWiden,
        &connector_witness_read_grant_effect_digest(&asked).expect("the grant's digest"),
    );
    let refused = grant_connector_witness_read_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        witness_request(agent, other_conversation, Some(check_in)),
    );
    assert!(
        refused.is_err(),
        "the approval covers the conversation it was asked for only; seen {refused:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    let other_grant = grant_connector_witness_read_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        witness_request(agent, other_conversation, None),
    )
    .expect("the Owner's own grant over the other conversation");
    assert!(
        other_grant.changed,
        "the refused call stood no grant over the other conversation"
    );

    let granted = grant_connector_witness_read_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        witness_request(agent, asked_conversation, Some(check_in)),
    )
    .expect("the Owner applies the approved ask");
    assert!(granted.changed, "the asked-for grant stands anew");
    assert!(spent(&vault, &check_in), "the grant spent the check-in");
    assert_eq!(
        granted.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}

fn plan_mode_request(
    agent: EntityId,
    expected: AgentPlanMode,
    plan_mode: AgentPlanMode,
    check_in_ref: Option<EntityId>,
) -> AgentPlanModeSetRequest {
    AgentPlanModeSetRequest {
        agent_def_ref: agent,
        expected,
        plan_mode,
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_plan_mode_change_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let own_agent = define_agent(&vault, "plan-keeper").expect("an agent definition");
    let own = set_agent_plan_mode_from_request_as(
        &vault,
        &owner_proof,
        plan_mode_request(
            own_agent,
            AgentPlanMode::Optional,
            AgentPlanMode::Required,
            None,
        ),
    )
    .expect("the Owner sets the plan mode");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own change records their own proof"
    );
    let same = set_agent_plan_mode_from_request_as(
        &vault,
        &owner_proof,
        plan_mode_request(
            own_agent,
            AgentPlanMode::Required,
            AgentPlanMode::Required,
            None,
        ),
    )
    .expect("the Owner sets the mode the agent has");
    assert_eq!(
        same.check_in, None,
        "a set that changes nothing records none"
    );

    let agent = define_agent(&vault, "plan-free").expect("an agent definition");
    let asked = plan_mode_request(agent, AgentPlanMode::Optional, AgentPlanMode::Off, None);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.agents.plan_mode.set",
        ActClass::GrantWiden,
        &agent_plan_mode_set_effect_digest(&asked).expect("the change's digest"),
    );
    let refused = set_agent_plan_mode_from_request_as(
        &vault,
        &owner_proof,
        plan_mode_request(
            agent,
            AgentPlanMode::Optional,
            AgentPlanMode::Required,
            Some(check_in),
        ),
    );
    assert!(
        refused.is_err(),
        "the approval covers the mode it was asked for only; seen {refused:?}"
    );
    assert_eq!(
        vault.agent_plan_mode(agent).expect("the agent's mode"),
        AgentPlanMode::Optional,
        "the refused set changes nothing"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    let set = set_agent_plan_mode_from_request_as(
        &vault,
        &owner_proof,
        plan_mode_request(
            agent,
            AgentPlanMode::Optional,
            AgentPlanMode::Off,
            Some(check_in),
        ),
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(
        vault.agent_plan_mode(agent).expect("the agent's mode"),
        AgentPlanMode::Off,
        "the asked-for mode stands"
    );
    assert!(spent(&vault, &check_in), "the set spent the check-in");
    assert_eq!(
        set.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}
