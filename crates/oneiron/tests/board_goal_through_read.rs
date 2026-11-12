//! The context board shows a project's goal only through the caller's own
//! read of the goal claim (untangle 6.6d, F4; Engine 10 Nov 07:23: a leak
//! fix). The board checked that the caller's read admits the project, then
//! took the goal and why from a getter with no actor. An agent whose grant
//! reads projects but not claims saw the owner's goal text that way.
//! `project_intake_goal_through` answers only when the read admits the goal
//! claim itself.
//!
//! Fixture (Sol's trace, map/BOARD-GOAL-FIXTURE.md): an agent with an
//! owner-agent `read` grant whose type bands hold only the project type.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test board_goal_through_read`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::test_doors::coach::{define_agent, write_root_goal};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EntityId, Vault};

/// A fresh agent holding an owner-agent `read` grant over `bands` (every
/// type when `None`), and its ordinary scoped read.
fn reader(vault: &Vault, owner: &AuthenticatedOwner, bands: Option<u8>) -> EntityId {
    let agent = define_agent(vault).expect("an agent");
    let mut authority_scope = Scope::top();
    if let Some(band) = bands {
        authority_scope.bands = ScopeAxis::Some(BTreeSet::from([band]));
    }
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )
    .expect("the owner's read grant");
    assert!(minted.grant.confers);
    agent
}

fn key(agent: EntityId) -> ScopedReadActorKey {
    ScopedReadActorKey::with_actor_class(agent.to_hex(), "agent")
        .expect("agent key")
        .require_access_grants(Some(agent))
}

#[test]
fn a_reader_of_the_project_but_not_its_goal_claim_sees_no_goal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("goal");
    let goal_claim = EntityId::from_hex(
        vault
            .project(project)
            .expect("project read")
            .expect("root project")
            .goal
            .as_deref()
            .expect("goal claim pointer"),
    )
    .expect("goal claim id");

    // Reads projects only: the project, not its goal claim.
    let projects_only = reader(
        &vault,
        &owner_proof,
        Some(vault.project_type_byte().unwrap()),
    );
    let read = vault.scoped_read(key(projects_only));
    assert!(
        read.is_entity_readable(&project).unwrap(),
        "reads the project"
    );
    assert!(
        !read.is_entity_readable(&goal_claim).unwrap(),
        "does not read the goal claim"
    );
    assert_eq!(
        vault.project_intake_goal_through(&read, project).unwrap(),
        None,
        "the board shows no goal to a reader of the project alone"
    );

    // A reader of every type reads the goal claim, and so the goal.
    let everything = reader(&vault, &owner_proof, None);
    let read = vault.scoped_read(key(everything));
    let goal = vault
        .project_intake_goal_through(&read, project)
        .unwrap()
        .expect("a reader of the claim sees the goal");
    assert_eq!(goal.goal, "Answer customer requests correctly");
    assert_eq!(goal.why, "Reduce repeat support tickets");
}
