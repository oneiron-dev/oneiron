//! TEST ONLY, NOT FOR MERGE: the red proof for 6.6d's board goal fix, on
//! 6.6c. The board reads the goal with the actor-less getter
//! `project_intake_goal`. An agent whose read grant covers only the project
//! type reads the project and not its goal claim, yet that getter returns
//! the goal. The last assertion states the fix and fails here.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::authority::ActSurface;
use oneiron::claim::ScopedReadActorKey;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::test_doors::coach::{define_agent, write_root_goal};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};

#[test]
fn the_board_goal_getter_ignores_the_readers_goal_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("goal");
    let goal_claim = EntityId::from_hex(
        vault
            .project(project)
            .unwrap()
            .expect("root project")
            .goal
            .as_deref()
            .expect("goal claim pointer"),
    )
    .unwrap();
    let agent = define_agent(&vault).expect("an agent");
    let mut authority_scope = Scope::top();
    authority_scope.bands = ScopeAxis::Some(BTreeSet::from([vault.project_type_byte().unwrap()]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
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
    let read = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(agent.to_hex(), "agent")
            .expect("agent key")
            .require_access_grants(Some(agent)),
    );

    assert!(
        read.is_entity_readable(&project).unwrap(),
        "reads the project"
    );
    assert!(
        !read.is_entity_readable(&goal_claim).unwrap(),
        "does not read the goal claim"
    );
    // What the board shows this reader on 6.6c: the goal it cannot read.
    let shown = vault.project_intake_goal(project).unwrap();
    assert!(
        shown.is_none(),
        "the board's getter showed the goal to a reader of the project alone: {shown:?}"
    );
}
