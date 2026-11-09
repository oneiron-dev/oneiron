//! The goal read is an ordinary granted read with an actor (untangle 6.6d,
//! F4; Engine 10 Nov 06:53 and 07:23). `vault.projects.goal.get` answers
//! the vault's owner, or an agent holding a live Steward grant naming
//! `read`, the Coach by its default grant, checked at each call. An agent
//! without the grant, or a Coach whose grant was narrowed off `read`, is
//! refused without learning the goal.
//!
//! Uses only doors the base has: on the base the verb answers the owner
//! alone, so the granted agent's read fails there.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test goal_read_through_grant`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{coach, define_agent, write_root_goal};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, STEWARD_VERBS, open_owner_carrier_vault, owner, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

fn goal_get(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    project: EntityId,
) -> MemoryResult<Value> {
    invoke(
        &vault.memory(actor, class),
        "vault.projects.goal.get",
        json!({ "project_ref": project.to_hex() }),
    )
}

/// The goal text the answer carries, if any.
fn goal_text(answer: &Value) -> Option<&str> {
    answer.get("record")?.get("goal")?.as_str()
}

fn assert_refused(answer: MemoryResult<Value>) {
    let error = answer.expect_err("an agent without `read` is refused");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
}

#[test]
fn a_read_holder_reads_the_goal_and_others_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("goal");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = define_agent(&vault).expect("an agent");

    // The owner reads it.
    let answer = goal_get(&vault, owner, EdgeActorClass::Human, project).expect("the owner reads");
    let goal = goal_text(&answer)
        .expect("the owner sees the goal")
        .to_owned();

    // An agent with no grant is refused.
    assert_refused(goal_get(&vault, agent, EdgeActorClass::Agent, project));

    // With a Steward grant naming `read`, it reads the same goal.
    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    let answer = goal_get(&vault, agent, EdgeActorClass::Agent, project)
        .expect("a `read` holder reads the goal");
    assert_eq!(goal_text(&answer), Some(goal.as_str()));

    // The Coach reads it through its own grant, and the grant is checked at
    // each call: narrowed to verbs without `read`, it reads nothing.
    let coach = coach(&vault).expect("the Coach");
    stand_steward_grant(&vault, coach, &[STEWARD_READ_VERB]).expect("the Coach's read");
    let answer = goal_get(&vault, coach, EdgeActorClass::System, project).expect("the Coach reads");
    assert_eq!(goal_text(&answer), Some(goal.as_str()));
    let without_read: Vec<&str> = STEWARD_VERBS
        .iter()
        .copied()
        .filter(|verb| *verb != STEWARD_READ_VERB)
        .collect();
    stand_steward_grant(&vault, coach, &without_read).expect("narrowed off read");
    assert_refused(goal_get(&vault, coach, EdgeActorClass::System, project));
}
