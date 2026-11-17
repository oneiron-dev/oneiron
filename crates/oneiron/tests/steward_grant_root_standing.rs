//! A Steward Grant on a personal vault's root gives an agent that is no base agent only what
//! the owner's counted mint gives it (pass 28 R3b3).
//!
//! A FEDERATION_GRANT row gives nothing by itself: a Steward row naming such an agent that no
//! counted mint gives (one another device sent alone) holds no `engine.controls` class and
//! reads no substrate row, and the owner's `engine.controls` Grant widened in place gives
//! nothing. The owner's own Grant gives its class until he takes it back.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test steward_grant_root_standing`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::federation::{
    EngineControlActor, EngineControlClass, FederationGrant, ScopeAxis,
    decode_federation_grant_body,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_WORK_BUDGET_VERB, define_agent, write_root_goal};
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, owner, receive_steward_grant_row,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

/// The `engine.controls` verb of the wake cadence class.
const WAKE_CADENCE_VERB: &str = "engine.controls.wake_cadence";

fn allowed(vault: &Vault, agent: EntityId, class: EngineControlClass) -> bool {
    vault
        .engine_control_allowed(EngineControlActor::Holder(agent), class)
        .expect("the engine-control check")
}

fn goal_get(vault: &Vault, agent: EntityId, project: EntityId) -> MemoryResult<Value> {
    invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        "vault.projects.goal.get",
        json!({ "project_ref": project.to_hex() }),
    )
}

/// The Grant row `id` as it is stored now.
fn row(vault: &Vault, id: EntityId) -> FederationGrant {
    let body = vault
        .get(&id)
        .expect("grant read")
        .expect("a live Grant row");
    decode_federation_grant_body(&body).expect("the Grant row decodes")
}

#[test]
fn the_wake_cadence_verb_names_its_class() {
    assert_eq!(
        EngineControlClass::WakeCadence.grant_verb(),
        WAKE_CADENCE_VERB
    );
    assert_eq!(
        EngineControlClass::WorkBudget.grant_verb(),
        ENGINE_CONTROLS_WORK_BUDGET_VERB
    );
}

#[test]
fn a_bare_steward_row_gives_an_agent_no_engine_control() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let agent = define_agent(&vault).expect("an agent");
    let id = receive_steward_grant_row(&vault, agent, &[ENGINE_CONTROLS_WORK_BUDGET_VERB])
        .expect("the bare row lands");

    assert!(
        !allowed(&vault, agent, EngineControlClass::WorkBudget),
        "agent={agent:?} row={id:?}; expected a Steward row no counted mint gives to hold no \
         engine.controls class; seen it held"
    );
}

#[test]
fn a_bare_steward_read_row_reads_an_agent_no_goal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("goal");
    let agent = define_agent(&vault).expect("an agent");
    let id =
        receive_steward_grant_row(&vault, agent, &[STEWARD_READ_VERB]).expect("the bare row lands");

    let answer = goal_get(&vault, agent, project);
    let error = answer.as_ref().expect_err(&format!(
        "agent={agent:?} row={id:?}; expected a `read` row no counted mint gives to read no \
         goal; seen {answer:?}"
    ));
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
}

#[test]
fn an_engine_controls_grant_widened_in_place_gives_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let agent = define_agent(&vault).expect("an agent");
    let id = vault
        .grant_engine_controls(
            &owner_proof,
            agent,
            &BTreeSet::from([EngineControlClass::WorkBudget]),
        )
        .expect("the owner's grant");
    let mut widened = row(&vault, id);
    widened.authority_scope.verbs = ScopeAxis::Some(
        [ENGINE_CONTROLS_WORK_BUDGET_VERB, WAKE_CADENCE_VERB]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );
    put_unkeyed_member_grant(&vault, id, &widened).expect("the widened row lands");

    let wake = allowed(&vault, agent, EngineControlClass::WakeCadence);
    let budget = allowed(&vault, agent, EngineControlClass::WorkBudget);
    assert!(
        !wake && !budget,
        "agent={agent:?} grant={id:?}; expected a row whose terms are not its mint's to give \
         no class; seen wake_cadence={wake} work_budget={budget}"
    );
}

#[test]
fn the_owners_engine_controls_grant_gives_its_class_until_he_takes_it_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let agent = define_agent(&vault).expect("an agent");
    let id = vault
        .grant_engine_controls(
            &owner_proof,
            agent,
            &BTreeSet::from([EngineControlClass::WorkBudget]),
        )
        .expect("the owner's grant");

    assert!(
        allowed(&vault, agent, EngineControlClass::WorkBudget),
        "agent={agent:?} grant={id:?}; expected the owner's mint to give its class"
    );
    assert!(
        !allowed(&vault, agent, EngineControlClass::WakeCadence),
        "agent={agent:?} grant={id:?}; expected the mint to give no other class"
    );

    let revoked = vault
        .revoke_engine_controls(&owner_proof, agent)
        .expect("the owner takes it back");
    assert_eq!(revoked, vec![id]);
    assert!(
        !allowed(&vault, agent, EngineControlClass::WorkBudget),
        "agent={agent:?} grant={id:?}; expected the revoked grant to give nothing"
    );
}
