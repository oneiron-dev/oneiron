//! FIX-LIST [ASK-READER-KEY-CLASSLESS]: a task ask checks that the asker and
//! the recipient can each read every question and context ref
//! (`validate_task_answer_unit`). It built each party's read key from the
//! party's id alone, with no actor class, and a read row that names a class
//! never matches a key without one (`scoped_read_actor_matches`). So the
//! owner's TURN read row written for an agent as `{actor_class: "agent",
//! actor_ref: <agent>}` did nothing at ask time: the ask was refused as
//! absent, and a run settled as a generic agent_run_failed. Only a classless
//! row admitted the agent. Each party's key now takes the class of its live
//! entity row (an AGENT_DEF reads as agent, a PERSON as human), as a graph
//! ask's asker already does (`asker_reader_in_txn`).
//!
//! Red on main: the two class-named tests fail (the check refuses). The
//! guards pass on both: a classless exact-actor row still admits, and a row
//! naming another class, or no row, still refuses.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test task_ask_reader_class`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::test_doors::graph_ask_centre::task_answer_unit_admitted;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    turn: EntityId,
    _dir: tempfile::TempDir,
}

/// The TURN read row the owner writes for the agent: read of TURN rows
/// only, no receipt, with `actor_class` set to `class` when one is given.
fn turn_read_row(agent: EntityId, class: Option<&str>) -> Value {
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    read.bands = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_TURN]));
    let mut row = json!({
        "actor_ref": agent.to_hex(),
        "effector": "core:read",
        "scope": read,
        "receipt_required": false,
    });
    if let Some(class) = class {
        row["actor_class"] = json!(class);
    }
    row
}

/// A vault with its owner, one Auto agent and one written TURN, under an
/// owner policy whose only read row is `read_row`.
fn fixture(read_row: Option<fn(EntityId) -> Value>) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"task ask reader class integration host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let human = vault.memory(owner, EdgeActorClass::Human);
    let proof = human.embedded_owner("vault.agents.create")?;
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": "task-ask-reader",
        "display_name": "Task ask reader",
        "desc": "Asks about a TURN",
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        &vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    let policy = json!({
        "schema_version": "1.2",
        "pack_id": "task-ask-reader-class",
        "pack_version": "1.0.0",
        "min_engine_version": "0.0.0",
        "defaults": {},
        "rules": [],
        "actor_ceilings": [{
            "actor_class": "agent",
            "actor_ref": agent.to_hex(),
            "ceiling": "auto",
        }],
        "scoped_grants": read_row.map(|row| vec![row(agent)]).unwrap_or_default(),
    });
    vault.install_owner_policy_manifest(
        &proof,
        EntityId::now(),
        rmp_serde::to_vec_named(&policy)?,
        vault.now_recorded_at(),
    )?;

    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )?;
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        TimeRange { start: 2, end: 2 },
        2,
        &body,
    )?;
    Ok(Fixture {
        vault,
        owner,
        agent,
        turn,
        _dir: dir,
    })
}

#[test]
fn an_agents_class_named_turn_row_admits_its_ask() -> TestResult {
    let f = fixture(Some(|agent| turn_read_row(agent, Some("agent"))))?;
    assert!(
        task_answer_unit_admitted(&f.vault, f.agent, f.owner, f.turn)?,
        "the owner's TURN read row names the agent with its class agent, so the \
         agent's ask to the owner may cite the TURN"
    );
    Ok(())
}

#[test]
fn an_agent_recipients_class_named_turn_row_admits_the_owners_ask() -> TestResult {
    let f = fixture(Some(|agent| turn_read_row(agent, Some("agent"))))?;
    assert!(
        task_answer_unit_admitted(&f.vault, f.owner, f.agent, f.turn)?,
        "the recipient agent reads the TURN through its class-named row, so the \
         owner's ask to the agent may cite it"
    );
    Ok(())
}

#[test]
fn an_agents_classless_turn_row_still_admits_its_ask() -> TestResult {
    let f = fixture(Some(|agent| turn_read_row(agent, None)))?;
    assert!(
        task_answer_unit_admitted(&f.vault, f.agent, f.owner, f.turn)?,
        "a row that names the agent and no class still admits it"
    );
    Ok(())
}

#[test]
fn a_turn_row_naming_another_class_admits_no_agent_ask() -> TestResult {
    let f = fixture(Some(|agent| turn_read_row(agent, Some("human"))))?;
    assert!(
        !task_answer_unit_admitted(&f.vault, f.agent, f.owner, f.turn)?,
        "a row for the agent's id under the class human does not admit the agent"
    );
    Ok(())
}

#[test]
fn an_agent_with_no_turn_row_is_refused() -> TestResult {
    let f = fixture(None)?;
    assert!(
        !task_answer_unit_admitted(&f.vault, f.agent, f.owner, f.turn)?,
        "with no read row the agent's ask may not cite the TURN"
    );
    Ok(())
}
