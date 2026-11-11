//! An agent definition and its person land in one write transaction.
//!
//! PEOPLE (ARCH-0067): every agent is a person, so each agent-definition
//! writer also writes the agent's model PERSON and the anchor to it. The
//! public definition writer (`Vault::put_agent_definition`, `define_agent`)
//! and the running agent's authoring door (`vault.agents.put`, through
//! `HostSelfDispatcher::put_agent_definition`) used to commit the definition
//! first and build the person in a second transaction. A person that could
//! not be built returned an error with the definition already stored, and a
//! retry of the create-only authoring door then found its id occupied (FIX
//! AGENT-DEF-PERSON-AFTER-COMMIT). Each case here blocks the person with a
//! row of another kind at the agent's derived PERSON id: the writer must
//! refuse and leave no definition behind.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::HostSelfDispatcher;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value;

/// The domain the engine derives an agent's PERSON id under
/// (`context_board/people.rs`, `AGENT_PERSON_DOMAIN`).
const AGENT_PERSON_DOMAIN: &[u8] = b"oneiron.people.agent-person.v1";

/// The refusal the person build meets over a row that is no PERSON.
const NOT_A_PERSON: &str = "person.substrate subject must be a PERSON";

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "agent person transaction fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

/// A fresh vault on a manual clock at 10.
fn open() -> (tempfile::TempDir, Arc<ManualClock>, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let clock = ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config.embedding_model = None;
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open the vault");
    (dir, clock, vault)
}

/// Plants an ORG row at `agent`'s derived PERSON id, so its person cannot
/// be built, and returns that id.
fn block_person(vault: &Vault, agent: EntityId) -> EntityId {
    let person = EntityId::derive(AGENT_PERSON_DOMAIN, &[agent.as_bytes()])
        .expect("derive the agent's PERSON id");
    assert_ne!(agent, person);
    assert!(
        vault
            .get_agent_definition(&agent)
            .expect("read the agent id")
            .is_none()
    );
    assert!(
        vault
            .get_entity_type(&person)
            .expect("read the PERSON id")
            .is_none()
    );
    vault
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_ORG,
            TimeRange { start: 12, end: 12 },
            12,
            &[0x80],
        )
        .expect("plant an ORG at the PERSON id");
    person
}

/// Holds a writer's answer when its agent's person cannot be built: the
/// person's refusal, no definition stored, and the blocking row untouched.
fn assert_no_definition_without_its_person(
    case: &str,
    result: &Result<(), Error>,
    vault: &Vault,
    agent: EntityId,
    person: EntityId,
) {
    let stored = vault
        .get_agent_definition(&agent)
        .expect("read the agent id");
    println!(
        "CONFORMANCE case={case} result={result:?} stored={}",
        stored.is_some()
    );
    assert!(
        matches!(result, Err(Error::InvalidClaimBody(reason)) if *reason == NOT_A_PERSON),
        "{case}: the person's refusal is the writer's answer: {result:?}"
    );
    assert!(
        stored.is_none(),
        "{case}: a definition whose person cannot be built is not stored"
    );
    assert_eq!(
        vault.get_entity_type(&person).expect("read the PERSON id"),
        Some(oneiron::registry::ENTITY_TYPE_ORG),
        "{case}: the blocking row is left as it was"
    );
}

#[test]
fn define_agent_stores_no_definition_whose_person_cannot_be_built() {
    let (_dir, clock, vault) = open();
    let agent = EntityId::from_bytes([0x92; 16]).expect("agent id");
    let person = block_person(&vault, agent);
    clock.set(12);
    let result = vault.define_agent(
        &agent,
        &definition("fixture.person-transaction-direct"),
        TimeRange { start: 12, end: 12 },
        12,
    );
    assert_no_definition_without_its_person("define_agent", &result, &vault, agent, person);
}

#[test]
fn an_agents_authored_definition_is_not_stored_when_its_person_cannot_be_built() {
    let (_dir, clock, vault) = open();
    let author = EntityId::from_bytes([0x91; 16]).expect("author id");
    vault
        .put_agent_definition(
            &author,
            &definition("fixture.person-transaction-author"),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("define the author");
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(author),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })
        .expect("dispatch the author")
    else {
        panic!("expected a newly dispatched author attempt");
    };
    clock.set(11);
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&vault)
        .claim(ClaimAttempt {
            lease_owner: "person-transaction-worker".into(),
            now: 11,
        })
        .expect("claim the author attempt")
    else {
        panic!("expected the author attempt lease");
    };
    assert_eq!(leased.id, status.attempt.id);
    let host = HostSelfDispatcher::for_leased_agent_attempt(
        &vault,
        WriteActor::new(author, EdgeActorClass::Agent),
        &leased,
    )
    .expect("the leased author's host door");
    let agent = EntityId::from_bytes([0x92; 16]).expect("agent id");
    clock.set(12);
    let person = block_person(&vault, agent);
    let result = host
        .put_agent_definition(
            &agent,
            &definition("fixture.person-transaction-authored"),
            TimeRange { start: 12, end: 12 },
            12,
        )
        .map(|_| ());
    assert_no_definition_without_its_person("vault.agents.put", &result, &vault, agent, person);
}
