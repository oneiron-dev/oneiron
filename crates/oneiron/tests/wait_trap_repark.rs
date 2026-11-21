//! A run a person's pause took off its park re-enters the same wait and
//! parks again under the trap still bound to it (FIX
//! PAUSE-BOUNDARY-PARKED-RUN): `open_wait_trap` answers that trap while it
//! waits for the run's attempt and step, so one wait never holds two open
//! traps, and the wait's reply then wakes the run once.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{WaitDeliveries, WaitKey, open_wait_trap, park_and_bind_wait_trap};
use oneiron::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, ParkDreamerAttempt,
};
use oneiron::llm::{self, DreamerTrapKind, TrapRef};
use oneiron::store::GateDecisionId;
use oneiron::{
    DreamerParkCause, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKER: &str = "wait-trap-repark";
const RUN: &str = "run-wait-trap-repark";

fn definition() -> AgentDefinition {
    AgentDefinition::new(
        "fixture.repark.agent",
        "wait trap repark fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
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
        // The codec requires a non-empty provenance map.
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// A device vault, its owner, one agent and the agent's run, leased.
fn fixture() -> TestResult<(tempfile::TempDir, Vault, EntityId, EntityId, AttemptRecord)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let now = vault.now_recorded_at();
    let agent = EntityId::from_bytes([0xb3; 16])?;
    vault.create_agent_definition_as(
        &proof,
        &agent,
        &definition(),
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN.to_owned()),
            now,
        })?
    else {
        panic!("the agent dispatches without running a model")
    };
    let leased = claim(&vault, status.attempt.id)?;
    Ok((dir, vault, owner, agent, leased))
}

fn claim(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let ClaimOutcome::Claimed(row) = AttemptQueue::new(vault).claim_kind(
        DREAMER_RUNNER_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: WORKER.to_owned(),
            now: vault.now_recorded_at(),
        },
    )?
    else {
        return Err("the run is ready to claim".into());
    };
    assert_eq!(row.id, id, "the run is the one ready row");
    Ok(row)
}

fn as_owner(vault: &Vault, owner: EntityId, verb: &str, input: Value) -> TestResult<Value> {
    oneiron::task_verb::sdk::invoke(&vault.memory(owner, EdgeActorClass::Human), verb, input)
        .map_err(|error| format!("{error:?}").into())
}

/// The run's wait and the step hash its trap names.
fn wait_of(leased: &AttemptRecord) -> TestResult<(WaitKey, [u8; 32])> {
    let run = EntityId::from_bytes(*leased.id.as_bytes())?;
    let wait_id = EntityId::from_bytes([0xb7; 16])?;
    let mut step = [0_u8; 32];
    step[..16].copy_from_slice(run.as_bytes());
    step[16..].copy_from_slice(wait_id.as_bytes());
    Ok((
        WaitKey {
            run,
            wait_id,
            generation: 0,
        },
        step,
    ))
}

/// Parks `leased` on `key` under `trap`, as the resident pump does.
fn park(vault: &Vault, leased: &AttemptRecord, key: &WaitKey, trap: &TrapRef) -> TestResult {
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let woke = park_and_bind_wait_trap(
        vault,
        ParkDreamerAttempt {
            attempt_id: leased.id,
            reason: "agent_run_waiting".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap.trap_claim_id),
            carried_spend: None,
            now: now_ms / 1_000,
        },
        key,
        trap,
        now_ms,
    )?;
    assert!(!woke, "the park binds with no reply delivered");
    Ok(())
}

fn parked(vault: &Vault, id: AttemptId) -> TestResult<bool> {
    let (_, park) = DreamerRunnerStore::new(vault)
        .status_with_park(id)?
        .ok_or("the run's status reads back")?;
    Ok(park.is_some())
}

/// The run parks on its wait; the owner's pause takes it off its park and
/// the resume queues it. The next lease finds the same trap still open for
/// the wait, parks under it again with no second trap, and the reply wakes
/// the run once.
#[test]
fn a_resumed_run_parks_again_under_its_open_wait_trap() -> TestResult {
    let (_dir, vault, owner, agent, leased) = fixture()?;
    let (key, step) = wait_of(&leased)?;
    assert!(
        !WaitDeliveries::canonical(&vault).park(&key)?,
        "the run waits with no reply"
    );
    let now_ms = vault.now_recorded_at().saturating_mul(1_000);
    let trap = llm::open_trap(
        &vault,
        &llm::DurableStepContext {
            vault: &vault,
            attempt_id: leased.id,
            run_id: leased.run_id.clone(),
            envelope_actor: WriteActor::new(agent, EdgeActorClass::Agent),
            subject: key.wait_id,
            deadline: None,
            now_ms,
            spend_scope: None,
            wake_pass_bound: false,
        },
        DreamerTrapKind::Consent,
        step,
        "code-run wait",
    )?;
    assert_eq!(
        llm::register_wait(&vault, &trap, now_ms)?,
        llm::DreamerTrapState::Waiting
    );
    park(&vault, &leased, &key, &trap)?;
    assert_eq!(open_wait_trap(&vault, &key, leased.id)?, Some(trap));

    let paused = as_owner(
        &vault,
        owner,
        "vault.agents.pause_tree",
        json!({"agent_def_ref": agent}),
    )?;
    assert_eq!(paused["pausing_at_next_step"], json!([]), "{paused}");
    assert!(!parked(&vault, leased.id)?, "the pause clears the park");
    as_owner(
        &vault,
        owner,
        "vault.agents.resume_tree",
        json!({"pause_ref": paused["pause_ref"].clone()}),
    )?;
    let released = claim(&vault, leased.id)?;
    assert!(released.attempt_count > leased.attempt_count, "a new lease");

    assert_eq!(
        open_wait_trap(&vault, &key, released.id)?,
        Some(trap),
        "the wait's trap still waits for the run"
    );
    let other = EntityId::from_bytes([0xb9; 16])?;
    assert_eq!(
        open_wait_trap(&vault, &key, AttemptId::from_bytes(other.as_bytes())?)?,
        None,
        "it waits for no other attempt"
    );
    park(&vault, &released, &key, &trap)?;
    assert!(
        parked(&vault, leased.id)?,
        "parked again under the same trap"
    );

    let delivered = WaitDeliveries::canonical(&vault).deliver(
        key.wait_id,
        &json!({"sent": true}),
        vault.now_recorded_at().saturating_mul(1_000),
    )?;
    assert_eq!(delivered, 1);
    let woken = AttemptQueue::new(&vault)
        .get(leased.id)?
        .ok_or("the run's row reads back")?;
    assert_eq!(woken.state, AttemptState::Queued, "the reply wakes the run");
    assert!(!parked(&vault, leased.id)?);
    assert_eq!(
        open_wait_trap(&vault, &key, leased.id)?,
        None,
        "a woken trap is not open"
    );
    Ok(())
}
