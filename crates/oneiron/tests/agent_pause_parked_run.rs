//! A person's pause of a run parked on a durable wait (FIX
//! PAUSE-BOUNDARY-PARKED-RUN, after Engine RULING PAUSE-BOUNDARY-SCOPE = B).
//! A run that stops on a wait has committed its step's checkpoint and runs
//! no step until the wait's reply comes, so the wait is the step boundary
//! the pause waits for:
//! - a pause pending when the run stops on its wait is taken there, and the
//!   run returns paused, never parked;
//! - a pause of a run already parked is taken at once, in the pause's own
//!   write, and the park is cleared;
//! - a reply that lands while the run is paused is kept, and the resumed run
//!   goes on from it before its next model request;
//! - a run resumed before the reply re-enters its wait and parks again.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    CodeRunDeterminism, HostSelfDispatcher, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall,
    SelfDispatchOutcome, SelfDispatcher, SelfFixtureEffectCall, WaitDeliveries, WaitKey,
    park_and_bind_wait_trap,
};
use oneiron::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, ParkDreamerAttempt,
};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineNativeExecutor,
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::{self, ReplyAssertions};
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::run_tree::{RunBranchSignal, RunSignalState, RunTreeAdapter};
use oneiron::store::GateDecisionId;
use oneiron::{
    BudgetLease, ContentPart, DreamerParkCause, EdgeActorClass, EntityId, FatalLlmError,
    FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault,
    VaultConfig, WriteActor,
};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PAUSE_TREE: &str = "vault.agents.pause_tree";
const RESUME_TREE: &str = "vault.agents.resume_tree";
const RUNS_PAUSE: &str = "vault.runs.pause";
const RUNS_RESUME: &str = "vault.runs.resume";

/// The worker this test leases its rows to; the resident pump's own lease
/// stands in its place.
const WORKER: &str = "agent-pause-parked-run";

/// The resident pump's park reason for a run parked on its wait.
const WAITING_PARK_REASON: &str = "agent_run_waiting";

const RUN: &str = "run-agent-pause-parked-run";

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "pause parked run fixture",
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

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The author: an owner-made Base agent whose root attempt spawns.
    agent: EntityId,
    /// The agent every spawn here starts.
    worker: EntityId,
    /// The author's root attempt, leased.
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A device vault with its embedded owner, the author and the worker, and
/// the author's root attempt, leased.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let now = vault.now_recorded_at();
    let agent = EntityId::from_bytes([0xa3; 16])?;
    let worker = EntityId::from_bytes([0xa6; 16])?;
    for (id, name) in [
        (agent, "fixture.parked.author"),
        (worker, "fixture.parked.worker"),
    ] {
        vault.create_agent_definition_as(
            &proof,
            &id,
            &definition(name),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN.to_owned()),
            now,
        })?
    else {
        panic!("the author dispatches without running a model")
    };
    let leased = claim(&vault, status.attempt.id)?;
    Ok(Fixture {
        vault,
        owner,
        agent,
        worker,
        leased,
        _dir: dir,
    })
}

/// Leases `id` to this test's worker. Rows are claimed oldest first, so a
/// row queued before it is claimed past.
fn claim(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(row);
        }
    }
    Err("the attempt is ready to claim".into())
}

fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The author's `self.agents.spawn` of the worker under `key`: the queued
/// child's attempt.
fn spawn_child(f: &Fixture, key: &str) -> TestResult<AttemptId> {
    let host = HostSelfDispatcher::for_leased_agent_attempt(
        &f.vault,
        WriteActor::new(f.agent, EdgeActorClass::Agent),
        &f.leased,
    )?;
    let call = SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
        target: Some(AgentDispatchTarget::Custom(f.worker)),
        context: AgentSpawnContext::default(),
        intent_key: key.to_owned(),
        ask: None,
    }));
    match host.dispatch(call)? {
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref, .. }) => {
            Ok(attempt_ref)
        }
        other => Err(format!("expected a queued child, got {other:?}").into()),
    }
}

fn as_owner(f: &Fixture, verb: &str, input: Value) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(&f.vault.memory(f.owner, EdgeActorClass::Human), verb, input)
        .map_err(|error| format!("{error:?}"))
}

fn row(f: &Fixture, id: AttemptId) -> TestResult<AttemptRecord> {
    Ok(AttemptQueue::new(&f.vault)
        .get(id)?
        .ok_or("the branch's row reads back")?)
}

/// Whether `id` is parked, as the attempt's park row reads.
fn parked(f: &Fixture, id: AttemptId) -> TestResult<bool> {
    let (_, park) = DreamerRunnerStore::new(&f.vault)
        .status_with_park(id)?
        .ok_or("the attempt's status reads back")?;
    Ok(park.is_some())
}

/// The run signals on branch `id` of the fixture's run.
fn branch_signals(f: &Fixture, id: AttemptId) -> TestResult<Vec<RunBranchSignal>> {
    Ok(RunTreeAdapter::new(&f.vault)
        .read_branch_signals(id, RUN)?
        .ok_or("the branch's signals read")?)
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("executor future unexpectedly pending"),
    }
}

/// A model that answers every step with one program and counts the
/// requests it received.
struct CountingBackend {
    requests: Mutex<usize>,
}

impl CountingBackend {
    fn new() -> Self {
        Self {
            requests: Mutex::new(0),
        }
    }

    fn requests(&self) -> usize {
        *self.requests.lock().expect("the request count")
    }
}

impl LlmBackend for CountingBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        *self.requests.lock().expect("the request count") += 1;
        let mut usage = LlmUsage::zero();
        usage.raw_provider = json!({});
        let response = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "console.log('step');".to_owned(),
                    signature: None,
                }],
            },
            usage,
            finish_reason: FinishReason::Stop,
            reply_assertions: ReplyAssertions::default(),
            token_scores: None,
        };
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// A runtime whose steps park on an outbound effect's durable wait while
/// `parks` holds, and otherwise run and leave the run going on.
struct WaitRuntime {
    parks: bool,
}

impl JsCodeModeRuntime for WaitRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        if self.parks {
            host.dispatch_self(SelfCall::OutboundFixture(SelfFixtureEffectCall::new(
                "send the report",
            )))?;
            return Ok(JsCodeModeStepOutcome::pending(
                "parked on an outbound effect",
            ));
        }
        Ok(JsCodeModeStepOutcome::pending("step observation"))
    }
}

/// Runs the leased child `leased`, the worker agent's run, through the
/// engine executor, as its worker does, for at most `soft_steps` steps.
fn run_child(
    f: &Fixture,
    leased: &AttemptRecord,
    backend: &CountingBackend,
    parks: bool,
    soft_steps: u32,
) -> TestResult<EngineExecutorOutcome> {
    let actor = WriteActor::new(f.worker, EdgeActorClass::Agent);
    let gated = HostSelfDispatcher::for_leased_agent_attempt(&f.vault, actor, leased)?;
    let lease = BudgetLease::for_test("agent-pause-parked-run");
    let mut runtime = WaitRuntime { parks };
    let config = EngineExecutorConfig {
        run_id: EntityId::from_bytes(*leased.id.as_bytes())?,
        task: "count carefully".to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()?,
        model: ModelId::new("seat/generative_reasoner@1cadcf6de87a")?,
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [7_u8; 32]),
        limits: EngineExecutorLimits { soft_steps },
        wake: None,
    };
    let mut executor = EngineNativeExecutor::new(&f.vault, backend, &lease, &mut runtime, &gated);
    Ok(block_on_ready(executor.run(&config)).map_err(|error| format!("the run: {error:?}"))?)
}

/// How a run returned, as its status reads.
fn status(outcome: &EngineExecutorOutcome) -> String {
    format!("{:?}", outcome.status)
}

/// The step checkpoints the run's record holds.
fn steps(outcome: &EngineExecutorOutcome) -> Vec<u64> {
    outcome
        .replay_record
        .step_checkpoints
        .iter()
        .map(|checkpoint| checkpoint.seq)
        .collect()
}

/// Parks the leased child `leased`, whose run returned `outcome` on its
/// wait, as the resident pump does: the wait's trap opens and waits, and
/// the attempt parks under the trap bound to the wait in one commit. The
/// trap's park owner and the wait's key.
fn park_as_pump(
    f: &Fixture,
    leased: &AttemptRecord,
    outcome: &EngineExecutorOutcome,
) -> TestResult<(String, WaitKey)> {
    let parked = outcome.parked_wait().ok_or("the run waits on a wait")?;
    let now_ms = f.vault.now_recorded_at().saturating_mul(1_000);
    let trap = llm::open_trap(
        &f.vault,
        &llm::DurableStepContext {
            vault: &f.vault,
            attempt_id: leased.id,
            run_id: leased.run_id.clone(),
            envelope_actor: WriteActor::new(f.worker, EdgeActorClass::Agent),
            subject: parked.wait.wait_id,
            deadline: None,
            now_ms,
            spend_scope: None,
            wake_pass_bound: false,
        },
        llm::trap_for_durable_wait(&parked.wait, parked.step_hash),
        parked.step_hash,
        "code-run wait",
    )?;
    assert_eq!(
        llm::register_wait(&f.vault, &trap, now_ms)?,
        llm::DreamerTrapState::Waiting,
        "the trap waits for its reply"
    );
    let owner = llm::trap_park_owner(&trap.trap_claim_id);
    let woke = park_and_bind_wait_trap(
        &f.vault,
        ParkDreamerAttempt {
            attempt_id: leased.id,
            reason: WAITING_PARK_REASON.to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: owner.clone(),
            carried_spend: None,
            now: now_ms / 1_000,
        },
        &parked.key,
        &trap,
        now_ms,
    )?;
    assert!(!woke, "the park binds with no reply delivered");
    Ok((owner, parked.key))
}

/// A child whose step parks on its wait, leased and parked as the pump
/// parks it: the child's attempt and its wait's key.
fn parked_child(f: &Fixture, key: &str) -> TestResult<(AttemptId, WaitKey)> {
    let child = spawn_child(f, key)?;
    let leased = claim(&f.vault, child)?;
    let backend = CountingBackend::new();
    let outcome = run_child(f, &leased, &backend, true, 3)?;
    assert!(
        status(&outcome).starts_with("Waiting("),
        "the step parks on its wait: {}",
        status(&outcome)
    );
    assert_eq!(backend.requests(), 1, "one step ran");
    let (_, wait) = park_as_pump(f, &leased, &outcome)?;
    let parked_row = row(f, child)?;
    assert_eq!(
        parked_row.state,
        AttemptState::Leased,
        "a park keeps its lease"
    );
    assert!(parked(f, child)?, "the child is parked on its wait");
    Ok((child, wait))
}

/// A pause posted while the child's step runs is pending when the step
/// stops on its wait: the run takes it there, once the step's checkpoint
/// commits, and returns paused instead of parked. The resumed run re-enters
/// its wait with no model request and waits on, still on step 0.
#[test]
fn a_pause_pending_when_a_run_stops_on_its_wait_pauses_it_there() -> TestResult {
    let f = fixture()?;
    let child = spawn_child(&f, "parked-pending")?;
    let leased = claim(&f.vault, child)?;

    let paused = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        paused["pausing_at_next_step"],
        json!([hex(child)]),
        "{paused}"
    );

    let backend = CountingBackend::new();
    let outcome = run_child(&f, &leased, &backend, true, 3)?;
    assert_eq!(
        status(&outcome),
        "Paused { next_step_seq: 1 }",
        "the step that parked commits, then the run stops paused"
    );
    assert_eq!(backend.requests(), 1, "no model request after the boundary");
    let paused_row = row(&f, child)?;
    assert_eq!(paused_row.state, AttemptState::Paused);
    assert_eq!(paused_row.lease_owner, None, "its lease is released");
    assert!(!parked(&f, child)?, "a paused run is not parked");
    let signals = branch_signals(&f, child)?;
    assert_eq!(signals.len(), 1, "{signals:?}");
    assert_eq!(
        signals[0].state,
        RunSignalState::Settled,
        "the pause is taken"
    );

    let resumed = as_owner(
        &f,
        RESUME_TREE,
        json!({"pause_ref": paused["pause_ref"].clone()}),
    )?;
    assert_eq!(
        resumed["resumed"]["branches"],
        json!([hex(child)]),
        "{resumed}"
    );
    assert_eq!(row(&f, child)?.state, AttemptState::Queued);

    let released = claim(&f.vault, child)?;
    let again = CountingBackend::new();
    let outcome = run_child(&f, &released, &again, true, 3)?;
    assert!(
        status(&outcome).starts_with("Waiting("),
        "the resumed run waits on its wait again: {}",
        status(&outcome)
    );
    assert_eq!(again.requests(), 0, "no step runs before the reply");
    assert_eq!(steps(&outcome), vec![0], "no step runs twice");
    Ok(())
}

/// pause_tree of a child already parked on its wait pauses it at once: it
/// is listed paused, not pausing at its next step, its row stands under the
/// owner's pause and its park is cleared. A reply that lands while it is
/// paused leaves it paused and is kept: the resumed run goes on from it,
/// at step 1, before any other model request.
#[test]
fn pause_tree_pauses_a_parked_run_at_once_and_keeps_its_reply() -> TestResult {
    let f = fixture()?;
    let (child, wait) = parked_child(&f, "parked-at-once")?;

    let paused = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(paused["pausing_at_next_step"], json!([]), "{paused}");
    assert_eq!(
        paused["paused"]["branches"],
        json!([hex(child)]),
        "{paused}"
    );
    let paused_row = row(&f, child)?;
    assert_eq!(paused_row.state, AttemptState::Paused, "paused at once");
    assert_eq!(paused_row.lease_owner, None, "the park's lease is released");
    let event = paused_row.events.last().ok_or("the pause is on the row")?;
    assert_eq!(event.actor, f.owner.to_hex(), "the owner's pause");
    assert!(!parked(&f, child)?, "the park is cleared");
    let signals = branch_signals(&f, child)?;
    assert_eq!(signals.len(), 1, "{signals:?}");
    assert_eq!(
        signals[0].state,
        RunSignalState::Settled,
        "the pause is taken"
    );

    let now_ms = f.vault.now_recorded_at().saturating_mul(1_000);
    let delivered = WaitDeliveries::canonical(&f.vault).deliver(
        wait.wait_id,
        &json!({"sent": true}),
        now_ms,
    )?;
    assert_eq!(delivered, 1, "the reply reaches the paused run's wait");
    assert_eq!(
        row(&f, child)?.state,
        AttemptState::Paused,
        "a reply wakes no paused run"
    );

    let resumed = as_owner(
        &f,
        RESUME_TREE,
        json!({"pause_ref": paused["pause_ref"].clone()}),
    )?;
    assert_eq!(
        resumed["resumed"]["branches"],
        json!([hex(child)]),
        "{resumed}"
    );
    assert_eq!(row(&f, child)?.state, AttemptState::Queued);

    let released = claim(&f.vault, child)?;
    let backend = CountingBackend::new();
    let outcome = run_child(&f, &released, &backend, false, 1)?;
    assert_eq!(
        status(&outcome),
        "Yielded { next_step_seq: 2 }",
        "the run goes on from the reply at step 1"
    );
    assert_eq!(backend.requests(), 1, "step 1 alone asks the model");
    assert_eq!(steps(&outcome), vec![0, 1], "no step runs twice");
    Ok(())
}

/// vault.runs.pause of a parked run answers `paused`, not
/// `pausing_at_next_step`. Resumed before its reply, the run re-enters its
/// wait with no model request, and the host parks it again: the pause left
/// no park behind for a second park to collide with, and the reply then
/// wakes the run once.
#[test]
fn runs_pause_pauses_a_parked_run_and_its_resume_parks_again() -> TestResult {
    let f = fixture()?;
    let (child, wait) = parked_child(&f, "parked-runs-pause")?;

    let paused = as_owner(&f, RUNS_PAUSE, json!({"branch": hex(child)}))?;
    assert_eq!(paused["effect"], json!("paused"), "{paused}");
    assert_eq!(paused["branch"]["state"], json!("Paused"), "{paused}");
    assert!(!parked(&f, child)?, "the park is cleared");
    let again = as_owner(&f, RUNS_PAUSE, json!({"branch": hex(child)}))?;
    assert_eq!(again["effect"], json!("already_paused"), "{again}");

    let resumed = as_owner(&f, RUNS_RESUME, json!({"branch": hex(child)}))?;
    assert_eq!(resumed["effect"], json!("resumed"), "{resumed}");
    assert_eq!(row(&f, child)?.state, AttemptState::Queued);

    let released = claim(&f.vault, child)?;
    let backend = CountingBackend::new();
    let outcome = run_child(&f, &released, &backend, true, 3)?;
    assert!(
        status(&outcome).starts_with("Waiting("),
        "the resumed run waits on its wait again: {}",
        status(&outcome)
    );
    assert_eq!(backend.requests(), 0, "no step runs before the reply");
    let (_, rewait) = park_as_pump(&f, &released, &outcome)?;
    assert_eq!(rewait, wait, "the same wait");
    assert!(parked(&f, child)?, "parked again");

    let now_ms = f.vault.now_recorded_at().saturating_mul(1_000);
    let delivered = WaitDeliveries::canonical(&f.vault).deliver(
        wait.wait_id,
        &json!({"sent": true}),
        now_ms,
    )?;
    assert_eq!(delivered, 1, "the reply reaches the wait");
    let woken = row(&f, child)?;
    assert_eq!(woken.state, AttemptState::Queued, "the reply wakes the run");
    assert_eq!(woken.lease_owner, None);
    assert!(!parked(&f, child)?, "its park is cleared");
    Ok(())
}
