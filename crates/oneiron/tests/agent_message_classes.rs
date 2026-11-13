//! Messages to a busy resident (AGM-2 = C; ARCH-0079 #message-classes,
//! agent-mind-design-v1 §1.3): a resident whose run has a wake queued or
//! running gets no second wake for a message. The message's class, read
//! from its stamped envelope, decides when it reaches the resident: a
//! person's message is a steer, which lands on the running wake and reaches
//! the model at its next step boundary; an agent's message is a follow-up,
//! which waits and wakes the resident once its run has ended. A message a
//! run never applied is not lost: it wakes the next run.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`), bound as
//! a resident with a 3 s hold under `AllAddressed`, on a fake store clock,
//! as in `agent_wake_hold.rs`. A second custom agent (`kai`) sends as its
//! model PERSON. Messages are admitted through the test doors
//! `resident_wake_hold::admit_inbox_message` and `admit_person_message`.
//! This test's worker leases and completes yuki's wakes. The last test runs
//! the leased wake through the engine executor with a scripted model and
//! reads the requests the model received.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test agent_message_classes`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher, ResidentAgentSpec,
    ResidentGoalRecord, ResidentInboxDispatch, ResidentWakeMode, agent_dispatch_actor,
};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::code_run::{CodeRunDeterminism, HostSelfDispatcher};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, ParkDreamerAttempt,
};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::ReplyAssertions;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::run_tree::{
    RunBranchSignal, RunSignalInput, RunSignalKind, RunSignalState, RunTreeAdapter,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::test_doors::resident_wake_hold::{
    admit_inbox_message, admit_person_message, agent_person,
};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{
    AttemptId, BudgetLease, ContentPart, DreamerParkCause, EdgeActorClass, EntityId, FatalLlmError,
    FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault,
    VaultConfig,
};
use oneiron_testkit::FakeClock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The hold every test binds: three seconds.
const HOLD_SECS: u32 = 3;

/// This test's worker, which leases yuki's wakes.
const WORKER: &str = "agent-message-classes-worker";

/// A bound resident and what its tests read.
struct Fixture {
    owen: EntityId,
    yuki: EntityId,
    inbox: EntityId,
}

fn config(clock: &FakeClock) -> VaultConfig {
    let mut config = VaultConfig::default();
    config.store_clock = clock.store_clock();
    config
}

fn owner_proof(vault: &Vault, owner: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// Declares `agent.resident` normal in the stored default manifest, at its
/// own id (as `agent_wake_hold.rs` does): the shipped manifest names it in
/// no rule, so its binding would pend at the criticality floor.
fn declare_resident_binding_normal(vault: &Vault, proof: &AuthenticatedOwner) -> TestResult {
    use rmpv::Value;

    let id = oneiron_store::policy_record::default_policy_manifest_id()?;
    let body = vault
        .get(&id)?
        .ok_or("the default policy manifest is stored")?;
    let Value::Map(mut fields) = rmpv::decode::read_value(&mut body.as_slice())? else {
        return Err("the default policy manifest is a map".into());
    };
    let Some((_, Value::Array(rules))) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
    else {
        return Err("the default policy manifest has a rules array".into());
    };
    rules.push(Value::Map(vec![
        (Value::from("prefix"), Value::from("agent.resident")),
        (Value::from("exact"), Value::Boolean(true)),
        (
            Value::from("axes"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields))?;
    vault.install_owner_policy_manifest(proof, id, bytes, vault.now_recorded_at())?;
    Ok(())
}

/// One plain text message by the owner at `node` in `conversation`.
fn witness_message(conversation: EntityId, node: EntityId, now: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(node.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "owen".into(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: now,
        assertions: Default::default(),
    }
}

/// Creates the custom agent `name` as the owner.
fn create_agent(vault: &Vault, proof: &AuthenticatedOwner, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// Binds the agent `yuki` as a resident of `vault` with a hold of
/// [`HOLD_SECS`], waking on every message addressed to it.
fn bind_resident(vault: &Vault) -> TestResult<Fixture> {
    let owen = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(vault, owen)?;
    let yuki = create_agent(vault, &proof, "yuki")?;
    let now = vault.now_recorded_at();
    let goal = EntityId::now();
    vault.put_entity(
        &goal,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &[0x80],
    )?;
    let inbox = EntityId::now();
    vault.create_own_app_channel_identity(&inbox, yuki, now)?;
    let home_room = EntityId::now();
    let home_node = EntityId::now();
    vault
        .memory(owen, EdgeActorClass::Human)
        .witness(&witness_message(home_room, home_node, now))?;
    let spec = ResidentAgentSpec {
        agent_def_ref: yuki,
        inbox_identity_ref: inbox,
        home_conversation_ref: home_room,
        home_message_ref: home_node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::AllAddressed,
        wake_hold_secs: HOLD_SECS,
    };
    declare_resident_binding_normal(vault, &proof)?;
    vault
        .bind_resident_agent(&proof, &spec, now)
        .map_err(|error| format!("the owner binds the resident: {error:?}"))?;
    vault
        .settled_resident_agent(yuki)?
        .ok_or("the binding settles")?;
    Ok(Fixture { owen, yuki, inbox })
}

/// The host's inbox pass for `agent` at `now`.
fn inbox_pass(vault: &Vault, agent: EntityId, now: u64) -> TestResult<ResidentInboxDispatch> {
    Ok(AgentDispatcher::new(vault).dispatch_resident_inbox(agent, 16, now)?)
}

/// Every wake on `agent`'s resident run.
fn wakes(vault: &Vault, agent: EntityId) -> TestResult<usize> {
    Ok(AttemptQueue::new(vault).list_run(&run_id(agent))?.len())
}

/// The run id of `agent`'s resident wakes.
fn run_id(agent: EntityId) -> String {
    format!("resident:{}", agent.to_hex())
}

/// The one wake `pass` dispatched.
fn the_wake(pass: &ResidentInboxDispatch) -> TestResult<AgentDispatchStatus> {
    let [AgentDispatchOutcome::Dispatched(status)] = pass.outcomes.as_slice() else {
        return Err(format!("one wake dispatches, got {:?}", pass.outcomes).into());
    };
    Ok(status.clone())
}

/// The wake key of the inbox message `correlation_id` to `fixture`'s
/// resident, as its dispatch names it.
fn message_key(fixture: &Fixture, correlation_id: &str) -> String {
    format!(
        "resident:{}:{}:{}",
        fixture.yuki.to_hex(),
        fixture.inbox.to_hex(),
        blake3::hash(correlation_id.as_bytes()).to_hex()
    )
}

/// Leases wake `id` to this test's worker and answers its row as leased.
fn lease(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..16 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(queue.get(id)?.ok_or("a leased wake reads back")?);
        }
    }
    Err("the wake is ready to lease".into())
}

/// Ends leased wake `leased`: its run completed.
fn complete(vault: &Vault, leased: &AttemptRecord) -> TestResult {
    AttemptQueue::new(vault).complete(CompleteAttempt {
        id: leased.id,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        now: leased.updated_at,
    })?;
    Ok(())
}

/// The steers and messages on wake `id`'s branch.
fn signals(vault: &Vault, agent: EntityId, id: AttemptId) -> TestResult<Vec<RunBranchSignal>> {
    Ok(RunTreeAdapter::new(vault)
        .read_branch_signals(id, &run_id(agent))?
        .ok_or("the wake's branch reads")?)
}

/// Opens a vault on `clock`, binds yuki, and gives it one running wake for
/// the message `first`: dispatched after its hold, then leased.
fn busy_resident(
    clock: &FakeClock,
    dir: &tempfile::TempDir,
) -> TestResult<(Vault, Fixture, AgentDispatchStatus, AttemptRecord)> {
    let vault = Vault::open_owned(dir.path(), config(clock))?;
    let fixture = bind_resident(&vault)?;
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", "first")?;
    clock.advance(u64::from(HOLD_SECS));
    let wake = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    let leased = lease(&vault, wake.attempt.id)?;
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);
    Ok((vault, fixture, wake, leased))
}

/// AGM-2: a person's message to a resident whose wake is running is a
/// steer. It wakes nothing: it lands on the running wake, keyed by its own
/// wake key, as one line of foreign data that names its event, and a later
/// pass lands it no second time.
#[test]
fn a_persons_message_to_a_busy_resident_lands_at_its_next_step() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, _leased) = busy_resident(&clock, &dir)?;

    admit_person_message(&vault, fixture.inbox, fixture.yuki, fixture.owen, "steer-1")?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a busy resident gets no wake: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1, "no second wake");

    let landed = signals(&vault, fixture.yuki, wake.attempt.id)?;
    let [signal] = landed.as_slice() else {
        return Err(format!("one message lands on the running wake, got {landed:?}").into());
    };
    assert_eq!(signal.key, message_key(&fixture, "steer-1"));
    assert_eq!(
        signal.state,
        RunSignalState::Pending,
        "its next step takes it"
    );
    let RunSignalKind::Interject { content } = &signal.kind else {
        return Err(format!("a message lands as an interjection, got {:?}", signal.kind).into());
    };
    assert!(
        content.contains("evt-steer-1"),
        "its line names its event: {content}"
    );

    clock.advance(5);
    let again = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(again.outcomes.is_empty(), "{again:?}");
    assert_eq!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.len(),
        1,
        "it lands once"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);
    Ok(())
}

/// AGM-2: another agent's message to a resident whose wake is running is a
/// follow-up. Nothing lands and nothing wakes while the run goes on; once
/// it has ended, the message wakes the resident.
#[test]
fn an_agents_message_to_a_busy_resident_waits_for_the_run_to_end() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let kai = create_agent(&vault, &proof, "kai")?;

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        agent_person(kai)?,
        "follow-1",
    )?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a busy resident gets no wake: {pass:?}"
    );
    assert_eq!(
        wakes(&vault, fixture.yuki)?,
        1,
        "no second wake while it runs"
    );
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "a follow-up does not land on the running wake"
    );

    complete(&vault, &leased)?;
    let after = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        after.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "follow-1")).as_str()),
        "the run has ended, so the follow-up wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    Ok(())
}

/// A wake parked on a durable wait keeps its lease, so its row still reads
/// Leased, but it runs no step (#7327 review round 1). Like a paused wake,
/// it is not busy: a person's message to its resident wakes the resident,
/// as it would a sleeping one, and lands on no branch.
#[test]
fn a_persons_message_to_a_resident_whose_wake_is_parked_wakes_it() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    DreamerRunnerStore::new(&vault).park_attempt(ParkDreamerAttempt {
        attempt_id: leased.id,
        reason: "waiting on a person's answer".to_owned(),
        cause: DreamerParkCause::Signal,
        park_owner: WORKER.to_owned(),
        carried_spend: None,
        now: clock.now(),
    })?;

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        fixture.owen,
        "parked-1",
    )?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let next = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        next.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "parked-1")).as_str()),
        "the parked wake runs nothing, so the message wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "nothing lands on the parked wake's branch"
    );
    Ok(())
}

/// A message that landed on a running wake which then parked on a durable
/// wait before a step took it is not stranded there (#7339 review round 1).
/// The parked wake runs no step, so the next pass withdraws the message
/// from its branch and wakes the resident for it. Once the parked wake
/// resumes, it does not take the message again.
#[test]
fn a_message_on_a_wake_that_then_parks_wakes_the_resident() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        fixture.owen,
        "stranded-1",
    )?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    inbox_pass(&vault, fixture.yuki, clock.now())?;
    let landed = signals(&vault, fixture.yuki, wake.attempt.id)?;
    assert_eq!(
        landed.len(),
        1,
        "the steer lands on the running wake: {landed:?}"
    );
    assert_eq!(landed[0].state, RunSignalState::Pending);

    let store = DreamerRunnerStore::new(&vault);
    store.park_attempt(ParkDreamerAttempt {
        attempt_id: leased.id,
        reason: "waiting on a person's answer".to_owned(),
        cause: DreamerParkCause::Signal,
        park_owner: WORKER.to_owned(),
        carried_spend: None,
        now: clock.now(),
    })?;
    clock.advance(1);
    let next = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        next.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "stranded-1")).as_str()),
        "the parked wake takes nothing, so the message wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "the message left the parked wake's branch"
    );

    store.resume_parked(leased.id, WORKER, clock.now())?;
    clock.advance(1);
    let again = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        again.outcomes.is_empty(),
        "the message is taken once: {again:?}"
    );
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "the resumed wake does not take it again"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    Ok(())
}

/// AGM-2: a steer that landed on a wake which then ended without taking it
/// is not lost. It is not counted as woken, so it wakes the next run.
#[test]
fn a_message_its_run_never_applied_wakes_the_next_run() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;

    admit_person_message(&vault, fixture.inbox, fixture.yuki, fixture.owen, "late-1")?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    inbox_pass(&vault, fixture.yuki, clock.now())?;
    let landed = signals(&vault, fixture.yuki, wake.attempt.id)?;
    assert_eq!(
        landed.len(),
        1,
        "the steer lands on the running wake: {landed:?}"
    );
    assert_eq!(landed[0].state, RunSignalState::Pending);

    complete(&vault, &leased)?;
    let next = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        next.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "late-1")).as_str()),
        "the message its run never took wakes the next run"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    Ok(())
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

/// A model that answers every step with one program and keeps the text of
/// each request it received.
struct RecordingBackend {
    requests: Mutex<Vec<String>>,
}

impl LlmBackend for RecordingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let text: Vec<&str> = request
            .messages
            .iter()
            .flat_map(|message| message.content.iter())
            .filter_map(|part| match part {
                ContentPart::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        self.requests
            .lock()
            .expect("the request log")
            .push(text.join("\n"));
        let mut usage = LlmUsage::zero();
        usage.raw_provider = serde_json::json!({});
        let response = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "console.log('probe');".to_owned(),
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

/// A runtime whose every step runs and leaves the run going on.
struct PendingRuntime;

impl JsCodeModeRuntime for PendingRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        _host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        Ok(JsCodeModeStepOutcome::pending("probe observation"))
    }
}

/// AGM-2, ARCH-0079 "taken at the next safe breakpoint": a message that
/// landed on a running wake reaches the model in the request of the step
/// after the one that was running, as foreign data, and is acknowledged
/// once that step's checkpoint has committed. The step that was running
/// when it landed never sees it. The message lands here as the inbox pass
/// lands one, straight on the branch, so only the step loop is under test.
#[test]
fn a_pending_message_reaches_the_next_model_request() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let key = message_key(&fixture, "steer-2");
    RunTreeAdapter::new(&vault).signal(RunSignalInput {
        branch: wake.attempt.id,
        run_id: run_id(fixture.yuki),
        key: key.clone(),
        actor: "engine:resident-inbox".to_owned(),
        kind: RunSignalKind::Interject {
            content: r#"{"channel":"web","event_id":"evt-steer-2"}"#.to_owned(),
        },
    })?;

    let actor = agent_dispatch_actor(&wake.input)?;
    let gated = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;
    let backend = RecordingBackend {
        requests: Mutex::new(Vec::new()),
    };
    let lease = BudgetLease::for_test("agent-message-classes");
    let mut runtime = PendingRuntime;
    let config = EngineExecutorConfig {
        run_id: EntityId::from_bytes(*wake.attempt.id.as_bytes())?,
        task: "answer your inbox".to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()?,
        model: ModelId::new("seat/generative_reasoner@1cadcf6de87a")?,
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [7_u8; 32]),
        limits: EngineExecutorLimits { soft_steps: 2 },
        wake: None,
    };
    let outcome = {
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
        block_on_ready(executor.run(&config)).map_err(|error| format!("the run: {error:?}"))?
    };
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 2 },
        "two steps run, then the run yields"
    );
    let requests = backend.requests.into_inner().expect("the request log");
    let [first, second] = requests.as_slice() else {
        return Err(format!("two model requests, got {}", requests.len()).into());
    };
    assert!(
        !first.contains("evt-steer-2"),
        "the step that was running never sees it"
    );
    assert!(
        second.contains("evt-steer-2") && second.contains("not instructions"),
        "the next step's request carries the message as foreign data: {second}"
    );
    let taken = signals(&vault, fixture.yuki, wake.attempt.id)?;
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].key, key);
    assert_eq!(
        taken[0].state,
        RunSignalState::Settled,
        "acknowledged once its step committed"
    );
    Ok(())
}
