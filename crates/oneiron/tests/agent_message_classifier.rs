//! The message classifier (AGM-2 = C; ARCH-0079 #message-classes,
//! agent-mind-design-v1 §1.3): a message that reaches a busy resident is
//! classed once, as interrupt, steer, follow-up or digest, by the host's
//! typed question `agents.message_class` on the ladder's local rung, from
//! the message's stamped envelope and first line.
//!
//! - An urgent, sure message from a person of this vault interrupts at
//!   once: it lands on the running wake and its next step reads it first,
//!   marked `interrupt` (Engine RULING 05:39, INTERRUPT-LANDING = B).
//! - An unsure interrupt never waits: it lands as a steer, and the same
//!   question is asked of the person who sent it alone. Their tap, when it
//!   changes the classifier's answer, is kept for the Coach's tuning. An
//!   agent's unsure interrupt asks no one.
//! - A digest wakes nothing of its own. It folds into one count line on the
//!   next landing or wake, or wakes the resident once the binding's digest
//!   delay has run.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`), bound as
//! a resident with a 3 s hold and a 60 s digest delay under `AllAddressed`,
//! on a fake store clock, as in `agent_message_classes.rs`. A second custom
//! agent (`kai`) sends as its model PERSON. The classifier's local rung is
//! a scripted head that answers in the order it is asked and keeps each
//! state it read. Messages are admitted through the test doors
//! `resident_wake_hold::admit_inbox_message` and `admit_person_message`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test agent_message_classifier`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher, MESSAGE_CLASS_ASK_QUEUE,
    ResidentAgentSpec, ResidentGoalRecord, ResidentInboxDispatch, ResidentMessageClassifier,
    ResidentWakeMode, agent_dispatch_actor,
};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{CodeRunDeterminism, HostSelfDispatcher};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::ReplyAssertions;
use oneiron::llm::decision::questions::person_changed_pairs;
use oneiron::llm::decision::{
    AnswerActor, AskRole, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall,
    DecisionProvider, DecisionRung, HeldLadder, ProviderDecision, ProviderPin, RoleRank,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::run_tree::{RunBranchSignal, RunSignalKind, RunSignalState, RunTreeAdapter};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::test_doors::resident_wake_hold::{
    admit_inbox_message, admit_person_message, agent_person,
};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{
    AttemptId, BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig,
    WriteActor,
};
use oneiron_testkit::FakeClock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The hold every test binds: three seconds.
const HOLD_SECS: u32 = 3;

/// The digest delay every test binds: one minute.
const DIGEST_DELAY_SECS: u32 = 60;

/// The class question's wording in these tests.
const WORDING: &str = "Which class does this message to a busy agent take?";

/// This test's worker, which leases yuki's wakes.
const WORKER: &str = "agent-message-classifier-worker";

/// A bound resident and what its tests read.
struct Fixture {
    owen: EntityId,
    yuki: EntityId,
    inbox: EntityId,
}

/// A local class head that answers each read with the next scripted class
/// and its probability, and keeps the state each read handed it.
struct ScriptedClassHead {
    answers: Mutex<VecDeque<(&'static str, f64)>>,
    states: Mutex<Vec<serde_json::Value>>,
}

impl ScriptedClassHead {
    fn new(answers: &[(&'static str, f64)]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().copied().collect()),
            states: Mutex::new(Vec::new()),
        })
    }

    /// Every state a read handed it, in order.
    fn states(&self) -> Vec<serde_json::Value> {
        self.states.lock().expect("the read log").clone()
    }
}

impl DecisionProvider for ScriptedClassHead {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "message-class-head".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.states
            .lock()
            .expect("the read log")
            .push(call.state.clone());
        let (class, probability) = self
            .answers
            .lock()
            .expect("the script")
            .pop_front()
            .ok_or_else(|| oneiron::Error::InvalidConfig("the class head ran out".to_owned()))?;
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice(class.to_owned()),
            probability: Some(probability),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// A ladder whose only rung is `head`, on the local slot.
fn class_ladder(head: &Arc<ScriptedClassHead>) -> HeldLadder {
    let mut ladder = HeldLadder::unstaffed();
    let local: Arc<dyn DecisionProvider> = head.clone();
    ladder.local = Some(local);
    ladder
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
/// [`HOLD_SECS`] and a digest delay of [`DIGEST_DELAY_SECS`], waking on
/// every message addressed to it.
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
        digest_delay_secs: DIGEST_DELAY_SECS,
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

/// The host's inbox pass for `agent` at `now`, with no classifier.
fn inbox_pass(vault: &Vault, agent: EntityId, now: u64) -> TestResult<ResidentInboxDispatch> {
    Ok(AgentDispatcher::new(vault).dispatch_resident_inbox(agent, 16, now)?)
}

/// The host's inbox pass for `agent` at `now`, classing on `head`.
fn classed_pass(
    vault: &Vault,
    head: &Arc<ScriptedClassHead>,
    agent: EntityId,
    now: u64,
) -> TestResult<ResidentInboxDispatch> {
    let ladder = class_ladder(head);
    let bands = DecisionBandPolicy::default();
    let classifier = ResidentMessageClassifier {
        ladder: &ladder,
        wording: WORDING,
        bands: &bands,
        band: DecisionBand::default(),
    };
    Ok(AgentDispatcher::new(vault)
        .with_message_classifier(classifier)
        .dispatch_resident_inbox(agent, 16, now)?)
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

/// The briefing wake `status` was dispatched with.
fn briefing(status: &AgentDispatchStatus) -> TestResult<String> {
    Ok(status
        .input
        .context_spec
        .as_ref()
        .and_then(|spec| spec.briefing.clone())
        .ok_or("the wake carries a briefing")?)
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

/// The landed line of the message `key` on wake `id`'s branch.
fn landed_line(
    vault: &Vault,
    agent: EntityId,
    id: AttemptId,
    key: &str,
) -> TestResult<serde_json::Value> {
    let landed = signals(vault, agent, id)?;
    let signal = landed
        .iter()
        .find(|signal| signal.key == key)
        .ok_or_else(|| format!("{key} lands on the running wake: {landed:?}"))?;
    let RunSignalKind::Interject { content } = &signal.kind else {
        return Err(format!("a message lands as an interjection, got {:?}", signal.kind).into());
    };
    Ok(serde_json::from_str(content)?)
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

/// Runs leased wake `leased` of `fixture`'s resident for two steps with a
/// scripted model; the text of each model request.
fn run_two_steps(
    vault: &Vault,
    wake: &AgentDispatchStatus,
    leased: &AttemptRecord,
) -> TestResult<Vec<String>> {
    let actor = agent_dispatch_actor(&wake.input)?;
    let gated = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, leased)?;
    let backend = RecordingBackend {
        requests: Mutex::new(Vec::new()),
    };
    let lease = BudgetLease::for_test("agent-message-classifier");
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
        let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
        block_on_ready(executor.run(&config)).map_err(|error| format!("the run: {error:?}"))?
    };
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 2 },
        "two steps run, then the run yields"
    );
    Ok(backend.requests.into_inner().expect("the request log"))
}

/// Where `needle` first appears in `haystack`.
fn at(haystack: &str, needle: &str) -> TestResult<usize> {
    Ok(haystack
        .find(needle)
        .ok_or_else(|| format!("{needle} is in the request: {haystack}"))?)
}

/// ARCH-0079: "An urgent, sure message interrupts at once." The owner's
/// urgent message to the busy resident, which the classifier is sure of,
/// lands on the running wake marked `interrupt` and asks no one. A calm
/// steer that arrived before it, and an agent's digest that arrived before
/// both, land with it. The run's first model turn reads the interrupt at
/// once, before its turn instruction ([INTERRUPT-CUTS-MODEL-REQUEST-IN-FLIGHT]);
/// the next step boundary reads the steer, then the digest folded into one
/// count line, and the interrupt no second time. Each message is read once,
/// on the local rung, from its envelope and first line.
#[test]
fn an_urgent_sure_message_interrupts_at_once() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let kai = create_agent(&vault, &proof, "kai")?;
    let head = ScriptedClassHead::new(&[("digest", 0.9), ("steer", 0.9), ("interrupt", 0.9)]);

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        agent_person(kai)?,
        "digest-0",
    )?;
    clock.advance(1);
    admit_person_message(&vault, fixture.inbox, fixture.yuki, fixture.owen, "calm-1")?;
    clock.advance(1);
    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        fixture.owen,
        "urgent-1",
    )?;
    clock.advance(1);
    let pass = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a busy resident gets no wake: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1, "no second wake");

    let urgent = landed_line(
        &vault,
        fixture.yuki,
        wake.attempt.id,
        &message_key(&fixture, "urgent-1"),
    )?;
    assert_eq!(urgent["class"], "interrupt", "{urgent}");
    assert_eq!(urgent["event_id"], "evt-urgent-1");
    let calm = landed_line(
        &vault,
        fixture.yuki,
        wake.attempt.id,
        &message_key(&fixture, "calm-1"),
    )?;
    assert_eq!(calm["class"], "steer", "{calm}");
    let digest = landed_line(
        &vault,
        fixture.yuki,
        wake.attempt.id,
        &message_key(&fixture, "digest-0"),
    )?;
    assert_eq!(
        digest["class"], "digest",
        "the digest rides the landing: {digest}"
    );
    assert!(
        vault.decision_asks(None, 16, false)?.is_empty(),
        "a sure interrupt asks no one"
    );

    let states = head.states();
    assert_eq!(states.len(), 3, "each message is read once: {states:?}");
    assert_eq!(states[0]["envelope"]["sender"], "agent");
    assert_eq!(states[1]["envelope"]["sender"], "vault_person");
    assert_eq!(states[2]["envelope"]["channel"], "web");
    assert!(
        states[2]["first_line"]["foreign_inbound_data"].is_string(),
        "its first line is fenced as data: {}",
        states[2]
    );
    clock.advance(5);
    let again = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(again.outcomes.is_empty(), "{again:?}");
    assert_eq!(head.states().len(), 3, "a landed message is not read again");
    assert_eq!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.len(),
        3,
        "each lands once"
    );

    let requests = run_two_steps(&vault, &wake, &leased)?;
    let [first, second] = requests.as_slice() else {
        return Err(format!("two model requests, got {}", requests.len()).into());
    };
    // The interrupt, at once: the first request reads it just before its
    // turn instruction.
    let at_once = &first[at(first, "Reached you before your reply to step 0")?..];
    let interrupt = at(at_once, "interrupt: a message to your inbox")?;
    let urgent = at(at_once, "evt-urgent-1")?;
    let instruction = at(at_once, "Emit the source for durable step 0")?;
    assert!(
        interrupt < urgent && urgent < instruction,
        "the interrupt is read before the turn instruction: {at_once}"
    );
    assert!(
        !first.contains("Reached you while step"),
        "the steer and the digest wait for the step boundary"
    );
    // The host's message of the step boundary, after anything the board
    // shows of the inbox, and after the interrupt where the first turn
    // read it.
    let boundary = at(second, "Reached you while step")?;
    assert!(
        second[..boundary].contains("Reached you before your reply to step 0"),
        "the second request keeps the interrupt where the first turn read it: {second}"
    );
    let delivered = &second[boundary..];
    let calm = at(delivered, "evt-calm-1")?;
    let folded = at(delivered, "digest: 1 more messages wait in your INBOX")?;
    assert!(
        calm < folded,
        "the steer is read, the digest folds last: {delivered}"
    );
    assert!(
        !delivered.contains("evt-urgent-1"),
        "the boundary reads the interrupt no second time: {delivered}"
    );
    assert!(
        delivered[folded..].contains("evt-digest-0"),
        "the count line names the digest's event: {delivered}"
    );
    assert!(
        !delivered[..folded].contains("evt-digest-0"),
        "the digest is no line of its own: {delivered}"
    );
    for signal in signals(&vault, fixture.yuki, wake.attempt.id)? {
        assert_eq!(
            signal.state,
            RunSignalState::Settled,
            "{} is acknowledged once its step committed",
            signal.key
        );
    }
    Ok(())
}

/// ARCH-0079: "For an unsure or risky one, one tap asks the person
/// 'interrupt it?'. Those taps tune the classifier. It never blocks a
/// message." The owner's message the classifier leans to interrupt, but is
/// unsure of, lands at once as a steer, and the class question is asked of
/// the owner alone, with the classifier's read as its prior. Their tap,
/// "not an interrupt", changes that answer and is kept for the Coach's
/// tuning of the class question's bands. An agent's unsure interrupt falls
/// to steer and asks no one.
#[test]
fn an_unsure_interrupt_asks_and_the_tap_is_recorded_for_tuning() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, _leased) = busy_resident(&clock, &dir)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let kai = create_agent(&vault, &proof, "kai")?;
    let head = ScriptedClassHead::new(&[("interrupt", 0.5), ("interrupt", 0.5)]);

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        fixture.owen,
        "unsure-1",
    )?;
    clock.advance(1);
    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        agent_person(kai)?,
        "agent-unsure-1",
    )?;
    clock.advance(1);
    let pass = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(pass.outcomes.is_empty(), "{pass:?}");
    assert_eq!(head.states().len(), 2);

    let owners = landed_line(
        &vault,
        fixture.yuki,
        wake.attempt.id,
        &message_key(&fixture, "unsure-1"),
    )?;
    assert_eq!(
        owners["class"], "steer",
        "it lands at once as a steer, never waiting on the tap: {owners}"
    );
    let agents = landed_line(
        &vault,
        fixture.yuki,
        wake.attempt.id,
        &message_key(&fixture, "agent-unsure-1"),
    )?;
    assert_eq!(
        agents["class"], "steer",
        "an agent's interrupt falls to steer: {agents}"
    );

    let asks = vault.decision_asks(None, 16, false)?;
    let [ask] = asks.as_slice() else {
        return Err(format!("one ask, to the owner alone, got {asks:?}").into());
    };
    assert_eq!(ask.queue_pin.model, MESSAGE_CLASS_ASK_QUEUE);
    assert_eq!(
        ask.to.role,
        AskRole::Responsible {
            actor: AnswerActor::Actor(fixture.owen),
            project: None,
        },
        "the sender is asked"
    );
    assert_eq!(
        ask.to.ceiling,
        RoleRank::Responsible,
        "and no one above them"
    );
    let prior = ask
        .prior
        .as_ref()
        .ok_or("the classifier's read is its prior")?;
    assert_eq!(prior.answer, DecisionAnswer::Choice("interrupt".to_owned()));
    assert_eq!(prior.probability, Some(0.5));
    assert_eq!(prior.provider.rung, DecisionRung::Local);
    let question = ask.question.id;

    let tapped = vault.answer_decision_ask_as(
        &WriteActor::new(fixture.owen, EdgeActorClass::Human),
        ask.seq,
        DecisionAnswer::Choice("steer".to_owned()),
    )?;
    let answer = tapped.answer.ok_or("the tap is the ask's answer")?;
    assert!(answer.changed, "the tap changed the classifier's answer");
    let pairs = person_changed_pairs(&vault, fixture.yuki, question, CallerLocality::OnDevice)?;
    assert_eq!(
        pairs.len(),
        1,
        "the tap is kept for the Coach's tuning: {pairs:?}"
    );

    clock.advance(5);
    classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert_eq!(
        vault.decision_asks(None, 16, false)?.len(),
        1,
        "a message is asked about once"
    );
    Ok(())
}

/// ARCH-0079 digest; Engine RULING 05:03 (Digest A): a message the
/// classifier is sure can wait as a digest wakes nothing of its own, and
/// lands on nothing while the run goes on. Once the run has ended it holds
/// for the binding's digest delay. A message that wakes the resident before
/// then carries it as one count line. A later digest that nothing carries
/// wakes the resident itself once the delay has run.
#[test]
fn a_digest_message_folds_into_the_next_wake() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let kai = create_agent(&vault, &proof, "kai")?;
    let head = ScriptedClassHead::new(&[("digest", 0.9), ("digest", 0.9)]);

    let digest_at = clock.now();
    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        agent_person(kai)?,
        "digest-1",
    )?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(pass.outcomes.is_empty(), "{pass:?}");
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "a digest with nothing to ride lands on nothing"
    );

    complete(&vault, &leased)?;
    let idle = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(
        idle.outcomes.is_empty(),
        "a digest wakes nothing of its own: {idle:?}"
    );
    assert_eq!(
        idle.held_until,
        Some(digest_at + u64::from(DIGEST_DELAY_SECS)),
        "it holds for the digest delay"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);

    admit_person_message(&vault, fixture.inbox, fixture.yuki, fixture.owen, "next-1")?;
    clock.advance(u64::from(HOLD_SECS));
    let next = the_wake(&classed_pass(&vault, &head, fixture.yuki, clock.now())?)?;
    assert_eq!(
        next.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "next-1")).as_str()),
        "the owner's message wakes the resident"
    );
    assert_eq!(
        next.input.carried_wake_keys,
        vec![message_key(&fixture, "digest-1")],
        "the digest rides that wake"
    );
    let text = briefing(&next)?;
    assert!(
        text.contains("digest: 1 more messages wait in your INBOX")
            && text.contains("evt-digest-1"),
        "as one count line: {text}"
    );
    assert_eq!(
        head.states().len(),
        1,
        "a message to a sleeping resident is not classed"
    );

    let leased = lease(&vault, next.attempt.id)?;
    let later_at = clock.now();
    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        agent_person(kai)?,
        "digest-2",
    )?;
    clock.advance(1);
    classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    complete(&vault, &leased)?;
    clock.advance(u64::from(DIGEST_DELAY_SECS));
    let own = the_wake(&classed_pass(&vault, &head, fixture.yuki, clock.now())?)?;
    assert!(
        clock.now() >= later_at + u64::from(DIGEST_DELAY_SECS),
        "the delay has run"
    );
    assert_eq!(
        own.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "digest-2")).as_str()),
        "the digest wakes the resident itself once its delay has run"
    );
    let text = briefing(&own)?;
    assert!(
        text.contains("digest: 1 more messages wait in your INBOX")
            && text.contains("evt-digest-2"),
        "{text}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 3);
    Ok(())
}

/// #7321 review round 2, for digests: a wake folds only the digests its
/// count line names inside the briefing cap. Sixteen digests from kai with
/// 254-byte correlation ids are classed while yuki is busy. Once the run
/// has ended, ten owner messages with ids as long wake yuki. Their wake
/// lines and the sixteen digest ids together pass the cap, so each wake
/// names every message and digest it carries, and its count line counts
/// only those digests.
#[test]
fn a_wake_folds_only_the_digests_its_briefing_names() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, _wake, leased) = busy_resident(&clock, &dir)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let kai = create_agent(&vault, &proof, "kai")?;
    let head = ScriptedClassHead::new(&[("digest", 0.9); 16]);
    let long = |prefix: &str, index: usize| format!("{prefix}{index:02}{}", "c".repeat(250));
    let digests: Vec<String> = (0..16).map(|index| long("dg", index)).collect();
    for correlation_id in &digests {
        admit_person_message(
            &vault,
            fixture.inbox,
            fixture.yuki,
            agent_person(kai)?,
            correlation_id,
        )?;
    }
    clock.advance(u64::from(HOLD_SECS) + 1);
    let busy = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(busy.outcomes.is_empty(), "{busy:?}");
    assert_eq!(head.states().len(), 16, "each digest is classed once");

    complete(&vault, &leased)?;
    let sent: Vec<String> = (0..10).map(|index| long("ow", index)).collect();
    for correlation_id in &sent {
        admit_person_message(
            &vault,
            fixture.inbox,
            fixture.yuki,
            fixture.owen,
            correlation_id,
        )?;
    }
    clock.advance(u64::from(HOLD_SECS));
    let pass = classed_pass(&vault, &head, fixture.yuki, clock.now())?;
    assert!(!pass.outcomes.is_empty(), "the owner's messages wake yuki");
    let mut woke = Vec::new();
    for outcome in &pass.outcomes {
        let AgentDispatchOutcome::Dispatched(status) = outcome else {
            return Err(format!("each wake dispatches, got {outcome:?}").into());
        };
        let text = briefing(status)?;
        let own = status
            .attempt
            .dedupe_key
            .as_deref()
            .and_then(|key| key.strip_prefix("agent.dispatch:"))
            .ok_or("a wake's dedupe key is its first message's wake key")?
            .to_owned();
        let mut folded = 0;
        for key in std::iter::once(own).chain(status.input.carried_wake_keys.iter().cloned()) {
            if let Some(correlation_id) = digests
                .iter()
                .find(|digest| message_key(&fixture, digest) == key)
            {
                assert!(
                    text.contains(&format!("evt-{correlation_id}")),
                    "the count line names digest {} in full",
                    &correlation_id[..4]
                );
                folded += 1;
                continue;
            }
            let correlation_id = sent
                .iter()
                .find(|sent| message_key(&fixture, sent) == key)
                .ok_or("each key a wake carries names a sent message")?;
            assert!(
                text.contains(&format!("\"correlation_id\":\"{correlation_id}\""))
                    && text.contains(&format!("\"event_id\":\"evt-{correlation_id}\"")),
                "the wake line names message {} in full",
                &correlation_id[..4]
            );
            woke.push(key);
        }
        if folded > 0 {
            assert!(
                text.contains(&format!(
                    "digest: {folded} more messages wait in your INBOX"
                )),
                "the count line counts the {folded} digests the wake carries"
            );
        }
    }
    woke.sort();
    let mut expected: Vec<String> = sent
        .iter()
        .map(|sent| message_key(&fixture, sent))
        .collect();
    expected.sort();
    assert_eq!(woke, expected, "every owner message wakes yuki, once");
    Ok(())
}
