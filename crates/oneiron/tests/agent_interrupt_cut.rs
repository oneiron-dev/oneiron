//! An interrupt cuts a busy resident's model request in flight (AGM-2 = C;
//! ARCH-0079 #message-classes, "An urgent, sure message interrupts at once";
//! [INTERRUPT-CUTS-MODEL-REQUEST-IN-FLIGHT]). While a step's model request
//! is in flight, an interrupt that lands on the run's branch cuts it: the
//! call is dropped, the turn asks again with the interrupt read before its
//! turn instruction, and the step runs the answer to that request. The cut
//! call settles as dispatched with unknown usage, its reservation kept as
//! spend (agent-mind-design-v1 §8). A steer cuts nothing: it waits for the
//! step boundary.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`), bound as
//! a resident with a 3 s hold under `AllAddressed`, on a fake store clock,
//! as in `agent_message_classes.rs`. Yuki's wake is dispatched and leased by
//! this test's worker, then run through the engine executor with a scripted
//! model. The scripted model lands a message on the running wake as the
//! inbox pass lands one, straight on the branch, while its first request is
//! in flight.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test agent_interrupt_cut`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher, RESIDENT_DIGEST_DELAY_DEFAULT_SECS,
    ResidentAgentSpec, ResidentGoalRecord, ResidentInboxDispatch, ResidentWakeMode,
    agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::code_run::{CodeRunDeterminism, HostSelfDispatcher};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorStatus,
    EngineNativeExecutor, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::run_admission::{
    BudgetLine, GatedBackend, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute,
    Payer, RunAdmission, RunCall, RunCallError, RunDeclaration, RunEvent,
};
use oneiron::llm::{ReplyAssertions, SingleRouteBackend};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::run_tree::{RunSignalInput, RunSignalKind, RunSignalState, RunTreeAdapter};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::test_doors::resident_wake_hold::admit_inbox_message;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{
    AttemptId, BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason,
    LlmBackend, LlmError, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmResult, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault,
    VaultConfig,
};
use oneiron_testkit::FakeClock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The hold every test binds: three seconds.
const HOLD_SECS: u32 = 3;

/// This test's worker, which leases yuki's wakes.
const WORKER: &str = "agent-interrupt-cut-worker";

/// The model the executor asks, and the run admission's offer serves.
const MODEL: &str = "seat/generative_reasoner@1cadcf6de87a";

/// What each admitted model call reserves, in tokens.
const CALL_RESERVE: u64 = 500;

/// The provider event the landed message names.
const LANDED_EVENT: &str = "evt-landed-9";

/// A bound resident and what its tests read.
struct Fixture {
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
        digest_delay_secs: RESIDENT_DIGEST_DELAY_DEFAULT_SECS,
    };
    declare_resident_binding_normal(vault, &proof)?;
    vault
        .bind_resident_agent(&proof, &spec, now)
        .map_err(|error| format!("the owner binds the resident: {error:?}"))?;
    vault
        .settled_resident_agent(yuki)?
        .ok_or("the binding settles")?;
    Ok(Fixture { yuki, inbox })
}

/// The host's inbox pass for `agent` at `now`.
fn inbox_pass(vault: &Vault, agent: EntityId, now: u64) -> TestResult<ResidentInboxDispatch> {
    Ok(AgentDispatcher::new(vault).dispatch_resident_inbox(agent, 16, now)?)
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
    Ok((vault, fixture, wake, leased))
}

/// A message the inbox pass lands on a running wake, marked with its class.
struct Landing<'v> {
    vault: &'v Vault,
    branch: AttemptId,
    run_id: String,
    key: String,
    class: &'static str,
}

impl Landing<'_> {
    /// Lands the message on the running wake, as the inbox pass lands one.
    fn land(&self) {
        RunTreeAdapter::new(self.vault)
            .signal(RunSignalInput {
                branch: self.branch,
                run_id: self.run_id.clone(),
                key: self.key.clone(),
                actor: "engine:resident-inbox".to_owned(),
                kind: RunSignalKind::Interject {
                    content: serde_json::json!({
                        "channel": "web",
                        "event_id": LANDED_EVENT,
                        "class": self.class,
                    })
                    .to_string(),
                },
            })
            .expect("the message lands on the running wake");
    }

    /// The state of the landed message on the wake's branch.
    fn state(&self) -> TestResult<RunSignalState> {
        let signals = RunTreeAdapter::new(self.vault)
            .read_branch_signals(self.branch, &self.run_id)?
            .ok_or("the wake's branch reads")?;
        let [signal] = signals.as_slice() else {
            return Err(format!("one message on the branch, got {signals:?}").into());
        };
        assert_eq!(signal.key, self.key);
        Ok(signal.state)
    }
}

/// The landing of a `class` message on `wake`, keyed `key`.
fn landing<'v>(
    vault: &'v Vault,
    fixture: &Fixture,
    wake: &AgentDispatchStatus,
    key: &str,
    class: &'static str,
) -> Landing<'v> {
    Landing {
        vault,
        branch: wake.attempt.id,
        run_id: run_id(fixture.yuki),
        key: key.to_owned(),
        class,
    }
}

/// The text of every part of `request`, one part per line.
fn request_text(request: &LlmRequest) -> String {
    request
        .messages
        .iter()
        .flat_map(|message| message.content.iter())
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The scripted model's one answer: a program.
fn program_reply() -> LlmResponse {
    let mut usage = LlmUsage::zero();
    usage.raw_provider = serde_json::json!({});
    LlmResponse {
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
    }
}

/// Sets its flag when the call that holds it is dropped.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A reply that never finishes; `dropped` is set once the call is dropped.
fn never_finishes(dropped: &Arc<AtomicBool>) -> LlmGenerateFuture<'static> {
    let flag = DropFlag(Arc::clone(dropped));
    Box::pin(async move {
        let _flag = flag;
        std::future::pending::<LlmResult<LlmResponse>>().await
    })
}

/// A reply that is pending once, then answers.
struct AfterOneYield {
    yielded: bool,
    reply: Option<LlmResponse>,
}

impl Future for AfterOneYield {
    type Output = LlmResult<LlmResponse>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.yielded {
            self.yielded = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(
            self.reply
                .take()
                .ok_or_else(|| LlmError::from(FatalLlmError::EmptyResponse)),
        )
    }
}

/// How the scripted model's first reply goes.
#[derive(Clone, Copy)]
enum FirstReply {
    /// It never finishes.
    Never,
    /// It is pending once, then answers.
    AfterOneYield,
}

/// A model whose first call lands a message on the running wake while the
/// call is in flight, and whose first reply goes as `first` says; every
/// later call answers at once with one program. It keeps the text of every
/// request it received.
struct ScriptedModel<'v> {
    landing: Landing<'v>,
    first: FirstReply,
    calls: AtomicUsize,
    requests: Mutex<Vec<String>>,
    first_dropped: Arc<AtomicBool>,
}

impl<'v> ScriptedModel<'v> {
    fn new(landing: Landing<'v>, first: FirstReply) -> Self {
        Self {
            landing,
            first,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            first_dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the request log").clone()
    }
}

impl LlmBackend for ScriptedModel<'_> {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.requests
            .lock()
            .expect("the request log")
            .push(request_text(&request));
        if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
            return Box::pin(std::future::ready(Ok(program_reply())));
        }
        self.landing.land();
        match self.first {
            FirstReply::Never => never_finishes(&self.first_dropped),
            FirstReply::AfterOneYield => Box::pin(AfterOneYield {
                yielded: false,
                reply: Some(program_reply()),
            }),
        }
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// The provider behind the run admission's gate: its first reply never
/// finishes, every later one answers at once with one program.
struct HangingProvider {
    calls: AtomicUsize,
    first_dropped: Arc<AtomicBool>,
}

impl LlmBackend for HangingProvider {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return never_finishes(&self.first_dropped);
        }
        Box::pin(std::future::ready(Ok(program_reply())))
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl SingleRouteBackend for HangingProvider {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Ok(())
    }
}

/// The host's backend for one run, as a host builds it: each call is
/// admitted by the run's admission and sent through its gate, which settles
/// the call's permit however the call ends. The first call lands a message
/// on the running wake while it is in flight.
struct AdmittedModel<'v> {
    landing: Landing<'v>,
    run: RunAdmission,
    gated: GatedBackend,
    offer: OfferBinding,
    calls: AtomicUsize,
}

impl LlmBackend for AdmittedModel<'_> {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.landing.land();
        }
        Box::pin(async move {
            self.run
                .call(
                    &self.gated,
                    RunCall {
                        selector: None,
                        request: &request,
                        offer: &self.offer,
                    },
                )
                .await
                .map_err(|error| match error {
                    RunCallError::Denied(denied) => LlmError::from(denied),
                    RunCallError::Failed { error, .. } => error,
                })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// The offer the run admission's gate serves [`MODEL`] by: the customer's
/// own key on the owner's server, metered in tokens.
fn model_offer() -> TestResult<OfferBinding> {
    Ok(OfferBinding {
        offer: format!("{MODEL}@model.test"),
        model: ModelId::new(MODEL)?,
        route: OfferRoute::new("fake", "https://model.test:443")?,
        locality: ModelLocality::OwnServer,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    })
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

/// Polls `future` to its end with a no-op waker. Every model reply here
/// answers at once or after one yield, so a few polls end the run; a run
/// still pending after them waits on a reply that never finishes.
fn block_on_polls<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..64 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the run never ended: it still waits on a model reply that never finishes");
}

/// Runs leased wake `leased` for `steps` steps through `backend`.
fn run_wake(
    vault: &Vault,
    wake: &AgentDispatchStatus,
    leased: &AttemptRecord,
    backend: &dyn LlmBackend,
    steps: u32,
) -> TestResult<EngineExecutorOutcome> {
    let actor = agent_dispatch_actor(&wake.input)?;
    let gated = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, leased)?;
    let lease = BudgetLease::for_test("agent-interrupt-cut");
    let mut runtime = PendingRuntime;
    let config = EngineExecutorConfig {
        run_id: EntityId::from_bytes(*wake.attempt.id.as_bytes())?,
        task: "answer your inbox".to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()?,
        model: ModelId::new(MODEL)?,
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [7_u8; 32]),
        limits: EngineExecutorLimits { soft_steps: steps },
        wake: None,
    };
    let mut executor = EngineNativeExecutor::new(vault, backend, &lease, &mut runtime, &gated);
    Ok(block_on_polls(executor.run(&config)).map_err(|error| format!("the run: {error:?}"))?)
}

/// Where `needle` first appears in `haystack`.
fn at(haystack: &str, needle: &str) -> TestResult<usize> {
    Ok(haystack
        .find(needle)
        .ok_or_else(|| format!("{needle} is in the request: {haystack}"))?)
}

/// ARCH-0079: "An urgent, sure message interrupts at once." An interrupt
/// that lands while the step's model request is in flight cuts the request:
/// the call is dropped, and the turn asks again with the interrupt read
/// just before its turn instruction. The step runs the answer to that
/// request, and the interrupt is acknowledged once the step commits.
#[test]
fn an_interrupt_cuts_the_model_request_in_flight_and_asks_again_with_its_line() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let model = ScriptedModel::new(
        landing(&vault, &fixture, &wake, "urgent-9", "interrupt"),
        FirstReply::Never,
    );

    let outcome = run_wake(&vault, &wake, &leased, &model, 1)?;
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "the step runs the answer to the second request, then the run yields"
    );
    assert!(
        model.first_dropped.load(Ordering::SeqCst),
        "the request in flight is dropped"
    );
    let requests = model.requests();
    let [cut, asked_again] = requests.as_slice() else {
        return Err(format!("two model requests, got {}", requests.len()).into());
    };
    assert!(
        !cut.contains(LANDED_EVENT),
        "the cut request was sent before the interrupt landed"
    );
    let at_once = &asked_again[at(asked_again, "Reached you before your reply to step 0")?..];
    let interrupt = at(at_once, "interrupt: a message to your inbox classed urgent")?;
    let event = at(at_once, LANDED_EVENT)?;
    let instruction = at(at_once, "Emit the source for durable step 0")?;
    assert!(
        interrupt < event && event < instruction,
        "the request asked again reads the interrupt, as foreign data, before its turn \
         instruction: {at_once}"
    );
    assert!(
        at_once.contains("not instructions"),
        "the interrupt is foreign data: {at_once}"
    );
    assert_eq!(
        model.landing.state()?,
        RunSignalState::Settled,
        "the interrupt is acknowledged once its step committed"
    );
    Ok(())
}

/// agent-mind-design-v1 §8: "An aborted model call must still settle its
/// tokens and cost, or record them as unknown." The cut call goes through
/// the run admission's gate as a host's does. Its dispatch is receipted
/// unanswered, and its permit settles as dispatched with no usage, its
/// whole reservation kept as spend. The call asked again is admitted on a
/// permit of its own and answers.
#[test]
fn the_cut_request_settles_as_dispatched_with_unknown_usage() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let receipts = Arc::new(MemoryReceipts::default());
    let run = RunAdmission::new(
        "agent-interrupt-cut",
        RunDeclaration::declared(BudgetLine {
            limit_units: 10_000,
            reserve_units: CALL_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        None,
        receipts.clone(),
    );
    let offer = model_offer()?;
    let provider = Arc::new(HangingProvider {
        calls: AtomicUsize::new(0),
        first_dropped: Arc::new(AtomicBool::new(false)),
    });
    let model = AdmittedModel {
        landing: landing(&vault, &fixture, &wake, "urgent-9", "interrupt"),
        gated: run.gate(provider.clone(), &offer),
        run,
        offer,
        calls: AtomicUsize::new(0),
    };

    let outcome = run_wake(&vault, &wake, &leased, &model, 1)?;
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );
    assert!(
        provider.first_dropped.load(Ordering::SeqCst),
        "the provider's call in flight is dropped"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2, "asked again once");
    let rows = receipts.rows();
    let unanswered: Vec<&str> = rows
        .iter()
        .filter_map(|row| match &row.event {
            RunEvent::Dispatched {
                lease,
                answered: false,
                ..
            } => Some(lease.as_str()),
            _ => None,
        })
        .collect();
    let [cut] = unanswered.as_slice() else {
        return Err(format!("one dispatch receipted unanswered, got {rows:?}").into());
    };
    let settled: Vec<(bool, bool, u64)> = rows
        .iter()
        .filter_map(|row| match &row.event {
            RunEvent::Settled {
                lease,
                dispatched,
                usage,
                units,
                ..
            } if lease == cut => Some((*dispatched, usage.is_none(), *units)),
            _ => None,
        })
        .collect();
    assert_eq!(
        settled,
        vec![(true, true, CALL_RESERVE)],
        "the cut call settles once: dispatched, usage unknown, its reservation kept as spend: \
         {rows:?}"
    );
    assert!(
        rows.iter().any(|row| matches!(
            &row.event,
            RunEvent::Dispatched {
                lease,
                answered: true,
                ..
            } if lease != cut
        )),
        "the call asked again answers on a permit of its own: {rows:?}"
    );
    assert!(
        model.run.read().used_units >= CALL_RESERVE,
        "the run's line counts the cut call's reservation as used"
    );
    Ok(())
}

/// ARCH-0079: a steer is "taken at the next safe breakpoint". A steer that
/// lands while the step's model request is in flight cuts nothing: the
/// request answers, and the steer reaches the model at the step boundary,
/// in the next step's request.
#[test]
fn a_steer_in_flight_cuts_nothing_and_lands_at_the_step_boundary() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, wake, leased) = busy_resident(&clock, &dir)?;
    let model = ScriptedModel::new(
        landing(&vault, &fixture, &wake, "calm-9", "steer"),
        FirstReply::AfterOneYield,
    );

    let outcome = run_wake(&vault, &wake, &leased, &model, 2)?;
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 2 }
    );
    let requests = model.requests();
    let [first, second] = requests.as_slice() else {
        return Err(format!(
            "two model requests, one per step and none cut, got {}",
            requests.len()
        )
        .into());
    };
    assert!(!first.contains(LANDED_EVENT));
    assert!(
        !second.contains("Reached you before your reply"),
        "no turn reads it at once: {second}"
    );
    let delivered = &second[at(second, "Reached you while step 0")?..];
    assert!(
        delivered.contains(LANDED_EVENT) && !delivered.contains("interrupt:"),
        "the step boundary reads the steer as a message: {delivered}"
    );
    assert_eq!(model.landing.state()?, RunSignalState::Settled);
    Ok(())
}
