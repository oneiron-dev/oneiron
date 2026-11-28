//! CODE-MODE-LENDING-RUN-SPEND = A (FIX CODE-MODE-LENDING-W5, FIX
//! CODE-MODE-LENDING-W6): an MCP run is lent no reader seat and no window
//! compaction seat, and a Task run whose window outgrows its model's limit
//! ends with the refusal to start again, not a crash.
//!
//! - `a_resumed_task_run_past_its_window_ends_with_a_refusal_to_start_again`:
//!   a Task run over the MCP door whose scripted model backend answers its
//!   step with `LlmError::Fatal(ContextWindowExceeded)` ends with the -32020
//!   refusal of kind `code_run_window_outgrown` whose message says to start
//!   it again with execute; it is not -32603 `code_run_failed`. Red: the
//!   `WindowOutgrown` mapping in `run_engine_native_code_mode`
//!   (mcp/exec_host/native_run.rs), without which the entry crashes as
//!   `Run(..)`.
//! - `a_task_run_over_mcp_takes_no_compaction_seat`: a provider whose
//!   `compaction` factory counts its calls serves a Task entry with the
//!   count still 0. Red: the seat-taking block in `run_admitted`
//!   (mcp/exec_host/served.rs), which called the factory once per entry.
//! - `a_task_runs_spawn_over_mcp_is_denied_spawn_unbound`: a Task run on a
//!   host built `with_reader_seats(..)` whose program stores a result and
//!   spawns over it: the `can({child})` verdict answers reason
//!   `spawn_unbound` (the engine's preflight denial), and the spawn itself
//!   answers the typed unbound outcome. Red: the `reader_seat` pass-through
//!   in `run_admitted` (mcp/exec_host/served.rs), which lent the seat.
//!
//! Each test enters a Task run once through the kept task handler
//! (`execute_task_run_for_test`); no MCP tool starts a task run anymore.
//! Entered once, not entered-then-resumed: both entries share `run_admitted`
//! and the native mapping, so one entry proves the refusal.
//!
//! Run: `cargo test --locked -p oneiron-server --lib
//! api::tests::mcp_lending_run_spend`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::support_mcp::McpFixtureCodeRuntime;
use super::*;
use oneiron::agent_dispatch::SpendScopeId;
use oneiron::code_run::{
    CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism, CompactionHostBinding, SelfCall,
    SelfFixtureEffectCall, SelfReaderSpawnCall,
};
#[cfg(oneiron_test_support)]
use oneiron::engine_executor::BriefBoundary;
#[cfg(oneiron_test_support)]
use oneiron::engine_executor::BriefCandidateToken;
#[cfg(oneiron_test_support)]
use oneiron::engine_executor::BriefPrefix;
#[cfg(oneiron_test_support)]
use oneiron::engine_executor::BriefRecheck;
#[cfg(oneiron_test_support)]
use oneiron::engine_executor::SelfBriefPort;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep,
    JsCodeModeStepOutcome, JsCodeModeStream, JsResultCall, JsResultTarget, RunCompaction,
};
use oneiron::{
    BudgetLease, ContentPart, EntityId, FatalLlmError, FinishReason, LlmBackend, LlmError,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault,
};
use serde_json::Value;

use crate::mcp::{CodeRunLimits, McpCodeModeProvider, McpEngineNativeCodeHost};
#[cfg(oneiron_test_support)]
use oneiron::lens::{
    CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier,
    GeneratedUiCard, GeneratedUiRender, GeneratedUiStateSnapshot, LensAtom, LensAtomId, LensNode,
    LensRenderId, LensText, SegmentedControl, SelfUiAction, SelfUiActionId, SelfUiBindableProperty,
    SelfUiBinding, SelfUiControl, SelfUiControlId, SelfUiOption, SelfUiOptionValue, SelfUiStateKey,
    SelfUiStateValue,
};

/// What the scripted backend answers a step's model call with.
#[derive(Clone, Copy)]
enum Script {
    /// A plain step (the runtimes here ignore its text).
    Step(&'static str),
    /// The request outgrew the model's window.
    WindowExceeded,
}

/// A backend that answers every step's model call with `answer`, or the first
/// call with `answer` and every later call with `then` when scripted. It
/// counts every call in `calls`; the gated call signals `started` and waits
/// on `gate` before answering (T3 only).
struct LendingBackend {
    answer: Script,
    then: Option<Script>,
    calls: Arc<AtomicUsize>,
    started: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    gate: Option<Arc<tokio::sync::Notify>>,
    gate_on: usize,
}

impl LlmBackend for LendingBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let at = self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = if at == 0 {
            self.answer
        } else {
            self.then.unwrap_or(self.answer)
        };
        let started = self.started.clone();
        let gate = self.gate.clone();
        let gated = at == self.gate_on;
        Box::pin(async move {
            if gated {
                if let Some(started) = started {
                    let _ = started.send(());
                }
                if let Some(gate) = gate {
                    gate.notified().await;
                }
            }
            match answer {
                Script::Step(text) => Ok(LlmResponse {
                    message: LlmMessage {
                        role: LlmMessageRole::Assistant,
                        content: vec![ContentPart::Text {
                            text: text.to_owned(),
                            signature: None,
                        }],
                    },
                    usage: LlmUsage::zero(),
                    finish_reason: FinishReason::Stop,
                    reply_assertions: Default::default(),
                    token_scores: None,
                }),
                Script::WindowExceeded => {
                    Err(LlmError::Fatal(FatalLlmError::ContextWindowExceeded {
                        message: "this model's context window is exceeded".to_owned(),
                    }))
                }
            }
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        unimplemented!("the lending fixture never streams")
    }
}

/// What the spawn probe's step saw.
#[derive(Default)]
struct SpawnProbe {
    /// The `can({child})` verdict's reason.
    can_reason: Option<String>,
    /// The `self.spawn` outcome, debug-rendered.
    spawn_outcome: Option<String>,
}

/// A runtime whose program stores a result of its own, asks whether a reader
/// child could spawn over it, spawns over it, and parks: the probe records
/// the verdict and the spawn's answer.
struct SpawnProbeRuntime {
    witness: Arc<Mutex<SpawnProbe>>,
}

impl JsCodeModeRuntime for SpawnProbeRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        host.write_output(
            JsCodeModeStream::Store { start: true },
            b"{\"text\":\"launch plan\"}",
        )
        .expect("the store stream takes the probe body");
        let stored = host
            .result_call(JsResultCall::Store {
                name: Some("src".to_owned()),
                sources: Vec::new(),
                receipt: None,
            })
            .expect("the probe body stores");
        assert!(
            stored.get("output").is_some(),
            "storing names the result: {stored}"
        );
        let can = host
            .result_call(JsResultCall::CanRead {
                target: JsResultTarget::parse("src"),
                child: true,
            })
            .expect("the can-read answers");
        let spawned = host
            .dispatch_self(SelfCall::ReaderSpawn(Box::new(SelfReaderSpawnCall {
                source: "src".to_owned(),
                ask: "summarize it".to_owned(),
                intent_key: "spawn-probe-1".to_owned(),
                bound: None,
                powers: None,
            })))
            .expect("the spawn answers");
        {
            let mut probe = self.witness.lock().unwrap();
            probe.can_reason = can
                .pointer("/output/reason")
                .and_then(Value::as_str)
                .map(str::to_owned);
            probe.spawn_outcome = Some(format!("{:?}", spawned.outcome));
        }
        // Park the run, as the fixture runtime does, so the entry ends waiting.
        host.dispatch_self(SelfCall::OutboundFixture(SelfFixtureEffectCall::new(
            "spawn probe parks",
        )))?;
        Ok(JsCodeModeStepOutcome::pending("spawn probe parked"))
    }
}

/// A runtime that runs one successful step without parking: with
/// `soft_steps = 1` the entry yields after it, so a later resume runs the
/// next model turn.
struct YieldingRuntime;

impl JsCodeModeRuntime for YieldingRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        host.dispatch_self(SelfCall::MemorySearch(
            oneiron::code_run::SelfMemorySearchCall::new("launch plan", 3),
        ))?;
        Ok(JsCodeModeStepOutcome::pending("yielding step"))
    }
}

/// A provider over the scripted backend: production-ready so the gateway
/// binds it, its `compaction` factory counted, and the spawn probe's runtime
/// where a witness waits for it.
struct LendingProvider {
    backend: LendingBackend,
    lease: BudgetLease,
    compactions: Arc<AtomicUsize>,
    witness: Option<Arc<Mutex<SpawnProbe>>>,
    soft_steps: u32,
    yielding: bool,
}

impl McpCodeModeProvider for LendingProvider {
    fn production_runtime_available(&self) -> bool {
        true
    }

    fn backend(&self) -> &dyn LlmBackend {
        &self.backend
    }

    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        match &self.witness {
            Some(witness) => Box::new(SpawnProbeRuntime {
                witness: Arc::clone(witness),
            }),
            None if self.yielding => Box::new(YieldingRuntime),
            None => Box::new(McpFixtureCodeRuntime),
        }
    }

    fn executor_config(
        &self,
        _: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        Ok(EngineExecutorConfig {
            run_id,
            task: task.to_owned(),
            caller_source_digest: None,
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
                .expect("workspace test prompt package"),
            model: ModelId::new("fixture/lending@v1").expect("fixture model id"),
            model_locality: ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: ModelTierRef("fixture-tier".to_owned()),
            determinism: CodeRunDeterminism::new(1_000, [7; CODE_RUN_RNG_SEED_LEN]),
            limits: EngineExecutorLimits {
                soft_steps: self.soft_steps,
            },
            wake: None,
        })
    }

    fn compaction(
        &self,
        _host: CompactionHostBinding,
        _credential: &str,
        _spend: Option<&SpendScopeId>,
    ) -> Option<RunCompaction> {
        self.compactions.fetch_add(1, Ordering::SeqCst);
        None
    }
}

/// A server whose code host runs `provider`, lending reader seats where
/// `seats` holds, with `credential` registered for a human actor that reads.
async fn lending_server(
    provider: LendingProvider,
    seats: bool,
    credential: &str,
) -> (tempfile::TempDir, Arc<crate::server::SyncServer>) {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
    );
    crate::test_credentials::install_fixture_keystore(&vault, b"");
    let mut server = crate::server::SyncServer::new(
        Arc::clone(&vault),
        crate::config::SyncServerConfig {
            allow_unauthenticated: true,
            ..Default::default()
        },
    )
    .expect("sync server");
    let host =
        McpEngineNativeCodeHost::new(Arc::new(provider), CodeRunLimits::default(), Arc::default());
    let host = if seats {
        host.with_reader_seats(server.reader_runner.seats())
    } else {
        host
    };
    let host: Arc<dyn crate::mcp::McpCodeExecutionHost> = Arc::new(host);
    server.mcp_code_host = Some(host);
    let server = Arc::new(server);
    let actor_id = EntityId::now();
    register_mcp_actor(
        &server,
        credential,
        actor_id,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    put_actor_read_grant(&vault, actor_id, None);
    (dir, server)
}

fn lending_provider(answer: Script) -> (LendingProvider, Arc<AtomicUsize>) {
    let compactions = Arc::new(AtomicUsize::new(0));
    (
        LendingProvider {
            backend: LendingBackend {
                answer,
                then: None,
                calls: Arc::new(AtomicUsize::new(0)),
                started: None,
                gate: None,
                gate_on: usize::MAX,
            },
            lease: BudgetLease::for_test("mcp-lending-run-spend"),
            compactions: Arc::clone(&compactions),
            witness: None,
            soft_steps: EngineExecutorLimits::default().soft_steps,
            yielding: false,
        },
        compactions,
    )
}

/// A Task run over the MCP door whose window outgrew its model's limit ends
/// with the -32020 refusal to start again, not a crash.
#[tokio::test]
async fn a_resumed_task_run_past_its_window_ends_with_a_refusal_to_start_again() {
    let (provider, _) = lending_provider(Script::WindowExceeded);
    let (_dir, server) = lending_server(provider, false, "lending-window").await;
    let body = execute_task_run_for_test(
        &server,
        "lending-window",
        "lending-window-1",
        "summarize it",
    )
    .await;
    assert_eq!(body["error"]["code"].as_i64(), Some(-32020), "{body}");
    assert_ne!(body["error"]["code"].as_i64(), Some(-32603), "{body}");
    assert_eq!(
        body["error"]["data"]["error_code"], "code_run_window_outgrown",
        "{body}"
    );
    let message = body["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("start it again with execute"),
        "the refusal names the way on: {message}"
    );
}

#[cfg(oneiron_test_support)]
#[derive(Default)]
struct RecordingBrief {
    installs: AtomicUsize,
    closes: AtomicUsize,
}

#[cfg(oneiron_test_support)]
impl SelfBriefPort for RecordingBrief {
    fn prepare(&self, _boundary: BriefBoundary) -> oneiron::Result<Option<BriefPrefix>> {
        Ok(None)
    }

    fn recheck(&self, _held: &BriefPrefix) -> oneiron::Result<BriefRecheck> {
        Ok(BriefRecheck::Holds)
    }

    fn delivered(&self, _token: BriefCandidateToken) {}
}

#[cfg(oneiron_test_support)]
impl crate::mcp::McpCodeRunSelfBrief for RecordingBrief {
    fn install(&self) -> bool {
        self.installs.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn close(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}

/// Calls the host directly so that gateway cleanup cannot satisfy the close assertion.
/// The gateway's real verb door is exposed to tests by `oneiron_test_support`.
#[cfg(oneiron_test_support)]
#[tokio::test]
async fn a_task_run_past_its_window_closes_its_self_brief() {
    use crate::api::McpCodeModeVerbs;
    use crate::mcp::McpCodeExecutionError;
    use crate::mcp::McpCodeExecutionRequest;
    use crate::mcp::McpCodeRunInput;
    use crate::mcp::McpCodeRunSelfBrief;
    use crate::mcp::mcp_code_run_id;

    let credential = "lending-window-brief";
    let run_ref = "lending-window-brief-1";
    let (provider, _) = lending_provider(Script::WindowExceeded);
    let (_dir, server) = lending_server(provider, false, credential).await;
    let actor = mcp_test_context(&server, credential, run_ref).await;
    let run_id = mcp_code_run_id(run_ref, &actor);
    let verbs: Arc<dyn oneiron::code_run::AgentVerbDoor> =
        Arc::new(McpCodeModeVerbs::new(&server, &actor, run_id));
    let brief = Arc::new(RecordingBrief::default());

    let outcome = server
        .code_execution_host()
        .expect("the lending code host is bound")
        .execute(McpCodeExecutionRequest {
            vault: Arc::clone(&server.vault),
            actor: &actor,
            off_record_session: actor.off_record_session.clone(),
            run_ref,
            input: McpCodeRunInput::Task("summarize it"),
            run_id,
            verbs,
            consent_origin: None,
            brief: Some(Arc::clone(&brief) as Arc<dyn McpCodeRunSelfBrief>),
            run_end: None,
        })
        .await;

    assert!(
        matches!(&outcome, Err(McpCodeExecutionError::WindowOutgrown)),
        "expected WindowOutgrown, got {outcome:?}"
    );
    assert_eq!(brief.installs.load(Ordering::SeqCst), 1);
    assert_eq!(
        brief.closes.load(Ordering::SeqCst),
        1,
        "a run that ended with its window outgrown closes its brief"
    );
}

/// A Task run over the MCP door takes no compaction seat: its entry never
/// calls the provider's `compaction` factory.
#[tokio::test]
async fn a_task_run_over_mcp_takes_no_compaction_seat() {
    let (provider, compactions) = lending_provider(Script::Step(
        "const found = await self.memory.search(\"launch plan\");",
    ));
    let (_dir, server) = lending_server(provider, false, "lending-compaction").await;
    let body = execute_task_run_for_test(
        &server,
        "lending-compaction",
        "lending-compaction-1",
        "summarize it",
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(
        compactions.load(Ordering::SeqCst),
        0,
        "no entry takes a compaction seat"
    );
}

/// A Task run's spawn over MCP, on a host that lends reader seats, is denied
/// `spawn_unbound`: the run is lent no seat, so the `can({child})` verdict
/// answers that reason and the spawn answers the typed unbound outcome.
#[tokio::test]
async fn a_task_runs_spawn_over_mcp_is_denied_spawn_unbound() {
    let witness = Arc::new(Mutex::new(SpawnProbe::default()));
    let (mut provider, _) = lending_provider(Script::Step("await self.spawn(\"src\");"));
    provider.witness = Some(Arc::clone(&witness));
    let (_dir, server) = lending_server(provider, true, "lending-spawn").await;
    execute_task_run_for_test(&server, "lending-spawn", "lending-spawn-1", "summarize it").await;
    let probe = witness.lock().unwrap();
    assert_eq!(probe.can_reason.as_deref(), Some("spawn_unbound"));
    let outcome = probe.spawn_outcome.as_deref().expect("the spawn answered");
    assert!(
        outcome.contains("reader_spawn_unbound"),
        "the spawn answers the typed unbound outcome: {outcome}"
    );
}

/// A Task run past its window replays its refusal without calling the model
/// again: the first entry's -32020 refusal is the existing one, and the real
/// resume answers the same `code_run_window_outgrown` tool error with the
/// backend's call count still 1.
#[cfg(oneiron_test_support)]
#[tokio::test]
async fn a_task_run_past_its_window_replays_without_calling_the_model_again() {
    let credential = "lending-window-replay";
    let run_ref = "lending-window-replay-1";
    let (provider, _) = lending_provider(Script::WindowExceeded);
    let calls = Arc::clone(&provider.backend.calls);
    let (_dir, server) = lending_server(provider, false, credential).await;
    let body = execute_task_run_for_test(&server, credential, run_ref, "summarize it").await;
    assert_eq!(body["error"]["code"].as_i64(), Some(-32020), "{body}");
    assert_eq!(
        body["error"]["data"]["error_code"], "code_run_window_outgrown",
        "{body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the first entry called the model once: {body}"
    );
    let actor = mcp_test_context(&server, credential, "lending-window-replay-resume").await;
    let args = crate::mcp::McpResumeToolArgs {
        run_ref: run_ref.to_owned(),
        answer: None,
    };
    let reply = crate::api::mcp_gateway::execute_mcp_resume(&server, &actor, &args)
        .await
        .expect("the resume renders");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the resume replays the refusal without calling the model again: {reply}"
    );
    assert_eq!(reply["isError"].as_bool(), Some(true), "{reply}");
    assert_eq!(
        reply["structuredContent"]["error"]["code"], "code_run_window_outgrown",
        "{reply}"
    );
}

/// A resumed Task run past its window seals its run scratchpad: one
/// successful step first (`soft_steps = 1`), a run-bound pad line planted
/// while the run is yielded and unsealed, then the real resume meets the
/// window error and the pad is sealed, checked before any later entry.
#[cfg(oneiron_test_support)]
#[tokio::test]
async fn a_resumed_task_run_past_its_window_seals_its_run_scratchpad() {
    let credential = "lending-window-seal";
    let run_ref = "lending-window-seal-1";
    let (mut provider, _) = lending_provider(Script::Step("const found = 1;"));
    provider.backend.then = Some(Script::WindowExceeded);
    provider.soft_steps = 1;
    provider.yielding = true;
    let (_dir, server) = lending_server(provider, false, credential).await;
    let body = execute_task_run_for_test(&server, credential, run_ref, "summarize it").await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(
        body["result"]["structuredContent"]["result"]["status"], "yielded",
        "{body}"
    );
    let actor = mcp_test_context(&server, credential, run_ref).await;
    let run_id = crate::mcp::mcp_code_run_id(run_ref, &actor);
    let agent = EntityId::now();
    server
        .vault
        .put_entity(
            &agent,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .expect("agent PERSON");
    let pad = oneiron::test_doors::scratchpad_wake::run_bound_memory(&server.vault, agent, run_id)
        .expect("run-bound memory")
        .scratchpad_append("t2-label", "the run's first line", None, false)
        .expect("the line lands")
        .pad;
    assert!(
        !server.vault.scratchpad_sealed(pad).expect("seal read"),
        "a yielded run's pad is live"
    );
    let resume_actor = mcp_test_context(&server, credential, "lending-window-seal-resume").await;
    let args = crate::mcp::McpResumeToolArgs {
        run_ref: run_ref.to_owned(),
        answer: None,
    };
    let reply = crate::api::mcp_gateway::execute_mcp_resume(&server, &resume_actor, &args)
        .await
        .expect("the resume renders");
    assert_eq!(reply["isError"].as_bool(), Some(true), "{reply}");
    assert_eq!(
        reply["structuredContent"]["error"]["code"], "code_run_window_outgrown",
        "{reply}"
    );
    assert!(
        server.vault.scratchpad_sealed(pad).expect("seal read"),
        "an outgrown run's terminal write seals its pad"
    );
}

#[cfg(oneiron_test_support)]
fn lending_text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

#[cfg(oneiron_test_support)]
fn lending_walk_state(pace: &str, note: &str) -> GeneratedUiStateSnapshot {
    [
        (
            SelfUiStateKey::new("pace").expect("state key"),
            SelfUiStateValue::Token(SelfUiOptionValue::new(pace).expect("option value")),
        ),
        (
            SelfUiStateKey::new("note").expect("state key"),
            SelfUiStateValue::Text(lending_text(note)),
        ),
    ]
    .into_iter()
    .collect()
}

#[cfg(oneiron_test_support)]
fn lending_pace_action() -> SelfUiAction {
    SelfUiAction {
        command: SelfUiActionId::new("pace.set").expect("action id"),
        args: Vec::new(),
    }
}

/// The walk-planner card `card_id`, copied from
/// `crates/oneiron-server/tests/lens_frame_state_door.rs` for T3: a segmented
/// control offering `paces`, its selection bound to the `pace` key, and a
/// `note`; it starts at the first pace with no note.
#[cfg(oneiron_test_support)]
fn lending_planner(card_id: &str, paces: &[&str]) -> GeneratedUiRender {
    let mut pace = LensNode::with_fallback_text(
        LensAtomId::new("pace").expect("atom id"),
        LensAtom::SelfUi(SelfUiControl::Segmented(SegmentedControl {
            id: SelfUiControlId::new("pace").expect("control id"),
            label: lending_text("Pace"),
            options: paces
                .iter()
                .map(|value| SelfUiOption {
                    value: SelfUiOptionValue::new(*value).expect("option value"),
                    label: lending_text(value),
                })
                .collect(),
            selected: None,
            action: lending_pace_action(),
        })),
        lending_text("Pace"),
    );
    pace.state_bindings = vec![SelfUiBinding {
        state_key: SelfUiStateKey::new("pace").expect("state key"),
        property: SelfUiBindableProperty::Selected,
    }];
    let mut root = LensNode::with_fallback_text(
        LensAtomId::new("root").expect("atom id"),
        LensAtom::Sheet(CollectionAtom {
            title: lending_text("Walk"),
            rows: Vec::new(),
        }),
        lending_text("Walk"),
    );
    root.children = vec![pace];
    GeneratedUiCard::interactive(
        LensRenderId::new(card_id).expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        vec![GeneratedUiActionDeclaration {
            element_id: LensAtomId::new("pace").expect("atom id"),
            action_id: SelfUiActionId::new("pace.set").expect("action id"),
            tier: GeneratedUiActionTier::Local,
            action: lending_pace_action(),
        }],
        lending_walk_state(paces[0], "none yet"),
    )
    .expect("a planner card")
    .render()
    .expect("render")
}

/// A dropped Task resume still closes its outgrown run's lens card: the run
/// yields after one step, a card is planted for its id and held, then the
/// real resume is dropped once its model call starts and its gate opens so
/// the worker answers the window error. A direct host call under the same run
/// id with another Task awaits `RunRefReused` behind the same single flight,
/// proving the worker finished; then the card is gone.
#[cfg(oneiron_test_support)]
#[tokio::test]
async fn a_dropped_task_resume_still_closes_its_outgrown_runs_lens_card() {
    use crate::api::McpCodeModeVerbs;
    use crate::mcp::McpCodeExecutionError;
    use crate::mcp::McpCodeExecutionRequest;
    use crate::mcp::McpCodeRunInput;

    let credential = "lending-window-drop";
    let run_ref = "lending-window-drop-1";
    let (mut provider, _) = lending_provider(Script::Step("const found = 1;"));
    provider.backend.then = Some(Script::WindowExceeded);
    provider.soft_steps = 1;
    provider.yielding = true;
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let gate = Arc::new(tokio::sync::Notify::new());
    provider.backend.started = Some(started_tx);
    provider.backend.gate = Some(Arc::clone(&gate));
    provider.backend.gate_on = 1;
    let (_dir, server) = lending_server(provider, false, credential).await;
    let body = execute_task_run_for_test(&server, credential, run_ref, "summarize it").await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(
        body["result"]["structuredContent"]["result"]["status"], "yielded",
        "{body}"
    );
    let actor = mcp_test_context(&server, credential, run_ref).await;
    let run_id = crate::mcp::mcp_code_run_id(run_ref, &actor);
    let card_id = LensRenderId::new("t3-card").expect("card id");
    crate::test_doors::lens_frames::replace_run_card(
        &server,
        run_id,
        "t3",
        lending_planner("t3-card", &["easy", "brisk"]),
    )
    .await
    .expect("the card plants");
    assert!(
        server.lens_frames.card(&card_id).is_some(),
        "the server holds the card before the resume"
    );
    let resume_actor = mcp_test_context(&server, credential, "lending-window-drop-resume").await;
    let args = crate::mcp::McpResumeToolArgs {
        run_ref: run_ref.to_owned(),
        answer: None,
    };
    let mut resume = Box::pin(crate::api::mcp_gateway::execute_mcp_resume(
        &server,
        &resume_actor,
        &args,
    ));
    tokio::select! {
        result = &mut resume => panic!("the gated resume finished before its gate opened: {result:?}"),
        started = started_rx.recv() => {
            assert!(started.is_some(), "the worker reached its model call");
        }
    }
    drop(resume);
    gate.notify_one();
    let verbs: Arc<dyn oneiron::code_run::AgentVerbDoor> =
        Arc::new(McpCodeModeVerbs::new(&server, &actor, run_id));
    let outcome = server
        .code_execution_host()
        .expect("the lending code host is bound")
        .execute(McpCodeExecutionRequest {
            vault: Arc::clone(&server.vault),
            actor: &actor,
            off_record_session: actor.off_record_session.clone(),
            run_ref,
            input: McpCodeRunInput::Task("a different task"),
            run_id,
            verbs,
            consent_origin: None,
            brief: None,
            run_end: None,
        })
        .await;
    assert!(
        matches!(&outcome, Err(McpCodeExecutionError::RunRefReused)),
        "expected RunRefReused, got {outcome:?}"
    );
    assert!(
        server.lens_frames.card(&card_id).is_none(),
        "the worker closed the outgrown run's card"
    );
}
