//! OPUS-E2E-1: a code run whose actor may not witness a companion MESSAGE
//! completes anyway, and `execute_code` returns its `finish()` answer from
//! the run's own replay record. No MESSAGE lands.
//!
//! Each test drives a real QuickJS guest through the shipped executor
//! (`EngineNativeExecutor`) with a scripted model backend answering the one
//! program. No real model, no sleeps, no ports. The tier door below mirrors
//! the MCP door's scope checks without the MCP server: reads admit for
//! every tier, the run's own conversation is the run's record (Reads), and
//! anything else that commits needs full access. Recall executes for real
//! through the shipped `vault.recall` entry (`recall_unembedded`).
//!
//! Guest reply semantics: a typed host refusal rejects the awaited promise
//! with a JSON string containing `{denied, reasonCodes}`. The write program
//! catches and decodes that refusal; any other error fails the run.
//!
//! Red on main: a restricted run executes its program, then its trailing
//! witness fails with `gate.pending.actor_ceiling`, so the run fails and
//! these tests fail. Green with the fix: the run completes, its answer reads
//! back from its replay record, and nothing lands. The full-access control
//! passes both before and after.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --features oneiron-agent-runtime/code-sandbox-wasmtime --test code_run_restricted_actor_answer`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunDeterminism, GatedActorWrite, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfEffect,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult,
    EngineExecutorStatus, EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::memory::RecallRequest;
use oneiron::memory::caps::{check_as_of, check_deadline_ms, check_limit_nonzero};
use oneiron::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, recall_unembedded};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::code_run_answer as doors;
use oneiron::verb_names::VAULT_RECALL_LIMIT_DEFAULT;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, Error, FatalLlmError, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig,
    WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use sha2::{Digest, Sha256};

/// ARCH-0028's registration-time tiers, as the test's door enforces them.
/// The engine ceiling is binary: read-only and propose-only both carry
/// `proposed` (`authority::AgentTier::ceiling`); what differs between them
/// is the credential scope the door mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    ReadOnly,
    ProposeOnly,
    FullAccess,
}

impl Tier {
    const fn ceiling(self) -> &'static str {
        match self {
            Self::ReadOnly | Self::ProposeOnly => "proposed",
            Self::FullAccess => "auto",
        }
    }
}

/// The test's `AgentVerbDoor`: the MCP door's scope checks without the MCP
/// server. Reads admit for every tier; the run's own conversation is the
/// run's record (Reads); anything else that commits needs full access.
/// Recall executes for real through the shipped `vault.recall` entry.
struct TierDoor {
    vault: Arc<Vault>,
    actor: EntityId,
    tier: Tier,
}

impl TierDoor {
    fn refused(code: &str) -> AgentVerbRefusal {
        AgentVerbRefusal {
            code: code.to_owned(),
            hook_notice: None,
        }
    }
}

impl AgentVerbDoor for TierDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        // Only the recall row is bound: these programs call nothing else
        // through the verb door.
        if call.verb != AgentVerb::VaultRecall {
            return Ok(Err(Self::refused("mcp_verb_not_bound")));
        }
        // Recall is Reads, which every tier holds.
        let request: RecallRequest = serde_json::from_value(call.input.clone())
            .map_err(|error| Error::InvalidConfig(format!("tier door recall input: {error}")))?;
        // The row's own admission, as vault.recall.json spells it.
        check_limit_nonzero(request.limit.unwrap_or(VAULT_RECALL_LIMIT_DEFAULT))
            .map_err(|error| Error::InvalidConfig(format!("tier door recall: {}", error.message)))?;
        check_as_of(request.as_of)
            .map_err(|error| Error::InvalidConfig(format!("tier door recall: {}", error.message)))?;
        check_deadline_ms(request.deadline_ms)
            .map_err(|error| Error::InvalidConfig(format!("tier door recall: {}", error.message)))?;
        let memory = self.vault.memory(self.actor, EdgeActorClass::Agent);
        let pack = recall_unembedded(&memory, request).map_err(|error| {
            Error::InvalidConfig(format!("tier door recall: {}: {}", error.code, error.message))
        })?;
        let output = serde_json::to_value(pack)
            .map_err(|error| Error::InvalidConfig(format!("tier door recall pack: {error}")))?;
        Ok(Ok(AgentVerbAnswer::new(output, None)))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        match call {
            // Reads admit for every tier; the run reads as its own actor.
            RunCall::RecordedOutput | RunCall::Bridge(SelfEffect::MemorySearch) => Ok(None),
            // Every other bridge row commits, so it needs full access. At
            // the MCP gate no bridge call proposes: `of_run_call` answers
            // Reads or Commits only.
            RunCall::Bridge(_) if self.tier == Tier::FullAccess => Ok(None),
            RunCall::Bridge(_) => Err(Self::refused("mcp_auth_required")),
        }
    }

    fn admit_run_speech(
        &self,
        _effect: SelfEffect,
        destination: RunSpeechDestination,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        match destination {
            // The run's own derived conversation is the run's record: Reads.
            RunSpeechDestination::OwnRunConversation => Ok(None),
            RunSpeechDestination::SessionRoom if self.tier == Tier::FullAccess => Ok(None),
            RunSpeechDestination::SessionRoom => Err(Self::refused("mcp_auth_required")),
        }
    }
}

/// The scripted model: each turn answers with the next program. Counts every
/// call, so a re-entry proves it asked the model nothing.
struct FixtureBackend {
    programs: Mutex<VecDeque<String>>,
    calls: AtomicUsize,
}

impl FixtureBackend {
    fn new(programs: Vec<String>) -> Self {
        Self {
            programs: Mutex::new(programs.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for FixtureBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let program = self
            .programs
            .lock()
            .expect("fixture programs")
            .pop_front()
            .expect("the model was asked with no scripted reply left");
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: program,
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

/// The pinned first-party QuickJS component.
fn quickjs_factory() -> QuickJsRuntimeFactory {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm"))
        .expect("the pinned QuickJS component");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())
        .expect("the QuickJS component passes its readiness probe")
}

fn executor_config(run_id: EntityId) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: "recall the project note".to_owned(),
        prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
            .expect("the workspace test prompt package"),
        model: ModelId::new("test/executor@v1").expect("a model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
        limits: EngineExecutorLimits::default(),
        wake: None,
    }
}

/// One entry of one durable run: a fresh backend holding `programs`, the
/// tier's door, and a fresh guest. Answers the outcome with how many times
/// the entry asked the model.
fn execute_run(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    tier: Tier,
    actor: EntityId,
    run_id: EntityId,
    run_ref: &str,
    programs: Vec<String>,
) -> (EngineExecutorResult<EngineExecutorOutcome>, usize) {
    let backend = FixtureBackend::new(programs);
    let lease = BudgetLease::for_test("code-run-answer");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        run_ref,
    )
    .expect("a dispatcher binds")
    .with_agent_verb_door(Arc::new(TierDoor {
        vault: Arc::clone(vault),
        actor,
        tier,
    }));
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(run_id);
    let outcome = block_on_ready(executor.run(&config));
    (outcome, backend.calls())
}

/// The read program: one real recall, then its answer. A denied recall
/// throws, so only a genuinely served recall reaches `finish`.
const RECALL_PROGRAM: &str = r#"await vault.recall({query: "project note", limit: 5});
finish("recalled");"#;

/// The write program catches the typed Denied as the bridge's thrown JSON
/// string, then finishes with its code. A successful write or any other
/// error cannot produce the expected answer.
fn write_program(claim: &EntityId, subject: &EntityId) -> String {
    format!(
        r#"try {{
  await vault.claims.put({{id: "{id}", predicate: "profile.favorite_drink", subject: "{subject}", value: "sencha"}});
  finish("write-unexpectedly-allowed");
}} catch (error) {{
  const refusal = JSON.parse(String(error));
  if (typeof refusal.denied !== "string") throw error;
  finish("denied-caught:" + refusal.denied);
}}"#,
        id = claim.to_hex(),
        subject = subject.to_hex(),
    )
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault =
        Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("a vault opens"));
    (dir, vault)
}

/// A fresh entity id.
///
/// UUIDv7 rather than a fixed byte pattern: an open vault already holds its
/// seeded system agents at `[0xA1; 16]` through `[0xA6; 16]`, and a PERSON
/// put at one of those ids is refused with `EntityTypeImmutable`.
fn fresh_id() -> EntityId {
    EntityId::from_bytes(uuid::Uuid::now_v7().into_bytes()).expect("a test id")
}

fn seed_person(vault: &Vault) -> EntityId {
    let id = fresh_id();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("a person lands");
    id
}

/// (conversations, turns, messages) on the vault, through the public reads.
fn transcript_counts(vault: &Vault) -> (usize, usize, usize) {
    let count = |entity_type| {
        vault
            .entities_by_type(entity_type)
            .expect("typed entities")
            .len()
    };
    (
        count(ENTITY_TYPE_CONVERSATION),
        count(ENTITY_TYPE_TURN),
        count(ENTITY_TYPE_MESSAGE),
    )
}

/// The completed entry returns its answer in the replay result. These
/// short fixture answers fit whole in the observation preview; the separate
/// `finish_text` read below verifies the committed full bytes as well.
fn assert_returned_answer(outcome: &EngineExecutorOutcome, expected: &str) {
    let answer = outcome
        .replay_record
        .outputs
        .iter()
        .find(|output| output.path.ends_with(".observation.txt"))
        .expect("the returned replay result holds the answer");
    assert_eq!(answer.preview.text, expected);
}

/// The (kind, outcome) of a bridge row's recorded outcome.
fn recorded_outcome(outcome: &rmpv::Value) -> (Option<&str>, Option<&str>) {
    let rmpv::Value::Map(entries) = outcome else {
        return (None, None);
    };
    let field = |name: &str| {
        entries.iter().find_map(|(key, value)| {
            if key.as_str() == Some(name) {
                value.as_str()
            } else {
                None
            }
        })
    };
    (field("kind"), field("outcome"))
}

/// A read-only agent's run that only recalls and finishes: it completes,
/// its answer reads back from its replay record, and no companion MESSAGE
/// for the run lands. Red on main: the trailing witness fails with
/// `gate.pending.actor_ceiling`.
#[test]
fn read_only_recall_run_returns_its_answer_and_witnesses_no_message() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    doors::install_actor_ceiling(&vault, &actor, Tier::ReadOnly.ceiling())
        .expect("a proposed ceiling");
    let run_id = fresh_id();
    let before = transcript_counts(&vault);

    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        Tier::ReadOnly,
        actor,
        run_id,
        "run-read-only-recall",
        vec![RECALL_PROGRAM.to_owned()],
    );
    let outcome = outcome.expect("a read-only recall run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_returned_answer(&outcome, "recalled");
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    assert_eq!(
        outcome.replay_record.bridge_calls[0].effect,
        SelfEffect::AgentVerb
    );
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        "recalled"
    );
    assert_eq!(
        transcript_counts(&vault),
        before,
        "no companion MESSAGE lands"
    );

    // A re-entry replays the committed terminal record: it completes
    // without asking the model and witnesses nothing later.
    let (retry, retry_calls) = execute_run(
        &vault,
        &factory,
        Tier::ReadOnly,
        actor,
        run_id,
        "run-read-only-recall",
        Vec::new(),
    );
    let retry = retry.expect("the committed run re-enters");
    assert_eq!(retry_calls, 0, "re-entry asks the model nothing");
    assert_eq!(retry.status, EngineExecutorStatus::Complete);
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer still reads back"),
        "recalled"
    );
    assert_eq!(
        transcript_counts(&vault),
        before,
        "the retry witnesses nothing later"
    );
}

/// A propose-only agent's run that only recalls and finishes: it completes,
/// its answer reads back from its replay record, and no companion MESSAGE
/// for the run lands. Red on main for the same ceiling reason.
#[test]
fn propose_only_recall_run_returns_its_answer_and_witnesses_no_message() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    doors::install_actor_ceiling(&vault, &actor, Tier::ProposeOnly.ceiling())
        .expect("a proposed ceiling");
    let run_id = fresh_id();
    let before = transcript_counts(&vault);

    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        Tier::ProposeOnly,
        actor,
        run_id,
        "run-propose-only-recall",
        vec![RECALL_PROGRAM.to_owned()],
    );
    let outcome = outcome.expect("a propose-only recall run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_returned_answer(&outcome, "recalled");
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        "recalled"
    );
    assert_eq!(
        transcript_counts(&vault),
        before,
        "no companion MESSAGE lands"
    );

    let (retry, retry_calls) = execute_run(
        &vault,
        &factory,
        Tier::ProposeOnly,
        actor,
        run_id,
        "run-propose-only-recall",
        Vec::new(),
    );
    let retry = retry.expect("the committed run re-enters");
    assert_eq!(retry_calls, 0, "re-entry asks the model nothing");
    assert_eq!(retry.status, EngineExecutorStatus::Complete);
    assert_eq!(
        transcript_counts(&vault),
        before,
        "the retry witnesses nothing later"
    );
}

/// Control: a full-access agent's run returns its answer AND its companion
/// MESSAGE lands, with its turn and conversation. Green on main and with
/// the fix.
#[test]
fn full_access_recall_run_returns_its_answer_and_witnesses_its_message() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    doors::install_actor_ceiling(&vault, &actor, Tier::FullAccess.ceiling())
        .expect("an auto ceiling");
    let run_id = fresh_id();
    let before = transcript_counts(&vault);

    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        Tier::FullAccess,
        actor,
        run_id,
        "run-full-access-recall",
        vec![RECALL_PROGRAM.to_owned()],
    );
    let outcome = outcome.expect("a full-access recall run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_returned_answer(&outcome, "recalled");
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        "recalled"
    );
    let landed = transcript_counts(&vault);
    assert_eq!(
        (
            landed.0 - before.0,
            landed.1 - before.1,
            landed.2 - before.2
        ),
        (1, 1, 1),
        "the companion MESSAGE lands with its turn and conversation"
    );
    let messages = vault
        .entities_by_type(ENTITY_TYPE_MESSAGE)
        .expect("the MESSAGE census reads back");
    assert_eq!(messages.len(), 1, "the fresh vault holds only this answer");
    let raw = vault
        .get_raw(&messages[0])
        .expect("the companion MESSAGE reads back")
        .expect("the companion MESSAGE is present");
    let body = rmpv::decode::read_value(&mut &raw[ENTITY_METADATA_HEADER_LEN..])
        .expect("the companion MESSAGE body decodes");
    let fields = body.as_map().expect("the MESSAGE body is a map");
    let field = |name: &str| {
        fields.iter().find_map(|(key, value)| {
            (key.as_str() == Some(name)).then_some(value)
        })
    };
    assert_eq!(field("author").and_then(rmpv::Value::as_str), Some("companion"));
    assert_eq!(field("type").and_then(rmpv::Value::as_str), Some("executor.speak"));
    assert_eq!(field("content").and_then(rmpv::Value::as_str), Some("recalled"));
    assert_eq!(field("is_visible").and_then(rmpv::Value::as_bool), Some(true));

    let (retry, retry_calls) = execute_run(
        &vault,
        &factory,
        Tier::FullAccess,
        actor,
        run_id,
        "run-full-access-recall",
        Vec::new(),
    );
    let retry = retry.expect("the committed run re-enters");
    assert_eq!(retry_calls, 0, "re-entry asks the model nothing");
    assert_eq!(retry.status, EngineExecutorStatus::Complete);
    assert_eq!(
        transcript_counts(&vault),
        landed,
        "the retry mints no second bubble"
    );
}

/// A read-only agent's run that tries an explicit claim write: the write is
/// refused as a typed Denied the program catches, the run finishes and
/// completes, and nothing lands. Red on main for the same ceiling reason
/// (the trailing witness), green with the fix.
#[test]
fn read_only_write_run_catches_its_denied_and_witnesses_no_message() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    let subject = seed_person(&vault);
    let claim = fresh_id();
    doors::install_actor_ceiling(&vault, &actor, Tier::ReadOnly.ceiling())
        .expect("a proposed ceiling");
    let run_id = fresh_id();
    let before = transcript_counts(&vault);

    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        Tier::ReadOnly,
        actor,
        run_id,
        "run-read-only-write",
        vec![write_program(&claim, &subject)],
    );
    let outcome = outcome.expect("a read-only write run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_returned_answer(&outcome, "denied-caught:mcp_auth_required");
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let row = &outcome.replay_record.bridge_calls[0];
    assert_eq!(row.effect, SelfEffect::MemoryPutClaim);
    assert_eq!(
        recorded_outcome(&row.outcome),
        (Some("denied"), Some("mcp_auth_required"))
    );
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        "denied-caught:mcp_auth_required"
    );
    assert_eq!(
        transcript_counts(&vault),
        before,
        "no companion MESSAGE lands"
    );
    assert!(
        vault
            .get_claim(&claim)
            .expect("a claim read")
            .is_none(),
        "the refused write lands nothing"
    );

    let (retry, retry_calls) = execute_run(
        &vault,
        &factory,
        Tier::ReadOnly,
        actor,
        run_id,
        "run-read-only-write",
        Vec::new(),
    );
    let retry = retry.expect("the committed run re-enters");
    assert_eq!(retry_calls, 0, "re-entry asks the model nothing");
    assert_eq!(retry.status, EngineExecutorStatus::Complete);
    assert_eq!(
        transcript_counts(&vault),
        before,
        "the retry witnesses nothing later"
    );
}
