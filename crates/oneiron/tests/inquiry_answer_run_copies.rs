//! UNBUILT3-27 PR 1 (FIX INQUIRY-TASK-ANSWER-RUN-COPIES; canon
//! federation.md #inquiry-keep and #hosted-topology; Engine ruling
//! INQUIRE-SHAPE Q6 = A): a member's answer to an inquiry kept `task` is held
//! with the task alone, so a code run that asked it keeps no copy of the
//! member's words in its run records. The guest still reads the whole
//! answer, through the call's view, as it reads a `reveal.wait` value.
//!
//! Each run drives a real QuickJS guest through the shipped executor
//! (`EngineNativeExecutor`) with a scripted model backend answering one
//! program. The test's verb door answers `vault.inquire` as the company
//! host's door does once the member answered: outcome `answered`, the
//! member's statement, and the keep the inquiry was sent with. The program
//! finishes with the statement count and the first statement's length, so
//! its own answer (a company record by canon, federation.md:119) holds none
//! of the member's words and the test can still see what the guest read.
//!
//! - `a_code_run_keeps_no_task_held_statement_in_its_replay_record`: keep
//!   `task`. The run's bridge row, in the returned and in the stored replay
//!   record, keeps no statement text and keeps `statements_withheld`; no raw
//!   output of the run holds the text; the row says the guest read a view.
//!   Red on main: the bridge row keeps the statement verbatim
//!   (`keep_no_secret_value` strips `reveal.wait` only).
//! - `a_copy_inquiry_answer_is_kept_in_the_run_record`: keep `copy` lands
//!   in the company vault by canon (federation.md #inquiry-keep), so the row
//!   keeps its statement and no view is served. Passes on main and with the
//!   fix.
//! - `a_step_replay_context_keeps_no_inquiry_answer_view`: the step's replay
//!   context (FIX 6351) keeps no `vault.inquire` response the guest read
//!   through a view, as it keeps no `reveal.wait` response; any other verb's
//!   view is kept. Red on main: the context keeps the view.
//! - `a_vault_inquire_action_is_not_offered` (review of #9225): an action
//!   answers its caller from its replay record, which keeps the withheld
//!   form, so the app's action table offers no `vault.inquire`; another read
//!   row is still offered. Red on main: the table offers it, and its record
//!   kept the statements.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_answer_run_copies`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::actions::ActionRegistry;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunDeterminism, CodeRunReplayRecord,
    GatedActorWrite, RunCall, RunSpeechDestination, SelfAgentVerbCall, SelfCall, SelfEffect,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorStatus,
    EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::code_mode_capture::step_context_keeps_response;
use oneiron::test_doors::code_run_answer as doors;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The member's word, as the member host answered it. Distinct enough that
/// no other byte of a run record holds it by chance.
const MEMBER_WORD: &str = "out Thursday afternoon for the hospital visit, member word 7f3a";

/// The guest's answer: the statement count and the first statement's length,
/// never its text.
fn read_answer() -> String {
    format!("statements:1:{}", MEMBER_WORD.len())
}

/// The test's `AgentVerbDoor`: `vault.inquire` answers as the company host's
/// door does once the member answered, with the keep the inquiry was sent
/// with. Every other verb is refused; every run call and speech admits.
struct InquiryDoor {
    keep: &'static str,
}

impl AgentVerbDoor for InquiryDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if call.verb != AgentVerb::VaultInquire {
            return Ok(Err(AgentVerbRefusal {
                code: "verb_not_bound".to_owned(),
                hook_notice: None,
            }));
        }
        let output = json!({
            "inquiry_id": fresh_id(),
            "outcome": "answered",
            "statements": [{"text": MEMBER_WORD, "source": "member_word"}],
            "valid_until": 4_102_444_800_u64,
            "keep": self.keep,
            "receipt_id": "inquiry-receipt-1",
            "held": self.keep == "task",
        });
        Ok(Ok(AgentVerbAnswer::new(output, None)))
    }

    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }

    fn admit_run_speech(
        &self,
        _effect: SelfEffect,
        _destination: RunSpeechDestination,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
}

/// The scripted model: each turn answers with the next program.
struct FixtureBackend {
    programs: Mutex<VecDeque<String>>,
}

impl LlmBackend for FixtureBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
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
        task: "ask the member about Thursday".to_owned(),
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

fn fresh_id() -> EntityId {
    EntityId::from_bytes(uuid::Uuid::now_v7().into_bytes()).expect("a test id")
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("a vault opens"));
    (dir, vault)
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

/// The program: one `vault.inquire` for an open task, then the statement
/// count and the first statement's length.
fn inquire_program() -> String {
    format!(
        r#"const answer = await vault.inquire({{shared_vault_id: 1, member: "{member}", question: "Is the member free on Thursday?", task: "{task}", purpose: "plan the visit", expires_at: 4102444800}});
finish("statements:" + answer.statements.length + ":" + answer.statements[0].text.length);"#,
        member = fresh_id().to_hex(),
        task = fresh_id().to_hex(),
    )
}

/// One run of the inquiry program under a read-only agent whose door
/// answers with `keep`: the completed outcome.
fn run_inquiry(vault: &Arc<Vault>, keep: &'static str, run_id: EntityId) -> EngineExecutorOutcome {
    let factory = quickjs_factory();
    let actor = seed_person(vault);
    doors::install_actor_ceiling(vault, &actor, "proposed").expect("a proposed ceiling");
    let backend = FixtureBackend {
        programs: Mutex::new(VecDeque::from([inquire_program()])),
    };
    let lease = BudgetLease::for_test("inquiry-answer-run-copies");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-inquiry-answer",
    )
    .expect("a dispatcher binds")
    .with_agent_verb_door(Arc::new(InquiryDoor { keep }));
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(run_id);
    let outcome = block_on_ready(executor.run(&config)).expect("the inquiry run completes");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    outcome
}

/// Whether `value`, at any depth, holds `needle` in a string, a key, or
/// bytes.
fn holds_text(value: &rmpv::Value, needle: &str) -> bool {
    match value {
        rmpv::Value::String(text) => text.as_str().map_or_else(
            || contains(text.as_bytes(), needle),
            |text| text.contains(needle),
        ),
        rmpv::Value::Binary(bytes) | rmpv::Value::Ext(_, bytes) => contains(bytes, needle),
        rmpv::Value::Array(items) => items.iter().any(|item| holds_text(item, needle)),
        rmpv::Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| holds_text(key, needle) || holds_text(value, needle)),
        _ => false,
    }
}

fn contains(bytes: &[u8], needle: &str) -> bool {
    bytes
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The `vault.inquire` row of `record`: its only bridge row.
fn inquiry_row(record: &CodeRunReplayRecord) -> &oneiron::code_run::CodeRunBridgeCall {
    assert_eq!(record.bridge_calls.len(), 1, "one call, one row");
    let row = &record.bridge_calls[0];
    assert_eq!(row.effect, SelfEffect::AgentVerb);
    row
}

/// The finish answer the guest gave, read back from the run's record.
fn finish_text(vault: &Vault, run_id: &EntityId) -> String {
    doors::finish_text(vault, run_id).expect("the answer reads back")
}

#[test]
fn a_code_run_keeps_no_task_held_statement_in_its_replay_record() {
    let (_dir, vault) = open_vault();
    let run_id = fresh_id();
    let outcome = run_inquiry(&vault, "task", run_id);

    // The guest read the member's whole answer, through the call's view.
    assert_eq!(finish_text(&vault, &run_id), read_answer());

    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("the replay record reads")
        .expect("the run kept its replay record");
    for (which, record) in [("returned", &outcome.replay_record), ("stored", &stored)] {
        let row = inquiry_row(record);
        assert!(
            !holds_text(&row.outcome, MEMBER_WORD),
            "the {which} bridge row keeps no task-held statement: {:?}",
            row.outcome
        );
        assert!(
            holds_text(&row.outcome, "statements_withheld"),
            "the {which} bridge row marks the statements withheld: {:?}",
            row.outcome
        );
        assert!(
            row.hook_view_served,
            "the {which} row says the guest read the answer through a view"
        );
        for output in &record.outputs {
            let bytes = vault
                .get_code_run_raw_output(output)
                .expect("a raw output reads")
                .unwrap_or_default();
            assert!(
                !contains(&bytes, MEMBER_WORD),
                "the {which} record's raw output {} holds no task-held statement",
                output.path
            );
        }
    }
}

#[test]
fn a_copy_inquiry_answer_is_kept_in_the_run_record() {
    let (_dir, vault) = open_vault();
    let run_id = fresh_id();
    let outcome = run_inquiry(&vault, "copy", run_id);

    assert_eq!(finish_text(&vault, &run_id), read_answer());
    let row = inquiry_row(&outcome.replay_record);
    assert!(
        holds_text(&row.outcome, MEMBER_WORD),
        "a copy answer is a company record: its row keeps the statement: {:?}",
        row.outcome
    );
    assert!(
        !holds_text(&row.outcome, "statements_withheld"),
        "a copy answer withholds nothing: {:?}",
        row.outcome
    );
    assert!(!row.hook_view_served, "the guest read the row's own answer");
}

#[test]
fn a_step_replay_context_keeps_no_inquiry_answer_view() {
    let call = |verb| {
        SelfCall::AgentVerb(SelfAgentVerbCall {
            verb,
            input: json!({}),
        })
    };
    let view: Value = json!({"output": {
        "outcome": "answered",
        "statements": [{"text": MEMBER_WORD, "source": "member_word"}],
        "keep": "task",
    }});
    assert!(
        !step_context_keeps_response(&call(AgentVerb::VaultInquire), Some(&view)),
        "no step context keeps the view a task-kept inquiry answer was read through"
    );
    assert!(
        step_context_keeps_response(&call(AgentVerb::VaultInquire), None),
        "an inquiry response read with no view is kept as any other"
    );
    assert!(
        step_context_keeps_response(&call(AgentVerb::VaultRecall), Some(&view)),
        "another verb's view is kept as before"
    );
}

#[test]
fn a_vault_inquire_action_is_not_offered() {
    let registry = ActionRegistry::app().expect("the app's action table");
    assert!(
        registry.resolve("vault.inquire").is_err(),
        "no action answers vault.inquire from a record that withholds its statements"
    );
    assert_eq!(registry.row_verb("vault.inquire"), None);
    assert_eq!(
        registry.row_verb("vault.recall"),
        Some("vault.recall"),
        "another read row is still offered"
    );
}
