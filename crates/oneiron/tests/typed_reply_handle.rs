//! Census L8-13: a big reply is a handle for every outcome on the typed bridge.
//!
//! 1. `a_redacted_view_past_the_message_bound_returns_its_card`: a Redact post
//!    hook's large view is stored and its card stands for it, so the guest's
//!    call answers the card instead of failing past the message bound. Red on
//!    main: the view replaces the card after the fit, so the call fails
//!    `host_response_over_budget` (typed bridge) or returns the view inline
//!    instead of a card.
//! 2. `a_redacted_result_binds_no_readable_original`: a redacted result binds
//!    no readable original, while the replay row still holds a card of the
//!    real result. Red on main: the original binds to `r1` and reads back
//!    with its secret title (the call's own over-budget throw is caught).
//! 3. `a_large_wait_set_with_feedback_is_stored_before_its_replay_row`: a
//!    large wait set with program feedback spills to a card with its feedback
//!    typed beside it. Red on main: the new source kind does not decode.
//! 4. `a_host_with_no_store_still_sends_the_reply_as_it_is`: a small reply
//!    arrives inline and whole, a large one as a readable card. Green on main
//!    and on the head.
//!
//! Tests 1-2 run live on `connector.answer` with a staged pack body and a
//! Redact post hook. Test 3 runs the host's real pre-record spill through a
//! door. Test 4 pins the with-store control; a storageless executor host
//! cannot be built through the public harness (see the test).
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --features oneiron-agent-runtime/code-sandbox-wasmtime --test typed_reply_handle`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunBridgeCall, CodeRunDeterminism,
    ConnectorAnswerRequest, GatedActorWrite, RunCall, SelfAgentVerbCall,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult,
    EngineExecutorStatus, EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::code_run_answer as doors;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::typed_reply_handle as handle_doors;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use sha2::{Digest, Sha256};

/// The hooked call's answer title, which the Redact hides.
const TAG: &str = "secret-title-7";
/// A large answer: past `RESULT_REPLY_INLINE_BYTES` (512 KiB) and past
/// `message_bytes` (1 MiB).
const RECALL_BYTES: usize = 1_572_864;
/// A small answer: under the inline bound.
const SMALL_BYTES: usize = 204_800;

/// The test's `AgentVerbDoor`: it answers `vault.recall` with a synthetic
/// object whose `text` is `bytes` of `b`, sized by the input's `bytes`.
struct RecallDoor {
    tag: String,
}

impl RecallDoor {
    fn refused(code: &str) -> AgentVerbRefusal {
        AgentVerbRefusal {
            code: code.to_owned(),
            hook_notice: None,
        }
    }
}

impl AgentVerbDoor for RecallDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if call.verb != AgentVerb::VaultRecall {
            return Ok(Err(Self::refused("mcp_verb_not_bound")));
        }
        let bytes = call
            .input
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(RECALL_BYTES as u64) as usize;
        let output = serde_json::json!({
            "title": self.tag,
            "text": "b".repeat(bytes),
        });
        Ok(Ok(AgentVerbAnswer::new(output, None)))
    }

    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
}

/// The test's `AgentVerbDoor` for the hooked call: it answers
/// `connector.answer` with a synthetic object whose `text` is `bytes` of
/// `b`, sized by the request's `handle` parsed as a byte count.
struct ConnectorDoor {
    tag: String,
}

impl ConnectorDoor {
    fn refused(code: &str) -> AgentVerbRefusal {
        AgentVerbRefusal {
            code: code.to_owned(),
            hook_notice: None,
        }
    }
}

impl AgentVerbDoor for ConnectorDoor {
    fn call(
        &self,
        _call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(Self::refused("mcp_verb_not_bound")))
    }

    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }

    fn connector_answer(
        &self,
        request: &ConnectorAnswerRequest,
        _invocation: InvocationId,
    ) -> oneiron::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let bytes = request.handle.parse::<usize>().unwrap_or(RECALL_BYTES);
        let output = serde_json::json!({
            "title": self.tag,
            "text": "b".repeat(bytes),
        });
        Ok(Ok(AgentVerbAnswer::new(output, None)))
    }
}

/// The scripted model: each turn answers with the next program.
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
        task: "read the hooked call's large answer".to_owned(),
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
/// recall door, and a fresh guest.
fn execute_run(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    actor: EntityId,
    run_id: EntityId,
    run_ref: &str,
    tag: &str,
    programs: Vec<String>,
) -> (EngineExecutorResult<EngineExecutorOutcome>, usize) {
    let backend = FixtureBackend::new(programs);
    let lease = BudgetLease::for_test("typed-reply-handle");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        run_ref,
    )
    .expect("a dispatcher binds")
    .with_agent_verb_door(Arc::new(RecallDoor {
        tag: tag.to_owned(),
    }));
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(run_id);
    let outcome = block_on_ready(executor.run(&config));
    (outcome, backend.calls())
}

/// One entry of one durable run: a fresh backend holding `programs`, the
/// connector door answering the hooked call, and a fresh guest.
fn execute_connector_run(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    actor: EntityId,
    run_id: EntityId,
    run_ref: &str,
    tag: &str,
    programs: Vec<String>,
) -> (EngineExecutorResult<EngineExecutorOutcome>, usize) {
    let backend = FixtureBackend::new(programs);
    let lease = BudgetLease::for_test("typed-reply-handle");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        run_ref,
    )
    .expect("a dispatcher binds")
    .with_agent_verb_door(Arc::new(ConnectorDoor {
        tag: tag.to_owned(),
    }));
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(run_id);
    let outcome = block_on_ready(executor.run(&config));
    (outcome, backend.calls())
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("a vault opens"));
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

/// A bridge row's recorded outcome as JSON: the `output` member parsed.
fn bridge_output(row: &CodeRunBridgeCall) -> serde_json::Value {
    let rmpv::Value::Map(entries) = &row.outcome else {
        panic!("bridge outcome is a map");
    };
    let text = entries
        .iter()
        .find_map(|(key, value)| {
            if key.as_str() == Some("output") {
                value.as_str()
            } else {
                None
            }
        })
        .expect("an agent verb output");
    serde_json::from_str(text).expect("the output parses")
}

/// Binds the Redact post hook on `connector.answer` and installs its runtime.
fn bind_redact_hook(vault: &Arc<Vault>) {
    let (owner, proof) = embedded_owner(vault).expect("owner proof");
    handle_doors::bind_redact_post_hook(vault, owner, &proof, "connector.answer")
        .expect("the Redact hook binds");
    handle_doors::install_redact_runtime(vault, vec!["/output/title".to_owned()])
        .expect("the Redact runtime installs");
}

/// The redacted-view program: it calls the hooked call, checks the reply is
/// a card, reads the card's body whole through `slice`, and finishes with
/// whether the title survived and the text it read.
const REDACT_PROGRAM: &str = r#"let out = null, recallError = null;
try {
  out = await connector.answer({handle: "1572864", answers: [{key: "q", action: "accept", content: {}}]});
} catch (e) {
  recallError = String(e).slice(0, 100);
}
if (recallError !== null) {
  finish("recall-threw:" + recallError);
} else {
  const isCard = out && typeof out === "object"
    && typeof out.handle === "string" && typeof out.preview === "string"
    && typeof out.bytes === "number" && typeof out.kind === "string"
    && typeof out.complete === "boolean";
  if (!isCard) {
    finish("not-a-card:" + JSON.stringify(out).slice(0, 200));
  } else {
    let text = "", next = {bytes: [0]};
    for (;;) {
      const piece = await slice(out, next);
      if (typeof piece.text !== "string") {
        finish("not-text");
        break;
      }
      text += piece.text;
      if (piece.done || !piece.next) {
        const body = JSON.parse(text);
        const hasTitle = body && typeof body === "object" && "title" in body;
        const textLen = body && typeof body.text === "string" ? body.text.length : -1;
        const prefixOk = body && typeof body.text === "string" && body.text.startsWith("bbbbbbbb");
        finish("card:has-title:" + hasTitle + ":text-len:" + textLen + ":prefix-ok:" + prefixOk);
        break;
      }
      next = piece.next;
    }
  }
}"#;

/// A Redact post hook hiding `/output/title` on the call: the guest calls the
/// call, reads the reply's card back, and finishes with what it saw. The call
/// returns a card with no `host_response_over_budget`; the body read back has
/// no `title` and the whole `text`.
#[test]
fn a_redacted_view_past_the_message_bound_returns_its_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    bind_redact_hook(&vault);
    let run_id = fresh_id();

    let (outcome, calls) = execute_connector_run(
        &vault,
        &factory,
        actor,
        run_id,
        "run-redacted-view",
        TAG,
        vec![REDACT_PROGRAM.to_owned()],
    );
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        format!("card:has-title:false:text-len:{RECALL_BYTES}:prefix-ok:true"),
    );
}

/// The re-read program: it calls the hooked call, then reads every name
/// `r1` .. `r8` back, and finishes with every text it read. A call that
/// throws still reads the names, so the names are what this test judges.
const REREAD_PROGRAM: &str = r#"let out = null;
try {
  out = await connector.answer({handle: "1572864", answers: [{key: "q", action: "accept", content: {}}]});
} catch (e) {
  out = "threw:" + String(e).slice(0, 100);
}
const seen = [];
seen.push("reply:" + JSON.stringify(out).slice(0, 300));
for (let n = 1; n <= 8; n++) {
  const name = "r" + n;
  try {
    const d = await describe(name);
    seen.push(name + ":describe:" + JSON.stringify(d).slice(0, 300));
  } catch (e) {
    seen.push(name + ":describe-threw");
  }
  try {
    const s = await slice(name, {bytes: [0, 256]});
    seen.push(name + ":slice:" + JSON.stringify(s).slice(0, 300));
  } catch (e) {
    seen.push(name + ":slice-threw");
  }
}
finish(seen.join("\n"));"#;

/// The same hook and call: no read of `r1` .. `r8` returns the secret title,
/// and the run's replay row for the call still holds a card of the real
/// result.
#[test]
fn a_redacted_result_binds_no_readable_original() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    bind_redact_hook(&vault);
    let run_id = fresh_id();

    let (outcome, calls) = execute_connector_run(
        &vault,
        &factory,
        actor,
        run_id,
        "run-redacted-reread",
        TAG,
        vec![REREAD_PROGRAM.to_owned()],
    );
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let text = doors::finish_text(&vault, &run_id).expect("the answer reads back");
    assert!(
        !text.contains("secret-title-"),
        "no read returned the secret title:\n{text}",
    );
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let output = bridge_output(&outcome.replay_record.bridge_calls[0]);
    assert!(
        output
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "the replay row holds a card of the real result: {output}",
    );
}

/// A `TaskWaitSet` outcome whose findings total ~700 KiB with one type
/// feedback item: it spills to a card with its feedback typed beside it, the
/// encoded outcome stays under 16 KiB, and the stored body reads back whole
/// with no `program_steps`. The probe reads the kind as the encoded map's
/// `source_kind` string, so this file names no head-only item.
#[test]
fn a_large_wait_set_with_feedback_is_stored_before_its_replay_row() {
    let (_dir, vault) = open_vault();
    let run_id = fresh_id();
    let probe =
        handle_doors::probe_stored_wait_set_feedback(&vault, &run_id, 700 * 1024).expect("a probe");
    assert!(
        probe.inline_len > 700 * 1024,
        "the inline wait set encodes past 700 KiB: {}",
        probe.inline_len,
    );
    assert!(
        probe.record_encode_ok,
        "the stored wait-set feedback form encodes",
    );
    assert!(
        probe.stored_outcome_len < 16 * 1024,
        "the stored outcome is under 16 KiB: {}",
        probe.stored_outcome_len,
    );
    assert_eq!(probe.source_kind, "task_wait_set_with_feedback");
    assert_eq!(probe.program_steps_len, 1);
    assert!(
        probe.body_matches_findings,
        "the stored body reads back whole",
    );
    assert!(
        !probe.body_has_program_steps,
        "the stored body holds no program_steps",
    );
}

/// A ~200 KiB reply arrives inline and whole; a 1.5 MiB reply arrives as a
/// readable card. A storageless executor host cannot be built through the
/// public harness (`RecordingJsHost::new` is `pub(super)` and every executor
/// path binds storage through `with_recoverable_outputs`), so this pins the
/// with-store control instead: green on main and on the head.
#[test]
fn a_host_with_no_store_still_sends_the_reply_as_it_is() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);

    let small_program = format!(
        r#"const out = await vault.recall({{query: "notes", bytes: {SMALL_BYTES}}});
const len = out && typeof out.text === "string" ? out.text.length : -1;
finish("inline:text-len:" + len);"#,
    );
    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        actor,
        fresh_id(),
        "run-small-reply",
        TAG,
        vec![small_program],
    );
    let outcome = outcome.expect("the small run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let run_id = outcome.replay_record.run_id;
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        format!("inline:text-len:{SMALL_BYTES}"),
    );
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let output = bridge_output(&outcome.replay_record.bridge_calls[0]);
    assert!(
        output.get("handle").is_none(),
        "the small reply stays inline: {output}",
    );
    assert_eq!(
        output
            .get("text")
            .and_then(serde_json::Value::as_str)
            .map(str::len),
        Some(SMALL_BYTES),
    );

    let large_program = format!(
        r#"const out = await vault.recall({{query: "notes", bytes: {RECALL_BYTES}}});
const isCard = out && typeof out === "object"
  && typeof out.handle === "string" && typeof out.bytes === "number";
if (!isCard) {{
  finish("not-a-card");
}} else {{
  const head = await slice(out, {{bytes: [0, 4096]}});
  const prefixOk = typeof head.text === "string"
    && head.text.includes("\"title\":\"secret-title-7\"")
    && head.text.includes("\"text\":\"bbbbbbbb");
  finish("card:bytes:" + out.bytes + ":prefix-ok:" + prefixOk);
}}"#,
    );
    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        actor,
        fresh_id(),
        "run-large-reply",
        TAG,
        vec![large_program],
    );
    let outcome = outcome.expect("the large run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let run_id = outcome.replay_record.run_id;
    let expected = serde_json::json!({"title": TAG, "text": "b".repeat(RECALL_BYTES)}).to_string();
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        format!("card:bytes:{}:prefix-ok:true", expected.len()),
    );
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let output = bridge_output(&outcome.replay_record.bridge_calls[0]);
    assert!(
        output
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "the large reply arrives as a card: {output}",
    );
    assert_eq!(
        output.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
}
