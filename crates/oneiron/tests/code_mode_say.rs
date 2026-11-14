//! Census L8-25: code mode's `say(text or result, {to?, kind?, refs?})` and
//! `self.think.aloud` (agent-runtime-v1 #d6; ARCH-0067 tasks table;
//! ARCH-0079 #channels).
//!
//! Each test drives a real QuickJS guest through the shipped executor
//! (`EngineNativeExecutor`), as `code_run_restricted_actor_answer.rs` does,
//! with a scripted model answering one program. The run's verb door hands
//! every verb-table call to the shipped engine entry
//! (`task_verb::sdk::invoke`) on the agent's own memory, so the `say` row
//! runs its generated OF-063 refs check and its engine door for real.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`) seated in
//! one project's home room. Every run's actor is yuki.
//!
//! Red on main: `say` is no global and `self.think.aloud` is undefined, so
//! every program throws before its `finish` and no test gets its answer.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --features oneiron-agent-runtime/code-sandbox-wasmtime
//! --test code_mode_say`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunDeterminism, GatedActorWrite, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfEffect,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorStatus,
    EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use oneiron::runtime_hooks::InvocationId;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The run's verb door: every verb-table call runs the shipped engine entry
/// on the agent's own memory, and an engine refusal is the door's refusal,
/// by its code. Every run call and every speech is admitted.
struct EngineDoor {
    vault: Arc<Vault>,
    actor: EntityId,
}

impl AgentVerbDoor for EngineDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let memory = self.vault.memory(self.actor, EdgeActorClass::Agent);
        Ok(
            match invoke(&memory, call.verb.as_str(), call.input.clone()) {
                Ok(output) => Ok(AgentVerbAnswer::new(output, None)),
                Err(error) => Err(AgentVerbRefusal {
                    code: error.code,
                    hook_notice: None,
                }),
            },
        )
    }

    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }

    fn admit_run_speech(
        &self,
        _effect: SelfEffect,
        _destination: RunSpeechDestination,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
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

/// The owner, the agent the runs act as, and the room both are seated in.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owen: EntityId,
    yuki: EntityId,
    room: EntityId,
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open_owned(dir.path(), VaultConfig::default())?);
    let owen = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owen, &owen.to_hex(), true, GateDecisionId::now())?;
    let yuki = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": "yuki",
        "display_name": "yuki",
        "desc": "yuki",
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        &vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: yuki,
            definition,
        },
    )?;
    let root = vault.root_project()?;
    let project_id = EntityId::now();
    let mut project = ProjectRecord::new(project_id, Some(root), root, owen)?;
    project.roster.push(yuki.to_hex());
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owen,
        yuki,
        room,
    })
}

/// One run of `program` as yuki, to its end.
fn run_program(fixture: &Fixture, program: &str) -> EngineExecutorOutcome {
    let backend = FixtureBackend {
        programs: Mutex::new(VecDeque::from([program.to_owned()])),
    };
    let lease = BudgetLease::for_test("code-mode-say");
    let gated = GatedActorWrite::new(
        &fixture.vault,
        WriteActor::new(fixture.yuki, EdgeActorClass::Agent),
        "run-code-mode-say",
    )
    .expect("a dispatcher binds")
    .with_agent_verb_door(Arc::new(EngineDoor {
        vault: Arc::clone(&fixture.vault),
        actor: fixture.yuki,
    }));
    let factory = quickjs_factory();
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor =
        EngineNativeExecutor::new(&fixture.vault, &backend, &lease, &mut runtime, &gated);
    let config = EngineExecutorConfig {
        run_id: EntityId::now(),
        task: "speak through say".to_owned(),
        prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
            .expect("the workspace test prompt package"),
        model: ModelId::new("test/executor@v1").expect("a model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
        limits: EngineExecutorLimits::default(),
        wake: None,
    };
    let outcome = block_on_ready(executor.run(&config)).expect("the run ends");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Complete,
        "the run completes"
    );
    outcome
}

/// The run's `finish` answer.
fn answer(outcome: &EngineExecutorOutcome) -> &str {
    &outcome
        .replay_record
        .outputs
        .iter()
        .find(|output| output.path.ends_with(".observation.txt"))
        .expect("the run's replay result holds its answer")
        .preview
        .text
}

/// (conversations, turns, messages) on the vault.
fn transcript_counts(vault: &Vault) -> TestResult<(usize, usize, usize)> {
    Ok((
        vault.entities_by_type(ENTITY_TYPE_CONVERSATION)?.len(),
        vault.entities_by_type(ENTITY_TYPE_TURN)?.len(),
        vault.entities_by_type(ENTITY_TYPE_MESSAGE)?.len(),
    ))
}

/// Every stored MESSAGE whose content is `content`, as its body map.
fn messages_saying(
    vault: &Vault,
    content: &str,
) -> TestResult<Vec<Vec<(rmpv::Value, rmpv::Value)>>> {
    let mut found = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_MESSAGE)? {
        let Some(raw) = vault.get_raw(&id)? else {
            continue;
        };
        let body = rmpv::decode::read_value(&mut &raw[ENTITY_METADATA_HEADER_LEN..])?;
        let rmpv::Value::Map(fields) = body else {
            continue;
        };
        if field(&fields, "content").and_then(rmpv::Value::as_str) == Some(content) {
            found.push(fields);
        }
    }
    Ok(found)
}

fn field<'f>(fields: &'f [(rmpv::Value, rmpv::Value)], name: &str) -> Option<&'f rmpv::Value> {
    fields
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

/// The `say_kind` a MESSAGE's metadata names.
fn say_kind(fields: &[(rmpv::Value, rmpv::Value)]) -> Option<String> {
    let rmpv::Value::Map(metadata) = field(fields, "metadata")? else {
        return None;
    };
    field(metadata, "say_kind")
        .and_then(rmpv::Value::as_str)
        .map(str::to_owned)
}

/// `say(text, {to: room, kind, refs})` lands one text MESSAGE in that room,
/// authored by the agent, marked with its kind; the run's own conversation
/// gets no bubble of it, so the options were not dropped.
#[test]
fn say_to_a_room_lands_one_message_there_marked_with_its_kind() -> TestResult {
    let fixture = fixture()?;
    let room = fixture.room.to_hex();
    let program = format!(
        r#"const receipt = await say("hi room", {{to: "{room}", kind: "note", refs: ["{room}"]}});
finish(receipt.room);"#
    );
    let outcome = run_program(&fixture, &program);
    assert_eq!(
        answer(&outcome),
        room,
        "the message lands in the named room"
    );
    let landed = messages_saying(&fixture.vault, "hi room")?;
    assert_eq!(landed.len(), 1, "one MESSAGE, and no run bubble of it");
    let message = &landed[0];
    assert_eq!(
        field(message, "type").and_then(rmpv::Value::as_str),
        Some("text")
    );
    assert_eq!(
        field(message, "author").and_then(rmpv::Value::as_str),
        Some("companion")
    );
    assert_eq!(say_kind(message).as_deref(), Some("note"));
    Ok(())
}

/// `say(text)` with no destination speaks where `self.speak` speaks: both
/// land as `executor.speak` bubbles in the run's one conversation and turn.
#[test]
fn a_say_with_no_destination_speaks_where_self_speak_speaks() -> TestResult {
    let fixture = fixture()?;
    let before = transcript_counts(&fixture.vault)?;
    let outcome = run_program(
        &fixture,
        r#"await say("said here");
await self.speak("spoken here");
finish("spoke");"#,
    );
    assert_eq!(answer(&outcome), "spoke");
    for content in ["said here", "spoken here"] {
        let landed = messages_saying(&fixture.vault, content)?;
        assert_eq!(landed.len(), 1, "one bubble of {content:?}");
        assert_eq!(
            field(&landed[0], "type").and_then(rmpv::Value::as_str),
            Some("executor.speak")
        );
    }
    let after = transcript_counts(&fixture.vault)?;
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (1, 1),
        "the run's one conversation and turn hold both bubbles"
    );
    assert!(after.2 - before.2 >= 2, "both bubbles land");
    Ok(())
}

/// `self.think.aloud(text)` witnesses one visible thought in the run's own
/// conversation.
#[test]
fn self_think_aloud_witnesses_one_visible_thought() -> TestResult {
    let fixture = fixture()?;
    let outcome = run_program(
        &fixture,
        r#"await self.think.aloud("checking the ledger");
finish("thought");"#,
    );
    assert_eq!(answer(&outcome), "thought");
    let landed = messages_saying(&fixture.vault, "checking the ledger")?;
    assert_eq!(landed.len(), 1, "one thought");
    assert_eq!(
        field(&landed[0], "type").and_then(rmpv::Value::as_str),
        Some("executor.think_aloud")
    );
    assert_eq!(
        field(&landed[0], "is_visible").and_then(rmpv::Value::as_bool),
        Some(true)
    );
    Ok(())
}

/// The program that says `call` and finishes with the refusal's code.
fn refused_program(call: &str) -> String {
    format!(
        r#"try {{
  await {call};
  finish("sent");
}} catch (error) {{
  finish("refused:" + JSON.parse(String(error)).denied);
}}"#
    )
}

/// A `to` that names nothing the agent can read is refused before any write.
#[test]
fn say_to_an_unknown_destination_is_refused_before_any_write() -> TestResult {
    let fixture = fixture()?;
    let outcome = run_program(&fixture, &refused_program(r#"say("lost", {to: "zz9"})"#));
    assert_eq!(answer(&outcome), "refused:say_unknown_destination");
    assert!(messages_saying(&fixture.vault, "lost")?.is_empty());
    Ok(())
}

/// A kind marks an addressed message: with no `to` the say is refused.
#[test]
fn a_say_marked_with_a_kind_and_no_destination_is_refused() -> TestResult {
    let fixture = fixture()?;
    let outcome = run_program(
        &fixture,
        &refused_program(r#"say("unsent", {kind: "ask"})"#),
    );
    assert_eq!(answer(&outcome), "refused:say_needs_a_destination");
    assert!(messages_saying(&fixture.vault, "unsent")?.is_empty());
    Ok(())
}

/// A ref that resolves for no one is refused by the row's OF-063 check, and
/// nothing lands in the room.
#[test]
fn a_say_citing_a_record_that_does_not_resolve_is_refused() -> TestResult {
    let fixture = fixture()?;
    let call = format!(
        r#"say("cites", {{to: "{room}", refs: ["{missing}"]}})"#,
        room = fixture.room.to_hex(),
        missing = EntityId::now().to_hex(),
    );
    let outcome = run_program(&fixture, &refused_program(&call));
    assert_eq!(answer(&outcome), "refused:INVENTED_REFERENCE");
    assert!(messages_saying(&fixture.vault, "cites")?.is_empty());
    Ok(())
}

/// `say(text, {to: person})` lands in the Direct room the agent and that
/// person share, marked with its kind.
#[test]
fn say_to_a_person_lands_in_the_room_they_share() -> TestResult {
    let fixture = fixture()?;
    let program = format!(
        r#"const receipt = await say("for owen", {{to: "{owen}", kind: "ask"}});
finish(receipt.room);"#,
        owen = fixture.owen.to_hex(),
    );
    let outcome = run_program(&fixture, &program);
    assert_ne!(
        answer(&outcome),
        fixture.room.to_hex(),
        "a person's message goes to the room the two share, not the project room"
    );
    let landed = messages_saying(&fixture.vault, "for owen")?;
    assert_eq!(landed.len(), 1, "one MESSAGE");
    assert_eq!(
        field(&landed[0], "type").and_then(rmpv::Value::as_str),
        Some("text")
    );
    assert_eq!(say_kind(&landed[0]).as_deref(), Some("ask"));
    Ok(())
}
