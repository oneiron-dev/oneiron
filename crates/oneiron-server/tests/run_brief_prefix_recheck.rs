#![cfg(oneiron_test_support)]
//! [BRIEF-PREFIX-STALE-PAST-REVOKE]: a pumped run's self brief goes again
//! only while every row it shows stands for the reader its PEOPLE were read
//! under.
//!
//! An identity agent's own floor reads no person; it reads the person the
//! owner created only through the owner's live read Grant over PERSON rows.
//! Its pumped run's brief, prepared at the run's birth through the port the
//! resident pump's entry lends the native executor, shows that person on
//! its roster, and its first model request carries it. While the step that
//! request answered runs, the owner revokes the Grant. The run's second
//! request comes with no fold between, so its brief is the prefix held since
//! birth: it must not show the person any more. The port withdraws that
//! prefix and stages one afresh, which the agent's lane now reads without
//! the person.
//!
//! Red on main: the executor sends the held prefix unchanged until the next
//! fold, so the second request still carries the person's row.
//!
//! Public paths, plus two test doors: the port a pumped run's entry lends
//! its executor (`oneiron_server::test_doors::run_self_brief_port`) and the
//! test prompt package. The owner's acts are public verbs
//! (`oneiron::verbs::invoke`).
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! run_brief_prefix_recheck`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use engine_stack::on_engine_stack;
use oneiron::authority::MachineRole;
use oneiron::code_run::{CodeRunDeterminism, GatedActorWrite};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineNativeExecutor, JsCodeModeHost,
    JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::ReplyAssertions;
use oneiron::memory::Memory;
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::run_self_brief_port::resident_self_brief;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The person's name, as the owner created it.
const NAME: &str = "Ilse Varga";

/// The run's task, which its host declares the caller's own, so each request
/// names the rows it was read from.
const TASK: &str = "say who is on the roster";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("executor future unexpectedly pending"),
    }
}

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    oneiron::verbs::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> EntityId {
    let hex = answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"));
    EntityId::from_hex(hex).unwrap_or_else(|_| panic!("{hex} at {pointer} is no entity id"))
}

/// A MESSAGE row holding `content`, the existing record a new person's
/// identity cites.
fn message(vault: &Vault, content: &str) -> EntityId {
    let id = vault.new_entity_id().expect("a message id");
    let now = vault.now_recorded_at();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("content"),
            rmpv::Value::from(content),
        )]),
    )
    .expect("the message body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_MESSAGE,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .expect("the message");
    id
}

/// Answers each call with one program, and keeps each request it got with
/// the rows it was sent with.
#[derive(Default)]
struct RecordingBackend {
    sent: Mutex<Vec<(LlmRequest, Option<Vec<EntityId>>)>>,
}

impl RecordingBackend {
    fn answer(&self, request: LlmRequest, sources: Option<Vec<EntityId>>) -> LlmGenerateFuture<'_> {
        self.sent
            .lock()
            .expect("sent requests")
            .push((request, sources));
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "console.log('roster');".to_owned(),
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: ReplyAssertions::default(),
                token_scores: None,
            })
        })
    }

    fn sent(&self) -> Vec<(LlmRequest, Option<Vec<EntityId>>)> {
        self.sent.lock().expect("sent requests").clone()
    }
}

impl LlmBackend for RecordingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.answer(request, None)
    }

    fn generate_sourced<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
        sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'a> {
        self.answer(request, sources)
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Answers each step with a pending observation; while the first step runs,
/// after the request it answered was sent, the owner revokes `grant`.
struct RevokingRuntime<'a> {
    vault: &'a Vault,
    owner: EntityId,
    grant: String,
    steps: usize,
}

impl JsCodeModeRuntime for RevokingRuntime<'_> {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        _host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        if self.steps == 0 {
            call(
                &self.vault.memory(self.owner, EdgeActorClass::Human),
                "vault.agents.grants.revoke",
                json!({"grant_ref": self.grant}),
            );
        }
        self.steps += 1;
        Ok(JsCodeModeStepOutcome::pending("roster observation"))
    }
}

fn determinism_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(EntityId::now().as_bytes());
    seed[16..].copy_from_slice(EntityId::now().as_bytes());
    seed
}

/// The self brief `request` carries: its user message that opens with the
/// brief's skill block.
fn brief_text(request: &LlmRequest) -> Option<String> {
    request.messages.iter().find_map(|message| {
        matches!(message.role, LlmMessageRole::User)
            .then(|| {
                message.content.iter().find_map(|part| match part {
                    ContentPart::Text { text, .. } if text.starts_with("<skills>") => {
                        Some(text.clone())
                    }
                    _ => None,
                })
            })
            .flatten()
    })
}

/// Whether `sources`, the rows a request was sent with, name `row`.
fn names(sources: Option<&Vec<EntityId>>, row: EntityId) -> bool {
    sources.is_some_and(|sources| sources.contains(&row))
}

async fn a_revoked_grant_drops_its_person_from_the_next_request_of_the_run() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open_owned(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner = vault.memory(owner_id, EdgeActorClass::Human);

    let agent = vault.new_entity_id()?;
    call(
        &owner,
        "vault.agents.create",
        json!({
            "agent_def_ref": agent.to_hex(),
            "definition": {
                "agent_id": "roster-reader",
                "desc": "an agent that reads the roster through the owner's read Grant",
                "version": "1",
            },
        }),
    );
    // The name ceiling only says what the model channel may be told; it
    // grants no read.
    call(
        &owner,
        "vault.disclosure.ceiling.set",
        json!({"connection": format!("agent:{}", agent.to_hex()), "ceiling": "restricted"}),
    );
    let evidence = message(&vault, &format!("{NAME} joined the roster review"));
    let created = call(
        &owner,
        "vault.people.create",
        json!({
            "identity": {"name": NAME},
            "identity_evidence_refs": [evidence.to_hex()],
            "occurred_at": vault.now_recorded_at(),
        }),
    );
    let person = id_at(&created, "/person/id_hex");
    let minted = call(
        &owner,
        "vault.agents.grants.mint",
        json!({
            "agent": agent.to_hex(),
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "some", "values": [ENTITY_TYPE_PERSON]},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": ["read"]},
                "sensitivity": {"kind": "all"},
            },
        }),
    );
    assert_eq!(
        minted.pointer("/grant/confers"),
        Some(&Value::Bool(true)),
        "FIXTURE: the agent's read Grant over PERSON rows is live: {minted:#}"
    );
    let grant = minted
        .pointer("/grant/grant_ref")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("FIXTURE: no grant ref: {minted:#}"))
        .to_owned();
    let reader = vault.memory(agent, EdgeActorClass::Agent);
    assert!(
        vault
            .scoped_read(reader.read_key().expect("the agent's read key"))
            .is_entity_readable(&person)?,
        "FIXTURE: the agent's own lane reads the person through its Grant"
    );

    let server = Arc::new(SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("run-brief-prefix-recheck".into()),
            ..Default::default()
        },
    )?);
    let run_id = EntityId::now();
    let actor = WriteActor::new(agent, EdgeActorClass::Agent);
    let port = resident_self_brief(&server, actor, run_id, tokio::runtime::Handle::current())?
        .unwrap_or_else(|| panic!("FIXTURE: the run's self brief installs"));

    let config = EngineExecutorConfig {
        run_id,
        task: TASK.to_owned(),
        caller_source_digest: None,
        prompt_package_root: workspace_test_prompt_package_root()?,
        model: ModelId::new("test/executor@v1").expect("model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, determinism_seed()),
        limits: EngineExecutorLimits { soft_steps: 2 },
        wake: None,
    };
    let backend = RecordingBackend::default();
    let lease = BudgetLease::for_test("run-brief-prefix-recheck");
    let gated = GatedActorWrite::new(&vault, actor, "run-brief-prefix-recheck")?
        .with_caller_task(run_id, TASK);
    let mut runtime = RevokingRuntime {
        vault: &vault,
        owner: owner_id,
        grant,
        steps: 0,
    };
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated)
        .with_self_brief(&*port);
    let status = block_on_ready(executor.run(&config)).map(|outcome| outcome.status);
    let sent = backend.sent();
    assert!(
        sent.len() >= 2,
        "FIXTURE: the run sends two model requests ({} sent; {status:?})",
        sent.len()
    );
    let (first, first_sources) = &sent[0];
    let (second, second_sources) = &sent[1];

    let first_brief = brief_text(first).unwrap_or_else(|| {
        panic!(
            "FIXTURE: the run's first request carries its self brief ({} messages)",
            first.messages.len()
        )
    });
    assert!(
        names(first_sources.as_ref(), person),
        "FIXTURE: the first request's brief shows the person the agent's Grant reads \
         (sources {first_sources:?}; brief {first_brief})"
    );
    assert!(
        !vault
            .scoped_read(reader.read_key().expect("the agent's read key"))
            .is_entity_readable(&person)?,
        "FIXTURE: once the owner revoked the Grant, the agent's own lane no longer reads the \
         person"
    );

    let second_brief = brief_text(second);
    assert!(
        !names(second_sources.as_ref(), person)
            && !second_brief
                .as_deref()
                .is_some_and(|brief| brief.contains(NAME)),
        "the owner revoked the only Grant through which the agent reads the person while the \
         first step ran, yet the run's second request, with no fold between, still carries the \
         brief prefix that shows them (sources {second_sources:?}; brief {second_brief:?})"
    );
    assert!(
        second_brief.is_some(),
        "the run's second request carries the brief staged afresh in place of the withdrawn one"
    );
    Ok(())
}

#[test]
fn a_revoked_grant_drops_its_person_from_the_next_request() -> TestResult {
    on_engine_stack(a_revoked_grant_drops_its_person_from_the_next_request_of_the_run)
}
