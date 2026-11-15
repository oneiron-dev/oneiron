//! VAULT-SUMMARIZE-SET (OPUS-UNBUILT-B4A, set B): code-mode `summarize`
//! over NOTEs named by id.
//!
//! Each test drives a real QuickJS guest through the shipped executor
//! (`EngineNativeExecutor`) with a scripted model backend answering the
//! programs. No real model, no sleeps, no ports. The full-access door below
//! admits every run call as the run's own actor, so the run reads NOTEs as
//! actor A reads them; a reader seat on the host meter (`ReaderSpend::Host`,
//! no ledger scope to fund) lets `dispatch_summarize` queue the summary job.
//! A fake runner whose `wake` only notes the task stands in for the reader
//! runner: the test body settles the job after the first call parks, then
//! re-enters the run with the identical program, which hits the summary memo
//! and answers the one digest card.
//!
//! Guest reply semantics (as the template's): a typed host refusal rejects
//! the awaited promise with a JSON string containing `{denied,
//! reasonCodes}`, which the refused program catches and decodes.
//!
//! Red on main: the `summarize` wrapper takes only a result ref, so a null
//! ref throws `result ref must be a name, handle or card` before anything is
//! dispatched, and `note_refs` is an unknown field the wire input rejects.
//! The first test's program then fails instead of parking, and the second
//! test's program catches the wrapper's TypeError instead of the typed
//! refusal, so its answer carries the `other:` prefix and misses.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --features oneiron-agent-runtime/code-sandbox-wasmtime --test summarize_note_set`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, ClaimOutcome, CodeRunDeterminism,
    DEFAULT_READER_WINDOW_TOKENS, GatedActorWrite, ReaderJobKind, ReaderJobRunner, ReaderJobState,
    ReaderJobWake, ReaderJobs, ReaderRunEnd, ReaderSpend, RunCall, RunDeadline,
    RunSpeechDestination, SUMMARY_READ_BYTES_PER_TOKEN, SelfAgentVerbCall, SelfDurableWaitReason,
    SelfEffect, SpawnHostSeat, SummaryRead, summary_token_budget,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult,
    EngineExecutorStatus, EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::code_run_answer as doors;
use oneiron::test_doors::summarize_note_set as note_doors;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use sha2::{Digest, Sha256};

/// The two NOTEs' words: distinct markdown, so the settled members prove the
/// host read each NOTE's own text.
const A_TEXT: &str = "The lighthouse keeper logs the tide at dawn.";
const B_TEXT: &str = "The cartographer charts the reef by starlight.";

/// The digest the test stores as the summary's finding.
const DIGEST: &str = "Both NOTEs keep the night watch over the strait.";

/// The test's `AgentVerbDoor`: full access without the MCP server. Every run
/// call is admitted as the run's own actor, so the run reads NOTEs as actor
/// A reads them. No agent verb is bound: these programs call nothing through
/// the verb door.
struct FullAccessDoor;

impl FullAccessDoor {
    fn refused(code: &str) -> AgentVerbRefusal {
        AgentVerbRefusal {
            code: code.to_owned(),
            hook_notice: None,
        }
    }
}

impl AgentVerbDoor for FullAccessDoor {
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
        call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        match call {
            // Full access: the run reads as its own actor.
            RunCall::RecordedOutput | RunCall::Bridge(_) => Ok(None),
        }
    }

    fn admit_run_speech(
        &self,
        _effect: SelfEffect,
        _destination: RunSpeechDestination,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
}

/// The scripted model: each turn answers with the next program. Counts every
/// call, so the re-entry proves the resumed run asked the model again.
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

/// The fake reader runner: `wake` only notes the job, as the trait contract
/// requires. The test body settles the noted job after the run parks.
#[derive(Debug, Default)]
struct NotingRunner {
    wakes: Mutex<Vec<ReaderJobWake>>,
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

impl ReaderJobRunner for NotingRunner {
    fn wake(&self, wake: ReaderJobWake) {
        self.wakes.lock().expect("wakes").push(wake);
    }
}

/// Wall-clock unix milliseconds. (`oneiron::unix_millis_now` is crate-only,
/// so the test reads the clock itself.)
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the Unix epoch")
        .as_millis() as u64
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

/// What the host lends the run so it may queue its summary: the host meter
/// (no ledger scope to fund), one reader window from now, and the default
/// model window in tokens.
fn reader_seat() -> SpawnHostSeat {
    let now = now_ms();
    SpawnHostSeat {
        spend: ReaderSpend::Host,
        deadline: RunDeadline::with_default_reserve(now + 600_000, now),
        hold_units: 0,
        window_tokens: DEFAULT_READER_WINDOW_TOKENS,
        memory_bytes: 0,
        listed: Vec::new(),
        parent_lease: None,
    }
}

fn executor_config(run_id: EntityId) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: "summarize the NOTEs".to_owned(),
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
/// full-access door, a reader seat, and a fresh guest. Answers the outcome
/// with how many times the entry asked the model.
fn execute_run(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
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
    .with_agent_verb_door(Arc::new(FullAccessDoor))
    .with_reader_spawn(reader_seat());
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(run_id);
    let outcome = block_on_ready(executor.run(&config));
    (outcome, backend.calls())
}

/// The summarize program: one call over the two NOTEs by id, then its card
/// as the run's answer.
fn summarize_program(a: &EntityId, b: &EntityId) -> String {
    format!(
        r#"const s = await summarize(null, {{note_refs: ["{a}", "{b}"]}}); finish(JSON.stringify(s));"#,
        a = a.to_hex(),
        b = b.to_hex(),
    )
}

/// The refused program catches the typed Denied as the bridge's thrown JSON
/// string, then finishes with its code. Any other error answers with the
/// `other:` prefix instead, so a wrong refusal cannot pass.
fn refused_program(a: &EntityId, b: &EntityId) -> String {
    format!(
        r#"try {{ await summarize(null, {{note_refs: ["{a}", "{b}"]}}); finish("summarized"); }} catch (error) {{ let code; try {{ code = JSON.parse(String(error)).denied; }} catch (_) {{ code = "other:" + String(error); }} finish("denied-caught:" + code); }}"#,
        a = a.to_hex(),
        b = b.to_hex(),
    )
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

/// The single-step entry returns its answer in the replay result. This short
/// fixture answer fits whole in the observation preview; the separate
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

/// The finished run's answer is the summary's card: it names the settled
/// task, carries a handle, and previews the stored digest.
fn assert_card_answer(answer: &str, task: &EntityId) {
    let card: serde_json::Value =
        serde_json::from_str(answer).expect("the answer parses as a card");
    let task_hex = task.to_hex();
    assert_eq!(
        card.get("task").and_then(serde_json::Value::as_str),
        Some(task_hex.as_str()),
        "the card names the settled task"
    );
    assert!(
        card.get("handle")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "the card carries a handle"
    );
    let preview = card.get("preview").and_then(serde_json::Value::as_str);
    assert!(
        preview.is_some_and(|preview| preview.contains(DIGEST)),
        "the card previews the stored digest"
    );
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

/// A summary over two NOTEs the caller reads answers one digest card: the
/// first call parks on its summary job; the test settles the job, reading
/// back each NOTE's own words as its members; the re-entered run's identical
/// call hits the memo and finishes with the card. Exactly one summary job is
/// ever queued.
#[test]
fn a_summary_over_two_named_notes_answers_one_digest_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    doors::install_actor_ceiling(&vault, &actor, "auto").expect("an auto ceiling");
    let note_a = vault
        .create_note(
            "research",
            A_TEXT,
            WriteActor::new(actor, EdgeActorClass::Agent),
        )
        .expect("NOTE A lands");
    let note_b = vault
        .create_note(
            "research",
            B_TEXT,
            WriteActor::new(actor, EdgeActorClass::Agent),
        )
        .expect("NOTE B lands");
    let runner = Arc::new(NotingRunner::default());
    vault.set_reader_job_runner(Arc::clone(&runner));
    let run_id = fresh_id();
    let program = summarize_program(&note_a, &note_b);

    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        actor,
        run_id,
        "run-summarize-note-set",
        vec![program.clone()],
    );
    let outcome = outcome.expect("the first call parks");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    assert_eq!(
        outcome.replay_record.bridge_calls[0].effect,
        SelfEffect::Summarize
    );
    let task = {
        let wakes = runner.wakes.lock().expect("wakes");
        assert_eq!(wakes.len(), 1, "one summary job was queued");
        wakes[0].task
    };
    match &outcome.status {
        EngineExecutorStatus::Waiting(wait) => {
            assert_eq!(wait.wait_id, task, "the run parks on the summary task");
            assert_eq!(wait.effect, SelfEffect::Summarize);
            assert!(
                matches!(wait.reason, SelfDurableWaitReason::PeerResult),
                "the run parks on a peer result"
            );
        }
        _ => panic!("the first call parks"),
    }

    // The test settles the job as its runner would: claim it, read its
    // members, store the digest, complete it. The members must be the two
    // NOTEs' own words in order: that is what proves the host read each
    // NOTE's text.
    let jobs = ReaderJobs::canonical(&vault);
    let generation = match jobs.claim(task, now_ms()).expect("the job claims") {
        ClaimOutcome::Claimed(job) => job.generation,
        outcome => panic!("the summary job claims, not {outcome:?}"),
    };
    let max_bytes = summary_token_budget(DEFAULT_READER_WINDOW_TOKENS)
        .saturating_mul(SUMMARY_READ_BYTES_PER_TOKEN);
    match jobs
        .summary_members(task, generation, max_bytes)
        .expect("the members read")
    {
        SummaryRead::Members(members) => {
            assert_eq!(members.len(), 2, "the summary reads both NOTEs");
            assert_eq!(
                members[0].text, A_TEXT,
                "the first member is NOTE A's words"
            );
            assert_eq!(
                members[1].text, B_TEXT,
                "the second member is NOTE B's words"
            );
        }
        SummaryRead::Refused(reason) => panic!("the members read, not refused: {reason}"),
    }
    assert_eq!(
        jobs.store_summary(task, generation, DIGEST)
            .expect("the digest stores"),
        Ok(()),
        "the digest is kept as the finding"
    );
    let state = jobs
        .complete(task, generation, ReaderRunEnd::Completed, now_ms())
        .expect("the job completes");
    assert_eq!(state, ReaderJobState::Done);
    assert!(
        jobs.queued(8).expect("the queue reads").is_empty(),
        "nothing stays queued"
    );

    // The re-entered run's identical call hits the memo: it completes with
    // the one digest card, and no second job is queued.
    let (retry, retry_calls) = execute_run(
        &vault,
        &factory,
        actor,
        run_id,
        "run-summarize-note-set",
        vec![program],
    );
    let retry = retry.expect("the re-entered run completes");
    assert_eq!(retry_calls, 1, "the resumed run asks the model again");
    assert_eq!(retry.status, EngineExecutorStatus::Complete);
    assert_eq!(
        runner.wakes.lock().expect("wakes").len(),
        1,
        "the memo hit queues no second job"
    );
    let job = jobs
        .job(task)
        .expect("the job reads")
        .expect("the settled job row stays");
    assert_eq!(job.state, ReaderJobState::Done);
    assert!(
        matches!(&job.kind, ReaderJobKind::Summarize { members, .. } if members.len() == 2),
        "the one job summarized the two NOTE members"
    );
    let answer =
        note_doors::observation_text(&vault, &run_id, 1).expect("the step-1 answer reads back");
    assert_card_answer(&answer, &task);
}

/// A NOTE the caller cannot read refuses the whole set: the call answers
/// the typed Denied, the program catches it, and no reader job is queued.
#[test]
fn a_note_the_caller_cannot_read_refuses_the_set() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let actor = seed_person(&vault);
    let other = seed_person(&vault);
    doors::install_actor_ceiling(&vault, &actor, "auto").expect("an auto ceiling");
    let note_a = vault
        .create_note(
            "research",
            A_TEXT,
            WriteActor::new(actor, EdgeActorClass::Agent),
        )
        .expect("NOTE A lands");
    let diary = vault
        .create_note(
            "diary",
            "The other keeper's private log.",
            WriteActor::new(other, EdgeActorClass::Agent),
        )
        .expect("the other actor's diary lands");
    let runner = Arc::new(NotingRunner::default());
    vault.set_reader_job_runner(Arc::clone(&runner));
    let run_id = fresh_id();

    let (outcome, calls) = execute_run(
        &vault,
        &factory,
        actor,
        run_id,
        "run-summarize-note-refused",
        vec![refused_program(&note_a, &diary)],
    );
    let outcome = outcome.expect("a refused summarize run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_returned_answer(&outcome, "denied-caught:summarize_note_unreadable");
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let row = &outcome.replay_record.bridge_calls[0];
    assert_eq!(row.effect, SelfEffect::Summarize);
    assert_eq!(
        recorded_outcome(&row.outcome),
        (Some("denied"), Some("summarize_note_unreadable"))
    );
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        "denied-caught:summarize_note_unreadable"
    );
    assert!(
        runner.wakes.lock().expect("wakes").is_empty(),
        "no reader job was queued"
    );
    assert!(
        ReaderJobs::canonical(&vault)
            .queued(8)
            .expect("the queue reads")
            .is_empty(),
        "no reader job was queued"
    );
}
