//! FIX 25025 (Engine RULING 22:31, option A): a skill-call post hook sees a
//! large skill answer's whole body, never only its card.
//!
//! 1. `a_post_hook_redacts_a_large_skill_answers_body_field`: a Redact post
//!    hook on `self.skills.call` hides `/output/title` of a >512 KiB skill
//!    answer. The guest reads the hooked body whole by its card (no
//!    `title`, the whole `text`), and no guessed `r<n>` and no occurrence
//!    ref derived from the run id and a bridge path reads the real body
//!    back. The bridge row holds a card of the real answer with no `name`,
//!    the record keeps its body, and no binding names that body. Red on
//!    the L8-13 head this stacks on: the answer is spilled and bound to
//!    `r1` before the post chain runs, so the hook judges the card alone,
//!    the title survives, and `r1` reads the real body.
//! 2. `a_post_hook_hiding_a_large_skill_answer_leaves_no_readable_body`:
//!    the same with a Redact of `/output`. The guest is shown no result,
//!    and again no guessed ref reads the body, while the row and record
//!    keep it as above. Red on that head for the same reason.
//! 3. `a_large_skill_answer_without_a_post_hook_still_arrives_as_a_card`:
//!    no hook bound: the answer still arrives as a card named `r1` whose
//!    body is the whole answer. Green on that head and with the fix.
//! 4. `an_admitted_answer_with_a_hook_for_another_class_still_arrives_as_a_card`
//!    (ASTRA F2): through the admitted entry (`execute_live_skill_call`),
//!    with the outer pre chain run as the generated facade runs it. The
//!    hook bound on the verb takes only Human callers and this caller is
//!    an Agent, so no chain is live: the answer and the record are
//!    exactly the no-hook ones (a bound readable card, no hook view
//!    served). On ae5c9088d10 the coarse verb-glob lookup took the whole
//!    path anyway: whole JSON back, body record-only and unbound,
//!    `hook_view_served` set with no view served.
//! 5. `an_admitted_answer_follows_the_outer_pre_chain_not_the_current_bindings`
//!    (ASTRA F1): the outer pre chain finds the hook live, the owner then
//!    turns the binding off before the admitted entry runs and back on
//!    before the outer post chain. The entry follows the pre chain's
//!    state it was given: the answer comes back whole for that chain,
//!    the record keeps it record-only with no name bound to it, and the
//!    post chain then hides its title. On ae5c9088d10 the entry re-read
//!    the (disabled) bindings, streamed the real body to a readable
//!    `r1`, persisted that binding, and answered the card.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features
//! --features oneiron-agent-runtime/code-sandbox-wasmtime
//! --test skill_post_hook_large_answer`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord, HostSelfDispatcher,
    ResultOccurrence, SkillCallInput,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult,
    EngineExecutorStatus, EngineNativeExecutor, JsCodeModeRuntime, execute_live_skill_call,
};
use oneiron::runtime_hooks::{InvocationId, VerbCall, VerbDomain, VerbHookPre, hook_class};
use oneiron::skill_hub::pack_catalog::HookActorClass;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::HostBinding;
use oneiron::test_doors::callable_skill;
use oneiron::test_doors::code_run_answer as doors;
use oneiron::test_doors::typed_reply_handle as handle_doors;
use oneiron::{
    AttemptId, AttemptQueue, BudgetLease, ContentPart, EntityId, FatalLlmError, FinishReason,
    LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig,
    WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use sha2::{Digest, Sha256};

/// The skill answer's title, which the first test's Redact hides.
const TAG: &str = "secret-title-7";
/// The answer's `text` length: its JSON is past `RESULT_REPLY_INLINE_BYTES`
/// (512 KiB) and past `message_bytes` (1 MiB).
const ANSWER_BYTES: usize = 1_572_864;
/// The lease owner this test claims its agent attempt as.
const WORKER: &str = "skill-post-hook-large-answer";

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
        task: "read the skill call's large answer".to_owned(),
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

/// Leases `id` to this test's worker. Rows are claimed oldest first, so a
/// row queued before it is claimed past.
fn claim(vault: &Vault, id: AttemptId) -> AttemptRecord {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: vault.now_recorded_at(),
                },
            )
            .expect("claim attempts")
        else {
            break;
        };
        if row.id == id {
            return queue
                .get(id)
                .expect("a claimed attempt reads")
                .expect("a claimed attempt reads back");
        }
    }
    panic!("the agent attempt is ready to claim");
}

/// One leased run of the seeded default agent for executor run `run_id`
/// (a callable runs only under its caller's leased run): its write actor
/// and its leased attempt.
fn leased_actor(vault: &Vault, run_id: EntityId) -> (WriteActor, AttemptRecord) {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("the seeded agent reads")
        .expect("the default agent is seeded");
    let spawn = AgentSpawnContext::default().with_depth_remaining(1);
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run_id.to_hex()),
                now: vault.now_recorded_at(),
            },
            spawn,
        )
        .expect("the agent dispatch lands")
    else {
        panic!("expected one fresh agent run");
    };
    let actor = agent_dispatch_actor(&status.input).expect("the run's actor");
    let attempt = claim(vault, status.attempt.id);
    (actor, attempt)
}

/// One entry of one durable run: a fresh backend holding `programs`, a
/// leased dispatcher lending the vault to callable skills, and a fresh
/// guest.
fn execute_run(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    run_id: EntityId,
    programs: Vec<String>,
) -> (EngineExecutorResult<EngineExecutorOutcome>, usize) {
    let backend = FixtureBackend::new(programs);
    let lease = BudgetLease::for_test("skill-post-hook-large-answer");
    let (actor, leased) = leased_actor(vault, run_id);
    let gated = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &leased)
        .expect("a leased dispatcher binds")
        .with_callable_skills(Arc::clone(vault))
        .expect("callable skills bind the run's vault");
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

/// A fresh entity id, UUIDv7 rather than a fixed byte pattern an open
/// vault already holds.
fn fresh_id() -> EntityId {
    EntityId::from_bytes(uuid::Uuid::now_v7().into_bytes()).expect("a test id")
}

/// Stores the active callable whose answer is `title` and a `text` of
/// `skillArgs.bytes` bytes of `b`, and answers its id.
fn large_skill(vault: &Vault) -> EntityId {
    let source = concat!(
        "finish(JSON.stringify({title:\"secret-title-7\",",
        "text:\"b\".repeat(skillArgs.bytes)}));",
    );
    callable_skill::put_active_callable(
        vault,
        "fixture.large-answer",
        source,
        &serde_json::json!({"bytes":"integer"}),
        &serde_json::json!({"title":"string","text":"string"}),
    )
    .expect("the large callable is stored and active")
}

/// Binds the Redact post hook on `self.skills.call` redacting `paths` and
/// installs its runtime, as `tests/typed_reply_handle.rs` binds its hook:
/// the bind is the owner's own write, signed with this install's key.
fn bind_redact_hook(vault: &Arc<Vault>, paths: Vec<String>) {
    bind_redact_hook_for_actors(vault, paths, Vec::new());
}

/// [`bind_redact_hook`] for a hook taking only calls by one of `actors`
/// (every class when empty), answering the binding and the owner's proof
/// so a test can work the owner's dial on the binding.
fn bind_redact_hook_for_actors(
    vault: &Arc<Vault>,
    paths: Vec<String>,
    actors: Vec<HookActorClass>,
) -> (EntityId, AuthenticatedOwner) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("this install's signing keys");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let binding = handle_doors::bind_redact_post_hook_for_actors(
        vault,
        owner,
        &proof,
        "self.skills.call",
        actors,
    )
    .expect("the Redact hook binds");
    handle_doors::install_redact_runtime(vault, paths).expect("the Redact runtime installs");
    (binding, proof)
}

/// The outer (host-door) pre chain of one admitted `self.skills.call` by
/// `actor`, as the generated facade runs it before its door: the chain
/// over the verb for this caller, on the call's own args.
fn outer_pre(vault: &Vault, actor: WriteActor, skill: EntityId) -> VerbHookPre {
    let call = VerbCall {
        verb: "self.skills.call".to_owned(),
        invocation: InvocationId::mint(),
        actor: actor.entity_ref(),
        class: hook_class(actor.actor_class()),
        scope: None,
        board_epoch: None,
        turn: None,
        domain: VerbDomain::Write,
        reader: None,
    };
    let args = serde_json::json!({"skill": skill.to_hex(), "args": {"bytes": ANSWER_BYTES}});
    let check = |_: &serde_json::Value| -> Result<(), String> { Ok(()) };
    vault
        .pre_verb_hooks(call, args, &check)
        .expect("the outer pre chain runs")
        .unwrap_or_else(|_| panic!("the outer pre chain lets the call run"))
}

/// The outer post chain over the admitted entry's `answer`, as the facade
/// runs it after its door: the caller's view of the answer.
fn outer_post(vault: &Vault, pre: VerbHookPre, answer: serde_json::Value) -> serde_json::Value {
    vault
        .post_verb_hooks(pre, answer)
        .expect("the outer post chain runs")
        .unwrap_or_else(|_| panic!("the outer post chain lets the answer through"))
}

/// One admitted (host-door) skill call on run `run_id` under its leased
/// attempt, between turns: the empty replay record a run between turns
/// holds is seeded first, then the entry runs with the outer pre chain's
/// state `outer_hooks_live`, as its generated caller gives it.
fn admitted_skill_call(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    run_id: EntityId,
    actor: WriteActor,
    leased: &AttemptRecord,
    skill: EntityId,
    outer_hooks_live: bool,
) -> serde_json::Value {
    let binding =
        HostBinding::from_leased(leased, Some(run_id)).expect("the leased run binds its door");
    let record = CodeRunReplayRecord::new(
        run_id,
        CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
    );
    vault
        .put_code_run_replay_record(&record)
        .expect("the run's empty replay record stands");
    let dispatcher = HostSelfDispatcher::for_live_run(vault, actor, &binding)
        .expect("a live-run dispatcher binds")
        .with_callable_skills(Arc::clone(vault))
        .expect("callable skills bind the run's vault");
    let model = ModelId::new("test/executor@v1").expect("a model id");
    let mut runtime = factory.runtime().expect("a guest runtime");
    let runtime: &mut dyn JsCodeModeRuntime = &mut runtime;
    execute_live_skill_call(
        vault,
        &binding,
        &dispatcher,
        &model,
        SkillCallInput {
            skill: skill.to_hex(),
            args: serde_json::json!({"bytes": ANSWER_BYTES}),
        },
        (runtime, None),
        outer_hooks_live,
    )
    .expect("the admitted skill call answers")
}

/// Run `run_id`'s replay record as the admitted entry left it.
fn admitted_record(vault: &Vault, run_id: &EntityId) -> CodeRunReplayRecord {
    vault
        .get_code_run_replay_record(run_id)
        .expect("the run record reads")
        .expect("the admitted call left its record")
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
        .expect("a skill call output");
    serde_json::from_str(text).expect("the output parses")
}

/// The occurrence refs a guest of run `run_id` derives with no card for
/// the bridge calls at positions `0..4`, as in
/// `tests/typed_reply_handle.rs`.
fn derived_bridge_refs(run_id: EntityId) -> Vec<String> {
    let mut refs = Vec::new();
    for seq in 0_u64..4 {
        for path in [
            format!("executor/repl/bridge/{seq:06}.result.json"),
            format!("executor/repl/bridge/{seq:06}.record-only.json"),
        ] {
            let occurrence = ResultOccurrence::owned(run_id, &path).expect("an occurrence id");
            refs.push(format!("occurrence:{}", occurrence.id().to_hex()));
        }
    }
    refs
}

/// `program` with the callable's id and the derived refs filled in.
fn program_with(program: &str, skill: EntityId, refs: &[String]) -> String {
    program.replace("__SKILL__", &skill.to_hex()).replace(
        "__REFS__",
        &serde_json::to_string(refs).expect("the refs encode"),
    )
}

/// The guesses a guest reads back after the call: sets `secret` in its
/// scope when any `describe` or `slice` of a guessed name or derived ref
/// shows the secret title.
const GUESSES: &str = r#"const probes = [];
for (let n = 1; n <= 8; n++) probes.push("r" + n);
for (const ref of __REFS__) probes.push(ref);
for (const probe of probes) {
  try {
    const d = await describe(probe);
    if (JSON.stringify(d).includes("secret-title-")) secret = true;
  } catch (e) {
    if (String(e).includes("secret-title-")) secret = true;
  }
  try {
    const s = await slice(probe, {bytes: [0, 256]});
    if (JSON.stringify(s).includes("secret-title-")) secret = true;
  } catch (e) {
    if (String(e).includes("secret-title-")) secret = true;
  }
}"#;

/// The redacted-field program: it calls the skill, reads the reply card's
/// body whole through `slice`, probes every guessed ref, and finishes
/// with what it saw.
const REDACT_PROGRAM: &str = r#"let out = null, callError = null;
try {
  out = await self.skills.call({skill: "__SKILL__", args: {bytes: 1572864}});
} catch (e) {
  callError = String(e).slice(0, 120);
}
if (callError !== null) {
  finish("call-threw:" + callError);
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
        let secret = false;
        __GUESSES__
        finish("card:has-title:" + hasTitle + ":text-len:" + textLen
          + ":secret-guessed:" + secret);
        break;
      }
      next = piece.next;
    }
  }
}"#;

/// The hidden-result program: it calls the skill (shown nothing, so the
/// call may throw), then probes every guessed ref.
const HIDDEN_PROGRAM: &str = r#"let out = null, callError = null;
try {
  out = await self.skills.call({skill: "__SKILL__", args: {bytes: 1572864}});
} catch (e) {
  callError = String(e).slice(0, 120);
}
let secret = false;
const shown = typeof out === "undefined" ? "" : JSON.stringify(out);
if (shown && shown.includes("secret-title-")) secret = true;
if (callError !== null && callError.includes("secret-title-")) secret = true;
__GUESSES__
finish("hidden:call-threw:" + (callError !== null) + ":secret-guessed:" + secret);"#;

/// The control program: it calls the skill, checks the reply is a card,
/// and reads the body's head through `slice`.
const CONTROL_PROGRAM: &str = r#"let out = null, callError = null;
try {
  out = await self.skills.call({skill: "__SKILL__", args: {bytes: 1572864}});
} catch (e) {
  callError = String(e).slice(0, 120);
}
if (callError !== null) {
  finish("call-threw:" + callError);
} else {
  const isCard = out && typeof out === "object"
    && typeof out.handle === "string" && typeof out.bytes === "number";
  if (!isCard) {
    finish("not-a-card:" + JSON.stringify(out).slice(0, 200));
  } else {
    const head = await slice(out, {bytes: [0, 4096]});
    const prefixOk = typeof head.text === "string"
      && head.text.includes("\"title\":\"secret-title-7\"")
      && head.text.includes("\"text\":\"bbbbbbbb");
    finish("card:bytes:" + out.bytes + ":prefix-ok:" + prefixOk);
  }
}"#;

/// Asserts the one bridge row holds a card of the real answer with no
/// name, the record keeps that body, and no binding names it.
fn assert_record_only(outcome: &EngineExecutorOutcome) {
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let output = bridge_output(&outcome.replay_record.bridge_calls[0]);
    let handle = output
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the replay row holds a card of the real answer: {output}"));
    assert!(
        output.get("name").is_none(),
        "the recorded real card carries no name: {output}",
    );
    assert!(
        outcome
            .replay_record
            .outputs
            .iter()
            .any(|kept| kept.handle == handle),
        "the record keeps the real answer's body",
    );
    assert!(
        !outcome
            .replay_record
            .bindings
            .iter()
            .any(|binding| binding.handle == handle),
        "no binding names the real answer's body",
    );
}

#[test]
fn a_post_hook_redacts_a_large_skill_answers_body_field() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = large_skill(&vault);
    bind_redact_hook(&vault, vec!["/output/title".to_owned()]);
    let run_id = fresh_id();
    let program = program_with(
        &REDACT_PROGRAM.replace("__GUESSES__", GUESSES),
        skill,
        &derived_bridge_refs(run_id),
    );

    let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        format!("card:has-title:false:text-len:{ANSWER_BYTES}:secret-guessed:false"),
    );
    assert_record_only(&outcome);
}

#[test]
fn a_post_hook_hiding_a_large_skill_answer_leaves_no_readable_body() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = large_skill(&vault);
    bind_redact_hook(&vault, vec!["/output".to_owned()]);
    let run_id = fresh_id();
    let program = program_with(
        &HIDDEN_PROGRAM.replace("__GUESSES__", GUESSES),
        skill,
        &derived_bridge_refs(run_id),
    );

    let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let text = doors::finish_text(&vault, &run_id).expect("the answer reads back");
    assert!(
        text.starts_with("hidden:") && text.contains(":secret-guessed:false"),
        "no guessed read returned the body:\n{text}",
    );
    assert!(
        !text.contains(TAG),
        "no read returned the secret title:\n{text}"
    );
    assert_record_only(&outcome);
}

#[test]
fn a_large_skill_answer_without_a_post_hook_still_arrives_as_a_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = large_skill(&vault);
    let run_id = fresh_id();
    let program = program_with(CONTROL_PROGRAM, skill, &[]);

    let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let expected = serde_json::json!({"title": TAG, "text": "b".repeat(ANSWER_BYTES)}).to_string();
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
        "the large answer arrives as a card: {output}",
    );
    assert_eq!(
        output.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
}

#[test]
fn an_admitted_answer_with_a_hook_for_another_class_still_arrives_as_a_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = large_skill(&vault);
    // The only hook on the verb takes Human callers; this run's caller is
    // an Agent, so its outer chain cannot take the call at all.
    bind_redact_hook_for_actors(
        &vault,
        vec!["/title".to_owned()],
        vec![HookActorClass::Human],
    );
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);
    assert_eq!(
        hook_class(actor.actor_class()),
        HookActorClass::Agent,
        "the run's caller is the class the hook cannot take",
    );

    let pre = outer_pre(&vault, actor, skill);
    assert!(
        pre.passed_through(),
        "a Human-only hook leaves an Agent caller's chain passed through",
    );
    let answer = admitted_skill_call(
        &vault,
        &factory,
        run_id,
        actor,
        &leased,
        skill,
        !pre.passed_through(),
    );
    let view = outer_post(&vault, pre, answer.clone());
    assert_eq!(view, answer, "no live chain, so the caller sees the answer");

    // Exactly the no-hook answer: the whole body by its bound card.
    let expected = serde_json::json!({"title": TAG, "text": "b".repeat(ANSWER_BYTES)}).to_string();
    assert_eq!(
        answer.get("bytes").and_then(serde_json::Value::as_u64),
        Some(expected.len() as u64),
        "the answer is the large body's card: {}",
        answer.to_string().chars().take(200).collect::<String>(),
    );
    assert_eq!(
        answer.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
    let handle = answer
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .expect("the card carries its handle");

    // And exactly the no-hook record: a readable bound body, no view served.
    let record = admitted_record(&vault, &run_id);
    assert_eq!(record.bridge_calls.len(), 1);
    let row = &record.bridge_calls[0];
    assert!(!row.hook_view_served, "no hook view was served");
    let output = bridge_output(row);
    assert_eq!(
        output.get("handle").and_then(serde_json::Value::as_str),
        Some(handle),
    );
    assert_eq!(
        output.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
    assert!(
        record
            .outputs
            .iter()
            .any(|kept| kept.path == "executor/repl/bridge/000000.result.json"),
        "the body stands at the readable bridge-result path",
    );
    assert!(
        !record
            .outputs
            .iter()
            .any(|kept| kept.path.ends_with(".record-only.json")),
        "nothing spills record-only with no live chain",
    );
    assert!(
        record
            .bindings
            .iter()
            .any(|binding| binding.name == "r1" && binding.handle == handle),
        "the card's name binds the readable body",
    );
}

#[test]
fn an_admitted_answer_follows_the_outer_pre_chain_not_the_current_bindings() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = large_skill(&vault);
    let (binding, proof) =
        bind_redact_hook_for_actors(&vault, vec!["/title".to_owned()], Vec::new());
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);

    // The outer pre chain finds the hook live for this caller. The owner
    // then turns the binding off, before the admitted entry runs: a fresh
    // read of the bindings now says no hook may run.
    let pre = outer_pre(&vault, actor, skill);
    assert!(
        !pre.passed_through(),
        "the outer pre chain found its post hook live",
    );
    vault
        .set_pack_hook_enabled(&proof, binding, false)
        .expect("the owner turns the binding off");

    let answer = admitted_skill_call(
        &vault,
        &factory,
        run_id,
        actor,
        &leased,
        skill,
        !pre.passed_through(),
    );

    // The entry followed the state it was given, not the bindings: the
    // caller (whose post chain runs next) holds the whole answer, never
    // a card, and the record binds no readable name to the real body.
    assert_eq!(
        answer.get("title").and_then(serde_json::Value::as_str),
        Some(TAG),
        "the outer chain is handed the whole answer",
    );
    assert_eq!(
        answer
            .get("text")
            .and_then(serde_json::Value::as_str)
            .map(str::len),
        Some(ANSWER_BYTES),
    );
    assert!(
        answer.get("handle").is_none() && answer.get("name").is_none(),
        "the whole answer is no card",
    );
    let record = admitted_record(&vault, &run_id);
    assert_eq!(record.bridge_calls.len(), 1);
    let row = &record.bridge_calls[0];
    assert!(row.hook_view_served, "the row stands as a view-served row");
    let output = bridge_output(row);
    let handle = output
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the replay row holds a card of the real answer: {output}"));
    assert!(
        output.get("name").is_none(),
        "the recorded real card carries no name: {output}",
    );
    assert!(
        record
            .outputs
            .iter()
            .any(|kept| kept.path == "executor/repl/bridge/000000.record-only.json"),
        "the real body stands record-only",
    );
    assert!(
        !record
            .outputs
            .iter()
            .any(|kept| kept.path.ends_with(".result.json")),
        "no readable bridge-result body stands for the real answer",
    );
    assert!(
        !record.bindings.iter().any(|bound| bound.handle == handle),
        "no binding names the real answer's body",
    );

    // The owner turns the binding back on before the outer post chain:
    // it judges the whole answer and hides the title.
    vault
        .set_pack_hook_enabled(&proof, binding, true)
        .expect("the owner turns the binding back on");
    let view = outer_post(&vault, pre, answer);
    assert!(
        view.get("title").is_none(),
        "the outer post chain hides the title: {}",
        view.to_string().chars().take(200).collect::<String>(),
    );
    assert_eq!(
        view.get("text")
            .and_then(serde_json::Value::as_str)
            .map(str::len),
        Some(ANSWER_BYTES),
    );
}
