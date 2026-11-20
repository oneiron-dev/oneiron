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
//! 6. `a_blocking_post_hook_that_cannot_judge_a_large_answer_refuses_the_call`
//!    (P1-A): the same >512 KiB answer, past the 1 MiB hook input cap,
//!    under a live BLOCKING Redact post hook whose runtime caps inputs as
//!    the real sandbox does. The hook cannot judge the answer, so the call
//!    is refused with the cause instead of serving the unredacted body:
//!    the guest reads the denial (never the title, never a card), no
//!    guessed ref reads the body, and the row and record keep it as in 1.
//!    Red without the fix: the failed blocking hook only records on the
//!    write, the guest reads a bound `r1` card for the unredacted body,
//!    and the title survives.
//! 7. `a_live_post_chain_refuses_a_too_deep_answer_precisely_never_as_non_json`
//!    (P1-B): through the admitted entry with its outer post chain live, a
//!    >512 KiB object answer nesting 150 arrays deep (valid JSON the spool
//!    check accepts, past the whole-answer parser's depth limit) is refused
//!    with the precise depth cause, never reported as non-JSON. Red without
//!    the fix: the refusal says non-JSON for valid JSON.
//! 8. `real_sandbox::a_two_mib_skill_answer_reaches_its_blocking_post_hook_redacted`
//!    ([SKILL-POST-HOOK-INPUT-BODY-CHANNEL]): a 2 MiB answer under a
//!    blocking Redact post hook running in the real hook sandbox comes back
//!    redacted: the hook input is held to the guest's memory, not to the
//!    1 MiB body cap. Red on main: the input passes the 1 MiB cap, the
//!    call is refused as in 6.
//! 9. `real_sandbox::a_skill_answer_its_hook_guest_cannot_hold_is_refused_unjudged`:
//!    a 3 MB answer of a million empty arrays passes the host's input
//!    limit (the guest's measured memory room) but not the guest's
//!    interpreter heap: the guest reports it not taken and the call is
//!    refused as in 6. Green on main too.
//! 10. `a_deep_skill_answer_without_a_post_hook_arrives_as_a_card`
//!     ([SKILL-ANSWER-DEEP-JSON-STACK-SAFE]): a small answer nesting 150
//!     arrays deep, past the whole-answer parser's depth, with no hook
//!     bound, reaches the program as a card named `r1` whose body is the
//!     whole answer, which the guest parses itself. No host value follows
//!     its depth. Red on main: the call is refused, "nests too deep to
//!     read whole".
//! 11. `an_admitted_deep_answer_without_a_live_chain_arrives_as_a_card`:
//!     the same answer through the admitted entry with no outer chain
//!     live: the bound card of the readable body, exactly as a large
//!     answer arrives (4). Red on main as in 10.
//!
//! Part 2a of [SKILL-ANSWER-DEEP-JSON-STACK-SAFE]: the call's own post
//! chain judges such an answer as JSON text, never read into a value. Red
//! at the red pin (this head with the host's refusal of a deep answer under
//! a live chain, and the sandbox's typed reading of a stack trap, put back):
//! the call is refused before any hook, "nests too deep".
//! 12. `a_post_hook_redacts_a_deep_skill_answer_held_as_text`: a Redact of
//!     `/output/pad` over the 150-deep answer: the guest reads the redacted
//!     body by its card, its whole depth kept; the real body is record-only.
//! 13. `a_post_hook_that_hides_nothing_leaves_a_deep_answer_its_named_card`:
//!     a Redact naming nothing: the guest reads the answer's own body by its
//!     card `r1`, and no hook view is served.
//! 14. `a_redact_path_through_a_deep_answer_masks_its_innermost_leaf`: a
//!     path through all 150 levels masks the leaf.
//! 15. `a_hook_input_carries_a_deep_answer_verbatim`: the hook's input holds
//!     the answer's text as the skill wrote it.
//! 16. `a_redact_over_a_text_view_matches_the_redact_over_its_value` and
//!     17. `a_redact_over_a_text_view_keeps_no_stack_for_its_depth` (the
//!     codec, coverage): the text Redact gives the value Redact's view,
//!     members in the same order, and walks 100,000 levels on a test
//!     thread's stack.
//! 18. `real_sandbox::a_deep_skill_answer_reaches_its_blocking_post_hook_redacted`:
//!     12 with the real hook sandbox and the staged blocking body.
//! 19. `real_sandbox::a_skill_answer_nesting_past_the_hook_guest_stack_is_refused_unjudged`:
//!     a million levels pass the hook guest's stack: the chain refuses the
//!     call, naming the nesting, and the caller never reads the answer.
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
/// The deep answer's `pad` length: its JSON is past `RESULT_REPLY_INLINE_BYTES`
/// (512 KiB) but well under `message_bytes` (1 MiB), so only its nesting
/// refuses it.
const DEEP_PAD_BYTES: usize = 614_400;
/// The deep answer's nesting: arrays around `0` under `deep`, past the
/// whole-answer parser's depth limit.
const DEEP_LEVELS: usize = 150;
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

/// Stores the active callable whose answer is an object with a `pad` of
/// `skillArgs.bytes` bytes of `b` and `deep`, 150 nested arrays around `0`:
/// valid JSON past the inline size and past the whole-answer parser's depth
/// limit, under the `object` return contract. Answers its id.
fn deep_skill(vault: &Vault) -> EntityId {
    let source = format!(
        r#"let deep = 0;for (let i = 0; i < {DEEP_LEVELS}; i++) deep = [deep];finish(JSON.stringify({{pad:"b".repeat(skillArgs.bytes),deep}}));"#,
    );
    callable_skill::put_active_callable(
        vault,
        "fixture.deep-answer",
        &source,
        &serde_json::json!({"bytes":"integer"}),
        &serde_json::json!("object"),
    )
    .expect("the deep callable is stored and active")
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
    let bound = bind_redact_binding(vault, actors);
    handle_doors::install_redact_runtime(vault, paths).expect("the Redact runtime installs");
    bound
}

/// Binds the non-blocking Redact post hook on `self.skills.call` for
/// `actors`, as [`bind_redact_hook_for_actors`] does, and installs no
/// runtime.
fn bind_redact_binding(
    vault: &Arc<Vault>,
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
    (binding, proof)
}

/// Binds the BLOCKING Redact post hook on `self.skills.call` redacting
/// `paths` and installs its input-capped runtime, as
/// [`bind_redact_hook_for_actors`] binds its hook: the bind is the owner's
/// own write, signed with this install's key. The runtime caps hook inputs
/// at `message_bytes`, as the real sandbox does, so a hook whose input
/// passes it fails the run before its body starts.
fn bind_blocking_capped_hook(vault: &Arc<Vault>, paths: Vec<String>, message_bytes: usize) {
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
    handle_doors::bind_blocking_redact_post_hook(vault, owner, &proof, "self.skills.call")
        .expect("the blocking Redact hook binds");
    handle_doors::install_capped_redact_runtime(vault, paths, message_bytes)
        .expect("the capped Redact runtime installs");
}

/// The outer (host-door) pre chain of one admitted `self.skills.call` by
/// `actor`, as the generated facade runs it before its door: the chain
/// over the verb for this caller, on the call's own args.
fn outer_pre(vault: &Vault, actor: WriteActor, skill: EntityId) -> VerbHookPre {
    outer_pre_with_bytes(vault, actor, skill, ANSWER_BYTES)
}

/// [`outer_pre`] for a call whose skill args carry `bytes`.
fn outer_pre_with_bytes(
    vault: &Vault,
    actor: WriteActor,
    skill: EntityId,
    bytes: usize,
) -> VerbHookPre {
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
    let args = serde_json::json!({"skill": skill.to_hex(), "args": {"bytes": bytes}});
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
    admitted_skill_call_result(
        vault,
        factory,
        run_id,
        actor,
        leased,
        skill,
        ANSWER_BYTES,
        outer_hooks_live,
    )
    .expect("the admitted skill call answers")
}

/// [`admitted_skill_call`] for a call whose skill args carry `bytes`,
/// answering the entry's result itself, so a test can read a refusal.
#[allow(clippy::too_many_arguments)]
fn admitted_skill_call_result(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    run_id: EntityId,
    actor: WriteActor,
    leased: &AttemptRecord,
    skill: EntityId,
    bytes: usize,
    outer_hooks_live: bool,
) -> oneiron::memory::MemoryResult<serde_json::Value> {
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
            args: serde_json::json!({"bytes": bytes}),
        },
        (runtime, None),
        outer_hooks_live,
    )
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

/// A bridge row's failed outcome as its kind and error: the `kind` and
/// `error` members of the recorded outcome map.
fn bridge_failed_error(row: &CodeRunBridgeCall) -> (String, String) {
    let rmpv::Value::Map(entries) = &row.outcome else {
        panic!("bridge outcome is a map");
    };
    let member = |name: &str| {
        entries
            .iter()
            .find_map(|(key, value)| {
                if key.as_str() == Some(name) {
                    value.as_str()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("a failed outcome names {name}"))
            .to_owned()
    };
    (member("kind"), member("error"))
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

/// The refused-call program: it calls the skill, which its blocking post
/// hook cannot judge whole, then probes every guessed ref. The call is
/// refused: the guest reads the denial (or the call throws it, which the
/// finish text keeps after `:thrown:`), never the answer and never a card
/// for it.
const DENIED_PROGRAM: &str = r#"let out = null, callError = null;
try {
  out = await self.skills.call({skill: "__SKILL__", args: {bytes: 1572864}});
} catch (e) {
  callError = String(e).slice(0, 600);
}
let secret = false;
const shown = typeof out === "undefined" ? "" : JSON.stringify(out);
if (shown && shown.includes("secret-title-")) secret = true;
if (callError !== null && callError.includes("secret-title-")) secret = true;
__GUESSES__
const denied = out && typeof out === "object" && typeof out.denied === "string" ? out.denied : "";
const cause = out && typeof out === "object" && out.reasonCodes ? JSON.stringify(out.reasonCodes).slice(0, 200) : "";
finish("denied:" + denied + ":cause:" + cause + ":call-threw:" + (callError !== null) + ":secret-guessed:" + secret + ":thrown:" + (callError ?? ""));"#;

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

#[test]
fn a_blocking_post_hook_that_cannot_judge_a_large_answer_refuses_the_call() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = large_skill(&vault);
    // The blocking Redact takes the call, but its input — the whole >1 MiB
    // answer — passes the cap its runtime enforces as the real sandbox
    // does, so the hook never judges it.
    bind_blocking_capped_hook(&vault, vec!["/output/title".to_owned()], 1024 * 1024);
    let run_id = fresh_id();
    let program = program_with(
        &DENIED_PROGRAM.replace("__GUESSES__", GUESSES),
        skill,
        &derived_bridge_refs(run_id),
    );

    let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let text = doors::finish_text(&vault, &run_id).expect("the answer reads back");
    assert!(
        text.contains(":secret-guessed:false"),
        "no guessed read returned the body:\n{text}",
    );
    assert!(
        !text.contains(TAG),
        "no read returned the secret title:\n{text}"
    );
    assert!(
        text.contains("verb_hook_skipped") || text.contains(":call-threw:true"),
        "the guest reads the refusal, never the answer:\n{text}",
    );
    assert!(
        text.contains("too large for the live post hook to judge")
            || text.contains(":call-threw:true"),
        "the refusal names its cause:\n{text}",
    );
    // The real body records record-only, exactly as a served view leaves
    // it: a nameless card, its body kept, no binding naming it.
    assert_record_only(&outcome);
    assert!(
        outcome.replay_record.bridge_calls[0].hook_view_served,
        "the row stands as a view-served row",
    );
}

#[test]
fn a_live_post_chain_refuses_a_too_deep_answer_precisely_never_as_non_json() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    // A live post chain over the call: the admitted entry reads the answer
    // whole for it. The runtime caps nothing here; the refusal below comes
    // from the answer's own nesting, before any hook runs.
    bind_redact_hook(&vault, vec!["/output/title".to_owned()]);
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);

    let pre = outer_pre_with_bytes(&vault, actor, skill, DEEP_PAD_BYTES);
    assert!(
        !pre.passed_through(),
        "the outer pre chain found its post hook live",
    );
    let refused = admitted_skill_call_result(
        &vault,
        &factory,
        run_id,
        actor,
        &leased,
        skill,
        DEEP_PAD_BYTES,
        !pre.passed_through(),
    )
    .expect_err("a too-deep answer under a live post chain is refused");
    assert!(
        refused.message.contains("nests too deep"),
        "the refusal names the depth cause:\n{}",
        refused.message,
    );
    assert!(
        !refused.message.contains("non-JSON"),
        "valid JSON is never reported as non-JSON:\n{}",
        refused.message,
    );

    // The record keeps the refusal's cause on its failed row, and binds no
    // readable body for the answer no hook judged.
    let record = admitted_record(&vault, &run_id);
    assert_eq!(record.bridge_calls.len(), 1);
    let (kind, error) = bridge_failed_error(&record.bridge_calls[0]);
    assert_eq!(kind, "failed");
    assert!(
        error.contains("nests too deep"),
        "the failed row names the depth cause:\n{error}",
    );
    assert!(
        !error.contains("non-JSON"),
        "the failed row never reports non-JSON:\n{error}",
    );
    assert!(
        record.bindings.is_empty(),
        "no binding names a body for the refused answer",
    );
}

/// The small deep answer's `pad` length: its JSON is far under
/// `RESULT_REPLY_INLINE_BYTES`, so only its nesting keeps it from the
/// inline reply.
const DEEP_SMALL_PAD_BYTES: usize = 16;

/// The deep skill's answer for a `pad` of `bytes` bytes, as its program
/// writes it: `pad`, then `deep`, [`DEEP_LEVELS`] arrays around `0`.
fn deep_answer_text(bytes: usize) -> String {
    format!(
        r#"{{"pad":"{}","deep":{}0{}}}"#,
        "b".repeat(bytes),
        "[".repeat(DEEP_LEVELS),
        "]".repeat(DEEP_LEVELS),
    )
}

/// The deep-card program: it calls the deep skill with a small pad,
/// checks the reply is a card, reads its body through `slice`, parses it
/// itself, and finishes with the card's size, the body's nesting under
/// `deep` and its leaf.
const DEEP_CARD_PROGRAM: &str = r#"let out = null, callError = null;
try {
  out = await self.skills.call({skill: "__SKILL__", args: {bytes: __BYTES__}});
} catch (e) {
  callError = String(e).slice(0, 160);
}
if (callError !== null) {
  finish("call-threw:" + callError);
} else {
  const isCard = out && typeof out === "object"
    && typeof out.handle === "string" && typeof out.bytes === "number";
  if (!isCard) {
    finish("not-a-card:" + JSON.stringify(out).slice(0, 200));
  } else {
    const piece = await slice(out, {bytes: [0, 4096]});
    let depth = 0, node = null;
    if (typeof piece.text === "string") {
      node = JSON.parse(piece.text).deep;
      while (Array.isArray(node)) {
        depth++;
        node = node[0];
      }
    }
    finish("card:bytes:" + out.bytes + ":depth:" + depth + ":leaf:" + node);
  }
}"#;

#[test]
fn a_deep_skill_answer_without_a_post_hook_arrives_as_a_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    let run_id = fresh_id();
    let program = program_with(DEEP_CARD_PROGRAM, skill, &[])
        .replace("__BYTES__", &DEEP_SMALL_PAD_BYTES.to_string());

    let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let expected = deep_answer_text(DEEP_SMALL_PAD_BYTES);
    assert_eq!(
        doors::finish_text(&vault, &run_id).expect("the answer reads back"),
        format!("card:bytes:{}:depth:{DEEP_LEVELS}:leaf:0", expected.len()),
    );
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    let output = bridge_output(&outcome.replay_record.bridge_calls[0]);
    assert!(
        output
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "the deep answer arrives as a card: {output}",
    );
    assert_eq!(
        output.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
}

#[test]
fn an_admitted_deep_answer_without_a_live_chain_arrives_as_a_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);

    let pre = outer_pre_with_bytes(&vault, actor, skill, DEEP_SMALL_PAD_BYTES);
    assert!(
        pre.passed_through(),
        "no hook is bound, so the outer chain passes through",
    );
    let answer = admitted_skill_call_result(
        &vault,
        &factory,
        run_id,
        actor,
        &leased,
        skill,
        DEEP_SMALL_PAD_BYTES,
        !pre.passed_through(),
    )
    .expect("the admitted deep answer arrives");
    let view = outer_post(&vault, pre, answer.clone());
    assert_eq!(view, answer, "no live chain, so the caller sees the answer");

    let expected = deep_answer_text(DEEP_SMALL_PAD_BYTES);
    assert_eq!(
        answer.get("bytes").and_then(serde_json::Value::as_u64),
        Some(expected.len() as u64),
        "the answer is the deep body's card: {answer}",
    );
    assert_eq!(
        answer.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
    let handle = answer
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .expect("the card carries its handle");
    let record = admitted_record(&vault, &run_id);
    assert_eq!(record.bridge_calls.len(), 1);
    assert!(
        !record.bridge_calls[0].hook_view_served,
        "no hook view was served",
    );
    assert!(
        record
            .bindings
            .iter()
            .any(|binding| binding.name == "r1" && binding.handle == handle),
        "the card's name binds the readable body",
    );
}

/// The deep-view program: it calls the skill with args `__ARGS__`, checks
/// the reply is a card, reads its body through `slice`, parses it itself,
/// and finishes with whether the body still holds `__FIELD__`, the body's
/// nesting under `deep` and its leaf.
const DEEP_VIEW_PROGRAM: &str = r#"let out = null, callError = null;
try {
  out = await self.skills.call({skill: "__SKILL__", args: __ARGS__});
} catch (e) {
  callError = String(e).slice(0, 300);
}
if (callError !== null) {
  finish("call-threw:" + callError);
} else {
  const isCard = out && typeof out === "object"
    && typeof out.handle === "string" && typeof out.bytes === "number";
  if (!isCard) {
    finish("not-a-card:" + JSON.stringify(out).slice(0, 300));
  } else {
    const piece = await slice(out, {bytes: [0, 65536]});
    let depth = 0, node = null, held = null;
    if (typeof piece.text === "string") {
      const body = JSON.parse(piece.text);
      held = "__FIELD__" in body;
      node = body.deep;
      while (Array.isArray(node)) {
        depth++;
        node = node[0];
      }
    }
    finish("card:has-__FIELD__:" + held + ":depth:" + depth + ":leaf:" + node);
  }
}"#;

/// [`DEEP_VIEW_PROGRAM`] for a call to [`deep_skill`] with a small pad,
/// reporting whether the body it reads holds `pad`.
fn deep_view_program(skill: EntityId) -> String {
    program_with(DEEP_VIEW_PROGRAM, skill, &[])
        .replace("__ARGS__", &format!("{{bytes: {DEEP_SMALL_PAD_BYTES}}}"))
        .replace("__FIELD__", "pad")
}

/// Binds the non-blocking Redact post hook on `self.skills.call` with the
/// runtime that redacts `paths` only when its input holds `needle`.
fn bind_input_match_hook(vault: &Arc<Vault>, paths: Vec<String>, needle: String) {
    bind_redact_binding(vault, Vec::new());
    handle_doors::install_input_match_redact_runtime(vault, paths, needle)
        .expect("the input-match Redact runtime installs");
}

/// Runs `program` as the run's one program and answers its outcome, once
/// it completed, and its finish text.
fn run_deep_program(
    vault: &Arc<Vault>,
    factory: &QuickJsRuntimeFactory,
    program: String,
) -> (EngineExecutorOutcome, String) {
    let run_id = fresh_id();
    let (outcome, calls) = execute_run(vault, factory, run_id, vec![program]);
    let outcome = outcome.expect("the run completes");
    assert_eq!(calls, 1, "one turn runs one program");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let text = doors::finish_text(vault, &run_id).expect("the answer reads back");
    (outcome, text)
}

#[test]
fn a_post_hook_redacts_a_deep_skill_answer_held_as_text() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    bind_redact_hook(&vault, vec!["/output/pad".to_owned()]);

    let (outcome, text) = run_deep_program(&vault, &factory, deep_view_program(skill));
    assert_eq!(
        text,
        format!("card:has-pad:false:depth:{DEEP_LEVELS}:leaf:0"),
        "the guest reads the redacted view, its whole depth kept",
    );
    // The real answer records record-only, exactly as a served view leaves
    // it: a nameless card, its body kept, no binding naming it.
    assert_record_only(&outcome);
    assert!(
        outcome.replay_record.bridge_calls[0].hook_view_served,
        "the row stands as a view-served row",
    );
}

#[test]
fn a_post_hook_that_hides_nothing_leaves_a_deep_answer_its_named_card() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    bind_redact_hook(&vault, vec!["/output/absent".to_owned()]);

    let (outcome, text) = run_deep_program(&vault, &factory, deep_view_program(skill));
    assert_eq!(
        text,
        format!("card:has-pad:true:depth:{DEEP_LEVELS}:leaf:0"),
        "the guest reads the answer itself",
    );
    let row = &outcome.replay_record.bridge_calls[0];
    assert!(!row.hook_view_served, "no hook view was served");
    let output = bridge_output(row);
    let handle = output
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the row holds the answer's card: {output}"));
    assert_eq!(
        output.get("name").and_then(serde_json::Value::as_str),
        Some("r1"),
    );
    assert!(
        outcome
            .replay_record
            .bindings
            .iter()
            .any(|binding| binding.name == "r1" && binding.handle == handle),
        "the card's name binds the answer's body",
    );
}

#[test]
fn a_redact_path_through_a_deep_answer_masks_its_innermost_leaf() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    // `deep` and then one `0` per array: the leaf inside the innermost one.
    let path = format!("/output/deep{}", "/0".repeat(DEEP_LEVELS));
    bind_redact_hook(&vault, vec![path]);

    let (outcome, text) = run_deep_program(&vault, &factory, deep_view_program(skill));
    assert_eq!(
        text,
        format!("card:has-pad:true:depth:{DEEP_LEVELS}:leaf:null"),
        "the path walks the whole depth and masks the leaf",
    );
    assert_record_only(&outcome);
}

#[test]
fn a_hook_input_carries_a_deep_answer_verbatim() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    let skill = deep_skill(&vault);
    let needle = format!(
        "\"deep\":{}0{}",
        "[".repeat(DEEP_LEVELS),
        "]".repeat(DEEP_LEVELS),
    );
    bind_input_match_hook(&vault, vec!["/output/pad".to_owned()], needle);

    let (_outcome, text) = run_deep_program(&vault, &factory, deep_view_program(skill));
    assert_eq!(
        text,
        format!("card:has-pad:false:depth:{DEEP_LEVELS}:leaf:0"),
        "the hook's input held the answer's text as the skill wrote it",
    );
}

/// What one Redact does to `text` held as JSON text, against what it does
/// to the same view as a value: the same view, members in the same order,
/// and `None` exactly when the value is unchanged.
fn assert_text_redact_matches_value(text: &str, paths: &[&str]) {
    let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
    let before: serde_json::Value = serde_json::from_str(text).expect("the case parses");
    let mut after = before.clone();
    handle_doors::redact_view_value(&mut after, &paths);
    let redacted = handle_doors::redact_view_text(text, &paths).expect("the text redacts");
    match redacted {
        None => assert_eq!(
            after, before,
            "{text} {paths:?}: the text hid nothing, the value nothing"
        ),
        Some(redacted) => {
            assert_ne!(
                after, before,
                "{text} {paths:?}: the text hid what the value kept"
            );
            let read: serde_json::Value =
                serde_json::from_str(&redacted).expect("the redacted text parses");
            assert_eq!(
                serde_json::to_string(&read).expect("encodes"),
                serde_json::to_string(&after).expect("encodes"),
                "{text} {paths:?}: the same view, members in the same order",
            );
        }
    }
}

#[test]
fn a_redact_over_a_text_view_matches_the_redact_over_its_value() {
    let object = r#"{"a":1,"b":{"c":2,"d":[1,2,3]},"e":"x"}"#;
    let object_cases: &[&[&str]] = &[
        &["/b/c"],
        &["b.d.1"],
        &["/b/d/*"],
        &["*"],
        &["b.*"],
        &["*.c"],
        &["/b/d/9"],
        &["/b/d/-1"],
        &["/b/d/+1"],
        &["a.z"],
        &[""],
        &["/"],
        &["/a", "/e"],
        &["/a", "/b/d/0"],
        &["b", "b.c"],
        &["/b/c", "/b/c"],
    ];
    for paths in object_cases {
        assert_text_redact_matches_value(object, paths);
    }
    // A repeated key keeps its first place and its last value.
    let repeated_cases: &[&[&str]] = &[&["/b"], &["/a"], &["a.c"], &["*"]];
    for paths in repeated_cases {
        assert_text_redact_matches_value(r#"{"a":1,"b":2,"a":{"c":3}}"#, paths);
    }
    // Pointer escapes, and a dotted path that cannot name a dotted key.
    let escaped_cases: &[&[&str]] = &[&["/x~1y"], &["/m~0n"], &["p.q"], &["/p.q"]];
    for paths in escaped_cases {
        assert_text_redact_matches_value(r#"{"x/y":1,"m~n":2,"p.q":3}"#, paths);
    }
    // Scalars, nulls already null, empty containers, rows under `*`.
    assert_text_redact_matches_value(r#""s""#, &["a"]);
    assert_text_redact_matches_value("[null,1]", &["0"]);
    assert_text_redact_matches_value("[null,1]", &["*"]);
    assert_text_redact_matches_value("{}", &["*"]);
    assert_text_redact_matches_value("[]", &["*"]);
    assert_text_redact_matches_value("null", &[""]);
    assert_text_redact_matches_value(
        r#"{"rows":[{"body":"x","id":1},{"body":"y"},3]}"#,
        &["rows.*.body"],
    );
    // Whitespace, escapes and numbers as the text spells them.
    assert_text_redact_matches_value(" { \"a\" : [ 1 , 2 ] , \"b\" : null } ", &["a.0"]);
    assert_text_redact_matches_value(r#"{"t":"a\"b\\cA","kA":1}"#, &["/kA"]);
    assert_text_redact_matches_value(r#"{"n":-1.5e+10,"m":0,"f":false,"t":true}"#, &["/m"]);
}

#[test]
fn a_redact_over_a_text_view_keeps_no_stack_for_its_depth() {
    // Far past any stack a recursion per level would fit on this thread.
    const LEVELS: usize = 100_000;
    let text = format!("{}0{}", "[".repeat(LEVELS), "]".repeat(LEVELS));
    let leaf = "/0".repeat(LEVELS);
    let redacted = handle_doors::redact_view_text(&text, &[leaf])
        .expect("the deep text redacts")
        .expect("the leaf is hidden");
    assert_eq!(
        redacted,
        format!("{}null{}", "[".repeat(LEVELS), "]".repeat(LEVELS)),
        "the innermost leaf is masked, every level kept",
    );
    let nothing =
        handle_doors::redact_view_text(&text, &["/1".to_owned()]).expect("the deep text reads");
    assert_eq!(nothing, None, "a path that names nothing hides nothing");
}

/// The custody value the masking tests hold: one test secret carries it,
/// so the run-known sweep stands it in wherever it appears.
const SECRET_CANARY: &str = "admitted-mask-canary-9f31-orchard-lantern";

/// Stores the active callable whose answer is `title`, the custody
/// `secret` and a `text` of `skillArgs.bytes` bytes of `b`, and answers
/// its id.
fn large_secret_skill(vault: &Vault, secret: &str) -> EntityId {
    let literal = serde_json::to_string(secret).expect("the secret encodes");
    let source = format!(
        "finish(JSON.stringify({{title:\"secret-title-7\",secret:{literal},text:\"b\".repeat(skillArgs.bytes)}}));",
    );
    callable_skill::put_active_callable(
        vault,
        "fixture.large-secret-answer",
        &source,
        &serde_json::json!({"bytes":"integer"}),
        &serde_json::json!({"title":"string","secret":"string","text":"string"}),
    )
    .expect("the large secret callable is stored and active")
}

/// Registers [`SECRET_CANARY`] as the custody value the run knows: one
/// portable test secret holding it, so the run-known sweep masks it.
fn hold_secret_canary(vault: &Vault) {
    vault
        .register_test_secret(
            "admitted-mask-canary",
            SECRET_CANARY.as_bytes(),
            Vec::new(),
            1,
        )
        .expect("the custody value registers");
}

/// An admitted large answer goes out with its run-known values masked:
/// the whole answer held for the live outer post chain carries the
/// custody value's stand-in, never the value itself.
#[test]
fn an_admitted_large_answer_goes_out_with_its_run_known_values_masked() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    bind_redact_hook(&vault, vec!["/title".to_owned()]);
    let skill = large_secret_skill(&vault, SECRET_CANARY);
    hold_secret_canary(&vault);
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);

    let pre = outer_pre(&vault, actor, skill);
    assert!(
        !pre.passed_through(),
        "the outer pre chain found its post hook live",
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
    let text = answer.to_string();
    assert!(
        !text.contains(SECRET_CANARY),
        "the whole answer masks the custody value: {}",
        text.chars().take(200).collect::<String>(),
    );
    let secret = answer
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .expect("the whole answer carries its secret field");
    assert_ne!(secret, SECRET_CANARY, "the secret field holds the stand-in");
    assert_eq!(
        answer.get("title").and_then(serde_json::Value::as_str),
        Some(TAG),
        "no hook changed the answer",
    );
}

/// An admitted large answer's hook view goes out masked: the outer post
/// chain's redacted view hides the title and carries the custody value's
/// stand-in, never the value itself.
#[test]
fn an_admitted_large_answers_hook_view_goes_out_masked() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    bind_redact_hook(&vault, vec!["/title".to_owned()]);
    let skill = large_secret_skill(&vault, SECRET_CANARY);
    hold_secret_canary(&vault);
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);

    let pre = outer_pre(&vault, actor, skill);
    assert!(
        !pre.passed_through(),
        "the outer pre chain found its post hook live",
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
    let view = outer_post(&vault, pre, answer);
    assert!(
        view.get("title").is_none(),
        "the outer post chain hides the title: {}",
        view.to_string().chars().take(200).collect::<String>(),
    );
    let text = view.to_string();
    assert!(
        !text.contains(SECRET_CANARY),
        "the hook view masks the custody value: {}",
        text.chars().take(200).collect::<String>(),
    );
}

/// A small admitted answer goes out as recorded: the entry returns the
/// recorded output itself, matching its bridge row.
#[test]
fn a_small_admitted_answer_goes_out_as_recorded() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory();
    bind_redact_hook(&vault, vec!["/title".to_owned()]);
    let skill = large_secret_skill(&vault, SECRET_CANARY);
    hold_secret_canary(&vault);
    let run_id = fresh_id();
    let (actor, leased) = leased_actor(&vault, run_id);

    let pre = outer_pre_with_bytes(&vault, actor, skill, 32);
    assert!(
        !pre.passed_through(),
        "the outer pre chain found its post hook live",
    );
    let answer = admitted_skill_call_result(
        &vault,
        &factory,
        run_id,
        actor,
        &leased,
        skill,
        32,
        !pre.passed_through(),
    )
    .expect("the admitted skill call answers");
    let record = admitted_record(&vault, &run_id);
    assert_eq!(record.bridge_calls.len(), 1);
    assert_eq!(
        answer,
        bridge_output(&record.bridge_calls[0]),
        "the small answer goes out as recorded",
    );
}

/// A deep hook view keeps a readable step replay context: a view nested
/// to the read-back limit is kept, and the context decodes to itself.
#[test]
fn a_deep_hook_view_keeps_a_readable_step_replay_context() {
    let mut rows = serde_json::Value::String("deep-leaf".to_owned());
    for _ in 0..125 {
        rows = serde_json::Value::Array(vec![rows]);
    }
    let view = serde_json::json!({"output": {"rows": rows}});
    assert_eq!(
        handle_doors::replay_context_view_reads_back(view),
        (true, true),
        "the deep view is kept and its context reads back",
    );
}

/// A hook view too deep to read back leaves the capture incomplete: the
/// view is not kept, and the context without it still reads back.
#[test]
fn a_hook_view_too_deep_to_read_back_leaves_the_capture_incomplete() {
    let mut rows = serde_json::Value::String("deep-leaf".to_owned());
    for _ in 0..126 {
        rows = serde_json::Value::Array(vec![rows]);
    }
    let view = serde_json::json!({"output": {"rows": rows}});
    assert_eq!(
        handle_doors::replay_context_view_reads_back(view),
        (false, true),
        "the too-deep view is not kept and its context reads back",
    );
}

/// The real-sandbox tests ([SKILL-POST-HOOK-INPUT-BODY-CHANNEL]): the
/// blocking post hook's staged body runs in the pinned QuickJS hook
/// sandbox, which only the `code-sandbox-wasmtime` feature builds.
#[cfg(feature = "code-sandbox-wasmtime")]
mod real_sandbox {
    use super::*;

    /// The channel test's answer `text` length: 2 MiB sits past the old 1 MiB
    /// hook input cap and under the guest's input limit.
    const CHANNEL_TWO_MIB_BYTES: usize = 2_097_152;
    /// The heavy answer's empty arrays: about 3 MB of JSON, under the input
    /// limit, far past the hook guest's 24 MiB interpreter heap once parsed.
    const HEAVY_ROWS: usize = 1_000_000;

    /// Stores the active callable whose answer is `title` and `rows`,
    /// `skillArgs.rows` empty arrays written as text, so the skill itself
    /// never holds them as objects. Answers its id.
    fn heavy_skill(vault: &Vault) -> EntityId {
        let source = r#"finish('{"title":"secret-title-7","rows":[' + "[],".repeat(skillArgs.rows - 1) + '[]]}');"#;
        callable_skill::put_active_callable(
            vault,
            "fixture.heavy-answer",
            source,
            &serde_json::json!({"rows":"integer"}),
            &serde_json::json!("object"),
        )
        .expect("the heavy callable is stored and active")
    }

    /// Binds the BLOCKING Redact post hook on `self.skills.call` as
    /// [`bind_blocking_capped_hook`] binds its hook, but installs no test
    /// runtime: with `--all-features` the vault builds the pinned QuickJS
    /// sandbox, so the staged body's real JS runs in the real sandbox.
    fn bind_blocking_real_hook(vault: &Arc<Vault>) {
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
        handle_doors::bind_blocking_redact_post_hook(vault, owner, &proof, "self.skills.call")
            .expect("the blocking Redact hook binds");
    }

    /// [`REDACT_PROGRAM`] for a call whose skill args carry `bytes` of `text`.
    fn redact_program_for(skill: EntityId, refs: &[String], bytes: usize) -> String {
        program_with(
            &REDACT_PROGRAM
                .replace("__GUESSES__", GUESSES)
                .replace(&ANSWER_BYTES.to_string(), &bytes.to_string()),
            skill,
            refs,
        )
    }

    /// [`DENIED_PROGRAM`] for a call to [`heavy_skill`] asking `rows` rows.
    fn denied_heavy_program(skill: EntityId, refs: &[String], rows: usize) -> String {
        program_with(
            &DENIED_PROGRAM
                .replace("__GUESSES__", GUESSES)
                .replace(&format!("bytes: {ANSWER_BYTES}"), &format!("rows: {rows}")),
            skill,
            refs,
        )
    }

    /// A 2 MiB skill answer reaches its blocking post hook and is redacted:
    /// past the old 1 MiB hook input cap and under the guest's input
    /// limit, the real sandbox runs the staged Redact body on the whole
    /// answer. Red on main: the host refuses the input past 1 MiB and the call
    /// is Skipped with the too-large cause.
    #[test]
    fn a_two_mib_skill_answer_reaches_its_blocking_post_hook_redacted() {
        let (_dir, vault) = open_vault();
        let factory = quickjs_factory();
        let skill = large_skill(&vault);
        bind_blocking_real_hook(&vault);
        let run_id = fresh_id();
        let program =
            redact_program_for(skill, &derived_bridge_refs(run_id), CHANNEL_TWO_MIB_BYTES);

        let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
        let outcome = outcome.expect("the run completes");
        assert_eq!(calls, 1, "one turn runs one program");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(
            doors::finish_text(&vault, &run_id).expect("the answer reads back"),
            format!("card:has-title:false:text-len:{CHANNEL_TWO_MIB_BYTES}:secret-guessed:false"),
        );
        assert_record_only(&outcome);
    }

    /// A skill answer its hook's guest cannot hold is refused unjudged: about
    /// 3 MB passes the host's input limit, but its million empty arrays pass
    /// the guest's interpreter heap, so the real sandbox reports the input not
    /// taken, the blocking post hook's body never starts, and the post chain
    /// refuses the call: the caller never reads the answer. Green on main too,
    /// there by the host's 1 MiB input cap.
    #[test]
    fn a_skill_answer_its_hook_guest_cannot_hold_is_refused_unjudged() {
        let (_dir, vault) = open_vault();
        let factory = quickjs_factory();
        let skill = heavy_skill(&vault);
        bind_blocking_real_hook(&vault);
        let run_id = fresh_id();
        let program = denied_heavy_program(skill, &derived_bridge_refs(run_id), HEAVY_ROWS);

        let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
        let outcome = outcome.expect("the run completes");
        assert_eq!(calls, 1, "one turn runs one program");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        let text = doors::finish_text(&vault, &run_id).expect("the answer reads back");
        assert!(
            text.contains(":secret-guessed:false"),
            "no guessed read returned the body:\n{text}",
        );
        assert!(
            !text.contains(TAG),
            "no read returned the secret title:\n{text}"
        );
        assert!(
            text.contains("verb_hook_skipped") || text.contains(":call-threw:true"),
            "the guest reads the refusal, never the answer:\n{text}",
        );
        assert!(
            text.contains("too large for the live post hook to judge")
                || text.contains(":call-threw:true"),
            "the refusal names its cause:\n{text}",
        );
        // The real body records record-only, exactly as a served view leaves
        // it: a nameless card, its body kept, no binding naming it.
        assert_record_only(&outcome);
        assert!(
            outcome.replay_record.bridge_calls[0].hook_view_served,
            "the row stands as a view-served row",
        );
    }

    /// The nesting of the answer past the hook guest's stack: a million
    /// arrays, about 2 MB of JSON, under the guest's input limit.
    const PAST_STACK_LEVELS: usize = 1_000_000;

    /// Stores the active callable whose answer is the secret `title` and
    /// `deep`, `skillArgs.levels` nested arrays around `0`, written as text
    /// so the skill itself never nests a value. Answers its id.
    fn deep_text_skill(vault: &Vault) -> EntityId {
        let source = concat!(
            r#"finish('{"title":"secret-title-7","deep":' + "[".repeat(skillArgs.levels)"#,
            r#" + "0" + "]".repeat(skillArgs.levels) + '}');"#,
        );
        callable_skill::put_active_callable(
            vault,
            "fixture.deep-text-answer",
            source,
            &serde_json::json!({"levels":"integer"}),
            &serde_json::json!("object"),
        )
        .expect("the deep text callable is stored and active")
    }

    /// A skill answer nesting past the whole-answer parser's depth reaches
    /// its blocking post hook in the real sandbox as text and comes back
    /// redacted ([SKILL-ANSWER-DEEP-JSON-STACK-SAFE] part 2a): the hook's
    /// guest parses its input itself, the staged body hides
    /// `/output/title`, and the guest reads the redacted body by its card,
    /// its whole depth kept. Red at the base: the call is refused, "nests
    /// too deep for the live post hook to judge".
    #[test]
    fn a_deep_skill_answer_reaches_its_blocking_post_hook_redacted() {
        let (_dir, vault) = open_vault();
        let factory = quickjs_factory();
        let skill = deep_text_skill(&vault);
        bind_blocking_real_hook(&vault);
        let program = program_with(DEEP_VIEW_PROGRAM, skill, &[])
            .replace("__ARGS__", &format!("{{levels: {DEEP_LEVELS}}}"))
            .replace("__FIELD__", "title");

        let (outcome, text) = run_deep_program(&vault, &factory, program);
        assert_eq!(
            text,
            format!("card:has-title:false:depth:{DEEP_LEVELS}:leaf:0"),
            "the guest reads the redacted view",
        );
        assert_record_only(&outcome);
    }

    /// A skill answer nesting past the hook guest's own stack is refused
    /// unjudged: the guest's JSON parse runs out of stack before the body
    /// starts, the run reads as never taken, and the blocking post hook's
    /// chain refuses the call, naming the nesting, so the caller never reads
    /// the answer. The guest's stack is the bound, and no trap lets the
    /// answer through as an ordinary failure. Red at the base: the host
    /// refuses the call before any hook, as too deep to read whole.
    #[test]
    fn a_skill_answer_nesting_past_the_hook_guest_stack_is_refused_unjudged() {
        let (_dir, vault) = open_vault();
        let factory = quickjs_factory();
        let skill = deep_text_skill(&vault);
        bind_blocking_real_hook(&vault);
        let run_id = fresh_id();
        let program = program_with(
            &DENIED_PROGRAM.replace("__GUESSES__", GUESSES).replace(
                &format!("bytes: {ANSWER_BYTES}"),
                &format!("levels: {PAST_STACK_LEVELS}"),
            ),
            skill,
            &derived_bridge_refs(run_id),
        );

        let (outcome, calls) = execute_run(&vault, &factory, run_id, vec![program]);
        let outcome = outcome.expect("the run completes");
        assert_eq!(calls, 1, "one turn runs one program");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        let text = doors::finish_text(&vault, &run_id).expect("the answer reads back");
        assert!(
            text.contains(":secret-guessed:false"),
            "no guessed read returned the body:\n{text}",
        );
        assert!(
            !text.contains(TAG),
            "no read returned the secret title:\n{text}"
        );
        // The typed bridge throws a denial, so it reads in the thrown text
        // or, were it returned, in `denied`; the host's own refusal before
        // the hook spells neither.
        assert!(
            text.contains("verb_hook_skipped"),
            "the hook's chain refuses the call, never the host before it:\n{text}",
        );
        assert!(
            text.contains("its size or its nesting passes what the hook runtime takes"),
            "the refusal names its cause:\n{text}",
        );
        assert_record_only(&outcome);
        assert!(
            outcome.replay_record.bridge_calls[0].hook_view_served,
            "the row stands as a view-served row",
        );
    }

    /// A callable whose answer nests `levels` deep beside `odd`, a string
    /// spelling a lone surrogate escape: valid JSON text, which no value
    /// reads.
    fn odd_text_skill(vault: &Vault) -> EntityId {
        let source = concat!(
            r#"finish('{"title":"secret-title-7","odd":"\\uD800","deep":'"#,
            r#" + "[".repeat(skillArgs.levels) + "0" + "]".repeat(skillArgs.levels) + '}');"#,
        );
        callable_skill::put_active_callable(
            vault,
            "fixture.odd-text-answer",
            source,
            &serde_json::json!({"levels":"integer"}),
            &serde_json::json!("object"),
        )
        .expect("the odd text callable is stored and active")
    }

    /// The run's status and finish text for a call to [`odd_text_skill`]
    /// nesting `levels` deep, its blocking post hook bound.
    fn odd_answer_run(levels: usize) -> (Option<EngineExecutorStatus>, Option<String>) {
        let (_dir, vault) = open_vault();
        let factory = quickjs_factory();
        let skill = odd_text_skill(&vault);
        bind_blocking_real_hook(&vault);
        let program = program_with(DEEP_VIEW_PROGRAM, skill, &[])
            .replace("__ARGS__", &format!("{{levels: {levels}}}"))
            .replace("__FIELD__", "title");
        let run_id = fresh_id();
        let (outcome, _) = execute_run(&vault, &factory, run_id, vec![program]);
        (
            outcome.ok().map(|outcome| outcome.status),
            doors::finish_text(&vault, &run_id).ok(),
        )
    }

    /// A deep answer whose text no value reads (a lone surrogate escape
    /// beside `deep`) ends as the same answer nesting two levels does: the
    /// text path takes no answer the value path refuses as non-JSON, and no
    /// hook judges it. Red at the pin that takes it as text: the hook
    /// redacts it and the guest reads a card.
    #[test]
    fn a_deep_answer_no_value_reads_ends_as_a_shallow_one_does() {
        let shallow = odd_answer_run(2);
        assert!(
            !shallow
                .1
                .as_deref()
                .is_some_and(|text| text.starts_with("card:")),
            "the value path never serves the answer: {shallow:?}",
        );
        assert_eq!(
            odd_answer_run(DEEP_LEVELS),
            shallow,
            "the deep answer ends as the shallow one does",
        );
    }
}

/// A hook input nesting past what a value may hold names the rows it spells
/// through `\u` escapes, as a decoded one names them: its saved run lists
/// them, so an erase of one retires the run's payload. Red at the pin whose
/// scan reads no escape: the escaped id is missed.
#[test]
fn a_deep_hook_input_names_a_row_it_spells_through_escapes() {
    let row = fresh_id();
    let escaped: String = row
        .to_hex()
        .chars()
        .map(|digit| format!("\\u{:04x}", u32::from(digit)))
        .collect();
    let input = format!(
        "{{\"args\":{{}},\"result\":{{\"output\":{{\"ref\":\"{escaped}\",\"deep\":{}0{}}}}}}}",
        "[".repeat(DEEP_LEVELS),
        "]".repeat(DEEP_LEVELS),
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&input).is_err(),
        "the input nests past what a value reads",
    );
    assert_eq!(
        handle_doors::rows_named_by_hook_input(&input),
        vec![row],
        "the run names the row its input spells through escapes",
    );
}

/// REVIEW-9897 round 1: a 64-digit hex run, such as a digest, names no row,
/// in a deep hook input as in a decoded value, whether its digits are
/// spelled through escapes or plain, though its last 32 digits are a row's
/// id. Red at 1cb524097a3: the escaped run names that row (the scan took
/// the last 32 digits of a longer run), and so does the plain one.
#[test]
fn a_deep_hook_input_names_no_row_inside_a_longer_hex_run() {
    let (escaped_row, plain_row) = (fresh_id(), fresh_id());
    let escaped: String = format!("{}{}", fresh_id().to_hex(), escaped_row.to_hex())
        .chars()
        .map(|digit| format!("\\u{:04x}", u32::from(digit)))
        .collect();
    let plain = format!("{}{}", fresh_id().to_hex(), plain_row.to_hex());
    let input = format!(
        "{{\"args\":{{}},\"result\":{{\"output\":{{\"escaped\":\"{escaped}\",\"plain\":\"{plain}\",\"deep\":{}0{}}}}}}}",
        "[".repeat(DEEP_LEVELS),
        "]".repeat(DEEP_LEVELS),
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&input).is_err(),
        "the input nests past what a value reads",
    );
    assert!(
        handle_doors::rows_named_by_hook_input(&input).is_empty(),
        "a longer hex run names no row",
    );
}
