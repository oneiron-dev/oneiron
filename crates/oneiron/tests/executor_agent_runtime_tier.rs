//! The 9 quarantined `FIX [LIBTEST-AGENT-RUNTIME-TIER]` lib unit tests, moved to one
//! integration binary: they need the real agent runtime (QuickJS, the wasmtime
//! sandbox), which the oneiron lib cannot link in its own unit tests, but this
//! target can through the `oneiron-agent-runtime` dev-dependency.
//!
//! Old lib paths:
//! - `code_run/agent_authoring/tests.rs::guest_agents_put_reaches_the_leased_host_and_fences_stale_leases`
//! - `code_sandbox/microvm/tests.rs::code_sandbox_microvm_isolating_tiers_never_fall_through_silently`
//! - `engine_executor/tests/host_services.rs::executor_code_reaches_no_file_or_credential_service_a_host_attached`
//! - `engine_executor/tests/memory_rows.rs::a_guest_call_through_each_memory_row_keeps_its_call_and_answer`
//! - `engine_executor/tests/memory_rows.rs::a_guest_call_through_a_memory_row_is_refused_as_before`
//! - `engine_executor/tests/memory_rows.rs::a_memory_row_refuses_a_field_its_input_does_not_list`
//! - `engine_executor/tests/memory_rows.rs::a_memory_row_sends_the_input_its_check_saw`
//! - `engine_executor/tests/output_decay.rs::real_quickjs_restores_large_unicode_output_in_bounded_chunks`
//! - `engine_executor/tests/output_decay.rs::guest_output_with_old_marker_bytes_cannot_create_compaction_coverage`
//!
//! Run line: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --features oneiron-agent-runtime/code-sandbox-wasmtime
//! --test executor_agent_runtime_tier`.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentDefinitionPutDisposition, AgentScope, CompactionOwnership,
    MemoryProfile,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, CompleteAttempt,
    CompleteOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, GatedActorWrite, HostSelfDispatcher, SelfCall,
    SelfDispatchOutcome, SelfDispatcher, parse_agent_put_request,
};
use oneiron::code_sandbox::microvm::{NoSandboxBackends, select_backend_for_tier};
use oneiron::code_sandbox::{
    ComponentBudget, FakeSandboxAdapter, SandboxBoundaryContract, SandboxGuestTier,
    SandboxMountTable, SandboxVirtualPath,
};
use oneiron::compaction::output::{OutputAffordance, OutputDecayPolicy, OutputRef};
use oneiron::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionCheck, CompactionDriver,
    CompactionGatePolicy, CompactionProduct, CompactionRefusal, CompactionRequest,
    CompactionTierClass, CompactionWindowMessage, gate_compaction,
};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorError, EngineExecutorLimits, EngineExecutorResult,
    EngineExecutorStatus, EngineNativeExecutor, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep,
    SelfDispatchResponse,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use oneiron::session_lifecycle::{SessionKey, SessionMintOutcome};
use oneiron::skill::SkillDependency;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::{
    agent_authoring as author_doors, code_run_answer as answer_doors,
    compaction as compaction_doors,
};
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EdgeKind, EntityId, Error, ErrorKind, FatalLlmError,
    FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, Result,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::executor_speech_identity::executor_compaction_session_id;
use rmpv::Value;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

/// Canonical test entity id: `[seed; 16]`, as the lib tests' `entity` read it.
fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test seed forms an entity id")
}

/// The lib tests' vault: `device()` with the 4-wide test embedding pin.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn seed_person(vault: &Vault, seed: u8) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("seed person");
    id
}

fn gated_actor_write<'a>(vault: &'a Vault, run_ref: &str) -> GatedActorWrite<'a> {
    let actor = seed_person(vault, 0xA0);
    GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        run_ref,
    )
    .expect("gated actor write")
}

/// The pinned first-party QuickJS component under `budget`.
fn quickjs_factory(budget: ComponentBudget) -> QuickJsRuntimeFactory {
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
    QuickJsRuntimeFactory::from_component(&bytes, pin, budget)
        .expect("the QuickJS component passes its readiness probe")
}

fn executor_config(run_id: EntityId, soft_steps: u32) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: "remember the project status".to_owned(),
        prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
            .expect("workspace test prompt package"),
        model: ModelId::new("test/executor@v1").expect("model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
        limits: EngineExecutorLimits { soft_steps },
        wake: None,
    }
}

/// The scripted model: each turn answers with the next program, and every
/// request is kept for the console-frame reads.
struct FixtureBackend {
    responses: Mutex<VecDeque<String>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl FixtureBackend {
    fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().map(Into::into).collect()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl LlmBackend for FixtureBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.requests.lock().expect("requests lock").push(request);
        let program = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("fixture response");
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

fn bridge_outcome_kind(call: &CodeRunBridgeCall) -> &str {
    let Value::Map(entries) = &call.outcome else {
        panic!("bridge outcome must be a map");
    };
    entries
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some("kind"))
                .then(|| value.as_str().expect("outcome kind must be a string"))
        })
        .expect("bridge outcome kind")
}

fn text_message(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Literal pin of `RECOVERABLE_OUTPUT_CHUNK_BYTES` (`engine_executor/store.rs`): the most
/// raw bytes one guest read takes. The const is `pub(super)` with no test-door path, so the
/// stubs' `max_chunk_bytes` is pinned against this literal instead.
const MAX_CHUNK_BYTES_PIN: usize = 64 * 1024;

/// The chunk-0 recoverable path the engine advertises for step `seq`'s `source`, as
/// `recoverable_chunk_path` renders it. That helper is `pub(super)` with no test-door path,
/// so the port renders its format literally; the guest restore through it proves the path.
fn chunk0_path(seq: u64, source: OutputRef) -> String {
    format!(
        "/mnt/outputs/.oneiron-context-ref/{seq}/{hash}/{len}/chunk/0",
        hash = bytes_to_hex_lower(&source.hash),
        len = source.byte_len,
    )
}

struct SdkHost<'a>(HostSelfDispatcher<'a>);

impl JsCodeModeHost for SdkHost<'_> {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        Ok(SelfDispatchResponse {
            outcome: self.0.dispatch(call)?,
            budget: None,
            view: None,
        })
    }
}

/// One guest `vault.agents.put` through the pinned first-party QuickJS
/// component and its typed host import.
fn guest_put(host: &mut SdkHost<'_>, id: EntityId, definition: &JsonValue) -> Result<String> {
    let factory = quickjs_factory(ComponentBudget::default());
    let mut runtime = factory.runtime()?;
    let script = format!(
        "const out = await vault.agents.put({{id: {id}, definition: {definition}}});\nfinish(JSON.stringify(out));",
        id = json!(id.to_hex()),
    );
    let outcome = runtime.run_step(
        JsCodeModeStep {
            run_id: entity(0x5A),
            seq: 0,
            script: &script,
            boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
            determinism: CodeRunDeterminism::new(1_700_000_000_000, [3; 32]),
        },
        host,
    )?;
    let observation = &outcome.observation;
    assert!(outcome.done, "{observation}");
    let out: JsonValue = serde_json::from_str(observation).expect("JSON reply");
    assert_eq!(out["id"], json!(id.to_hex()));
    Ok(out["disposition"].as_str().expect("disposition").to_owned())
}

fn put_call(id: EntityId) -> Result<SelfCall> {
    Ok(SelfCall::AgentsPut(Box::new(parse_agent_put_request(
        &id.to_hex(),
        json!({
            "agentId": "fixture.helper",
            "desc": "bounded helper",
            "version": "1",
            "scope": {"kind": "base"},
        }),
        1_700_000_000,
    )?)))
}

#[test]
fn guest_agents_put_reaches_the_leased_host_and_fences_stale_leases() -> Result<()> {
    let clock = ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), config).expect("open vault");
    let author_id = entity(0x91);
    let author = AgentDefinition::new(
        "fixture.author",
        "Authoring fixture",
        "1",
        None,
        vec![SkillDependency::new("fixture.known-skill")],
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    vault.put_agent_definition(&author_id, &author, TimeRange { start: 1, end: 1 }, 1)?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(author_id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })?
    else {
        panic!("author attempt dispatched")
    };
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".into(),
        now: 11,
    })?
    else {
        panic!("author attempt leased")
    };
    assert_eq!(leased.id, status.attempt.id);
    let actor = WriteActor::new(author_id, EdgeActorClass::Agent);

    let mut host = SdkHost(HostSelfDispatcher::for_leased_agent_attempt(
        &vault, actor, &leased,
    )?);
    let in_slice = entity(0x92);
    assert_eq!(
        guest_put(
            &mut host,
            in_slice,
            &json!({
                "agentId": "fixture.narrow",
                "desc": "narrow helper",
                "version": "1",
                "scope": {"kind": "base"},
                "skills": ["fixture.known-skill"],
            }),
        )?,
        "active"
    );
    let stored = vault.get_agent_definition(&in_slice)?.expect("active row");
    assert_eq!(stored.ceiling, author.ceiling);
    assert_eq!(stored.approval_status, author.approval_status);
    let wider = entity(0x93);
    assert_eq!(
        guest_put(
            &mut host,
            wider,
            &json!({
                "agentId": "fixture.wide",
                "desc": "wide helper",
                "version": "1",
                "scope": {"kind": "base"},
                "ceiling": "auto",
                "skills": ["fixture.unknown-skill"],
            }),
        )?,
        "proposed"
    );
    let proposal = vault.get_agent_definition(&wider)?.expect("proposal row");
    assert_eq!(proposal.approval_status, ClaimApprovalStatus::Proposed);
    // Authoring launches nothing: the author's own attempt is the only row.
    assert_eq!(queue.list()?.len(), 1);

    // The lease times out and the same worker name reclaims the same try at a
    // new generation. The old dispatcher cannot author on the new lease.
    queue.cleanup_leases(CleanupAttemptLeases {
        now: {
            clock.set(30);
            30
        },
        lease_timeout_secs: 1,
    })?;
    let ClaimOutcome::Claimed(relet) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".into(),
        now: {
            clock.set(31);
            31
        },
    })?
    else {
        panic!("author attempt re-leased")
    };
    assert_eq!(relet.id, leased.id);
    assert_ne!(relet.attempt_count, leased.attempt_count);
    let stale_put = entity(0x94);
    assert!(host.0.dispatch(put_call(stale_put)?).is_err());
    assert!(vault.get_agent_definition(&stale_put)?.is_none());
    assert!(HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased).is_err());

    let current = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &relet)?;
    let fresh = entity(0x95);
    assert!(matches!(
        current.dispatch(put_call(fresh)?)?,
        SelfDispatchOutcome::AgentDefinitionPut(result)
            if result.disposition == AgentDefinitionPutDisposition::Active
    ));

    // Terminalization fences the writer inside the definition's own write
    // transaction, not only at the dispatcher's earlier status read.
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: relet.id,
            lease_owner: "worker-a".into(),
            attempt_count: relet.attempt_count,
            now: 32,
        })?,
        CompleteOutcome::Completed(_)
    ));
    let after_close = entity(0x96);
    assert!(current.dispatch(put_call(after_close)?).is_err());
    let (_, definition) = match put_call(after_close)? {
        SelfCall::AgentsPut(call) => (call.id, call.definition),
        _ => unreachable!("authoring call"),
    };
    assert!(
        author_doors::put_for_author_with_scope_from_leased(
            &vault,
            &author_id,
            &after_close,
            &definition,
            false,
            Some(&relet),
            TimeRange { start: 33, end: 33 },
            33,
        )
        .is_err()
    );
    assert!(vault.get_agent_definition(&after_close)?.is_none());
    Ok(())
}

#[test]
fn code_sandbox_microvm_isolating_tiers_never_fall_through_silently() {
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        let Err(error) = select_backend_for_tier(&NoSandboxBackends, tier) else {
            panic!("an isolating tier with no backend fails closed");
        };
        assert_eq!(error.kind(), ErrorKind::MicroVmBackendUnavailable);
    }
}

struct NoSelfCalls;

impl JsCodeModeHost for NoSelfCalls {
    fn dispatch_self(&mut self, _call: SelfCall) -> Result<SelfDispatchResponse> {
        Err(Error::InvalidConfig("this step makes no self call".into()))
    }
}

const PROBE: &str = "let read = 'refused'; \
    try { read = String.fromCharCode(...(await sandbox.fs.read_file('/mnt/workspace/secret.txt'))); } catch (_) {} \
    let credential = 'refused'; \
    try { await sandbox.credential.call({operation: 'list', credentialHandle: 'handle-1', args: {}}); credential = 'served'; } catch (_) {} \
    finish({read, credential});";

#[test]
fn executor_code_reaches_no_file_or_credential_service_a_host_attached() -> Result<()> {
    let factory = quickjs_factory(ComponentBudget::default());
    let mounts = tempfile::tempdir().expect("tempdir");
    let staged_adapter = || -> Result<FakeSandboxAdapter> {
        let mut adapter = FakeSandboxAdapter::new(
            SandboxGuestTier::FirstPartyDreamer,
            SandboxMountTable::new(
                mounts.path().join("workspace"),
                mounts.path().join("uploads"),
                mounts.path().join("outputs"),
                mounts.path().join("skills"),
            ),
        );
        adapter.stage_file(
            SandboxVirtualPath::try_new("/mnt/workspace/secret.txt")?,
            b"host file".to_vec(),
        );
        Ok(adapter)
    };

    // The attached adapter answers a contract that links host services...
    let mut runtime = factory.runtime()?.with_adapter(Box::new(staged_adapter()?));
    let outcome = runtime.run_step(
        JsCodeModeStep {
            run_id: EntityId::from_bytes([1; 16])?,
            seq: 0,
            script: PROBE,
            boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
            determinism: CodeRunDeterminism::new(1_700_000_000_000, [7; 32]),
        },
        &mut NoSelfCalls,
    )?;
    let observation = &outcome.observation;
    assert!(outcome.done, "{observation}");
    let answer: JsonValue = serde_json::from_str(observation).expect("probe answers JSON");
    assert_eq!(answer, json!({"read": "host file", "credential": "served"}));

    // ...and never the executor's: the same probe as an executor program is refused both.
    // The executor builds its boundary from `executor_boundary_contract` on every run, so
    // this pins that contract end to end through public API alone.
    let (_dir, vault) = open_vault();
    let backend = FixtureBackend::new([PROBE]);
    let lease = BudgetLease::for_test("executor-boundary");
    let gated = gated_actor_write(&vault, "run-executor-boundary");
    let mut runtime = factory
        .runtime()
        .expect("executor guest")
        .with_adapter(Box::new(staged_adapter()?));
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(entity(0x61), 1);
    let outcome = block_on_ready(executor.run(&config)).expect("executor runs the probe");
    let answer =
        answer_doors::observation_text(&vault, &outcome.replay_record, 0).expect("probe answer");
    let answer: JsonValue = serde_json::from_str(&answer).expect("probe answers JSON");
    assert_eq!(answer, json!({"read": "refused", "credential": "refused"}));
    Ok(())
}

/// One single-step run of `program` through the real guest; the step's
/// `finish` text and its bridge rows as `effect kind`.
fn run_program(
    vault: &Vault,
    run: u8,
    program: &str,
) -> EngineExecutorResult<(String, Vec<String>)> {
    let factory = quickjs_factory(ComponentBudget::default());
    let backend = FixtureBackend::new([program]);
    let lease = BudgetLease::for_test("memory-rows");
    let gated = gated_actor_write(vault, &format!("run-memory-rows-{run}"));
    let mut runtime = factory.runtime().expect("real guest");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(entity(run), 1);
    let outcome = block_on_ready(executor.run(&config))?;
    let answer = answer_doors::observation_text(vault, &outcome.replay_record, 0)
        .map_err(EngineExecutorError::Engine)?;
    let rows = outcome
        .replay_record
        .bridge_calls
        .iter()
        .map(|row| {
            let effect = row.effect.as_str();
            let kind = bridge_outcome_kind(row);
            format!("{effect} {kind}")
        })
        .collect();
    Ok((answer, rows))
}

/// A guest call through a memory row still works end to end: the run's search
/// and its claim writes keep their effect, replay row, answer shape and gated
/// write. Each row's typed call, `supersede_claim` and `put_edge` included, is
/// pinned at the guest boundary by
/// `native_quickjs_memory_rows_make_the_calls_their_imports_made`.
#[test]
fn a_guest_call_through_each_memory_row_keeps_its_call_and_answer() {
    let (_dir, vault) = open_vault();
    let subject = seed_person(&vault, 0xB1);
    let [first, second] = [entity(0xC1), entity(0xC2)];
    let program = format!(
        "const subject = '{subject}'; const out = {{}}; try {{ \
         out.search = await self.memory.search({{query: 'sencha', limit: 3}}); \
         out.first = await self.memory.put_claim({{id: '{first}', subject, \
           predicate: 'profile.favorite_drink', value: 'sencha', confidence: 0.9, \
           occurred: {{start: 3, end: 4}}, learnedAt: 4}}); \
         out.second = await self.memory.put_claim({{id: '{second}', subject, \
           predicate: 'profile.favorite_drink', value: 'matcha'}}); \
         finish(JSON.stringify(out)); }} catch (error) {{ finish(`threw ${{error}}`); }}",
        subject = subject.to_hex(),
        first = first.to_hex(),
        second = second.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x71, &program).expect("run");
    let answer: JsonValue =
        serde_json::from_str(&answer).unwrap_or_else(|_| panic!("{answer}; {rows:?}"));
    assert_eq!(
        answer,
        json!({
            "search": {"results": []},
            "first": {"id": first.to_hex()},
            "second": {"id": second.to_hex()},
        })
    );
    assert_eq!(
        rows,
        [
            "self.memory.search memory_search",
            "self.memory.put_claim memory_write",
            "self.memory.put_claim memory_write",
        ]
    );
    let stored = vault.get_claim(&first).expect("read").expect("first claim");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(stored.value, Value::from("sencha"));
    assert_eq!(stored.confidence, 0.9);
    let stored = vault
        .get_claim(&second)
        .expect("read")
        .expect("second claim");
    assert_eq!(stored.value, Value::from("matcha"));
    assert_eq!(stored.confidence, 1.0);
}

/// A guest call through a memory row is refused as before: a non-finite
/// number (boxed or not), a time past JavaScript's safe range and an input
/// JSON cannot carry never reach the gate, the guest sees a stable code for
/// each, and a write the gate refuses stops the run with the gate's own error,
/// writing nothing.
#[test]
fn a_guest_call_through_a_memory_row_is_refused_as_before() {
    let (_dir, vault) = open_vault();
    let subject = seed_person(&vault, 0xB2);
    let claim = entity(0xC3);
    let program = format!(
        "const subject = '{subject}'; const out = {{}}; \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           confidence: NaN}}); out.nan = 'written'; }} catch (error) {{ out.nan = String(error); }} \
         try {{ await self.memory.put_edge({{src: '{claim}', kind: 'about', tgt: subject, \
           weight: Infinity}}); out.infinite = 'written'; }} catch (error) {{ out.infinite = String(error); }} \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           learnedAt: 2 ** 53}}); out.unsafe = 'written'; }} catch (error) {{ out.unsafe = String(error); }} \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: 1, \
           confidence: new Number(NaN)}}); out.boxed = 'written'; }} catch (error) {{ out.boxed = String(error); }} \
         const cyclic = {{}}; cyclic.self = cyclic; \
         try {{ await self.memory.put_claim({{id: '{claim}', subject, predicate: 'p.q', value: cyclic}}); \
           out.cyclic = 'written'; }} catch (error) {{ out.cyclic = String(error); }} \
         finish(JSON.stringify(out));",
        subject = subject.to_hex(),
        claim = claim.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x72, &program).expect("run");
    let answer: JsonValue = serde_json::from_str(&answer).expect("guest answer");
    assert_eq!(
        answer,
        json!({
            "nan": "RangeError: non_finite_verb_input",
            "infinite": "RangeError: non_finite_verb_input",
            "unsafe": "host_call_refused",
            "boxed": "RangeError: non_finite_verb_input",
            "cyclic": "TypeError: invalid_verb_input",
        })
    );
    assert!(rows.is_empty(), "{rows:?}");
    assert!(vault.get_claim(&claim).expect("read").is_none());

    let program = format!(
        "try {{ await self.memory.put_edge({{src: '{subject}', kind: 'same_as', \
           tgt: '{subject}', weight: 0}}); finish('written'); }} \
         catch (error) {{ finish(String(error)); }}",
        subject = subject.to_hex(),
    );
    let error = run_program(&vault, 0x73, &program).expect_err("same_as is refused");
    assert!(
        matches!(
            &error,
            EngineExecutorError::Engine(Error::InvalidClaimBody(reason))
                if *reason == "vault.edges.put rejects structural edge kinds"
        ),
        "{error:?}"
    );
    assert!(
        vault
            .targets(&subject, EdgeKind::SameAs, None)
            .expect("edges")
            .is_empty()
    );
}

/// A memory row's input is closed, as every row's is: a field it does not
/// list is refused before the gate, never dropped and written, and the guest
/// sees the refusal as a stable code.
#[test]
fn a_memory_row_refuses_a_field_its_input_does_not_list() {
    let (_dir, vault) = open_vault();
    let subject = seed_person(&vault, 0xB3);
    let claim = entity(0xC4);
    let program = format!(
        "try {{ await self.memory.put_claim({{id: '{claim}', subject: '{subject}', \
           predicate: 'profile.favorite_drink', value: 'tea', source: 'user_stated'}}); \
           finish('written'); }} catch (error) {{ finish(String(error)); }}",
        subject = subject.to_hex(),
        claim = claim.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x74, &program).expect("run");
    assert_eq!(answer, "host_call_refused");
    assert!(rows.is_empty(), "{rows:?}");
    assert!(vault.get_claim(&claim).expect("read").is_none());
}

/// A row's input is encoded once and the call sends that text, so neither a
/// getter nor an inherited `toJSON` can pass the finite check and then send a
/// different value.
#[test]
fn a_memory_row_sends_the_input_its_check_saw() {
    let (_dir, vault) = open_vault();
    let subject = seed_person(&vault, 0xB4);
    let [getter, hooked] = [entity(0xC5), entity(0xC6)];
    let program = format!(
        "const fields = id => ({{id, subject: '{subject}', predicate: 'profile.favorite_drink', \
           value: 'tea'}}); \
         let reads = 0; const input = fields('{getter}'); \
         Object.defineProperty(input, 'confidence', {{enumerable: true, \
           get() {{ reads += 1; return reads === 1 ? 0.5 : NaN; }}}}); \
         await self.memory.put_claim(input); \
         let hooks = 0; \
         Object.defineProperty(Object.prototype, 'toJSON', {{configurable: true, value() {{ \
           if (this.id !== '{hooked}') return this; hooks += 1; \
           return {{...this, confidence: hooks === 1 ? 0.25 : NaN}}; }}}}); \
         await self.memory.put_claim(fields('{hooked}')); \
         finish(`${{reads}} ${{hooks}}`);",
        subject = subject.to_hex(),
        getter = getter.to_hex(),
        hooked = hooked.to_hex(),
    );
    let (answer, rows) = run_program(&vault, 0x75, &program).expect("run");
    assert_eq!(answer, "1 1");
    assert_eq!(
        rows,
        [
            "self.memory.put_claim memory_write",
            "self.memory.put_claim memory_write",
        ]
    );
    for (id, confidence) in [(getter, 0.5), (hooked, 0.25)] {
        let stored = vault.get_claim(&id).expect("read").expect("claim");
        assert_eq!(stored.confidence, confidence);
    }
}

fn console(request: &LlmRequest, seq: usize) -> String {
    text_message(&request.messages[3 + seq * 2])
}

/// The typed read-file action the stub at step 0 advertises for `original`,
/// pinned against the chunk-0 path the engine renders: its whole length, its
/// bounded chunk size, and no unlinked action.
fn reexpand_action(request: &LlmRequest, original: &[u8], chunk0: &str) -> OutputAffordance {
    let source = OutputRef::from_bytes(original);
    let body = console(request, 0);
    let json = body
        .split("<console>\n")
        .nth(1)
        .expect("console frame")
        .split("\n</console>")
        .next()
        .expect("console body");
    let stub: JsonValue = serde_json::from_str(json).expect("typed read-file action");
    assert_eq!(stub["sandbox.fs.read_file"].as_str(), Some(chunk0));
    assert_eq!(stub["byte_len"].as_u64(), Some(original.len() as u64));
    assert_eq!(
        stub["max_chunk_bytes"].as_u64(),
        Some(MAX_CHUNK_BYTES_PIN as u64)
    );
    assert!(
        stub.get("Summarize").is_none(),
        "do not advertise an unlinked action"
    );
    OutputAffordance::Reexpand(source)
}

/// The frame a swapped epoch renders in place of its steps.
fn compacted(request: &LlmRequest) -> String {
    request
        .messages
        .iter()
        .map(text_message)
        .find(|text| text.starts_with("<compacted "))
        .expect("compacted frame")
}

/// The frame's typed read-file action for step 0, which re-expands its
/// exact original.
fn reexpand_from_frame(request: &LlmRequest, original: &[u8], chunk0: &str) -> OutputAffordance {
    let source = OutputRef::from_bytes(original);
    let frame = compacted(request);
    let handle: JsonValue = frame
        .lines()
        .find(|line| line.starts_with('{'))
        .map(serde_json::from_str)
        .expect("a handle")
        .expect("typed read-file action");
    assert_eq!(handle["step"].as_u64(), Some(0));
    assert_eq!(handle["sandbox.fs.read_file"].as_str(), Some(chunk0));
    assert_eq!(handle["byte_len"].as_u64(), Some(original.len() as u64));
    assert_eq!(
        handle["max_chunk_bytes"].as_u64(),
        Some(MAX_CHUNK_BYTES_PIN as u64)
    );
    OutputAffordance::Reexpand(source)
}

/// Step `seq`'s console once a one-step epoch covers step 0: the frame
/// stands for step 0's program and console both.
fn console_after_frame(request: &LlmRequest, seq: usize) -> String {
    text_message(&request.messages[2 + seq * 2])
}

struct Cheap;

impl CompactionBackend for Cheap {
    fn backend_key(&self) -> &str {
        "executor-output-test"
    }
    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }
    fn compact(
        &self,
        _request: &CompactionRequest,
        _retry: Option<CompactionCheck>,
    ) -> std::result::Result<CompactionProduct, CompactionRefusal> {
        // A one-word summary over the test's single-message window: smaller than the
        // window, so the gate's size check passes it under a zero floor (see below).
        Ok(CompactionProduct {
            summary_text: r#"{"from": 0, "through": 0, "summary": "kept"}"#.into(),
            finish: FinishReason::Stop,
            latency: Duration::from_millis(1),
        })
    }
}

/// A real first-party guest can restore a Unicode observation whose raw bytes
/// fit the host limit but whose one-piece JSON byte array does not.
#[test]
fn real_quickjs_restores_large_unicode_output_in_bounded_chunks() {
    let (_dir, vault) = open_vault();
    let budget = ComponentBudget {
        fuel: 2_000_000_000,
        memory_bytes: 128 * 1024 * 1024,
        wall_time: Duration::from_secs(30),
        ..ComponentBudget::default()
    };
    let factory = quickjs_factory(budget);
    let lease = BudgetLease::for_test("unicode-output-restore");
    let gated = gated_actor_write(&vault, "run-unicode-output-restore");
    let config = executor_config(entity(0xC3), 1);
    let original = "あ".repeat(100_000);
    assert_eq!(original.len(), 300_000);
    let first_backend = FixtureBackend::new(["console.log('あ'.repeat(100000));"]);
    let mut first_runtime = factory.runtime().expect("real first guest");
    let mut first =
        EngineNativeExecutor::new(&vault, &first_backend, &lease, &mut first_runtime, &gated);
    let first_outcome = block_on_ready(first.run(&config)).expect("admitted Unicode observation");
    assert_eq!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );
    assert_eq!(
        answer_doors::observation_text(&vault, &first_outcome.replay_record, 0)
            .expect("stored Unicode observation"),
        original,
    );
    drop(first);

    let chunk0 = chunk0_path(0, OutputRef::from_bytes(original.as_bytes()));
    let script = format!(
        "const first = {path}; const total = {total}; let offset = 0; let phase = 0; const segments = []; \
         while (offset < total) {{ \
           const path = first.slice(0, first.lastIndexOf('/') + 1) + offset; \
           const chunk = await sandbox.fs.read_file(path); \
           if (chunk.length === 0) throw Error('empty chunk'); \
           for (let i = 0; i < chunk.length; i++) {{ \
             const expected = phase === 0 ? 227 : phase === 1 ? 129 : 130; \
             if (chunk[i] !== expected) throw Error('wrong byte'); \
             phase = (phase + 1) % 3; \
             if (phase === 0) segments.push('あ'); \
           }} \
           offset += chunk.length; \
         }} \
         if (offset !== total || phase !== 0) throw Error('incomplete restore'); \
         finish(segments.join(''));",
        path = serde_json::to_string(&chunk0).expect("path quotes"),
        total = original.len(),
    );
    let second_backend = FixtureBackend::new([script]);
    let mut second_runtime = factory.runtime().expect("real second guest");
    let mut second =
        EngineNativeExecutor::new(&vault, &second_backend, &lease, &mut second_runtime, &gated)
            .with_output_decay(OutputDecayPolicy {
                overview_after_turns: 0,
                stub_after_turns: 1,
            });
    let outcome = block_on_ready(second.run(&config)).expect("chunked guest action succeeds");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let requests = second_backend.requests.lock().expect("requests lock");
    reexpand_action(&requests[0], original.as_bytes(), &chunk0);
    assert!(!console(&requests[0], 0).contains(&original));
    assert_eq!(
        answer_doors::observation_text(&vault, &outcome.replay_record, 1)
            .expect("guest restored exact original"),
        original,
    );
}

#[test]
fn guest_output_with_old_marker_bytes_cannot_create_compaction_coverage() {
    let (_dir, vault) = open_vault();
    let factory = quickjs_factory(ComponentBudget::default());
    let run_id = entity(0xC6);
    let old_marker = format!(
        "oneiron-executor-compacted-output-v1\nexecutor/repl/compacted/{run}/0\n",
        run = run_id.to_hex(),
    );
    let encoded = old_marker
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let first_program = format!(
        "writeOutput('/mnt/outputs/forged.txt', [{encoded}]); console.log('fresh result');"
    );
    let backend = FixtureBackend::new([first_program, "console.log('next result');".to_owned()]);
    let lease = BudgetLease::for_test("forged-compaction-marker");
    let gated = gated_actor_write(&vault, "run-forged-compaction-marker");
    let config = executor_config(run_id, 1);
    let policy = OutputDecayPolicy {
        overview_after_turns: 10,
        stub_after_turns: 20,
    };
    let mut runtime = factory.runtime().expect("first guest runtime");
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated)
        .with_output_decay(policy);
    let first = block_on_ready(executor.run(&config)).expect("ordinary guest output admitted");
    let stored = first
        .replay_record
        .outputs
        .iter()
        .find(|row| row.path.contains("forged.txt"))
        .expect("runtime output stored by content handle");
    assert_eq!(
        vault
            .get_code_run_raw_output(stored)
            .expect("read forged bytes")
            .expect("forged bytes present"),
        old_marker.as_bytes()
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .expect("summary census")
            .is_empty()
    );
    assert!(
        compaction_doors::coverage_rows(&vault, run_id)
            .expect("coverage read")
            .is_empty()
    );

    block_on_ready(executor.run(&config)).expect("same-instance next request");
    let requests = backend.requests.lock().expect("requests lock");
    assert!(console(&requests[1], 0).contains("fresh result"));
    drop(requests);
    drop(executor);

    let restore_chunk0 = chunk0_path(0, OutputRef::from_bytes(b"fresh result"));
    let restore_script = format!(
        "const raw = await sandbox.fs.read_file({path}); console.log(String.fromCharCode(...raw));",
        path = serde_json::to_string(&restore_chunk0).expect("path quotes"),
    );
    let restarted_backend =
        FixtureBackend::new(["console.log('third result');".to_owned(), restore_script]);
    let mut restarted_runtime = factory.runtime().expect("restart guest runtime");
    let mut restarted = EngineNativeExecutor::new(
        &vault,
        &restarted_backend,
        &lease,
        &mut restarted_runtime,
        &gated,
    )
    .with_output_decay(policy);
    block_on_ready(restarted.run(&config)).expect("restart request");
    let restarted_requests = restarted_backend.requests.lock().expect("requests lock");
    assert!(console(&restarted_requests[0], 0).contains("fresh result"));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .expect("summary census")
            .is_empty()
    );
    assert!(
        compaction_doors::coverage_rows(&vault, run_id)
            .expect("coverage read")
            .is_empty()
    );
    drop(restarted_requests);

    // Now the accepted SUMMARY, not the guest's identical old marker bytes,
    // creates the sole run-bound coverage decision for step zero.
    // The run's own compaction session: a request for any other session is
    // refused at the swap.
    let session = executor_compaction_session_id(gated.run_ref(), run_id).expect("run session");
    let _sitting = match vault
        .mint_session(
            SessionKey {
                actor: entity(0xD1),
                machine: entity(0xD2),
            },
            10,
        )
        .expect("session")
    {
        SessionMintOutcome::Minted(id) => id,
        other => panic!("unexpected session: {other:?}"),
    };
    let turn = entity(0xC7);
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            range(10),
            10,
            b"covered source turn",
        )
        .expect("covered turn");
    let mut registry = CompactionBackendRegistry::new();
    registry.register(Arc::new(Cheap)).expect("cheap backend");
    let profile = MemoryProfile::new(
        1000,
        ModelTierRef("executor-output-test".into()),
        CompactionOwnership::Engine,
    );
    let mut driver = CompactionDriver::for_profile(&profile, &registry)
        .expect("driver resolves")
        .expect("engine-owned profile compacts");
    driver
        .evaluate_now(&vault, u64::MAX)
        .expect("cross threshold");
    let request = driver
        .request_for(
            &vault,
            &session,
            vec![CompactionWindowMessage {
                message_id: entity(0xC8),
                turn_id: turn,
                content: "fresh result".into(),
                turn: 0,
                tokens: 2,
            }],
        )
        .expect("sealed window");
    let product = driver.backend().compact(&request, None).expect("product");
    // The lib test's `GatedCompaction::ungated_for_test` is `#[cfg(test)]`, which an
    // integration target never sees; the one-word summary passes the real gate instead.
    // The window holds two tokens against a zero floor, so the smaller summary fits.
    let gated_compaction = gate_compaction(
        &request,
        &product,
        &CompactionGatePolicy {
            floor_tokens: 0,
            ..Default::default()
        },
    )
    .expect("the one-word summary passes the gate");
    let plan = restarted
        .integrate_compaction(
            &mut driver,
            WriteActor::new(entity(0xA0), EdgeActorClass::Agent),
            gated_compaction,
            &[],
        )
        .expect("summary and typed run coverage committed together");
    let rows = compaction_doors::coverage_rows(&vault, run_id).expect("coverage rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].summary_id(), plan.summary_id);
    assert!(rows[0].covers(run_id, 0));
    assert!(!rows[0].covers(run_id, 1));
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .expect("summary census")
            .len(),
        1
    );

    let resumed = block_on_ready(restarted.run(&config)).expect("same-instance covered request");
    let requests = restarted_backend.requests.lock().expect("requests lock");
    assert!(!compacted(&requests[1]).contains("fresh result"));
    reexpand_from_frame(&requests[1], b"fresh result", &restore_chunk0);
    assert!(
        console_after_frame(&requests[1], 1).contains("next result"),
        "uncovered tail remains full"
    );
    assert_eq!(
        answer_doors::observation_text(&vault, &resumed.replay_record, 3)
            .expect("guest restored original through linked read"),
        "fresh result",
    );
    drop(requests);
    drop(restarted);

    let next_backend = FixtureBackend::new(["console.log('after restart');"]);
    let mut next_runtime = factory.runtime().expect("new guest runtime");
    let mut next =
        EngineNativeExecutor::new(&vault, &next_backend, &lease, &mut next_runtime, &gated)
            .with_output_decay(policy);
    block_on_ready(next.run(&config)).expect("restart reads typed coverage");
    let next_requests = next_backend.requests.lock().expect("requests lock");
    assert!(!compacted(&next_requests[0]).contains("fresh result"));
    reexpand_from_frame(&next_requests[0], b"fresh result", &restore_chunk0);
    assert!(console_after_frame(&next_requests[0], 1).contains("next result"));
}
