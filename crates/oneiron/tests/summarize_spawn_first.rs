//! A spawn-off child is denied before the recording host resolves result
//! members or reads and publishes NOTE members.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, ChildPowerRequest};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ScopedReadActorKey};
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunDeterminism, HostSelfDispatcher,
    RunCall, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfAgentVerbCall, SelfCall,
    SelfDispatchOutcome, SelfDispatcher, SelfEffect,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorStatus,
    EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::note::NoteReadRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::code_run_answer as doors;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use rmpv::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NOW: u64 = 1_700_000_000;

const SPAWN_OFF: &str = "gate.deny.agent_power.spawn_off";

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "agent powers fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    clock: Arc<ManualClock>,
    agent: EntityId,
    /// A second owner-created agent: the definition every spawn here starts.
    worker: EntityId,
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A default-policy device vault, its embedded owner, two owner-created Base
/// agents at ceiling Proposed, and the first one's root attempt, leased. The
/// owner set no power: both agents hold both.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;

    let agent = EntityId::from_bytes([0x93; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &agent,
        &definition("fixture.powers"),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;
    let worker = EntityId::from_bytes([0x96; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &worker,
        &definition("fixture.powers.worker"),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: NOW,
        })?
    else {
        panic!("the agent dispatches without running a model")
    };
    clock.set(NOW + 1);
    let leased = claim_next(&vault, NOW + 1)?;
    assert_eq!(leased.id, status.attempt.id);
    clock.set(NOW + 2);
    Ok(Fixture {
        vault,
        owner: owner_id,
        clock,
        agent,
        worker,
        leased,
        _dir: dir,
    })
}

fn claim_next(vault: &Vault, now: u64) -> TestResult<AttemptRecord> {
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault).claim(ClaimAttempt {
        lease_owner: "agent-powers-fixture".to_owned(),
        now,
    })?
    else {
        panic!("an attempt is ready to lease")
    };
    Ok(leased)
}

/// The leased host dispatcher of `leased`, running as `agent`.
fn host<'a>(
    f: &'a Fixture,
    agent: EntityId,
    leased: &AttemptRecord,
) -> oneiron::Result<HostSelfDispatcher<'a>> {
    HostSelfDispatcher::for_leased_agent_attempt(
        &f.vault,
        WriteActor::new(agent, EdgeActorClass::Agent),
        leased,
    )
}

/// `self.agents.spawn` of the worker agent under `key`, asking `powers`.
fn agents_spawn(f: &Fixture, key: &str, powers: Option<ChildPowerRequest>) -> SelfCall {
    SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
        target: Some(AgentDispatchTarget::Custom(f.worker)),
        context: AgentSpawnContext {
            powers,
            ..AgentSpawnContext::default()
        },
        intent_key: key.to_owned(),
        ask: None,
    }))
}

fn queued_attempt(outcome: SelfDispatchOutcome) -> AttemptId {
    match outcome {
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref, .. }) => {
            attempt_ref
        }
        other => panic!("expected a queued child, got {other:?}"),
    }
}

fn spawn_off_receipt_count(f: &Fixture, child: &AttemptRecord) -> TestResult<usize> {
    let actor_ref = f.worker.to_hex();
    let attempt_ref = EntityId::from_bytes(*child.id.as_bytes())?.to_hex();
    let grant_ref = format!("agent_power:01{attempt_ref}");
    Ok(f.vault
        .gate_decisions(4096)?
        .iter()
        .filter(|receipt| {
            receipt.outcome == "deny"
                && receipt.content_kind == "agent_power"
                && receipt.actor_ref.as_deref() == Some(actor_ref.as_str())
                && receipt.reason_codes.iter().any(|code| code == SPAWN_OFF)
                && receipt.grant_ref.as_deref() == Some(grant_ref.as_str())
        })
        .count())
}

/// A worker child the fixture's root attempt spawns asking `powers`, then
/// leased.
fn spawned_child(f: &Fixture, key: &str, powers: ChildPowerRequest) -> TestResult<AttemptRecord> {
    let parent = host(f, f.agent, &f.leased)?;
    let child = queued_attempt(parent.dispatch(agents_spawn(f, key, Some(powers)))?);
    f.clock.set(NOW + 3);
    let leased = claim_next(&f.vault, NOW + 3)?;
    assert_eq!(
        leased.id, child,
        "the spawned child is the next attempt to lease"
    );
    f.clock.set(NOW + 4);
    Ok(leased)
}

/// The test's `AgentVerbDoor`: full access without the MCP server. Every run
/// call is admitted as the run's own actor, and the host turn reads on that
/// actor's own key, so the run reads NOTEs as its worker reads them. A bound
/// door that answers no host-turn key reads nothing at all. No agent verb is
/// bound: these programs call nothing through the verb door.
struct FullAccessDoor {
    /// The run actor's own read key, as a run with no door derives it from
    /// the actor's class.
    key: ScopedReadActorKey,
}

impl FullAccessDoor {
    fn for_actor(actor: EntityId) -> Self {
        Self {
            key: ScopedReadActorKey::with_actor_class(
                actor.to_hex(),
                EdgeActorClass::Agent.gate_actor_class(),
            )
            .expect("the run actor's read key"),
        }
    }

    fn refused(code: &str) -> AgentVerbRefusal {
        AgentVerbRefusal {
            code: code.to_owned(),
            hook_notice: None,
            reason_codes: Vec::new(),
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
        _call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }

    /// The host turn reads as the run's own actor, as the server's run door
    /// answers it.
    fn host_turn_read_key(&self) -> Option<ScopedReadActorKey> {
        Some(self.key.clone())
    }
}

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
        task: "summarize as a spawn-off child".to_owned(),
        caller_source_digest: None,
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

fn refused_program(arguments: &str) -> String {
    format!(
        r#"try {{
    await summarize({arguments});
    finish("summarized");
}} catch (error) {{
    const refusal = JSON.parse(String(error));
    finish(refusal.denied + "|" + refusal.reasonCodes.join(","));
}}"#
    )
}

fn run_denied_summarize(
    f: &Fixture,
    child: &AttemptRecord,
    program: String,
) -> TestResult<EngineExecutorOutcome> {
    let before = spawn_off_receipt_count(f, child)?;
    let factory = quickjs_factory();
    let mut runtime = factory.runtime().expect("a guest runtime");
    let backend = FixtureBackend {
        programs: Mutex::new(VecDeque::from([program])),
    };
    let lease = BudgetLease::for_test("summarize-spawn-first");
    let gated = host(f, f.worker, child)?
        .with_agent_verb_door(Arc::new(FullAccessDoor::for_actor(f.worker)));
    let mut executor = EngineNativeExecutor::new(&f.vault, &backend, &lease, &mut runtime, &gated);
    let config = executor_config(EntityId::from_bytes(*child.id.as_bytes())?);
    let outcome = block_on_ready(executor.run(&config))?;
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    assert_eq!(
        outcome.replay_record.bridge_calls[0].effect,
        SelfEffect::Summarize
    );
    let answer = outcome
        .replay_record
        .outputs
        .iter()
        .find(|output| output.path.ends_with(".observation.txt"))
        .expect("the returned replay result holds the answer");
    assert_eq!(answer.preview.text, format!("deny|{SPAWN_OFF}"));
    let after = spawn_off_receipt_count(f, child)?;
    assert_eq!(
        after,
        before + 1,
        "one spawn-off receipt names the child's grant"
    );
    Ok(outcome)
}

#[test]
fn a_spawn_off_child_is_refused_for_a_missing_result_before_resolution() -> TestResult {
    let f = fixture()?;
    let child = spawned_child(
        &f,
        "child-spawn-first-missing",
        ChildPowerRequest {
            spawn: Some(false),
            save_agent: None,
        },
    )?;
    run_denied_summarize(&f, &child, refused_program(r#""missing-result", {}"#))?;
    Ok(())
}

#[test]
fn a_spawn_off_child_is_refused_for_a_readable_note_without_outputs() -> TestResult {
    let f = fixture()?;
    let child = spawned_child(
        &f,
        "child-spawn-first-note",
        ChildPowerRequest {
            spawn: Some(false),
            save_agent: None,
        },
    )?;
    doors::install_actor_ceiling(&f.vault, &f.worker, "proposed")?;
    let text = "The lighthouse keeper logs the tide at dawn.";
    let note = f.vault.create_note(
        "research",
        text,
        WriteActor::new(f.owner, EdgeActorClass::Human),
    )?;
    let note_ref = note.to_hex();
    let view = f
        .vault
        .memory(f.worker, EdgeActorClass::Agent)
        .read_note(&NoteReadRequest {
            note_ref: note_ref.clone(),
            reason: None,
            version: None,
            spans: Vec::new(),
        })?
        .value
        .expect("the child can read the NOTE");
    assert_eq!(view.markdown, text);

    let program = refused_program(&format!(r#"null, {{note_refs: ["{note_ref}"]}}"#));
    let outcome = run_denied_summarize(&f, &child, program)?;
    let member = format!("/summarize/{note_ref}.");
    assert!(
        !outcome
            .replay_record
            .outputs
            .iter()
            .any(|output| output.path.contains(&member)),
        "the NOTE was not published as a run output"
    );
    Ok(())
}
