//! REVIEW-10594: the admitted outer skill call belongs to the MCP caller,
//! but calls made by its skill are still run calls.
//!
//! 1. `an_admitted_outer_skill_call_is_admitted_as_its_callers_own`: the
//!    admitted entry answers `1` even though the run door refuses skill
//!    calls. Red with `let outer = false;` in `call_skill_on_stack`: the
//!    call meets `admit_run_call`, and `execute_live_skill_call` returns
//!    the error code `caller_code_refused` from `SelfDispatchOutcome::Denied`.
//! 2. `a_skill_body_s_own_skill_call_still_meets_the_run_door`: the outer
//!    skill answers `2`; the replay record keeps both calls and the inner
//!    call's `caller_code_refused` denial with `caller_code.credential_answer`.
//!    Red if every skill call is admitted as outer: the inner row is no
//!    longer denied, even though the outer answer is still `2`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features
//! --features oneiron-agent-runtime/code-sandbox-wasmtime
//! --test admitted_skill_call_outer_door`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunDeterminism, CodeRunReplayRecord,
    HostSelfDispatcher, RunCall, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfDispatcher,
    SelfEffect, SelfSkillCall, SkillCallInput,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::engine_executor::{AdmittedSkillAnswer, execute_live_skill_call};
use oneiron::memory::{HostWriteOrigin, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::HostBinding;
use oneiron::test_doors::callable_skill;
use oneiron::{AttemptId, AttemptQueue, EntityId, ModelId, Vault, VaultConfig, WriteActor};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const WORKER: &str = "admitted-skill-call-outer-door";

struct OuterOnlyDoor;

impl AgentVerbDoor for OuterOnlyDoor {
    fn call(
        &self,
        _call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            hook_notice: None,
            code: "mcp_verb_not_bound".into(),
            reason_codes: Vec::new(),
        }))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        match call {
            RunCall::Bridge(SelfEffect::SkillsCall) => Err(AgentVerbRefusal {
                hook_notice: None,
                code: "caller_code_refused".into(),
                reason_codes: vec!["caller_code.credential_answer".into()],
            }),
            _ => Ok(None),
        }
    }

    fn admit_outer_skill_call(
        &self,
    ) -> std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
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

fn one_skill(vault: &Vault) -> EntityId {
    callable_skill::put_active_callable(
        vault,
        "fixture.outer-door-one",
        "finish(JSON.stringify(1));",
        &json!({}),
        &json!("integer"),
    )
    .expect("the integer callable is stored and active")
}

fn nesting_skill(vault: &Vault) -> EntityId {
    callable_skill::put_active_callable(
        vault,
        "fixture.outer-door-nesting",
        r"try {
    await self.skills.call({skill: skillArgs.inner, args: {}});
} catch {
    // The replay record, not this answer, proves the refusal.
}
finish(JSON.stringify(2));",
        &json!({"inner": "string"}),
        &json!("integer"),
    )
    .expect("the nesting callable is stored and active")
}

fn admitted_skill_call(
    vault: &Arc<Vault>,
    run_id: EntityId,
    skill: EntityId,
    args: Value,
) -> MemoryResult<AdmittedSkillAnswer> {
    let (actor, leased) = leased_actor(vault, run_id);
    let binding =
        HostBinding::from_leased(&leased, Some(run_id)).expect("the leased run binds its door");
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
        .expect("callable skills bind the run's vault")
        .with_agent_verb_door(Arc::new(OuterOnlyDoor) as Arc<dyn AgentVerbDoor>);
    let model = ModelId::new("test/executor@v1").expect("a model id");
    let mut runtime = quickjs_factory().runtime().expect("a guest runtime");
    execute_live_skill_call(
        vault,
        &binding,
        &dispatcher,
        &model,
        SkillCallInput {
            skill: skill.to_hex(),
            args,
        },
        (&mut runtime, None),
        false,
    )
}

/// Run `run_id`'s replay record as the admitted entry left it.
fn admitted_record(vault: &Vault, run_id: &EntityId) -> CodeRunReplayRecord {
    vault
        .get_code_run_replay_record(run_id)
        .expect("the run record reads")
        .expect("the admitted call left its record")
}

#[test]
fn an_admitted_outer_skill_call_is_admitted_as_its_callers_own() {
    let (_dir, vault) = open_vault();
    let skill = one_skill(&vault);
    let answer = admitted_skill_call(&vault, fresh_id(), skill, json!({}))
        .expect("the caller's own skill call is admitted");

    assert!(
        matches!(&answer, AdmittedSkillAnswer::Value(value) if value == &json!(1)),
        "expected the inline integer 1, got {answer:?}"
    );
}

#[test]
fn a_skill_body_s_own_skill_call_still_meets_the_run_door() {
    let (_dir, vault) = open_vault();
    let inner = one_skill(&vault);
    let outer = nesting_skill(&vault);
    let run_id = fresh_id();
    let args = json!({"inner": inner.to_hex()});
    let answer = admitted_skill_call(&vault, run_id, outer, args.clone())
        .expect("the caller's own skill finishes after its nested call");
    assert!(
        matches!(&answer, AdmittedSkillAnswer::Value(value) if value == &json!(2)),
        "expected the inline integer 2, got {answer:?}"
    );

    let record = admitted_record(&vault, &run_id);
    let [outer_row, inner_row] = record.bridge_calls.as_slice() else {
        panic!(
            "expected two bridge rows, got {}",
            record.bridge_calls.len()
        );
    };
    assert_eq!(outer_row.effect, SelfEffect::SkillsCall);
    assert_eq!(inner_row.effect, SelfEffect::SkillsCall);

    let replay = record.replay_cursor();
    replay
        .dispatch(SelfCall::SkillsCall(SelfSkillCall { skill: outer, args }))
        .expect("the first replay row matches the outer call");
    let inner_outcome = replay
        .dispatch(SelfCall::SkillsCall(SelfSkillCall {
            skill: inner,
            args: json!({}),
        }))
        .expect("the second replay row matches the nested call");
    let SelfDispatchOutcome::Denied(denied) = inner_outcome else {
        panic!("expected the nested call to be denied, got {inner_outcome:?}");
    };
    assert_eq!(denied.outcome, "caller_code_refused");
    assert_eq!(denied.reason_codes, ["caller_code.credential_answer"]);
}
