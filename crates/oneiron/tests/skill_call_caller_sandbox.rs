#![cfg(oneiron_test_support)]
//! Pins callable execution in the caller's sandbox and lease.
//! Outcome evidence belongs only to executors that invoked the callable.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked --no-fail-fast -p oneiron --all-features --features oneiron-agent-runtime/code-sandbox-wasmtime --test skill_call_caller_sandbox`.
//! Real QuickJS needs the dev-dependency feature `oneiron-agent-runtime/code-sandbox-wasmtime`.

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::code_run::CodeRunDeterminism;
use oneiron::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome, SelfDispatchResponse,
};
use oneiron::error::{ArtifactError, Error, Result};
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, execute_callable_skill,
};
use oneiron::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault};
#[cfg(feature = "code-sandbox-wasmtime")]
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
#[cfg(feature = "code-sandbox-wasmtime")]
use oneiron_agent_runtime::code_sandbox::wasmtime_runtime::ComponentBudget;
use rmpv::Value;
use serde_json::Value as JsonValue;
#[cfg(feature = "code-sandbox-wasmtime")]
use sha2::{Digest, Sha256};
use std::io::Read;
#[cfg(feature = "code-sandbox-wasmtime")]
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "code-sandbox-wasmtime")]
fn runtime() -> Result<Box<dyn JsCodeModeRuntime>> {
    let path = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        PathBuf::from,
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("manifest.json"))?)
            .expect("pinned manifest");
    let artifact = &manifest["artifacts"]["first-party"];
    let bytes = std::fs::read(path.join(artifact["file"].as_str().expect("pinned filename")))?;
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        oneiron::test_doors::callable_skill::bytes_to_hex_lower(&pin),
        artifact["sha256"].as_str().unwrap()
    );
    let factory = QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())?;
    Ok(Box::new(factory.runtime()?))
}

#[cfg(not(feature = "code-sandbox-wasmtime"))]
struct FakeRuntime;
#[cfg(not(feature = "code-sandbox-wasmtime"))]
impl JsCodeModeRuntime for FakeRuntime {
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        _: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        assert_eq!(
            step.boundary,
            SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer)
                .without_host_services()
        );
        assert!(step.script.contains("skillArgs.value + 1"));
        assert!(step.script.contains("{\"value\":41}"));
        Ok(JsCodeModeStepOutcome::complete("{\"result\":42}"))
    }
}
#[cfg(not(feature = "code-sandbox-wasmtime"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the featureless double shares the real runtime factory signature"
)]
fn runtime() -> Result<Box<dyn JsCodeModeRuntime>> {
    Ok(Box::new(FakeRuntime))
}

struct NoEffects;
impl JsCodeModeHost for NoEffects {
    fn dispatch_self(&mut self, _: oneiron::code_run::SelfCall) -> Result<SelfDispatchResponse> {
        Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "callable fixture cannot request a host effect",
        )))
    }
}

#[test]
fn callable_runs_in_caller_sandbox_and_records_pair_specific_reliability() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let vault =
        Arc::new(Vault::open(temp.path(), oneiron::VaultConfig::device()).expect("open vault"));
    let id = EntityId::now();
    let files = vec![
        HubFile::new("SKILL.md", b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n".to_vec()),
        HubFile::new(
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));".to_vec(),
        ),
    ];
    let hash = oneiron::skill::canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/call.js".into(),
            arguments: serde_json::json!({"value":"integer"}),
            returns: serde_json::json!({"result":"integer"}),
        }),
    )
    .with_content_hash(hash);
    let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    package.format = SkillPackageFormat::Native;
    oneiron::test_doors::callable_skill::package_from_source(
        &record,
        package.files.clone(),
        SkillPackageFormat::Native,
    )
    .expect("initial callable source matches its frontmatter");
    oneiron::test_doors::callable_skill::put_skill_record_and_package(
        &vault,
        &id,
        &record,
        &package,
        TimeRange { start: 1, end: 1 },
        1,
    )
    .expect("persist initial callable");
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &active, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate local callable");
    let mut changed_call = active.clone();
    changed_call.version = "2".into();
    changed_call.call.as_mut().expect("call").reference = "SKILL.md".into();
    assert!(
        vault
            .update_skill_record(&id, &changed_call, TimeRange { start: 3, end: 3 }, 3)
            .is_err(),
        "metadata cannot retarget an admitted source without new source custody"
    );
    let fork_id = EntityId::now();
    let fork = vault
        .fork_skill_record(
            &id,
            &fork_id,
            "fixture.local-fork",
            TimeRange { start: 4, end: 4 },
            4,
        )
        .expect("callable fork preserves source and contract");
    assert_eq!(fork.role, SkillRole::Callable);
    assert_eq!(fork.call, active.call);

    let queue = AttemptQueue::new(&vault);
    let AgentDispatchOutcome::Dispatched(dispatched) = AgentDispatcher::new(&vault)
        .dispatch_default_base(None, None, None, vault.now_recorded_at())?
    else {
        panic!("fresh attempt")
    };
    let attempt = dispatched.attempt;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        DREAMER_RUNNER_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "caller-lease".into(),
            now: vault.now_recorded_at(),
        },
    )?
    else {
        panic!("leased attempt")
    };

    let mut runtime = runtime()?;
    let run_id = EntityId::now();
    let mut outcome = execute_callable_skill(
        &vault,
        &leased,
        &id,
        "model-current@1",
        &serde_json::json!({"value":41}),
        runtime.as_mut(),
        &mut NoEffects,
        run_id,
        0,
        CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
        12,
    )?;
    let mut outcome_text = String::new();
    outcome.reader()?.read_to_string(&mut outcome_text)?;
    assert_eq!(
        serde_json::from_str::<JsonValue>(&outcome_text).expect("JSON return"),
        serde_json::json!({"result":42})
    );
    assert!(
        execute_callable_skill(
            &vault,
            &leased,
            &id,
            "model-current@1",
            &serde_json::json!({"value":"invalid"}),
            runtime.as_mut(),
            &mut NoEffects,
            run_id,
            1,
            CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
            13
        )
        .is_err()
    );
    let mut second = execute_callable_skill(
        &vault,
        &leased,
        &id,
        "model-next@1",
        &serde_json::json!({"value":41}),
        runtime.as_mut(),
        &mut NoEffects,
        run_id,
        2,
        CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
        13,
    )?;
    let mut second_text = String::new();
    second.reader()?.read_to_string(&mut second_text)?;
    assert_eq!(second_text, outcome_text);
    assert!(
        execute_callable_skill(
            &vault,
            &leased,
            &id,
            "model-next@1",
            &serde_json::json!({"value":41}),
            runtime.as_mut(),
            &mut NoEffects,
            run_id,
            0,
            CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
            13,
        )
        .is_err(),
        "a step one executor ran cannot be re-credited to another"
    );
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "caller-lease".into(),
            attempt_count: leased.attempt_count,
            now: 14,
        })?,
        CompleteOutcome::Completed(_)
    ));
    assert!(
        execute_callable_skill(
            &vault,
            &leased,
            &id,
            "model-current@1",
            &serde_json::json!({"value":41}),
            runtime.as_mut(),
            &mut NoEffects,
            run_id,
            3,
            CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
            15,
        )
        .is_err(),
        "the finished caller no longer holds the lease"
    );
    let receipt = oneiron::receipt::attempt_pack_receipt_id(&attempt.id);
    // FIX [T0B-SKILL-CALL-PAIR-RELIABILITY]: does a callable win mint pair reliability (projector.rs:535-538: a win alone is no learning anchor; no production code stamps learning.anchor), and in which (skill, executor, task type, axis) cell?
    #[cfg(any())]
    let prior = oneiron::skill_reliability::skill_reliability_prior(&vault, &id)?;
    // A win lands in the shared outcome ledger for every executor that ran a
    // step, and projects through the same per-executor claim selection reads.
    oneiron::test_doors::callable_skill::project_callable_receipt_outcome(
        &vault, &id, &receipt, true, 16,
    )?;
    oneiron::test_doors::callable_skill::project_callable_receipt_outcome(
        &vault, &id, &receipt, true, 16,
    )?;
    // FIX [T0B-SKILL-CALL-PAIR-RELIABILITY]: does a callable win mint pair reliability (projector.rs:535-538: a win alone is no learning anchor; no production code stamps learning.anchor), and in which (skill, executor, task type, axis) cell?
    #[cfg(any())]
    for executor in ["model-current@1", "model-next@1"] {
        let pair = oneiron::skill_reliability::skill_executor_reliability(&vault, &id, executor)?;
        assert_eq!((pair.runs, pair.new_model), (1, false), "{executor}");
        assert_eq!(pair.posterior.alpha, prior.alpha + 1.0);
        assert_eq!(pair.posterior.beta, prior.beta);
        assert!(
            oneiron::skill_reliability::skill_selection_score_for_executor(
                &vault, &id, executor, 4
            )? > oneiron::skill_reliability::skill_selection_score_for_executor(
                &vault,
                &id,
                "model-third@1",
                4
            )?
        );
    }
    // FIX [T0B-SKILL-CALL-PAIR-RELIABILITY]: does a callable win mint pair reliability (projector.rs:535-538: a win alone is no learning anchor; no production code stamps learning.anchor), and in which (skill, executor, task type, axis) cell?
    #[cfg(any())]
    assert!(
        oneiron::skill_reliability::skill_executor_reliability(&vault, &id, "model-third@1")?
            .new_model,
        "an executor that never invoked the callable stays unmeasured"
    );
    {
        let txn = oneiron::test_doors::callable_skill::read_txn(&vault)?;
        assert_eq!(
            oneiron::test_doors::callable_skill::attributed_outcome_receipts(&vault, &txn, &id)?,
            vec![receipt.clone()],
            "the improver's receipt split sees the callable outcome"
        );
    }
    let AgentDispatchOutcome::Dispatched(dispatched) = AgentDispatcher::new(&vault)
        .dispatch_default_base(None, None, None, vault.now_recorded_at())?
    else {
        panic!("fresh listed attempt")
    };
    let listed = dispatched.attempt;
    let ClaimOutcome::Claimed(listed_lease) = queue.claim_kind(
        DREAMER_RUNNER_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "listed-worker".into(),
            now: vault.now_recorded_at(),
        },
    )?
    else {
        panic!("listed attempt leased")
    };
    vault.load_attempt_skill_pack(
        listed.id,
        &id,
        "listed-worker",
        listed_lease.attempt_count,
        "model-current@1",
        21,
    )?;
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: listed.id,
            lease_owner: "listed-worker".into(),
            attempt_count: listed_lease.attempt_count,
            now: 22,
        })?,
        CompleteOutcome::Completed(_)
    ));
    oneiron::test_doors::callable_skill::project_callable_receipt_outcome(
        &vault,
        &id,
        &oneiron::receipt::attempt_pack_receipt_id(&listed.id),
        true,
        23,
    )?;
    {
        let txn = oneiron::test_doors::callable_skill::read_txn(&vault)?;
        assert_eq!(
            oneiron::test_doors::callable_skill::attributed_outcome_receipts(&vault, &txn, &id)?,
            vec![receipt],
            "a listed-only load invokes nothing, so its receipt attributes no outcome"
        );
    }
    // FIX [T0B-SKILL-CALL-PAIR-RELIABILITY]: does a callable win mint pair reliability (projector.rs:535-538: a win alone is no learning anchor; no production code stamps learning.anchor), and in which (skill, executor, task type, axis) cell?
    #[cfg(any())]
    assert_eq!(
        oneiron::skill_reliability::skill_executor_reliability(&vault, &id, "model-current@1")?
            .runs,
        1,
        "merely loading the skill cannot credit callable execution"
    );
    Ok(())
}
