use super::*;
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::code_sandbox::quickjs::QuickJsRuntimeFactory;
#[cfg(feature = "code-sandbox-wasmtime")]
use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
use crate::engine_executor::SelfDispatchResponse;
use crate::skill::{SkillCallContract, SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::temporal::TimeRange;
use rmpv::Value;
#[cfg(feature = "code-sandbox-wasmtime")]
use sha2::{Digest, Sha256};
#[cfg(feature = "code-sandbox-wasmtime")]
use std::path::PathBuf;

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
        crate::entity_id::bytes_to_hex_lower(&pin),
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
    fn dispatch_self(&mut self, _: crate::code_run::SelfCall) -> Result<SelfDispatchResponse> {
        Err(invalid("callable fixture cannot request a host effect"))
    }
}

#[test]
fn callable_runs_in_caller_sandbox_and_records_pair_specific_reliability() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let vault = Vault::open(temp.path(), crate::VaultConfig::device()).expect("open vault");
    let id = EntityId::now();
    let files = vec![
        HubFile::new("SKILL.md", b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n".to_vec()),
        HubFile::new(
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));".to_vec(),
        ),
    ];
    let hash = crate::skill::canonical_skill_tree_hash(
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
    crate::skill_hub::package_from_source(
        &record,
        package.files.clone(),
        SkillPackageFormat::Native,
    )
    .expect("initial callable source matches its frontmatter");
    vault
        .with_write_txn(|txn| {
            vault.put_skill_record_in_txn(txn, &id, &record, TimeRange { start: 1, end: 1 }, 1)?;
            vault.persist_hub_package_in_txn(txn, &id, &package)
        })
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
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "call.fixture".into(),
        payload: vec![],
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("fresh attempt")
    };
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "caller-lease".into(),
        now: 11,
    })?
    else {
        panic!("leased attempt")
    };

    let mut runtime = runtime()?;
    let run_id = EntityId::now();
    let outcome = execute_callable_skill(
        &vault,
        &leased,
        &id,
        "current-model",
        &serde_json::json!({"value":41}),
        runtime.as_mut(),
        &mut NoEffects,
        run_id,
        0,
        CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
        12,
    )?;
    assert_eq!(
        serde_json::from_str::<JsonValue>(&outcome.observation).expect("JSON return"),
        serde_json::json!({"result":42})
    );
    assert!(
        execute_callable_skill(
            &vault,
            &leased,
            &id,
            "current-model",
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
            "current-model",
            &serde_json::json!({"value":41}),
            runtime.as_mut(),
            &mut NoEffects,
            run_id,
            2,
            CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
            15,
        )
        .is_err(),
        "the finished caller no longer holds the lease"
    );
    let receipt = crate::receipt::attempt_pack_receipt_id(&attempt.id);
    let other =
        crate::skill_reliability::skill_executor_reliability_posterior(&vault, &id, "next-model")?;
    crate::skill_reliability::record_skill_executor_outcome(
        &vault,
        &id,
        "current-model",
        &receipt,
        true,
    )?;
    crate::skill_reliability::record_skill_executor_outcome(
        &vault,
        &id,
        "current-model",
        &receipt,
        true,
    )?;
    assert!(
        crate::skill_reliability::record_skill_executor_outcome(
            &vault,
            &id,
            "next-model",
            &receipt,
            true,
        )
        .is_err(),
        "the same receipt cannot credit another executor"
    );
    let current = crate::skill_reliability::skill_executor_reliability_posterior(
        &vault,
        &id,
        "current-model",
    )?;
    assert_eq!(current.alpha, other.alpha + 1.0);
    assert_eq!(current.beta, other.beta);
    assert_eq!(
        crate::skill_reliability::skill_executor_reliability_posterior(&vault, &id, "next-model")?,
        other
    );
    let EnqueueOutcome::Enqueued(listed) = queue.enqueue(EnqueueAttempt {
        kind: "call.listed-only".into(),
        payload: vec![],
        dedupe_key: None,
        run_id: None,
        now: 20,
    })?
    else {
        panic!("fresh listed attempt")
    };
    vault.load_attempt_skill_pack(listed.id, &id, 20)?;
    let ClaimOutcome::Claimed(listed_lease) = queue.claim(ClaimAttempt {
        lease_owner: "listed-worker".into(),
        now: 21,
    })?
    else {
        panic!("listed attempt leased")
    };
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: listed.id,
            lease_owner: "listed-worker".into(),
            attempt_count: listed_lease.attempt_count,
            now: 22,
        })?,
        CompleteOutcome::Completed(_)
    ));
    assert!(
        crate::skill_reliability::record_skill_executor_outcome(
            &vault,
            &id,
            "current-model",
            &crate::receipt::attempt_pack_receipt_id(&listed.id),
            true,
        )
        .is_err(),
        "merely loading the skill cannot credit callable execution"
    );
    Ok(())
}
