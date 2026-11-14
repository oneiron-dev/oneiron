//! ARCH-0068 #rc5-check-reuse: "The receipt of a reused check says 'reused from'
//! and names the source attempt" (FIX [L4-30-CHECK-REUSE-RECORD]).
//!
//! One batch on an enrolled queue, checked with an isolated host. The first
//! fast check runs and passes; the door unbinds its slot, reproducing the
//! finish that stored its receipt but did not bind the slot; the diagnosis
//! then reuses that receipt instead of running. Comparing `serde_json`
//! values keeps this file compiling on main, where `reused_from` is the
//! digest string: there the first assertion fails at runtime.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test queue_check_reuse_source`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    AgentRun, MATH_RS, RepoFixture, TestResult, agent_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::code_run::{RepoRequestWitness, SelfEffect};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::memory::merge_queue_doors::{
    CodeCheckReceiptRequest, MergeQueueBatchRequest, MergeQueueCheckRequest, MergeQueueCheckState,
    MergeQueueDiagnoseRequest, MergeQueueEnqueueRequest, QueueCheckPhase,
};
use oneiron::memory::repo_doors::RepoProposalSubmitInput;
use oneiron::merge_queue::{
    BatchState, QUEUE_CHECK_CANDIDATE_PREFIX, QueueCheckEnvironment, QueueCheckExecution,
    QueueCheckHost, QueueCheckInputs, QueueCheckInvocation, QueueCheckNeed, QueueCheckRun,
    QueueCheckStatus, QueueCheckWork, QueueCommandReceipt,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};
use std::collections::BTreeMap;

/// The change under check: `add_one` adds two.
const MATH_RS_CHANGED: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 2\n}\n";

/// The fixture's passing-checks host, but on the isolated backend with the
/// network denied, so [`QueueCheckInputs::reusable`] is true. It counts its
/// executions, so the test sees the reused check run nothing.
struct IsolatedPassingChecks {
    executes: u32,
}

impl QueueCheckHost for IsolatedPassingChecks {
    fn environment(&mut self) -> Result<QueueCheckEnvironment, QueueCheckNeed> {
        Ok(QueueCheckEnvironment {
            backend: "isolated".to_owned(),
            executor: "isolated".to_owned(),
            runtime: None,
            image: None,
            helper: Vec::new(),
            toolchain: BTreeMap::new(),
            limits: None,
            network: "deny".to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })
    }

    fn execute(
        &mut self,
        _invocation: &QueueCheckInvocation<'_>,
        inputs: &QueueCheckInputs,
        _stop: &dyn Fn() -> bool,
    ) -> oneiron::Result<QueueCheckExecution> {
        self.executes += 1;
        Ok(QueueCheckExecution::Completed(QueueCheckRun {
            commands: inputs
                .commands
                .iter()
                .map(|command| QueueCommandReceipt {
                    argv: command.argv.clone(),
                    status: Some(0),
                    signal: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    declared_outputs: BTreeMap::new(),
                })
                .collect(),
            contract_outputs: BTreeMap::new(),
            session: None,
            input_before: "unchanged".to_owned(),
            input_after: "unchanged".to_owned(),
        }))
    }
}

/// The witness of the model request the host served the run: the test builds
/// the request and captures it, as a host captures the finalized request at
/// its send. No model is called.
fn served_request_witness() -> TestResult<RepoRequestWitness> {
    let model = ModelId::new("local/queue-check-reuse-source@r1").expect("model id");
    let request = LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    };
    Ok(RepoRequestWitness::capture(&request).ok_or("the request has a canonical form")?)
}

/// The run's proposal of its math.rs change.
fn submit_math_proposal(
    vault: &Vault,
    run: &AgentRun,
    witness: &RepoRequestWitness,
) -> TestResult<EntityId> {
    let memory = vault.memory(run.actor.entity_ref(), run.actor.actor_class());
    let content = MATH_RS_CHANGED.as_bytes();
    assert_ne!(MATH_RS_CHANGED, MATH_RS);
    let content_hash = *blake3::hash(content).as_bytes();
    Ok(memory
        .repo_proposal_submit_for_run(
            &run.binding,
            RepoProposalSubmitInput {
                work: run.work,
                path: "math.rs".to_owned(),
                content: content.to_vec(),
                message: "add_one adds two".to_owned(),
                declaration: None,
                repair_of: None,
            },
            None,
            |stamp| {
                run.binding.sources_from_host(
                    vault,
                    stamp,
                    "math.rs".to_owned(),
                    content_hash,
                    witness,
                    SelfEffect::RepoProposalSubmit,
                )
            },
        )?
        .output
        .proposal)
}

/// Claims the one queued check and runs it on `host` to its end.
fn run_one_pending_check(
    vault: &Vault,
    host: &mut IsolatedPassingChecks,
) -> TestResult<QueueCheckWork> {
    let pending = vault.pending_queue_checks()?;
    assert_eq!(pending.len(), 1, "the request is the one queued work");
    let work = vault
        .claim_queue_check(&pending[0], "queue-check-reuse-checker", 1)?
        .ok_or("the checker claims the queued work")?;
    Ok(vault.run_queue_check(&work, host, &|| false)?)
}

/// The run's one retained receipt, as `vault.code.checks.get` carries it.
fn check_receipt_json(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    repo: EntityId,
    work: &QueueCheckWork,
) -> TestResult<serde_json::Value> {
    let digest = work
        .receipts
        .first()
        .ok_or("the run left its one receipt")?
        .inputs_digest
        .clone();
    let receipt_ref = format!("{QUEUE_CHECK_CANDIDATE_PREFIX}{digest}");
    let view = memory
        .merge_queue_check_receipt_as(
            owner,
            CodeCheckReceiptRequest {
                repo,
                work_ref: work.work_ref().to_owned(),
                receipt_ref,
            },
        )?
        .ok_or("the receipt reads back")?;
    let value = serde_json::to_value(view)?;
    let receipts = value
        .get("receipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("the view holds its receipts")?;
    receipts
        .first()
        .cloned()
        .ok_or("the view holds the one receipt")
        .map_err(Into::into)
}

/// One agent's math.rs proposal, queued and staged as its one batch: the
/// batch digest and its path mask.
fn staged_math_batch(fixture: &RepoFixture) -> TestResult<(String, u64)> {
    let vault = &fixture.vault;
    let bounds = fixture.bounds(&["*.rs"], &["*.rs"]);
    let agent = create_enabled_agent(vault, &fixture.owner_proof, "queue-check-reuse-agent")?;
    let slip = paired_agent_slip(vault, &fixture.issuer, &fixture.owner_proof, agent, 0x72)?;
    let grant = mint_repo_grant(vault, &fixture.owner_proof, agent, Some(&bounds))?;
    let owner_memory = fixture.owner_memory();
    let leased = leased_try(
        vault,
        &owner_memory,
        fixture.owner,
        agent,
        "queue check reuse",
    )?;
    let run = agent_run(vault, &slip, leased, fixture.repo, grant)?;
    let witness = served_request_witness()?;
    let proposal = submit_math_proposal(vault, &run, &witness)?;
    let memory = fixture.owner_memory();
    let enqueued = memory.merge_queue_enqueue_as(
        &fixture.owner_proof,
        MergeQueueEnqueueRequest {
            repo: fixture.repo,
            proposals: vec![proposal],
            base_green: fixture.commit.clone(),
        },
    )?;
    assert_eq!(enqueued.state, BatchState::Queued, "the batch queues");
    let staged = memory.merge_queue_stage_as(
        &fixture.owner_proof,
        MergeQueueBatchRequest {
            repo: fixture.repo,
            batch_ref: enqueued.batch_ref.clone(),
        },
    )?;
    assert_eq!(staged.state, BatchState::Staged, "the batch stages");
    assert_eq!(staged.paths.len(), 1, "one proposal stages its one path");
    Ok((staged.batch_ref.clone(), staged.paths[0].mask))
}

#[test]
fn a_reused_queue_check_names_its_source_attempt() -> TestResult {
    let fixture = RepoFixture::enrolled()?;
    let vault = &fixture.vault;
    let (batch, mask) = staged_math_batch(&fixture)?;
    let memory = fixture.owner_memory();

    let first_work = memory.merge_queue_check_as(
        &fixture.owner_proof,
        MergeQueueCheckRequest {
            repo: fixture.repo,
            batch_ref: batch.clone(),
            mask,
            phase: QueueCheckPhase::Fast,
            force_refresh: false,
        },
    )?;
    assert_eq!(
        first_work.status,
        MergeQueueCheckState::Queued,
        "the check queues"
    );
    let mut host = IsolatedPassingChecks { executes: 0 };
    let done_first = run_one_pending_check(vault, &mut host)?;
    assert_eq!(
        done_first.status,
        QueueCheckStatus::Completed { passed: true },
        "the first check passes"
    );
    assert_eq!(
        done_first.generation, 1,
        "the check ran its first generation"
    );
    assert_eq!(host.executes, 1, "the first check ran its commands");
    let first = check_receipt_json(&memory, &fixture.owner_proof, fixture.repo, &done_first)?;

    oneiron::test_doors::merge_queue_check::unbind_slot_verdict(vault, fixture.repo, &batch, mask)?;

    let second_work = memory.merge_queue_diagnose_as(
        &fixture.owner_proof,
        MergeQueueDiagnoseRequest {
            repo: fixture.repo,
            batch_ref: batch.clone(),
        },
    )?;
    assert_ne!(
        second_work.work_ref, first_work.work_ref,
        "the diagnosis is a new work row"
    );
    let done_second = run_one_pending_check(vault, &mut host)?;
    assert_eq!(
        done_second.status,
        QueueCheckStatus::Completed { passed: true },
        "the reused check passes"
    );
    assert_eq!(host.executes, 1, "the reused check ran nothing");
    let second = check_receipt_json(&memory, &fixture.owner_proof, fixture.repo, &done_second)?;

    assert_eq!(
        second["reused_from"]["attempt_id"], first["attempt_id"],
        "the reused receipt names the attempt whose run it stands on"
    );
    assert_eq!(
        second["reused_from"]["generation"], first["generation"],
        "the reused receipt names the source generation"
    );
    assert!(
        (second["attempt_id"].as_str(), second["generation"].as_u64())
            != (first["attempt_id"].as_str(), first["generation"].as_u64()),
        "the reused receipt is a distinct receipt from its source"
    );
    assert!(
        second["commands"].as_array().is_some_and(Vec::is_empty),
        "the reused receipt recorded no run"
    );
    assert_eq!(
        second["tests_passed"],
        serde_json::Value::Bool(true),
        "the reused receipt keeps the pass"
    );
    assert!(
        first["reused_from"].is_null(),
        "the first receipt reused nothing"
    );
    Ok(())
}
