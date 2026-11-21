//! [MERGE-QUEUE-ENQUEUE-SPLITS-LARGE-BATCH] (RULING RESTRICTION-WAVE-15-ROWS
//! C107 = A) on the driven queue: one real agent run proposes 64 new files
//! and queues them in one enqueue. The queue forms two entries of the work,
//! 63 proposals and 1. The automatic driver holds the second until the
//! first is green, then stages it on the head the first landed, checks it
//! and lands it through the reviewed landing, which admits its member on
//! the base the enqueue's first batch staged on, the one it was made on.
//!
//! The test plays the host and the checker, as `repo_queue_supersede.rs`
//! does: every check runs on [`PassingChecks`].
//!
//! Red on main: the enqueue of 64 proposals is refused ("a merge batch holds
//! one to 63 proposals"). The file uses main's API only, so it compiles there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test repo_queue_split_drive`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    AgentRun, PassingChecks, RepoFixture, TestResult, agent_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::code_run::{RepoRequestWitness, SelfEffect};
use oneiron::memory::repo_doors::{
    RepoMergeQueueEnqueueInput, RepoMergeQueueObserveInput, RepoProposalSubmitInput,
    RepoQueueEntryView,
};
use oneiron::merge_queue::{
    BatchState, QueueCheckStatus, QueueDriveOutcome, QueueDrivePass, QueueWork,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

/// The driver's pass in this test: the first since its host started, not a
/// lifecycle tick.
const PASS: QueueDrivePass = QueueDrivePass {
    tick: false,
    first: true,
};

/// The most driver steps one batch takes from queued to green here: stage,
/// one fast check per staged path (637 for 63 proposals), land, slow check
/// and settle, with room to spare.
const STEPS_TO_GREEN: usize = 2_000;

/// The proposals the run queues in one enqueue: one more than a batch holds.
const PROPOSALS: usize = 64;

/// A run on the enrolled repo: a new enabled agent with a repo Grant over
/// every `.rs` path, leased on a new TASK of its own, its work opened at the
/// queue's current green.
fn repo_run(repo: &RepoFixture, name: &str, seed: u8, label: &str) -> TestResult<AgentRun> {
    let vault = &repo.vault;
    let owner_proof = &repo.owner_proof;
    let bounds = repo.bounds(&["*.rs"], &["*.rs"]);
    let agent = create_enabled_agent(vault, owner_proof, name)?;
    let slip = paired_agent_slip(vault, &repo.issuer, owner_proof, agent, seed)?;
    let grant = mint_repo_grant(vault, owner_proof, agent, Some(&bounds))?;
    let leased = leased_try(vault, &repo.owner_memory(), repo.owner, agent, label)?;
    agent_run(vault, &slip, leased, repo.repo, grant)
}

/// `run` proposes `content` as the new file `path`: its stored proposal.
fn submit(vault: &Vault, run: &AgentRun, path: &str, content: &str) -> TestResult<EntityId> {
    let memory = vault.memory(run.actor.entity_ref(), run.actor.actor_class());
    let witness = served_request_witness()?;
    let content_hash = *blake3::hash(content.as_bytes()).as_bytes();
    Ok(memory
        .repo_proposal_submit_for_run(
            &run.binding,
            RepoProposalSubmitInput {
                work: run.work,
                path: path.to_owned(),
                content: content.as_bytes().to_vec(),
                message: format!("add {path}"),
                declaration: None,
                repair_of: None,
            },
            None,
            |stamp| {
                run.binding.sources_from_host(
                    vault,
                    stamp,
                    path.to_owned(),
                    content_hash,
                    &witness,
                    SelfEffect::RepoProposalSubmit,
                )
            },
        )?
        .output
        .proposal)
}

/// Every queue entry of `run`'s work, as `run` observes them.
fn entries(vault: &Vault, run: &AgentRun) -> TestResult<Vec<RepoQueueEntryView>> {
    Ok(vault
        .memory(run.actor.entity_ref(), run.actor.actor_class())
        .repo_merge_queue_observe_for_run(
            &run.binding,
            RepoMergeQueueObserveInput { work: run.work },
        )?
        .output
        .entries)
}

/// The entry of batch `batch`, as `run` observes it.
fn entry(vault: &Vault, run: &AgentRun, batch: &str) -> TestResult<RepoQueueEntryView> {
    entries(vault, run)?
        .into_iter()
        .find(|entry| entry.batch == batch)
        .ok_or_else(|| format!("the work holds the entry {batch}").into())
}

/// The batch a driver work acts on; recovery and a seal name none.
fn work_batch(work: &QueueWork) -> Option<&str> {
    match work {
        QueueWork::SettleSlow { batch, .. }
        | QueueWork::RepairPath { batch, .. }
        | QueueWork::RequestCheck { batch, .. }
        | QueueWork::Stage { batch, .. }
        | QueueWork::Diagnose { batch, .. }
        | QueueWork::RequeueSurvivors { batch, .. }
        | QueueWork::LandReviewed { batch, .. }
        | QueueWork::HandoffOverlap { batch, .. }
        | QueueWork::RecordDiverged { batch, .. }
        | QueueWork::ReleasePins { batch, .. } => Some(batch),
        QueueWork::Recover | QueueWork::SealTested { .. } => None,
    }
}

/// The checker's turn: it claims every queued check and runs it on
/// [`PassingChecks`].
fn complete_checks(vault: &Vault) -> TestResult {
    for key in vault.pending_queue_checks()? {
        let work = vault
            .claim_queue_check(&key, "repo-queue-split-checker", 1)?
            .ok_or("the checker claims the queued check")?;
        let done = vault.run_queue_check(&work, &mut PassingChecks, &|| false)?;
        if done.status != (QueueCheckStatus::Completed { passed: true }) {
            return Err(format!("a queued check did not pass: {:?}", done.status).into());
        }
    }
    Ok(())
}

/// One driver step on the enrolled queue: its next work on `batch` that
/// `pick` takes, then the checker's turn. `None` when it has no such work.
fn drive_next(
    vault: &Vault,
    batch: &str,
    pick: impl Fn(&QueueWork) -> bool,
) -> TestResult<Option<QueueDriveOutcome>> {
    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    let outcome = {
        let queue = vault.queue_driver_open(config)?;
        let Some(work) = queue
            .pending_work(PASS)?
            .into_iter()
            .find(|work| work_batch(work) == Some(batch) && pick(work))
        else {
            return Ok(None);
        };
        queue.drive_one(config, &work, PASS)?
    };
    complete_checks(vault)?;
    Ok(Some(outcome))
}

/// The stored state of `batch`.
fn batch_state(vault: &Vault, batch: &str) -> TestResult<BatchState> {
    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    Ok(vault.queue_driver_open(config)?.batch(batch)?.state)
}

/// Drives `batch` alone until it is green, never another batch's work.
fn drive_to_green(vault: &Vault, batch: &str) -> TestResult {
    for _ in 0..STEPS_TO_GREEN {
        if batch_state(vault, batch)? == BatchState::GreenAdvanced {
            return Ok(());
        }
        let moved = drive_next(vault, batch, |work| {
            !matches!(
                work,
                QueueWork::HandoffOverlap { .. } | QueueWork::ReleasePins { .. }
            )
        })?;
        if moved.is_none() {
            let state = batch_state(vault, batch)?;
            return Err(format!("the driver has no work on {batch}, which is {state:?}").into());
        }
    }
    Err(format!("{batch} did not reach green in {STEPS_TO_GREEN} steps").into())
}

/// The witness of a model request the host served: the test builds the
/// request and captures it, as a host captures the finalized request at its
/// send. No model is called.
fn served_request_witness() -> TestResult<RepoRequestWitness> {
    let model = ModelId::new("local/repo-queue-split-drive@r1").expect("model id");
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

#[test]
fn a_run_enqueue_of_64_lands_its_second_batch_through_the_reviewed_landing() -> TestResult {
    let repo = RepoFixture::enrolled()?;
    let vault = &repo.vault;
    let run = repo_run(&repo, "queue-split-agent", 0x73, "queue split")?;
    let proposals = (0..PROPOSALS)
        .map(|index| {
            submit(
                vault,
                &run,
                &format!("split_{index:03}.rs"),
                &format!("pub fn split_{index:03}() -> usize {{\n    {index}\n}}\n"),
            )
        })
        .collect::<TestResult<Vec<EntityId>>>()?;

    // One enqueue of 64: its answer is the first entry, of 63; the work
    // holds a second entry with the last proposal.
    let first = vault
        .memory(run.actor.entity_ref(), run.actor.actor_class())
        .repo_merge_queue_enqueue_for_run(
            &run.binding,
            RepoMergeQueueEnqueueInput {
                work: run.work,
                proposals: proposals.clone(),
                declaration: None,
            },
        )?
        .output;
    assert_eq!(
        first.proposals,
        proposals[..63].to_vec(),
        "the first batch holds 63"
    );
    assert_eq!(first.state, BatchState::Queued);
    let queued = entries(vault, &run)?;
    assert_eq!(queued.len(), 2, "the work holds two entries");
    let second = queued
        .into_iter()
        .find(|entry| entry.batch != first.batch)
        .ok_or("the second entry")?;
    assert_eq!(
        second.proposals,
        proposals[63..].to_vec(),
        "the second batch holds the last"
    );
    assert_eq!(second.state, BatchState::Queued);

    // Before the first lands, the driver holds the second, typed.
    match drive_next(vault, &second.batch, |work| {
        matches!(work, QueueWork::Stage { .. })
    })? {
        Some(QueueDriveOutcome::Waiting(hold)) => {
            assert_eq!(format!("{:?}", hold.reason), "WaitingFollowedBatch");
        }
        other => return Err(format!("the second batch waits for the first: {other:?}").into()),
    }
    assert_eq!(batch_state(vault, &second.batch)?, BatchState::Queued);

    drive_to_green(vault, &first.batch)?;
    let first_landed = entry(vault, &run, &first.batch)?
        .landed_head
        .ok_or("the first batch landed")?;

    // Now the driver stages the second on the first's landed head, checks
    // it and lands it through the reviewed landing.
    drive_to_green(vault, &second.batch)?;
    let landed = entry(vault, &run, &second.batch)?;
    assert_eq!(landed.state, BatchState::GreenAdvanced);
    assert_eq!(
        landed.expected_head, first_landed,
        "the second batch staged on the head the first landed"
    );
    assert!(
        landed.completion_receipt.is_some(),
        "the green entry is receipted"
    );
    Ok(())
}
