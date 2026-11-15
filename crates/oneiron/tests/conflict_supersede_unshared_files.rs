//! [CONFLICT-SUPERSEDE-DROPS-UNSHARED-FILES]: a handed-off batch ends
//! Superseded as a whole, so a resolution that covers only the conflicted
//! path must not also drop a file of that batch no conflict names.
//!
//! Real agent runs on an enrolled queue, as in `repo_queue_supersede.rs`.
//! - A queues one batch changing math.rs and label.rs; B queues math.rs
//!   alone on the same green. Staging A finds B on math.rs: both are
//!   handed to a reconciliation. label.rs is A's alone: it is no
//!   conflicted path.
//! - D resolves math.rs and lands green. The shared path resolves exactly
//!   as before: the hand-off step names D's batch as the resolution. But
//!   A and B do not end Superseded yet, because nobody has landed A's
//!   label.rs change.
//! - E then carries label.rs green on the new green, and only then does
//!   the next hand-off step end A and B Superseded, still by D's batch.
//! - The second test is the shared-path case on its own: with no unshared
//!   file in either batch, D's green resolution supersedes A and B at the
//!   first hand-off step, as it always has.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test conflict_supersede_unshared_files`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    AgentRun, LABEL_RS, MATH_RS, PassingChecks, RepoFixture, TestResult, agent_run,
    create_enabled_agent, leased_try, mint_repo_grant, paired_agent_slip,
};
use oneiron::agent_def::AgentCeiling;
use oneiron::code_run::{RepoRequestWitness, SelfEffect};
use oneiron::memory::repo_doors::{
    RepoMergeQueueEnqueueInput, RepoMergeQueueObserveInput, RepoProposalResolveInput,
    RepoProposalSubmitInput, RepoQueueEntryView,
};
use oneiron::merge_queue::{
    BatchState, QueueCheckStatus, QueueConflictLink, QueueDriveOutcome, QueueDrivePass,
    QueueDriveStatus, QueueWork,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

/// A's change: `add_one` adds two.
const A_MATH: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 2\n}\n";
/// B's change to the same function: `add_one` adds three.
const B_MATH: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 3\n}\n";
/// A's other change, on a path B never writes.
const A_LABEL: &str = "pub fn label() -> &'static str {\n    \"carried\"\n}\n";
/// D's resolution of A and B: the combined math.rs.
const D_MATH: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 5\n}\n";

/// The driver's pass in this test: the first since its host started, not a
/// lifecycle tick.
const PASS: QueueDrivePass = QueueDrivePass {
    tick: false,
    first: true,
};

/// The most driver steps one batch takes from queued to green here.
const STEPS_TO_GREEN: usize = 16;

/// A run on the enrolled repo, as in `repo_queue_supersede.rs`.
fn repo_run(
    repo: &RepoFixture,
    name: &str,
    seed: u8,
    label: &str,
) -> TestResult<(EntityId, AgentRun)> {
    let vault = &repo.vault;
    let owner_proof = &repo.owner_proof;
    let bounds = repo.bounds(&["*.rs"], &["*.rs"]);
    let agent = create_enabled_agent(vault, owner_proof, name)?;
    let slip = paired_agent_slip(vault, &repo.issuer, owner_proof, agent, seed)?;
    let grant = mint_repo_grant(vault, owner_proof, agent, Some(&bounds))?;
    let leased = leased_try(vault, &repo.owner_memory(), repo.owner, agent, label)?;
    Ok((agent, agent_run(vault, &slip, leased, repo.repo, grant)?))
}

/// `run` proposes `content` for `path`: the stored proposal.
fn submit_proposal(
    vault: &Vault,
    run: &AgentRun,
    path: &str,
    content: &str,
    message: &str,
) -> TestResult<EntityId> {
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
                message: message.to_owned(),
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

/// `run` queues its own `proposals` as one batch.
fn enqueue_many(
    vault: &Vault,
    run: &AgentRun,
    proposals: Vec<EntityId>,
) -> TestResult<RepoQueueEntryView> {
    let entry = vault
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
    assert_eq!(entry.proposals, proposals);
    assert_eq!(entry.state, BatchState::Queued);
    assert!(entry.blockers.is_empty(), "no run declared a symbol");
    Ok(entry)
}

/// `run` proposes `content` for `path` and queues it alone.
fn submit_and_enqueue(
    vault: &Vault,
    run: &AgentRun,
    path: &str,
    content: &str,
    message: &str,
) -> TestResult<RepoQueueEntryView> {
    let proposal = submit_proposal(vault, run, path, content, message)?;
    enqueue_many(vault, run, vec![proposal])
}

/// `run`'s one queue entry, as `run` observes it.
fn own_entry(vault: &Vault, run: &AgentRun) -> TestResult<RepoQueueEntryView> {
    let mut entries = vault
        .memory(run.actor.entity_ref(), run.actor.actor_class())
        .repo_merge_queue_observe_for_run(
            &run.binding,
            RepoMergeQueueObserveInput { work: run.work },
        )?
        .output
        .entries;
    assert_eq!(entries.len(), 1, "the run reads its one entry");
    Ok(entries.remove(0))
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
            .claim_queue_check(&key, "conflict-supersede-unshared-checker", 1)?
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

/// `batch`'s overlap link, as stored on its drive record.
fn read_link(vault: &Vault, batch: &str) -> TestResult<QueueConflictLink> {
    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    Ok(vault
        .queue_driver_open(config)?
        .batch(batch)?
        .drive
        .and_then(|drive| drive.overlap)
        .ok_or("the batch is handed off")?)
}

/// The enrolled queue's target branch.
fn driver_branch(vault: &Vault) -> TestResult<String> {
    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    Ok(config
        .driver_target
        .as_ref()
        .ok_or("the enrolled queue has a target branch")?
        .branch
        .clone())
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

/// `run` proposes `content` for `path` as the resolution of `link`'s
/// conflict and queues it alone.
fn resolve_and_enqueue(
    vault: &Vault,
    run: &AgentRun,
    link: &QueueConflictLink,
    branch: String,
    path: &str,
    content: &str,
    message: &str,
) -> TestResult<RepoQueueEntryView> {
    let witness = served_request_witness()?;
    let content_hash = *blake3::hash(content.as_bytes()).as_bytes();
    let resolution = vault
        .memory(run.actor.entity_ref(), run.actor.actor_class())
        .repo_proposal_resolve_for_run(
            &run.binding,
            RepoProposalResolveInput {
                work: run.work,
                branch_subject: link.branch_subject,
                conflict: link.conflict,
                branch,
                path: path.to_owned(),
                content: content.as_bytes().to_vec(),
                message: message.to_owned(),
                declaration: None,
            },
            None,
            |stamp| {
                run.binding.sources_from_host(
                    vault,
                    stamp,
                    path.to_owned(),
                    content_hash,
                    &witness,
                    SelfEffect::RepoProposalResolve,
                )
            },
        )?
        .output
        .proposal;
    enqueue_many(vault, run, vec![resolution])
}

/// A and B handed to one reconciliation: A queues math.rs (and label.rs,
/// when `with_unshared`), B queues math.rs, and staging A hands both off.
/// Answers A's agent run, both entries and their shared link.
fn handed_off_pair(
    repo: &RepoFixture,
    with_unshared: bool,
) -> TestResult<(
    AgentRun,
    RepoQueueEntryView,
    RepoQueueEntryView,
    QueueConflictLink,
)> {
    let vault = &repo.vault;
    let (agent_a, a) = repo_run(repo, "unshared-agent-a", 0x61, "unshared A")?;
    let (_, b) = repo_run(repo, "unshared-agent-b", 0x62, "unshared B")?;
    assert_ne!(A_MATH, MATH_RS);
    assert_ne!(A_LABEL, LABEL_RS);

    let a_math = submit_proposal(vault, &a, "math.rs", A_MATH, "add_one adds two")?;
    let entry_a = if with_unshared {
        let a_label = submit_proposal(vault, &a, "label.rs", A_LABEL, "label reads carried")?;
        enqueue_many(vault, &a, vec![a_math, a_label])?
    } else {
        enqueue_many(vault, &a, vec![a_math])?
    };
    let entry_b = submit_and_enqueue(vault, &b, "math.rs", B_MATH, "add_one adds three")?;
    assert_eq!(entry_a.base_green, entry_b.base_green);

    // A's proposer mints the reconciliation TASK: its policy ceiling admits
    // an agent's automatic write.
    let _ceiling =
        vault.grant_agent_principal(&repo.owner_proof, &agent_a.to_hex(), AgentCeiling::Auto)?;

    let staged = drive_next(vault, &entry_a.batch, |work| {
        matches!(work, QueueWork::Stage { .. })
    })?
    .ok_or("the driver's next work stages A")?;
    let link =
        read_link(vault, &entry_a.batch).map_err(|_| format!("A is handed off: {staged:?}"))?;
    assert_eq!(
        link,
        read_link(vault, &entry_b.batch)?,
        "A and B carry one link"
    );
    assert!(
        link.task.is_some(),
        "the reconciliation TASK is minted: {link:?}"
    );
    assert!(!link.superseded && link.resolution_batch.is_none());
    Ok((a, entry_a, entry_b, link))
}

/// One hand-off step on `batch`.
fn drive_handoff(vault: &Vault, batch: &str) -> TestResult<Option<QueueDriveOutcome>> {
    drive_next(vault, batch, |work| {
        matches!(work, QueueWork::HandoffOverlap { .. })
    })
}

/// The witness of a model request the host served, as in
/// `repo_queue_supersede.rs`. No model is called.
fn served_request_witness() -> TestResult<RepoRequestWitness> {
    let model = ModelId::new("local/conflict-supersede-unshared@r1").expect("model id");
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
fn a_resolution_that_drops_an_unshared_file_does_not_supersede_its_sources() -> TestResult {
    let repo = RepoFixture::enrolled()?;
    let vault = &repo.vault;
    let (a, entry_a, entry_b, link) = handed_off_pair(&repo, true)?;

    // D, on a TASK of its own, resolves only the conflicted math.rs.
    let (_, d) = repo_run(&repo, "unshared-agent-d", 0x64, "unshared D")?;
    let entry_d = resolve_and_enqueue(
        vault,
        &d,
        &link,
        driver_branch(vault)?,
        "math.rs",
        D_MATH,
        "add_one adds five",
    )?;
    drive_to_green(vault, &entry_d.batch)?;

    // The shared path resolves as it always has: this step names D's batch
    // as the resolution. But A's label.rs has landed nowhere, so neither
    // source ends Superseded here.
    let handed = drive_handoff(vault, &entry_a.batch)?
        .ok_or("the driver's next work on A is its hand-off")?;
    assert_eq!(handed, QueueDriveOutcome::Changed);
    assert_eq!(batch_state(vault, &entry_a.batch)?, BatchState::Queued);
    assert_eq!(batch_state(vault, &entry_b.batch)?, BatchState::Queued);
    let waiting = read_link(vault, &entry_a.batch)?;
    assert_eq!(
        waiting.resolution_batch.as_deref(),
        Some(entry_d.batch.as_str())
    );
    assert!(
        !waiting.superseded,
        "label.rs is not carried yet: {waiting:?}"
    );
    let seen_a = own_entry(vault, &a)?;
    assert_eq!(
        (seen_a.state, seen_a.drive),
        (BatchState::Queued, QueueDriveStatus::HeldOverlap)
    );

    // E carries A's label.rs change green on D's green.
    let (_, e) = repo_run(&repo, "unshared-agent-e", 0x65, "unshared E")?;
    let entry_e = submit_and_enqueue(vault, &e, "label.rs", A_LABEL, "label reads carried")?;
    drive_to_green(vault, &entry_e.batch)?;

    // Now every file of both sources has landed: the same hand-off ends A
    // and B Superseded, still naming D's batch, which resolved math.rs.
    let handed = drive_handoff(vault, &entry_a.batch)?
        .ok_or("the driver's next work on A is its hand-off")?;
    assert_eq!(handed, QueueDriveOutcome::Changed);
    assert_eq!(batch_state(vault, &entry_a.batch)?, BatchState::Superseded);
    assert_eq!(batch_state(vault, &entry_b.batch)?, BatchState::Superseded);
    let done = read_link(vault, &entry_a.batch)?;
    assert!(done.superseded, "both files landed: {done:?}");
    assert_eq!(
        done.resolution_batch.as_deref(),
        Some(entry_d.batch.as_str())
    );
    Ok(())
}

#[test]
fn a_shared_path_resolution_supersedes_as_before_when_no_file_is_unshared() -> TestResult {
    let repo = RepoFixture::enrolled()?;
    let vault = &repo.vault;
    let (_a, entry_a, entry_b, link) = handed_off_pair(&repo, false)?;

    let (_, d) = repo_run(&repo, "unshared-agent-d", 0x64, "unshared D")?;
    let entry_d = resolve_and_enqueue(
        vault,
        &d,
        &link,
        driver_branch(vault)?,
        "math.rs",
        D_MATH,
        "add_one adds five",
    )?;
    drive_to_green(vault, &entry_d.batch)?;

    let handed = drive_handoff(vault, &entry_a.batch)?
        .ok_or("the driver's next work on A is its hand-off")?;
    assert_eq!(handed, QueueDriveOutcome::Changed);
    assert_eq!(batch_state(vault, &entry_a.batch)?, BatchState::Superseded);
    assert_eq!(batch_state(vault, &entry_b.batch)?, BatchState::Superseded);
    let done = read_link(vault, &entry_a.batch)?;
    assert!(
        done.superseded,
        "math.rs alone resolves as before: {done:?}"
    );
    assert_eq!(
        done.resolution_batch.as_deref(),
        Some(entry_d.batch.as_str())
    );
    Ok(())
}
