//! NO-DOOR PROPOSAL-DECLARATION-QUEUE-BINDING (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-03), its end: every source entry of a reconciliation ends
//! with its own completion receipt (QUEUE Q1 = A).
//!
//! Four agent runs are real, as in `repo_queue_drive.rs`, on an enrolled
//! queue. A and B each change math.rs on the same green; C changes label.rs.
//! - Staging A finds B on the same path: both are handed to a
//!   reconciliation TASK and hold.
//! - C is disjoint and lands green.
//! - D, a fourth run on its own TASK, opens its work on the new green and
//!   proposes the combined math.rs as the resolution of that conflict, and
//!   it lands green. The successor is matched by the conflict it resolves,
//!   not by the TASK it runs under (RULING CODECUSTODY-RECONCILE-SUCCESSOR
//!   = A): no run is leased on the reconciliation TASK itself.
//! - The driver's next hand-off step on A ends A and B `Superseded`. Each
//!   gets a `repo.queue_completion` receipt with outcome "superseded" that
//!   names D's batch and D's own `green_advanced` completion. Each run reads
//!   `superseded` on its own entry, never `done`, and the successor batch
//!   only when its lane reads D's completion receipt.
//!
//! The test plays the host: it captures the witness of each model request
//! it built, as a host captures the request it serves, and it runs every
//! check with a host that reports each planned command passed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test repo_queue_supersede`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    AgentRun, LABEL_RS, MATH_RS, PassingChecks, RepoFixture, TestResult, agent_run,
    create_enabled_agent, leased_try, mint_repo_grant, paired_agent_slip,
};
use oneiron::agent_def::AgentCeiling;
use oneiron::claim::PointRead;
use oneiron::code_run::{RepoRequestWitness, SelfEffect};
use oneiron::memory::merge_queue_doors::MergeQueueObserveRequest;
use oneiron::memory::repo_doors::{
    RepoMergeQueueEnqueueInput, RepoMergeQueueObserveInput, RepoProposalResolveInput,
    RepoProposalSubmitInput, RepoQueueEntryView, RepoQueueSuccessor,
};
use oneiron::merge_queue::{
    BatchState, QueueCheckStatus, QueueDriveOutcome, QueueDrivePass, QueueDriveStatus, QueueWork,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};
use rmpv::Value;

/// A's change: `add_one` adds two.
const A_MATH: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 2\n}\n";
/// B's change to the same function: `add_one` adds three.
const B_MATH: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 3\n}\n";
/// C's disjoint change to label.rs.
const C_LABEL: &str = "pub fn label() -> &'static str {\n    \"queued\"\n}\n";
/// D's resolution of A and B: the combined math.rs.
const D_MATH: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 5\n}\n";

/// The driver's pass in this test: the first since its host started, not a
/// lifecycle tick.
const PASS: QueueDrivePass = QueueDrivePass {
    tick: false,
    first: true,
};

/// The most driver steps one batch takes from queued to green here: stage,
/// fast check, land, slow check and settle, with room to spare.
const STEPS_TO_GREEN: usize = 16;

/// A run on the enrolled repo: a new enabled agent with a repo Grant over
/// every `.rs` path, leased on a new TASK of its own, its work opened at the
/// queue's current green.
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

/// `run` proposes `content` for `path` and queues it: the queue's answer
/// for its new entry.
fn submit_and_enqueue(
    vault: &Vault,
    run: &AgentRun,
    path: &str,
    content: &str,
    message: &str,
) -> TestResult<RepoQueueEntryView> {
    let memory = vault.memory(run.actor.entity_ref(), run.actor.actor_class());
    let witness = served_request_witness()?;
    let content_hash = *blake3::hash(content.as_bytes()).as_bytes();
    let proposal = memory
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
        .proposal;
    enqueue(vault, run, proposal)
}

/// `run` queues its own `proposal`: the queue's answer for its new entry.
fn enqueue(vault: &Vault, run: &AgentRun, proposal: EntityId) -> TestResult<RepoQueueEntryView> {
    let entry = vault
        .memory(run.actor.entity_ref(), run.actor.actor_class())
        .repo_merge_queue_enqueue_for_run(
            &run.binding,
            RepoMergeQueueEnqueueInput {
                work: run.work,
                proposals: vec![proposal],
                declaration: None,
            },
        )?
        .output;
    assert_eq!(entry.proposals, vec![proposal]);
    assert_eq!(entry.state, BatchState::Queued);
    assert!(entry.blockers.is_empty(), "no run declared a symbol");
    Ok(entry)
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
            .claim_queue_check(&key, "repo-queue-supersede-checker", 1)?
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

/// The field `key` of a receipt's value map.
fn field<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, found)| found)
}

/// Whether `run`'s lane reads the row `id`, body included, as the run's
/// queue view reads its rows.
fn lane_reads(vault: &Vault, run: &AgentRun, id: EntityId) -> TestResult<bool> {
    let read = vault
        .scoped_read(run.reader.clone())
        .recorded_lane()?
        .read(&[PointRead::id(id)], None)?;
    Ok(read.value[0].as_ref().is_some_and(|row| row.body.is_some()))
}

/// The witness of a model request the host served: the test builds the
/// request and captures it, as a host captures the finalized request at its
/// send. No model is called.
fn served_request_witness() -> TestResult<RepoRequestWitness> {
    let model = ModelId::new("local/repo-queue-supersede@r1").expect("model id");
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
fn each_source_of_a_green_reconciliation_ends_superseded_with_its_own_completion_receipt()
-> TestResult {
    let repo = RepoFixture::enrolled()?;
    let vault = &repo.vault;
    let (agent_a, a) = repo_run(&repo, "supersede-agent-a", 0x61, "supersede A")?;
    let (_, b) = repo_run(&repo, "supersede-agent-b", 0x62, "supersede B")?;
    let (_, c) = repo_run(&repo, "supersede-agent-c", 0x63, "supersede C")?;
    assert_ne!(A_MATH, MATH_RS);
    assert_ne!(C_LABEL, LABEL_RS);

    // Three entries on the same green: A and B change math.rs, C label.rs.
    let entry_a = submit_and_enqueue(vault, &a, "math.rs", A_MATH, "add_one adds two")?;
    let entry_b = submit_and_enqueue(vault, &b, "math.rs", B_MATH, "add_one adds three")?;
    let entry_c = submit_and_enqueue(vault, &c, "label.rs", C_LABEL, "label reads queued")?;
    assert_eq!(entry_a.base_green, entry_b.base_green);

    // A's proposer mints the reconciliation TASK: its policy ceiling admits
    // an agent's automatic write.
    let _ceiling =
        vault.grant_agent_principal(&repo.owner_proof, &agent_a.to_hex(), AgentCeiling::Auto)?;

    // Staging A finds B on math.rs: both are handed to one reconciliation.
    let staged = drive_next(vault, &entry_a.batch, |work| {
        matches!(work, QueueWork::Stage { .. })
    })?
    .ok_or("the driver's next work stages A")?;
    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    let link = {
        let queue = vault.queue_driver_open(config)?;
        let link_a = queue
            .batch(&entry_a.batch)?
            .drive
            .and_then(|drive| drive.overlap)
            .ok_or_else(|| format!("A is handed off: {staged:?}"))?;
        let link_b = queue
            .batch(&entry_b.batch)?
            .drive
            .and_then(|drive| drive.overlap)
            .ok_or("B is handed off")?;
        assert_eq!(link_a, link_b, "A and B carry one conflict link");
        link_a
    };
    assert!(
        link.task.is_some(),
        "the reconciliation TASK is minted: {link:?}"
    );
    assert!(!link.superseded && link.resolution_batch.is_none());
    for (run, entry) in [(&a, &entry_a), (&b, &entry_b)] {
        let seen = own_entry(vault, run)?;
        assert_eq!(
            (&seen.batch, seen.state, seen.drive, &seen.superseded_by),
            (
                &entry.batch,
                BatchState::Queued,
                QueueDriveStatus::HeldOverlap,
                &None
            ),
        );
        assert!(
            seen.completion_receipt.is_none(),
            "a held entry has not completed"
        );
    }

    // C is disjoint and lands green.
    drive_to_green(vault, &entry_c.batch)?;
    let seen_c = own_entry(vault, &c)?;
    assert_eq!(
        (seen_c.state, seen_c.drive),
        (BatchState::GreenAdvanced, QueueDriveStatus::Done)
    );

    // D, on a TASK of its own, resolves the conflict on the new green.
    let (_, d) = repo_run(&repo, "supersede-agent-d", 0x64, "supersede D")?;
    let branch = config
        .driver_target
        .as_ref()
        .ok_or("the enrolled queue has a target branch")?
        .branch
        .clone();
    let witness = served_request_witness()?;
    let content_hash = *blake3::hash(D_MATH.as_bytes()).as_bytes();
    let resolution = vault
        .memory(d.actor.entity_ref(), d.actor.actor_class())
        .repo_proposal_resolve_for_run(
            &d.binding,
            RepoProposalResolveInput {
                work: d.work,
                branch_subject: link.branch_subject,
                conflict: link.conflict,
                branch,
                path: "math.rs".to_owned(),
                content: D_MATH.as_bytes().to_vec(),
                message: "add_one adds five".to_owned(),
                declaration: None,
            },
            None,
            |stamp| {
                d.binding.sources_from_host(
                    vault,
                    stamp,
                    "math.rs".to_owned(),
                    content_hash,
                    &witness,
                    SelfEffect::RepoProposalResolve,
                )
            },
        )?
        .output
        .proposal;
    let entry_d = enqueue(vault, &d, resolution)?;
    assert_ne!(
        entry_d.base_green, entry_a.base_green,
        "D works on C's green"
    );
    drive_to_green(vault, &entry_d.batch)?;
    let seen_d = own_entry(vault, &d)?;
    assert_eq!(
        (seen_d.state, seen_d.drive),
        (BatchState::GreenAdvanced, QueueDriveStatus::Done)
    );

    // One hand-off step on A ends A and B: D resolved their conflict.
    let handed = drive_next(vault, &entry_a.batch, |work| {
        matches!(work, QueueWork::HandoffOverlap { .. })
    })?
    .ok_or("the driver's next work on A is its hand-off")?;
    assert_eq!(handed, QueueDriveOutcome::Changed);
    assert_eq!(
        drive_next(vault, &entry_b.batch, |work| {
            matches!(work, QueueWork::HandoffOverlap { .. })
        })?,
        None,
        "B ended in the same step"
    );

    // The owner reads every entry and its receipt.
    let observed = repo.owner_memory().merge_queue_observe_as(
        &repo.owner_proof,
        MergeQueueObserveRequest {
            repo: repo.repo,
            batches: vec![
                entry_a.batch.clone(),
                entry_b.batch.clone(),
                entry_c.batch.clone(),
                entry_d.batch.clone(),
            ],
        },
    )?;
    let states: Vec<_> = observed.batches.iter().map(|view| view.state).collect();
    assert_eq!(
        states,
        vec![
            BatchState::Superseded,
            BatchState::Superseded,
            BatchState::GreenAdvanced,
            BatchState::GreenAdvanced,
        ]
    );
    let completion_of = |index: usize| {
        observed.batches[index]
            .completion_receipt
            .ok_or("every entry completed")
    };
    let d_completion = completion_of(3)?;
    let d_body = vault.get_claim(&d_completion)?.ok_or("D's receipt reads")?;
    assert_eq!(
        field(&d_body.value, "outcome").and_then(Value::as_str),
        Some("green_advanced")
    );
    let c_body = vault
        .get_claim(&completion_of(2)?)?
        .ok_or("C's receipt reads")?;
    assert_eq!(
        field(&c_body.value, "outcome").and_then(Value::as_str),
        Some("green_advanced")
    );
    for (index, entry) in [(0, &entry_a), (1, &entry_b)] {
        let body = vault
            .get_claim(&completion_of(index)?)?
            .ok_or("a superseded entry's receipt reads")?;
        assert_eq!(
            field(&body.value, "outcome").and_then(Value::as_str),
            Some("superseded")
        );
        assert_eq!(
            field(&body.value, "batch").and_then(Value::as_str),
            Some(entry.batch.as_str())
        );
        assert_eq!(
            field(&body.value, "landed_head"),
            Some(&Value::Nil),
            "a superseded entry never landed"
        );
        let by = field(&body.value, "superseded_by").ok_or("the receipt names its successor")?;
        assert_eq!(
            field(by, "batch").and_then(Value::as_str),
            Some(entry_d.batch.as_str())
        );
        let named = d_completion.to_hex();
        assert_eq!(
            field(by, "completion").and_then(Value::as_str),
            Some(named.as_str())
        );
    }

    // Each run reads `superseded` on its own entry, never `done`, and D's
    // batch only when its lane reads D's completion receipt.
    for (run, entry) in [(&a, &entry_a), (&b, &entry_b)] {
        let seen = own_entry(vault, run)?;
        let successor = if lane_reads(vault, run, d_completion)? {
            RepoQueueSuccessor::Batch(entry_d.batch.clone())
        } else {
            RepoQueueSuccessor::AnotherBatch
        };
        assert_eq!(
            (&seen.batch, seen.state, seen.drive, seen.superseded_by),
            (
                &entry.batch,
                BatchState::Superseded,
                QueueDriveStatus::Superseded,
                Some(successor)
            ),
        );
        assert!(seen.landed_head.is_none());
    }

    // A Superseded entry is settled: the owner cannot cancel it.
    let queue = vault.queue_driver_open(config)?;
    assert!(queue.cancel(&entry_a.batch).is_err());
    assert_eq!(queue.batch(&entry_a.batch)?.state, BatchState::Superseded);
    Ok(())
}
