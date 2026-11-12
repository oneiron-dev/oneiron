//! NO-DOOR PROPOSAL-DECLARATION-QUEUE-BINDING (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-03), its waiting state: a run's own queue entry shows where
//! the automatic driver stands on it, as the typed `drive` status of
//! `self.code.merge_queue.enqueue` and `self.code.merge_queue.observe`
//! (`Memory::repo_merge_queue_enqueue_for_run`,
//! `Memory::repo_merge_queue_observe_for_run`).
//!
//! Two agent runs are real, as in `symbol_lease_observe.rs`. A declares
//! `add_one` and holds it. B proposes a change to math.rs, which defines
//! `add_one`, and queues it: its entry waits behind A's TASK.
//! - On a queue no checked init enrolls, B's entry is `unenrolled`.
//! - On an enrolled queue, one driver step on B's entry stores the
//!   `waiting_symbols` hold, and B reads it. Observation changes nothing: the
//!   stored status stays after A releases, until the driver's next step
//!   stages the entry, which then reads `driving`.
//!
//! The test plays the host: it captures the witness of the model request it
//! built for B's change, as a host captures the request it serves, and it
//! runs the checker with a host that reports each planned command passed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test repo_queue_drive`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    AgentRun, MATH_RS, RepoFixture, TestResult, agent_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::claim::PointRead;
use oneiron::code_run::{RepoRequestWitness, SelfEffect};
use oneiron::memory::repo_doors::{
    RepoMergeQueueEnqueueInput, RepoMergeQueueObserveInput, RepoProposalSubmitInput,
    RepoQueueEntryView, RepoSymbolDeclarationView, RepoSymbolsDeclareInput,
    RepoSymbolsReleaseInput,
};
use oneiron::merge_queue::{
    BatchState, QueueDriveHoldReason, QueueDriveOutcome, QueueDrivePass, QueueDriveStatus,
    QueueWork,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

/// A declaration's lifetime here: long past the test, so no expiry moves a
/// row while it runs.
const TTL_SECONDS: u64 = 3_600;

/// B's change: `add_one` adds two.
const MATH_RS_CHANGED: &str = "pub fn add_one(value: u32) -> u32 {\n    value + 2\n}\n";

/// The driver's pass in this test: the first since its host started, not a
/// lifecycle tick.
const PASS: QueueDrivePass = QueueDrivePass {
    tick: false,
    first: true,
};

struct Fixture {
    repo: RepoFixture,
    symbol: EntityId,
    a: AgentRun,
    b: AgentRun,
}

impl Fixture {
    fn new(repo: RepoFixture) -> TestResult<Self> {
        // The one symbol A declares: `add_one` in math.rs, by its current
        // CODE_SYMBOL id.
        let symbol = repo.symbol("math.rs", "add_one")?;
        let (a, b) = {
            let vault = &repo.vault;
            let owner_proof = &repo.owner_proof;
            let bounds = repo.bounds(&["*.rs"], &["*.rs"]);
            let agent_a = create_enabled_agent(vault, owner_proof, "queue-drive-agent-a")?;
            let agent_b = create_enabled_agent(vault, owner_proof, "queue-drive-agent-b")?;
            let slip_a = paired_agent_slip(vault, &repo.issuer, owner_proof, agent_a, 0x61)?;
            let slip_b = paired_agent_slip(vault, &repo.issuer, owner_proof, agent_b, 0x62)?;
            let grant_a = mint_repo_grant(vault, owner_proof, agent_a, Some(&bounds))?;
            let grant_b = mint_repo_grant(vault, owner_proof, agent_b, Some(&bounds))?;

            // Both TASKs are created and both tries claimed before any
            // symbol is declared.
            let owner_memory = repo.owner_memory();
            let leased_a = leased_try(vault, &owner_memory, repo.owner, agent_a, "queue A")?;
            let leased_b = leased_try(vault, &owner_memory, repo.owner, agent_b, "queue B")?;
            (
                agent_run(vault, &slip_a, leased_a, repo.repo, grant_a)?,
                agent_run(vault, &slip_b, leased_b, repo.repo, grant_b)?,
            )
        };
        Ok(Self { repo, symbol, a, b })
    }

    fn vault(&self) -> &Vault {
        &self.repo.vault
    }

    /// A declares `add_one` and holds it; B's lane reads A's TASK, so A
    /// shows among B's blockers.
    fn a_holds_add_one(&self) -> TestResult<RepoSymbolDeclarationView> {
        let a = &self.a;
        let held = self
            .vault()
            .memory(a.actor.entity_ref(), a.actor.actor_class())
            .repo_symbols_declare_for_run(
                &a.binding,
                RepoSymbolsDeclareInput {
                    work: a.work,
                    symbols: vec![self.symbol],
                    ttl_seconds: TTL_SECONDS,
                },
            )?
            .output;
        assert!(held.held, "A declares first and holds");
        let lane = self
            .vault()
            .scoped_read(self.b.reader.clone())
            .read(&[PointRead::id(a.task)], None)?;
        assert!(
            lane.value[0].as_ref().is_some_and(|row| row.body.is_some()),
            "B's lane reads A's TASK"
        );
        Ok(held)
    }

    fn a_releases(&self, held: &RepoSymbolDeclarationView) -> TestResult {
        let a = &self.a;
        self.vault()
            .memory(a.actor.entity_ref(), a.actor.actor_class())
            .repo_symbols_release_for_run(
                &a.binding,
                RepoSymbolsReleaseInput {
                    work: a.work,
                    declaration: held.declaration,
                },
            )?;
        Ok(())
    }

    /// B proposes its change to math.rs with no declaration of its own, and
    /// queues it: the queue's answer for its new entry.
    fn b_queues_math(&self) -> TestResult<RepoQueueEntryView> {
        let (vault, b) = (self.vault(), &self.b);
        let memory = vault.memory(b.actor.entity_ref(), b.actor.actor_class());
        let witness = served_request_witness()?;
        let content = MATH_RS_CHANGED.as_bytes();
        assert_ne!(MATH_RS_CHANGED, MATH_RS);
        let content_hash = *blake3::hash(content).as_bytes();
        let proposal = memory
            .repo_proposal_submit_for_run(
                &b.binding,
                RepoProposalSubmitInput {
                    work: b.work,
                    path: "math.rs".to_owned(),
                    content: content.to_vec(),
                    message: "add_one adds two".to_owned(),
                    declaration: None,
                    repair_of: None,
                },
                None,
                |stamp| {
                    b.binding.sources_from_host(
                        vault,
                        stamp,
                        "math.rs".to_owned(),
                        content_hash,
                        &witness,
                        SelfEffect::RepoProposalSubmit,
                    )
                },
            )?
            .output
            .proposal;
        let entry = memory
            .repo_merge_queue_enqueue_for_run(
                &b.binding,
                RepoMergeQueueEnqueueInput {
                    work: b.work,
                    proposals: vec![proposal],
                    declaration: None,
                },
            )?
            .output;
        assert_eq!(entry.proposals, vec![proposal]);
        assert_eq!(entry.state, BatchState::Queued);
        assert_eq!(entry.blockers, vec![self.a.task], "B waits behind A's TASK");
        Ok(entry)
    }

    /// The queue entries `run` reads on its own work.
    fn observe(&self, run: &AgentRun) -> TestResult<Vec<RepoQueueEntryView>> {
        Ok(self
            .vault()
            .memory(run.actor.entity_ref(), run.actor.actor_class())
            .repo_merge_queue_observe_for_run(
                &run.binding,
                RepoMergeQueueObserveInput { work: run.work },
            )?
            .output
            .entries)
    }

    /// B's one entry, as B observes it.
    fn b_entry(&self) -> TestResult<RepoQueueEntryView> {
        let mut entries = self.observe(&self.b)?;
        assert_eq!(entries.len(), 1, "B reads its one entry");
        Ok(entries.remove(0))
    }

    /// One driver step on `batch`'s Stage work, as the enrolled queue's
    /// drain takes it.
    fn drive_stage(&self, batch: &str) -> TestResult<QueueDriveOutcome> {
        let vault = self.vault();
        let configs = vault.queue_driver_configurations()?;
        let config = configs.first().ok_or("the queue is enrolled")?;
        let queue = vault.queue_driver_open(config)?;
        let work = queue
            .pending_work(PASS)?
            .into_iter()
            .find(|work| matches!(work, QueueWork::Stage { batch: id, .. } if id == batch))
            .ok_or("the driver's next work stages B's queued entry")?;
        Ok(queue.drive_one(config, &work, PASS)?)
    }
}

/// The witness of the model request the host served B: the test builds the
/// request and captures it, as a host captures the finalized request at its
/// send. No model is called.
fn served_request_witness() -> TestResult<RepoRequestWitness> {
    let model = ModelId::new("local/repo-queue-drive@r1").expect("model id");
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
fn an_entry_on_a_queue_no_checked_init_enrolls_reads_unenrolled() -> TestResult {
    let fixture = Fixture::new(RepoFixture::new()?)?;
    fixture.a_holds_add_one()?;
    let queued = fixture.b_queues_math()?;
    assert_eq!(queued.drive, QueueDriveStatus::Unenrolled);
    let seen = fixture.b_entry()?;
    assert_eq!(
        (seen.batch, seen.state, seen.drive, seen.blockers),
        (
            queued.batch,
            BatchState::Queued,
            QueueDriveStatus::Unenrolled,
            vec![fixture.a.task]
        ),
    );
    Ok(())
}

#[test]
fn a_run_reads_the_drivers_stored_waiting_symbols_hold_on_its_entry() -> TestResult {
    let fixture = Fixture::new(RepoFixture::enrolled()?)?;
    let held = fixture.a_holds_add_one()?;
    let queued = fixture.b_queues_math()?;
    assert_eq!(
        queued.drive,
        QueueDriveStatus::Driving,
        "the driver has not stepped on the new entry yet"
    );

    // One driver step stores B's hold: it waits behind A's declaration.
    match fixture.drive_stage(&queued.batch)? {
        QueueDriveOutcome::Waiting(hold) => {
            assert_eq!(hold.reason, QueueDriveHoldReason::WaitingSymbols);
        }
        other => return Err(format!("B's entry waits behind A: {other:?}").into()),
    }

    // B reads the typed hold on its entry, the same on a second read.
    for _ in 0..2 {
        let seen = fixture.b_entry()?;
        assert_eq!(
            (
                &seen.batch,
                seen.state,
                seen.drive,
                &seen.blockers,
                &seen.proposals
            ),
            (
                &queued.batch,
                BatchState::Queued,
                QueueDriveStatus::WaitingSymbols,
                &vec![fixture.a.task],
                &queued.proposals,
            ),
        );
        assert_eq!(seen.admission_receipt, queued.admission_receipt);
        assert!(seen.admission_receipt.is_some(), "the queue admitted it");
    }
    // A's work queued nothing: B's entry is not A's to read.
    assert!(fixture.observe(&fixture.a)?.is_empty());

    // A releases. B's live blockers are empty at once; the stored status is
    // the driver's, so it stays until the driver's next step.
    fixture.a_releases(&held)?;
    let seen = fixture.b_entry()?;
    assert!(seen.blockers.is_empty(), "A's release leaves B no blocker");
    assert_eq!(
        (seen.state, seen.drive),
        (BatchState::Queued, QueueDriveStatus::WaitingSymbols)
    );

    // The next step stages B's entry and clears its hold.
    assert_eq!(
        fixture.drive_stage(&queued.batch)?,
        QueueDriveOutcome::Changed
    );
    let seen = fixture.b_entry()?;
    assert_eq!(
        (seen.state, seen.drive),
        (BatchState::Staged, QueueDriveStatus::Driving)
    );
    Ok(())
}
