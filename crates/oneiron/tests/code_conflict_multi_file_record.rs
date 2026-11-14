//! L4-25 PR 2 (ARCH-0050 #r7-conflicts): conflicts between file bundles,
//! recorded never blocking. The owner records a real Git overlap between
//! two stored file bundles at one retained base, each one file or a file
//! bundle, with both trees, every conflicted path and a linked
//! reconciliation task; neither branch moves. The merge queue hands a
//! same-base overlap of two bundles to the same typed conflict while every
//! other batch keeps building. One-file proposals record as before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_conflict_multi_file_record`.
#![cfg(oneiron_test_support)]

#[path = "code_bundle/fixture.rs"]
mod bundle_fixture;

use std::collections::BTreeMap;

use bundle_fixture::{A_RS, B_RS, BundleFixture, TestResult, bundle_file};
use oneiron::code_document::CodeOpProvenance;
use oneiron::memory::code_doors::{
    CodeConflictRecordRequest, CodeConflictView, CodeConflictViewRequest, CodeProposalBundleFile,
    CodeProposalSubmitRequest,
};
use oneiron::memory::merge_queue_doors::{
    MergeQueueEnqueueRequest, MergeQueueInitializeRequest, MergeQueueObserveRequest,
};
use oneiron::merge_queue::{
    BatchState, QueueCheckEnvironment, QueueCheckExecution, QueueCheckHost, QueueCheckInputs,
    QueueCheckInvocation, QueueCheckNeed, QueueCheckRun, QueueCheckStatus, QueueCommandReceipt,
    QueueDriveOutcome, QueueDrivePass, QueueDriveStatus, QueueWork,
};
use oneiron::{EdgeActorClass, EntityId, Vault};

/// The left bundle's `a.rs`: the base function returns 100 instead of 1.
const LEFT_A_RS: &str = "pub fn a() -> u32 {\n    100\n}\n";
/// The left bundle's `b.rs`: the base function returns 200 instead of 2.
const LEFT_B_RS: &str = "pub fn b() -> u32 {\n    200\n}\n";
/// The left bundle's new `c.rs`, which the base commit does not hold.
const LEFT_C_RS: &str = "pub fn c() -> u32 {\n    3\n}\n";
/// The right bundle's `a.rs`: the same line returns 1000 instead.
const RIGHT_A_RS: &str = "pub fn a() -> u32 {\n    1000\n}\n";
/// The right bundle's `b.rs`: the same line returns 2000 instead.
const RIGHT_B_RS: &str = "pub fn b() -> u32 {\n    2000\n}\n";
/// The guard's first one-file `a.rs`.
const GUARD_ONE_A_RS: &str = "pub fn a() -> u32 {\n    11\n}\n";
/// The guard's second one-file `a.rs`.
const GUARD_TWO_A_RS: &str = "pub fn a() -> u32 {\n    12\n}\n";

/// The driver's pass in this test: the first since its host started, not a
/// lifecycle tick.
const PASS: QueueDrivePass = QueueDrivePass {
    tick: false,
    first: true,
};

/// The left bundle: `a.rs` and `b.rs` changed, `c.rs` added.
fn left_bundle() -> Vec<CodeProposalBundleFile> {
    vec![
        bundle_file("a.rs", Some(LEFT_A_RS.as_bytes())),
        bundle_file("b.rs", Some(LEFT_B_RS.as_bytes())),
        bundle_file("c.rs", Some(LEFT_C_RS.as_bytes())),
    ]
}

/// The right bundle: `a.rs` and `b.rs` changed the other way.
fn right_bundle() -> Vec<CodeProposalBundleFile> {
    vec![
        bundle_file("a.rs", Some(RIGHT_A_RS.as_bytes())),
        bundle_file("b.rs", Some(RIGHT_B_RS.as_bytes())),
    ]
}

/// The test's checker host: it reports each command of a check's frozen plan
/// as exited zero, with no contract output. It stands in for the isolated
/// executor an operator configures.
struct PassingChecks;

impl QueueCheckHost for PassingChecks {
    fn environment(&mut self) -> Result<QueueCheckEnvironment, QueueCheckNeed> {
        Ok(QueueCheckEnvironment {
            backend: "host".to_owned(),
            executor: "host".to_owned(),
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

/// The owner's checked init of the fixture repo's queue at the base commit,
/// run to its end by the checker's own claim and run on [`PassingChecks`].
/// It enrolls the queue for the automatic driver.
fn checked_init(fixture: &BundleFixture) -> TestResult {
    let vault = &fixture.vault;
    vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.owner_proof)
        .merge_queue_init_as(
            &fixture.owner_proof,
            MergeQueueInitializeRequest {
                repo: fixture.repo,
                baseline_commit: fixture.commit.clone(),
                contract_baseline_ref: None,
            },
        )?;
    let pending = vault.pending_queue_checks()?;
    assert_eq!(pending.len(), 1, "the init request is the one queued work");
    let key = pending.first().ok_or("the init work is queued")?;
    let work = vault
        .claim_queue_check(key, "l425-bundle-checker", 1)?
        .ok_or("the checker claims the init work")?;
    let done = vault.run_queue_check(&work, &mut PassingChecks, &|| false)?;
    assert_eq!(
        done.status,
        QueueCheckStatus::Completed { passed: true },
        "the checked init completes: {:?}",
        done.status
    );
    Ok(())
}

/// The checker's turn: it claims every queued check and runs it on
/// [`PassingChecks`].
fn complete_checks(vault: &Vault) -> TestResult {
    for key in vault.pending_queue_checks()? {
        let work = vault
            .claim_queue_check(&key, "l425-bundle-checker", 1)?
            .ok_or("the checker claims the queued check")?;
        let done = vault.run_queue_check(&work, &mut PassingChecks, &|| false)?;
        if done.status != (QueueCheckStatus::Completed { passed: true }) {
            return Err(format!("a queued check did not pass: {:?}", done.status).into());
        }
    }
    Ok(())
}

/// One driver step on `batch`'s Stage work, as the enrolled queue's drain
/// takes it, then the checker's turn.
fn drive_stage(fixture: &BundleFixture, batch: &str) -> TestResult<QueueDriveOutcome> {
    let vault = &fixture.vault;
    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    let queue = vault.queue_driver_open(config)?;
    let work = queue
        .pending_work(PASS)?
        .into_iter()
        .find(|work| matches!(work, QueueWork::Stage { batch: id, .. } if id == batch))
        .ok_or("the driver's next work stages the queued batch")?;
    let outcome = queue.drive_one(config, &work, PASS)?;
    complete_checks(vault)?;
    Ok(outcome)
}

/// Stages one ordinary file change through the public owner door.
fn submit_file(
    fixture: &BundleFixture,
    path: &str,
    content: &str,
    message: &str,
) -> TestResult<EntityId> {
    Ok(fixture
        .owner_memory()
        .code_proposal_submit_as(
            &fixture.owner_proof,
            CodeProposalSubmitRequest {
                repo: fixture.repo,
                path: path.to_owned(),
                content: content.as_bytes().to_vec(),
                message: message.to_owned(),
                op_provenance: CodeOpProvenance::default(),
                catalog: None,
                repair_of: None,
            },
        )?
        .proposal)
}

/// Records the overlap of `left` and `right` through the public owner
/// door, on the repo artifact as branch subject: the same subject the
/// queue's own driver target names for its conflicts.
fn record_conflict(
    fixture: &BundleFixture,
    left: EntityId,
    right: EntityId,
) -> TestResult<CodeConflictView> {
    Ok(fixture.owner_memory().code_conflict_record_as(
        &fixture.owner_proof,
        CodeConflictRecordRequest {
            repo: fixture.repo,
            branch_subject: fixture.repo,
            branch: "main".to_owned(),
            left_proposal: left,
            right_proposal: right,
        },
    )?)
}

#[test]
fn the_owner_records_a_conflict_between_two_file_bundles() -> TestResult {
    let fixture = BundleFixture::new()?;
    assert_ne!(
        (LEFT_A_RS, LEFT_B_RS, RIGHT_A_RS, RIGHT_B_RS),
        (A_RS, B_RS, A_RS, B_RS),
        "both bundles change both base files"
    );
    assert_ne!(
        (LEFT_A_RS, LEFT_B_RS),
        (RIGHT_A_RS, RIGHT_B_RS),
        "the two bundles change the shared files differently"
    );
    let left = fixture
        .submit_bundle(left_bundle(), "Left bundle")?
        .proposal;
    let right = fixture
        .submit_bundle(right_bundle(), "Right bundle")?
        .proposal;

    let view = record_conflict(&fixture, left, right)?;
    assert!(view.open, "the recorded conflict is open");
    assert_eq!(
        view.paths,
        ["a.rs", "b.rs"],
        "every conflicted path, and only those (c.rs is not conflicted): {:?}",
        view.paths
    );
    assert_eq!(
        view.proposals,
        [left, right],
        "the conflict retains both sources in left/right order"
    );
    assert!(
        view.task.is_some() || view.held.is_some(),
        "the conflict links its reconciliation task or its hold"
    );

    let history = fixture.owner_memory().code_conflict_history_as(
        &fixture.owner_proof,
        CodeConflictViewRequest {
            branch_subject: fixture.repo,
        },
    )?;
    assert_eq!(
        history.conflicts.len(),
        1,
        "the branch subject lists the one recorded conflict"
    );
    assert_eq!(
        history.conflicts[0].conflict, view.conflict,
        "the listed conflict is the recorded one"
    );
    assert_eq!(
        history.conflicts[0].paths,
        ["a.rs", "b.rs"],
        "the listed conflict keeps every conflicted path"
    );
    Ok(())
}

#[test]
fn a_queued_overlap_of_two_file_bundles_records_its_conflict() -> TestResult {
    let fixture = BundleFixture::new()?;
    checked_init(&fixture)?;
    let vault = &fixture.vault;
    let memory = fixture.owner_memory();
    let left = fixture
        .submit_bundle(left_bundle(), "Left bundle")?
        .proposal;
    let right = fixture
        .submit_bundle(right_bundle(), "Right bundle")?
        .proposal;

    let batch = memory.merge_queue_enqueue_as(
        &fixture.owner_proof,
        MergeQueueEnqueueRequest {
            repo: fixture.repo,
            proposals: vec![left, right],
            base_green: fixture.commit.clone(),
        },
    )?;
    assert_eq!(
        batch.state,
        BatchState::Queued,
        "both bundles queue as one batch"
    );

    // One driver step hands the proven overlap to a reconciliation.
    let outcome = drive_stage(&fixture, &batch.batch_ref)?;
    assert_eq!(
        outcome,
        QueueDriveOutcome::Changed,
        "the overlap hands off to a reconciliation: {outcome:?}"
    );

    let configs = vault.queue_driver_configurations()?;
    let config = configs.first().ok_or("the queue is enrolled")?;
    let subject = config
        .driver_target
        .as_ref()
        .ok_or("the enrolled queue has a target branch")?
        .branch_subject;
    let history = memory.code_conflict_history_as(
        &fixture.owner_proof,
        CodeConflictViewRequest {
            branch_subject: subject,
        },
    )?;
    assert_eq!(
        history.conflicts.len(),
        1,
        "the target branch subject holds one open conflict"
    );
    let conflict = history.conflicts.first().ok_or("the recorded conflict")?;
    assert!(conflict.open, "the queued conflict is open");
    assert_eq!(
        conflict.paths,
        ["a.rs", "b.rs"],
        "the queued conflict keeps the shared paths: {:?}",
        conflict.paths
    );
    let mut sources = conflict.proposals.clone();
    sources.sort();
    let mut expected = [left, right];
    expected.sort();
    assert_eq!(
        sources, expected,
        "the queued conflict retains both bundle sources"
    );

    // The batch waits on its reconciliation, linked to the conflict.
    let observed = memory.merge_queue_observe_as(
        &fixture.owner_proof,
        MergeQueueObserveRequest {
            repo: fixture.repo,
            batches: vec![batch.batch_ref.clone()],
        },
    )?;
    let drive = observed.drive.first().ok_or("the batch is observed")?;
    assert!(
        matches!(
            drive.status,
            QueueDriveStatus::HeldOverlap | QueueDriveStatus::HeldTaskAuthority
        ),
        "the conflicted batch waits on its reconciliation: {:?}",
        drive.status
    );
    let link = drive
        .conflicts
        .first()
        .ok_or("the batch carries its overlap link")?;
    assert_eq!(
        link.conflict,
        conflict.conflict.to_hex(),
        "the batch's drive overlap link names the recorded conflict"
    );
    Ok(())
}

#[test]
fn two_one_file_proposals_still_record_their_conflict() -> TestResult {
    let fixture = BundleFixture::new()?;
    assert_ne!(
        (GUARD_ONE_A_RS, GUARD_TWO_A_RS),
        (A_RS, A_RS),
        "both one-file proposals change the base file"
    );
    assert_ne!(
        GUARD_ONE_A_RS, GUARD_TWO_A_RS,
        "the two one-file proposals differ"
    );
    let one = submit_file(&fixture, "a.rs", GUARD_ONE_A_RS, "Guard one")?;
    let two = submit_file(&fixture, "a.rs", GUARD_TWO_A_RS, "Guard two")?;

    let view = record_conflict(&fixture, one, two)?;
    assert!(view.open, "the one-file conflict is open");
    assert_eq!(
        view.paths,
        ["a.rs"],
        "the one shared path is conflicted: {:?}",
        view.paths
    );
    assert_eq!(
        view.proposals,
        [one, two],
        "the one-file conflict retains both sources in order"
    );
    Ok(())
}
