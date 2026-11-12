//! [FORCE-CANCEL-KEEPS-ACTIVE-PAUSE]: the hard cancel of a held row clears its pause, as the
//! operator's Cancel does, and deletes its annotation-hold index entry, so a terminal row never
//! names a live pause.
//!
//! Each row is enqueued, held Paused, and hard-cancelled through the public
//! `AttemptQueue::force_cancel` door. The stored pause and the annotation-hold index read through
//! `oneiron::test_doors::run_lifecycle`, built only under `--cfg oneiron_test_support`; the
//! annotation hold is placed through that door too, as a dispatch under an unattached comment
//! thread places it.
#![cfg(oneiron_test_support)]

use oneiron::attempt_queue::{
    AnnotationHold, AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState,
    EnqueueAttempt, EnqueueOutcome, ForceAttemptCancel, ForceCancelOutcome, InterveneAttempt,
    PauseKind,
};
use oneiron::test_doors::run_lifecycle::{
    annotation_hold_marked, force_cancel_authority, hold_for_annotation, pause_kind,
};
use oneiron::{EntityId, Vault};
use oneiron_testkit::{FixtureVault, TestVault, fixture_cache};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KIND: &str = "test.force_cancel_pause";
const OWNER: &str = "person:force-cancel-owner";

fn open_vault() -> Result<(TestVault, Vault), Box<dyn std::error::Error>> {
    let copy = FixtureVault::empty(&fixture_cache!())
        .and_then(|fixture| fixture.copy())
        .map_err(|error| format!("fixture: {error}"))?;
    let vault = copy.open().map_err(|error| format!("open: {error}"))?;
    Ok((copy, vault))
}

fn enqueue(
    queue: &AttemptQueue<'_>,
    now: u64,
) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    let outcome = queue.enqueue(EnqueueAttempt {
        kind: KIND.to_owned(),
        payload: b"run".to_vec(),
        dedupe_key: None,
        run_id: None,
        now,
    })?;
    let EnqueueOutcome::Enqueued(record) = outcome else {
        return Err("a fresh enqueue did not create a row".into());
    };
    Ok(record)
}

fn read(
    queue: &AttemptQueue<'_>,
    id: AttemptId,
) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    Ok(queue.get(id)?.ok_or("the row is missing")?)
}

fn force_cancel(
    queue: &AttemptQueue<'_>,
    id: AttemptId,
    now: u64,
) -> Result<ForceCancelOutcome, Box<dyn std::error::Error>> {
    Ok(queue.force_cancel(ForceAttemptCancel {
        id,
        authority: force_cancel_authority(OWNER)?,
        reason: None,
        now,
    })?)
}

#[test]
fn a_force_cancel_clears_a_persons_pause() -> TestResult {
    let (_copy, vault) = open_vault()?;
    let queue = AttemptQueue::new(&vault);
    let row = enqueue(&queue, 10)?;

    let paused = queue
        .intervene(InterveneAttempt {
            id: row.id,
            kind: AttemptInterventionKind::Pause,
            actor: OWNER.to_owned(),
            note: None,
            now: 11,
        })?
        .record;
    assert_eq!(
        paused.state,
        AttemptState::Paused,
        "the person's pause holds the row"
    );
    assert_eq!(
        pause_kind(&paused),
        Some(PauseKind::Person),
        "the held row names the person's pause"
    );

    let outcome = force_cancel(&queue, row.id, 12)?;
    assert!(
        matches!(outcome, ForceCancelOutcome::Cancelled(_)),
        "the hard cancel ends the held row"
    );
    let cancelled = read(&queue, row.id)?;
    assert_eq!(
        cancelled.state,
        AttemptState::Cancelled,
        "the row is cancelled"
    );
    assert_eq!(
        pause_kind(&cancelled),
        None,
        "the force cancel clears the person's pause, as Cancel does"
    );
    assert!(
        !annotation_hold_marked(&vault, row.id)?,
        "the hold index has no entry for the cancelled row"
    );

    // A replay answers the same terminal row.
    let replay = force_cancel(&queue, row.id, 13)?;
    assert!(
        matches!(&replay, ForceCancelOutcome::AlreadyCancelled(record) if pause_kind(record).is_none()),
        "a replayed hard cancel answers the cancelled row without a pause"
    );
    Ok(())
}

#[test]
fn a_force_cancel_clears_an_engine_hold_and_its_index_entry() -> TestResult {
    let (_copy, vault) = open_vault()?;
    let queue = AttemptQueue::new(&vault);
    let row = enqueue(&queue, 20)?;

    let hold = AnnotationHold {
        artifact_id: EntityId::now(),
        thread_id: EntityId::now(),
    };
    let held = hold_for_annotation(&vault, row.id, hold, 21)?;
    assert_eq!(
        held.state,
        AttemptState::Paused,
        "the annotation hold holds the row"
    );
    assert_eq!(
        pause_kind(&held),
        Some(PauseKind::Annotation),
        "the held row names the engine's annotation hold"
    );
    assert!(
        annotation_hold_marked(&vault, row.id)?,
        "the annotation hold marks its row in the hold index"
    );

    let outcome = force_cancel(&queue, row.id, 22)?;
    assert!(
        matches!(outcome, ForceCancelOutcome::Cancelled(_)),
        "the hard cancel ends the held row"
    );
    let cancelled = read(&queue, row.id)?;
    assert_eq!(
        cancelled.state,
        AttemptState::Cancelled,
        "the row is cancelled"
    );
    assert_eq!(
        pause_kind(&cancelled),
        None,
        "the force cancel clears the engine hold, as Cancel does"
    );
    assert!(
        !annotation_hold_marked(&vault, row.id)?,
        "the force cancel deletes the row's annotation-hold index entry"
    );
    Ok(())
}
