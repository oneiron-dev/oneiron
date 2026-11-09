//! The RUN-HOLD tests' shared fixture (`run_hold_override.rs`,
//! `run_hold_doors.rs`): a vault, the queue calls, and a row the annotation
//! hold parked.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::anchored_annotation::{Anchor, Locator, ReanchorOp};
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome,
    EnqueueAttempt, EnqueueOutcome, InterveneAttempt, InterveneOutcome, PauseKind, RunState,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

pub const KIND: &str = "test.run_hold";
pub const WORKER: &str = "worker:run-hold";

pub fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open(dir.path(), config).expect("vault opens");
    (dir, vault)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

pub fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

pub fn person(vault: &Vault, now: u64) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(now), now, b"operator")
        .expect("put person");
    id
}

pub fn enqueued(outcome: EnqueueOutcome) -> AttemptRecord {
    let EnqueueOutcome::Enqueued(record) = outcome else {
        panic!("a fresh row is enqueued");
    };
    record
}

pub fn claim(queue: &AttemptQueue<'_>, kind: &str, now: u64) -> ClaimOutcome {
    queue
        .claim_kind(
            kind,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now,
            },
        )
        .expect("claim")
}

pub fn claimed(outcome: ClaimOutcome) -> AttemptRecord {
    let ClaimOutcome::Claimed(record) = outcome else {
        panic!("the ready row is claimed");
    };
    record
}

pub fn resume(queue: &AttemptQueue<'_>, id: AttemptId, actor: &str, now: u64) -> InterveneOutcome {
    queue
        .intervene(InterveneAttempt {
            id,
            kind: AttemptInterventionKind::Resume,
            actor: actor.to_owned(),
            note: None,
            now,
        })
        .expect("a resume is admitted")
}

pub fn read(queue: &AttemptQueue<'_>, id: AttemptId) -> AttemptRecord {
    queue.get(id).expect("get").expect("row")
}

pub fn last_note(record: &AttemptRecord) -> Option<&str> {
    record.events.last().and_then(|event| event.note.as_deref())
}

/// A row of a comment's task that the claim parked while its comment is
/// unattached, and the person who wrote the comment.
pub fn annotation_held_row(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    now: u64,
) -> (AttemptRecord, EntityId) {
    let actor_id = person(vault, now);
    let actor = WriteActor::new(actor_id, EdgeActorClass::Human);
    let artifact_id = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact_id,
            &BlobArtifactBody::new(
                "forecast.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            at(now),
            now,
        )
        .expect("put workbook");
    vault
        .append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            at(now),
            now,
        )
        .expect("append v1");
    let thread = vault
        .open_annotation_thread(
            &Anchor::new(
                artifact_id,
                1,
                Locator::xlsx("Sheet1", "B5:C6").expect("locator"),
            ),
            actor,
            "Recompute these rows.",
            at(now + 1),
            now + 1,
        )
        .expect("open thread");
    let brief = vault
        .assign_annotation_thread_to_brief(
            &artifact_id,
            &thread.thread_id,
            None,
            actor,
            at(now + 2),
            now + 2,
        )
        .expect("assign");
    // Version 2 deletes the anchored rows: the comment is unattached.
    vault
        .append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v2",
            &BlobVersionProvenance::UserUpload,
            actor,
            at(now + 3),
            now + 3,
        )
        .expect("append v2");
    let summary = vault
        .reanchor_annotation_threads(
            &artifact_id,
            1,
            2,
            &[ReanchorOp::DeleteRows {
                sheet: "Sheet1".to_owned(),
                at_row: 5,
                count: 2,
            }],
            actor,
            at(now + 3),
            now + 3,
        )
        .expect("reanchor");
    assert_eq!(summary.drifted.len(), 1, "the thread drifted");

    let row = enqueued(
        queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: KIND.to_owned(),
                    payload: b"answer the comment".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now: now + 4,
                },
                Some(brief.task_id.to_hex()),
            )
            .expect("enqueue"),
    );
    assert!(
        matches!(claim(queue, KIND, now + 5), ClaimOutcome::Empty),
        "the claim parks the row while its comment is unattached"
    );
    assert_eq!(
        RunState::of(&read(queue, row.id)),
        RunState::Paused(PauseKind::Annotation)
    );

    (row, actor_id)
}
