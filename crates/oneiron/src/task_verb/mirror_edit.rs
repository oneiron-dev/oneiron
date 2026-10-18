//! The owner's public title edit on `tasks.update` (OF-427 C8), and the
//! Owner standing the mirror's mapping edits prove (C6).
//!
//! An `edit` report names the TASK revision the mirror's read surface
//! exposes (`vault.tasks.linear.mapping`'s `task_revision`, the board's body
//! revision) and the new title. It needs the caller's Owner standing through
//! L02's rule and writes the label alone, through the shared TASK-body
//! writer, which stamps the verified writer as every typed TASK put does: the
//! next mirror pass sends ONE outbound update carrying that writer through
//! the admitted-effect door. A brief is never a title, and no generic put
//! runs. The same report key with the same edit answers the first receipt;
//! another edit under it is refused.

use crate::authority::TaskActorVerb;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::linear_sync::{
    EventDirection, LinearMirrorEvent, event_in, put_event_in, request_digest, task_edit_key,
};
use crate::memory::{MEMORY_CODE_OFF_RECORD_SESSION_DOOR, Memory, MemoryError, MemoryResult};

use super::create_validation::{check_task_label, task_body_in_txn};
use super::highway::{invalid_state, not_found, phase_of};
use super::highway_types::{TaskCallReceipt, TaskHandle, TaskOutcome, TaskVia};
use super::lifecycle_receipt;

/// Proves this surface's actor holds Owner standing on `task` in `txn`,
/// through L02's rule over the immutable authority facts, never a body
/// field: the standing a mirror mapping edit needs (OF-427 C6).
pub(crate) fn prove_task_owner_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> MemoryResult<()> {
    memory.highway_task_actor_in(
        txn,
        task,
        TaskActorVerb::Owner,
        "Ask the task's owner to change its issue mirror.",
    )?;
    Ok(())
}

/// The stored receipt a replayed edit answers; another edit under its key
/// refuses.
fn replayed_edit(row: &LinearMirrorEvent, digest: &str) -> MemoryResult<TaskCallReceipt> {
    if row.body_digest.as_deref() != Some(digest) {
        return Err(MemoryError::bad_request_with(
            "this report key already names a different request",
            &["Re-issue the same report, or use a new report key."],
        ));
    }
    let mut receipt: TaskCallReceipt = row
        .receipt
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .ok_or(Error::CorruptedIndex("task title edit receipt"))?;
    receipt.idempotent_replay = true;
    Ok(receipt)
}

impl Memory<'_> {
    /// Report `Edit`: the owner's title edit at `expected_revision`.
    pub(super) fn report_edit(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        expected_revision: u64,
        title: String,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        check_task_label(&title)?;
        if self.keeps_no_record() {
            return Err(MemoryError::new(
                MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
                "a title edit is mirrored, so an off-record session makes none",
                &["Edit the title outside the off-record session."],
            ));
        }
        if self.credential_withholds(task_ref)? {
            return Err(not_found());
        }
        let digest = request_digest(&[
            task_ref.as_bytes(),
            &expected_revision.to_be_bytes(),
            title.as_bytes(),
        ]);
        let event = task_edit_key(task_ref, self.actor(), key);
        let mut lifecycle =
            self.lifecycle_record(via, "report", "edited", Some(task_ref), None, now);
        lifecycle
            .fields
            .insert("report_key".to_owned(), key.to_owned());
        lifecycle
            .fields
            .insert("body".to_owned(), "edit".to_owned());
        lifecycle.fields.insert(
            "expected_revision".to_owned(),
            expected_revision.to_string(),
        );
        let receipt_id = self.report_receipt_id_for_edit(task_ref, key)?;
        let receipt = self.with_verified_actor_write_txn(|wtxn| {
            let vault = self.vault();
            if let Some(row) = event_in(vault, wtxn, &event)? {
                return replayed_edit(&row, &digest);
            }
            self.highway_task_actor_in(
                wtxn,
                task_ref,
                TaskActorVerb::Owner,
                "Ask the task's owner to edit its title.",
            )?;
            let mut body = task_body_in_txn(vault, wtxn, task_ref)?;
            if body.terminal().is_some() {
                return Err(invalid_state(
                    "a settled task's title cannot change",
                    "Post a new task for new work.",
                ));
            }
            let revision = super::linear_store::task_revision_in_txn(&vault.store, wtxn, task_ref)?;
            if revision != expected_revision {
                return Err(invalid_state(
                    "the task moved since the revision this edit names",
                    "Read the task again and edit at its current revision.",
                ));
            }
            body.label = Some(title);
            let phase = phase_of(&body);
            self.rewrite_task_in_txn(wtxn, task_ref, body, now)?;
            let receipt_ref = receipt_id
                .map(|id| lifecycle_receipt::stamp_record_in(vault, wtxn, &lifecycle, id, None))
                .transpose()?;
            let receipt = TaskCallReceipt {
                handle: TaskHandle::Task { task_ref },
                related: Vec::new(),
                outcome: TaskOutcome::Reported { phase },
                receipt_ref,
                lifecycle: Some(lifecycle),
                idempotent_replay: false,
            };
            let row = self.edit_row(task_ref, digest, &receipt)?;
            put_event_in(vault, wtxn, &event, &row)?;
            Ok(receipt)
        })?;
        if !receipt.idempotent_replay {
            self.vault().store.notify_task_updates([task_ref]);
        }
        Ok(receipt)
    }

    /// The event row one title edit is recorded under: its TASK, request
    /// digest, verified writer and receipt.
    fn edit_row(
        &self,
        task_ref: EntityId,
        digest: String,
        receipt: &TaskCallReceipt,
    ) -> MemoryResult<LinearMirrorEvent> {
        let mut row = LinearMirrorEvent::blank(
            EventDirection::TaskEdit,
            "edited",
            self.vault().now_recorded_at(),
        );
        row.task_ref = Some(task_ref.to_hex());
        row.body_digest = Some(digest);
        row.written_by(self.actor(), self.actor_class());
        row.receipt = Some(
            serde_json::to_string(receipt)
                .map_err(|_| Error::InvariantViolation("task title edit receipt encoding"))?,
        );
        Ok(row)
    }

    /// The id a title edit keeps its lifecycle receipt under, `None` when
    /// this surface keeps no record: the same for the edit and its replays.
    fn report_receipt_id_for_edit(
        &self,
        task_ref: EntityId,
        key: &str,
    ) -> MemoryResult<Option<String>> {
        if !self.keeps_lifecycle() {
            return Ok(None);
        }
        lifecycle_receipt::receipt_id(
            "edit",
            &[task_ref.as_bytes(), self.actor().as_bytes(), key.as_bytes()],
        )
        .map(Some)
    }
}
