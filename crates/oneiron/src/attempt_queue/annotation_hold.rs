//! OF-368: a comment's agent task waits while its comment is unattached.
//!
//! Assigning a comment thread mints a TASK and an `annotation.brief` claim
//! naming it ([`crate::Vault::assign_annotation_thread_to_brief`]). While that
//! thread is unattached ([`crate::Vault::annotation_thread_task_hold`]), the
//! TASK's attempts are parked, never dropped or cancelled: a dispatch mints its
//! attempt paused, and a claim pauses a ready one instead of leasing it. Both
//! pauses carry the typed [`AnnotationHold`] reason, so a reattach resumes
//! exactly those rows and never one a person paused.

use std::collections::BTreeMap;

use rmpv::Value;

use crate::Vault;
use crate::anchored_annotation::ANNOTATION_BRIEF_PREDICATE;
use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::AttemptQueue;
use super::types::{
    AttemptId, AttemptInterventionKind, AttemptRecord, AttemptState, InterveneAttempt,
};

/// The intervention actor of an annotation-hold pause and of its release.
/// Reserved: no other intervention may name it.
pub const ANNOTATION_HOLD_ACTOR: &str = "engine:annotation_hold";

/// Refusal for an intervention that names [`ANNOTATION_HOLD_ACTOR`].
pub(in crate::attempt_queue) const ERR_ANNOTATION_HOLD_ACTOR_RESERVED: &str =
    "intervention actor is reserved for the annotation hold";

/// Brief claims read per page of the predicate posting list. A page size, not
/// a cap: the walk reads every page.
const BRIEF_PAGE: usize = 256;

/// The stored keys of an `annotation.brief` claim value that name its thread
/// and its TASK (the wire form `anchored_annotation` persists).
const BRIEF_KEY_THREAD_ID: &str = "thread_id";
const BRIEF_KEY_TASK_ID: &str = "task_id";

/// Why the engine paused an attempt: its TASK answers a comment thread that is
/// unattached. Recorded as the pause event's note under
/// [`ANNOTATION_HOLD_ACTOR`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnotationHold {
    /// The artifact the comment is on.
    pub artifact_id: EntityId,
    /// The comment thread the TASK was assigned from.
    pub thread_id: EntityId,
}

impl AnnotationHold {
    /// The pause note naming this hold: `<artifact hex>:<thread hex>`.
    #[must_use]
    pub fn note(&self) -> String {
        format!("{}:{}", self.artifact_id.to_hex(), self.thread_id.to_hex())
    }

    /// Reads a hold back from its pause note; `None` for any other note.
    #[must_use]
    pub fn from_note(note: &str) -> Option<Self> {
        let (artifact, thread) = note.split_once(':')?;
        Some(Self {
            artifact_id: EntityId::from_hex(artifact).ok()?,
            thread_id: EntityId::from_hex(thread).ok()?,
        })
    }
}

/// What one [`Vault::release_annotation_holds`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnnotationHoldSweep {
    /// Rows resumed because their hold is gone.
    pub resumed: usize,
    /// Rows still paused for a hold.
    pub held: usize,
}

impl AttemptRecord {
    /// The annotation hold this row is paused for. `None` unless the row is
    /// paused and its newest pause is the engine's hold: a row a person paused
    /// reads `None` even while a hold also applies, so nothing resumes it.
    #[must_use]
    pub fn annotation_hold(&self) -> Option<AnnotationHold> {
        if self.state != AttemptState::Paused {
            return None;
        }
        let event = self.events.iter().rev().find(|event| {
            matches!(
                event.kind,
                AttemptInterventionKind::Pause | AttemptInterventionKind::Resume
            )
        })?;
        if event.kind != AttemptInterventionKind::Pause || event.actor != ANNOTATION_HOLD_ACTOR {
            return None;
        }
        AnnotationHold::from_note(event.note.as_deref()?)
    }
}

impl AttemptQueue<'_> {
    /// The hold on this row's TASK, read in the caller's transaction. `None`
    /// for a row with no TASK and for a store-only handle.
    pub(crate) fn annotation_hold_for_row_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<Option<AnnotationHold>> {
        let (Some(vault), Some(task)) = (
            self.vault,
            record
                .task_ref
                .as_deref()
                .and_then(|id| EntityId::from_hex(id).ok()),
        ) else {
            return Ok(None);
        };
        vault.annotation_task_hold_in_txn(txn, &task)
    }

    /// Pauses a queued or scheduled row for `hold` in the caller's
    /// transaction. The row keeps its readiness instant, as any pause does.
    pub(crate) fn hold_for_annotation_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        hold: AnnotationHold,
        now: u64,
    ) -> Result<AttemptRecord> {
        Ok(self
            .apply_intervention_in_txn(
                wtxn,
                InterveneAttempt {
                    id,
                    kind: AttemptInterventionKind::Pause,
                    actor: ANNOTATION_HOLD_ACTOR.to_owned(),
                    note: Some(hold.note()),
                    now,
                },
            )?
            .record)
    }
}

impl Vault {
    /// The hold on `task`: its comment thread, while that thread is
    /// unattached and `task` is the one its newest assignment made (the task
    /// [`Vault::annotation_thread_task_hold`] names). Read in the caller's
    /// transaction.
    pub(crate) fn annotation_task_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: &EntityId,
    ) -> Result<Option<AnnotationHold>> {
        let Some(hold) = self.annotation_brief_of_task_in_txn(txn, task)? else {
            return Ok(None);
        };
        Ok(self
            .annotation_thread_unattached_in_txn(txn, &hold.artifact_id, &hold.thread_id)?
            .then_some(hold))
    }

    /// The comment thread `task` was assigned from, by the brief claims'
    /// posting list. A TASK names no brief of its own, and each assignment
    /// mints a fresh TASK, so the walk matches the brief carrying `task`. The
    /// list runs in claim-id order: a later brief on the same thread is a
    /// newer assignment, and the hold is that one's task, not this one.
    fn annotation_brief_of_task_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: &EntityId,
    ) -> Result<Option<AnnotationHold>> {
        let mut found = None;
        let mut after = None;
        loop {
            let page = crate::claim::claim_ids_for_predicate_page_in_txn(
                &self.store,
                txn,
                ANNOTATION_BRIEF_PREDICATE,
                after,
                BRIEF_PAGE,
            )?;
            for claim_id in &page {
                let Some(body) = self.get_claim_in_txn(txn, claim_id)? else {
                    continue;
                };
                if !crate::claim::claim_surfaceable(&body) {
                    continue;
                }
                let ClaimSubject::Entity(artifact_id) = &body.subject else {
                    continue;
                };
                let (Some(thread_id), Some(brief_task)) = (
                    brief_entity(&body.value, BRIEF_KEY_THREAD_ID),
                    brief_entity(&body.value, BRIEF_KEY_TASK_ID),
                ) else {
                    continue;
                };
                let brief = AnnotationHold {
                    artifact_id: *artifact_id,
                    thread_id,
                };
                if brief_task == *task {
                    found = Some(brief);
                } else if found == Some(brief) {
                    return Ok(None);
                }
            }
            if page.len() < BRIEF_PAGE {
                return Ok(found);
            }
            after = page.last().copied();
        }
    }

    /// Resumes `task`'s attempts paused for its annotation hold, once that
    /// hold is gone. Rows a person paused stay paused. Returns how many
    /// resumed. A reattach door calls this in its own transaction; the caller
    /// signals attempt observers after it commits.
    pub(crate) fn resume_annotation_held_attempts_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        task: &EntityId,
    ) -> Result<usize> {
        if self.annotation_task_hold_in_txn(txn, task)?.is_some() {
            return Ok(0);
        }
        let queue = AttemptQueue::new(self);
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let mut resumed = 0;
        for row in queue.list_task_in_write_txn(txn, &task.to_hex())? {
            let Some(hold) = row.annotation_hold() else {
                continue;
            };
            queue.apply_intervention_in_txn(
                txn,
                InterveneAttempt {
                    id: row.id,
                    kind: AttemptInterventionKind::Resume,
                    actor: ANNOTATION_HOLD_ACTOR.to_owned(),
                    note: Some(hold.note()),
                    now,
                },
            )?;
            resumed += 1;
        }
        Ok(resumed)
    }

    /// Resumes every attempt whose annotation hold is gone, for a runner pump
    /// that does not wait on the reattach door. Reads outside the writer and
    /// takes it only when a hold has lifted.
    pub fn release_annotation_holds(&self) -> Result<AnnotationHoldSweep> {
        let queue = AttemptQueue::new(self);
        let mut held: BTreeMap<EntityId, usize> = BTreeMap::new();
        let mut lifted = Vec::new();
        {
            let rtxn = self.store.env.read_txn()?;
            for row in queue.list_in_txn(&rtxn)? {
                if row.annotation_hold().is_none() {
                    continue;
                }
                let Some(task) = row
                    .task_ref
                    .as_deref()
                    .and_then(|id| EntityId::from_hex(id).ok())
                else {
                    continue;
                };
                *held.entry(task).or_default() += 1;
            }
            for task in held.keys() {
                if self.annotation_task_hold_in_txn(&rtxn, task)?.is_none() {
                    lifted.push(*task);
                }
            }
        }
        let held: usize = held.values().sum();
        if lifted.is_empty() {
            return Ok(AnnotationHoldSweep { resumed: 0, held });
        }
        let mut wtxn = self.store.env.write_txn()?;
        let mut resumed = 0;
        for task in &lifted {
            resumed += self.resume_annotation_held_attempts_in_txn(&mut wtxn, task)?;
        }
        wtxn.commit()?;
        if resumed > 0 {
            self.store.notify_attempt_observers();
        }
        Ok(AnnotationHoldSweep {
            resumed,
            held: held.saturating_sub(resumed),
        })
    }
}

/// One entity id of a brief claim value, by its stored key.
fn brief_entity(value: &Value, key: &str) -> Option<EntityId> {
    let Value::Map(entries) = value else {
        return None;
    };
    let (_, Value::Binary(bytes)) = entries.iter().find(|(k, _)| k.as_str() == Some(key))? else {
        return None;
    };
    let raw: [u8; crate::entity_id::ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
    EntityId::from_bytes(raw).ok()
}
