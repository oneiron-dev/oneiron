//! The stage-2 topic summary trigger (ARCH-0032 write gate, OF-073 / FIX
//! 907). A NOTE review whose classification names the note's topic keeps it
//! on the NOTE's review record, the one record of topic membership, and in
//! that same write declares the summary of the topic's group: every
//! reviewed NOTE whose record keeps the same topic, facet and project, and
//! that a NOTE set's summary takes now on its requester's own read. The
//! declaration is the existing NOTE-set one, under the review's attempt and
//! run, for the default `note_summary` purpose. So a replay never finds a
//! NOTE reviewed with its topic's summary unqueued.
//!
//! A NOTE set names its summary, so a group that grew declares the summary
//! of its whole set beside the one its smaller set has; a summary that
//! landed stays as it is. A group is never cut: a NOTE of another facet or
//! project is in its own group, declared when that NOTE is reviewed.
//!
//! A declaration whose group the topic's current group strictly outgrew
//! before it ran completes without composing (Engine 10-21, option A), so a
//! burst of reviews composes no summary per growth step. It first declares
//! the current group itself, under the same review and run (FIX 7492): a
//! group that grew with no new review (a member became readable or was
//! unarchived) still has its summary owed. Only a NOTE review's own
//! declarations are read so; any other NOTE set composes.
//!
//! A NOTE whose review moves it to another topic, or to none, re-declares
//! the group it left in the same write (FIX 7459), so that group's summary
//! is composed again without it.
//!
//! The review's write also moves the NOTE's row in the topic index (FIX
//! 7457), so a group is one keyed read, never a walk of every review record.
//! Each indexed NOTE is checked against its record, which stays the truth.

use std::collections::BTreeSet;

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{DREAMER_NOTE_REVIEW_ATTEMPT_KIND, DreamerAdmittedAttempt};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault, WriteActor};

const TOPIC_DOMAIN: &[u8] = b"oneiron:note-topic-key:v1";
/// One row per reviewed NOTE, keyed by the membership its review record
/// keeps, then the NOTE (FIX 7457).
const TOPIC_INDEX: SideTable<([u8; 32], (EntityId, EntityId), EntityId), (), Named> =
    SideTable::new(&side_table::DREAMER_NOTE_REVIEW_TOPIC);

/// One reviewed NOTE's topic membership, as its review record keeps it: a
/// digest of the `topic_key` its classification named (the record keeps no
/// model text), and the birth facet and project its beliefs take. NOTEs
/// whose memberships are equal are one topic group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct NoteTopicMembership {
    topic: [u8; 32],
    facet: EntityId,
    project: EntityId,
}

impl NoteTopicMembership {
    /// The membership of a NOTE whose classification named `topic_key`.
    pub(super) fn new(topic_key: &str, facet: EntityId, project: EntityId) -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(TOPIC_DOMAIN);
        hash.update(topic_key.as_bytes());
        Self {
            topic: *hash.finalize().as_bytes(),
            facet,
            project,
        }
    }

    /// `note`'s row in the topic index.
    fn index_key(&self, note: EntityId) -> ([u8; 32], (EntityId, EntityId), EntityId) {
        (self.topic, (self.facet, self.project), note)
    }

    /// The index key bytes every NOTE of this group shares.
    fn index_prefix(&self) -> Vec<u8> {
        let mut prefix = self.topic.to_vec();
        prefix.extend_from_slice(self.facet.as_bytes());
        prefix.extend_from_slice(self.project.as_bytes());
        prefix
    }
}

/// Moves `note`'s topic index row in `txn`, the write that keeps its review
/// record (FIX 7457): off the topic it `left`, onto the topic it `kept`.
pub(super) fn index_note_topic_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    left: Option<&NoteTopicMembership>,
    kept: Option<&NoteTopicMembership>,
) -> Result<()> {
    if let Some(left) = left {
        TOPIC_INDEX.delete(&vault.store, txn, &left.index_key(note))?;
    }
    if let Some(kept) = kept {
        TOPIC_INDEX.put(&vault.store, txn, &kept.index_key(note), &())?;
    }
    Ok(())
}

/// Every reviewed NOTE whose review record keeps `topic`, in id order: the
/// topic index's rows for it, each checked against its record (FIX 7457).
fn topic_members_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    topic: &NoteTopicMembership,
) -> Result<Vec<EntityId>> {
    let mut members = Vec::new();
    for (_, _, note) in TOPIC_INDEX.scan_keys(&vault.store, txn, &topic.index_prefix())? {
        if super::note_review::topic_of_in_txn(vault, txn, &note).as_ref() == Some(topic) {
            members.push(note);
        }
    }
    Ok(members)
}

/// Who declares a topic group's summary, and under which attempt and run.
pub(super) struct NoteTopicLineage<'a> {
    /// The vault Dreamer that reviewed the NOTE.
    pub(super) requester: WriteActor,
    /// The NOTE review attempt.
    pub(super) parent: AttemptId,
    pub(super) run_id: Option<&'a str>,
    /// Recorded-at seconds.
    pub(super) now: u64,
}

/// One topic group: of the NOTEs whose review records keep one membership,
/// those a NOTE set's summary takes now, in id order.
pub(super) struct NoteTopicGroup {
    notes: Vec<EntityId>,
}

impl NoteTopicGroup {
    /// `topic`'s group as `requester` declares it, or `None` when a NOTE
    /// set's summary takes none of its NOTEs.
    fn in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        topic: &NoteTopicMembership,
        requester: WriteActor,
    ) -> Result<Option<Self>> {
        let members = topic_members_in_txn(vault, txn, topic)?;
        let notes = vault.note_summary_sources_in_txn(txn, requester, &members)?;
        Ok((!notes.is_empty()).then_some(Self { notes }))
    }

    /// The group's summary declaration: its NOTEs as a NOTE set, in no
    /// conversation.
    fn request(self, requester: WriteActor) -> ScopeSummaryRequest {
        ScopeSummaryRequest {
            target: ScopeSummaryTarget::Sources {
                scope: None,
                sources: self.notes,
            },
            requester,
        }
    }
}

/// Declares the summary of `topic`'s group in `txn`, the write that keeps
/// the reviewed NOTE's membership, and returns whether it declared one.
/// The declaration writes in its own savepoint: one the summary doors refuse
/// rolls back alone and is logged, and the review stands, as it does for a
/// NOTE that names no topic. A storage failure fails the write.
pub(super) fn queue_note_topic_summaries_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    topic: &NoteTopicMembership,
    lineage: &NoteTopicLineage<'_>,
) -> Result<bool> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match declare_in_txn(vault, &mut savepoint, topic, lineage) {
        Ok(Some(notes)) => {
            savepoint.commit()?;
            tracing::info!(
                target: "oneiron::dreamer",
                notes,
                "note review declared its topic's summary"
            );
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => Err(error),
        Err(error) => {
            tracing::warn!(
                target: "oneiron::dreamer",
                kind = ?error.kind(),
                "note review's topic summary was not declared"
            );
            Ok(false)
        }
    }
}

/// `topic`'s group declared in `txn`: how many NOTEs it holds, or `None`
/// when there is no group to declare.
fn declare_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    topic: &NoteTopicMembership,
    lineage: &NoteTopicLineage<'_>,
) -> Result<Option<usize>> {
    let Some(group) = NoteTopicGroup::in_txn(vault, txn, topic, lineage.requester)? else {
        return Ok(None);
    };
    let notes = group.notes.len();
    vault.request_scope_summary_in_txn(
        txn,
        &group.request(lineage.requester),
        Some(lineage.parent),
        lineage.run_id,
        lineage.now,
    )?;
    Ok(Some(notes))
}

/// Whether `attempt`, a NOTE set's summary declaration planned over
/// `declared` for `requester`, is one a NOTE review declared for a topic
/// whose current group strictly outgrew it (Engine 10-21, option A): the
/// current group's own declaration is queued first, under the same review
/// and run (FIX 7492), and this one then completes without composing. A
/// declaration under no NOTE review attempt, a declared NOTE whose review
/// record is gone, does not read or keeps another topic, a read that fails
/// and a larger declaration that does not queue all answer no: the summary
/// composes as it would.
pub(super) fn note_topic_summary_outgrown(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    requester: WriteActor,
    declared: &[EntityId],
) -> bool {
    let Some(parent) = attempt.status.payload.parent_attempt else {
        return false;
    };
    let run_id = attempt.status.attempt.run_id.as_deref();
    let queued = vault.store.authorization_now().and_then(|_| {
        let now = vault.store.clock.now_recorded_at();
        vault.with_write_txn_grouped(|txn| {
            let Some(group) = outgrown_in_txn(vault, txn, parent, requester, declared)? else {
                return Ok(None);
            };
            let current = group.notes.len();
            let queued = vault.request_scope_summary_in_txn(
                txn,
                &group.request(requester),
                Some(parent),
                run_id,
                now,
            )?;
            Ok(Some((current, queued.coalesced)))
        })
    });
    let (current, coalesced) = match queued {
        Ok(Some(outgrown)) => outgrown,
        Ok(None) => return false,
        Err(error) => {
            tracing::warn!(
                target: "oneiron::dreamer",
                kind = ?error.kind(),
                "an outgrown topic summary composes: its larger group did not queue"
            );
            return false;
        }
    };
    vault.store.notify_attempt_observers();
    tracing::info!(
        target: "oneiron::dreamer",
        code = "note_topic_summary_outgrown",
        attempt = %bytes_to_hex_lower(attempt.status.attempt.id.as_bytes()),
        declared = declared.len(),
        current,
        coalesced,
        "topic summary completes without composing; its larger group is declared"
    );
    true
}

/// The declared topic's current group, in `txn`, when it strictly outgrew
/// `declared`.
fn outgrown_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    parent: AttemptId,
    requester: WriteActor,
    declared: &[EntityId],
) -> Result<Option<NoteTopicGroup>> {
    // Only a NOTE review declares a NOTE set under its own attempt.
    let review = AttemptQueue::new(vault).get_in_txn(txn, parent)?;
    if review.is_none_or(|row| row.kind != DREAMER_NOTE_REVIEW_ATTEMPT_KIND) {
        return Ok(None);
    }
    let mut topic = None;
    for note in declared {
        let Some(kept) = super::note_review::topic_of_in_txn(vault, txn, note) else {
            return Ok(None);
        };
        if topic.is_some_and(|topic| topic != kept) {
            return Ok(None);
        }
        topic = Some(kept);
    }
    let Some(topic) = topic else {
        return Ok(None);
    };
    let Some(group) = NoteTopicGroup::in_txn(vault, txn, &topic, requester)? else {
        return Ok(None);
    };
    let current: BTreeSet<EntityId> = group.notes.iter().copied().collect();
    let declared: BTreeSet<EntityId> = declared.iter().copied().collect();
    Ok((current.len() > declared.len() && current.is_superset(&declared)).then_some(group))
}
