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
//! of its whole set beside the one its smaller set has; that one stays as it
//! is. A group is never cut: a NOTE of another facet or project is in its
//! own group, declared when that NOTE is reviewed.

use crate::attempt_queue::AttemptId;
use crate::error::Error;
use crate::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use crate::{EntityId, Result, Vault, WriteActor};

const TOPIC_DOMAIN: &[u8] = b"oneiron:note-topic-key:v1";

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
        let members = super::note_review::topic_members_in_txn(vault, txn, topic)?;
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
