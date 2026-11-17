//! Typed side tables for the code-revision row families: finalized records, forks, per-revision
//! integrity folds, per-session frontiers, and the parent/session/fork indices over them.

use crate::entity_id::EntityId;
use crate::side_table::{self, Raw, SideTable};

use super::types::{
    CodeRevision, CodeRevisionFork, CodeRevisionFrontierRecord, CodeRevisionIntegrityRecord,
};

pub(super) use crate::store::code_revision_record::tables::RECORDS;

/// Recorded code-revision fork/branch row. Key: fork session id.
pub(super) const FORKS: SideTable<EntityId, CodeRevisionFork, Raw> =
    SideTable::new(&side_table::CODE_REVISION_FORK);

/// Cached integrity/hash-fold record for one revision. Key: revision id.
pub(super) const INTEGRITY: SideTable<EntityId, CodeRevisionIntegrityRecord, Raw> =
    SideTable::new(&side_table::CODE_REVISION_INTEGRITY);

/// A session's current revision-frontier record. Key: session id.
pub(super) const FRONTIER: SideTable<EntityId, CodeRevisionFrontierRecord, Raw> =
    SideTable::new(&side_table::CODE_REVISION_FRONTIER);

/// Index of revisions belonging to a session, empty marker value. Key: session id + revision id.
pub(super) const SESSION_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CODE_REVISION_SESSION_INDEX);

/// Index of child revisions by parent revision, empty marker value. Key: parent revision id +
/// revision id.
pub(super) const PARENT_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CODE_REVISION_PARENT_INDEX);

/// The checked Baseline a tested queue revision's chain ends at (a Baseline names itself),
/// written when its seal is finalized (FIX 7390, 7391). Key: revision id.
pub(super) const QUEUE_ROOTS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CODE_REVISION_QUEUE_ROOT);

/// Index of forks by parent session, empty marker value. Key: parent session id + fork session id.
pub(super) const FORK_PARENT_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CODE_REVISION_FORK_PARENT_INDEX);

/// OF-222 (FIX 2768) archive seam: the code-revision tables a whole-vault archive carries
/// beside each revision and session (records, integrity folds, the session, parent and fork
/// indexes, forks and frontiers), lent with their own key types and codec.
pub(crate) fn archive_revision_tables() -> [crate::batch::export::LentSideTable; 7] {
    [
        &RECORDS,
        &INTEGRITY,
        &SESSION_INDEX,
        &PARENT_INDEX,
        &FORKS,
        &FORK_PARENT_INDEX,
        &FRONTIER,
    ]
}

/// Puts an integrity row for the checkpoint-pins door: `key`'s revision of
/// `session_id` with `artifact_hash`'s bytes and `revision_fold`'s fold, a
/// root with no parent, reverted-to or claim rows.
#[cfg(oneiron_test_support)]
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per integrity field the door sets"
)]
pub(crate) fn put_pins_code_revision_integrity_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    key: &EntityId,
    revision_id: &EntityId,
    session_id: &EntityId,
    artifact_hash: &[u8; 32],
    revision_fold: &[u8; 32],
    finalized_at: u64,
) -> crate::error::Result<()> {
    INTEGRITY.put(
        store,
        txn,
        key,
        &CodeRevisionIntegrityRecord {
            revision_id: *revision_id,
            session_id: *session_id,
            parent_revision_id: None,
            reverted_to_revision_id: None,
            provenance_claim_id: None,
            artifact_hash: *artifact_hash,
            parent_fold: None,
            reverted_to_fold: None,
            revision_fold: *revision_fold,
            finalized_at,
        },
    )
}

/// Puts a session-frontier row for the checkpoint-pins door: `key`'s
/// session standing at `revision_id` with `revision_fold`'s fold.
#[cfg(oneiron_test_support)]
pub(crate) fn put_pins_code_revision_frontier_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    key: &EntityId,
    session_id: &EntityId,
    revision_id: &EntityId,
    revision_fold: &[u8; 32],
    finalized_at: u64,
) -> crate::error::Result<()> {
    FRONTIER.put(
        store,
        txn,
        key,
        &CodeRevisionFrontierRecord {
            session_id: *session_id,
            revision_id: *revision_id,
            revision_fold: *revision_fold,
            finalized_at,
        },
    )
}
