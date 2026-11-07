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

/// One code-revision table whose stored value names rows, as an archive reads
/// it ([`archive_revision_rows`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchivedRevisionTable {
    Record,
    Integrity,
    Proposal,
    Promotion,
    Fork,
    Frontier,
}

/// Each entity row a stored value of `table` names, read through the table's
/// own codec (fix list row 15416): a finalized revision's rows
/// ([`revision_rows`]); an integrity fold's revision, session, parent,
/// reverted-to revision and provenance claim; a stranded proposal's revision
/// inside it, read through the revision's own codec, and its head revision;
/// the reviewed proposals a promotion names; a fork's sessions and base
/// revision; a frontier's session and revision. `None` when the value, or a
/// record inside it, does not read.
pub(crate) fn archive_revision_rows(
    table: ArchivedRevisionTable,
    value: &[u8],
) -> Option<Vec<EntityId>> {
    match table {
        ArchivedRevisionTable::Record => RECORDS
            .decode_value(value)
            .ok()
            .map(|revision| revision_rows(&revision)),
        ArchivedRevisionTable::Integrity => INTEGRITY.decode_value(value).ok().map(|record| {
            let mut rows = vec![record.revision_id, record.session_id];
            rows.extend(record.parent_revision_id);
            rows.extend(record.reverted_to_revision_id);
            rows.extend(record.provenance_claim_id);
            rows
        }),
        ArchivedRevisionTable::Proposal => super::proposals::archive_proposal_rows(value),
        ArchivedRevisionTable::Promotion => crate::store::code_revision_record::tables::PROMOTIONS
            .decode_value(value)
            .ok()?
            .iter()
            .map(|id| EntityId::from_hex(id).ok())
            .collect(),
        ArchivedRevisionTable::Fork => FORKS.decode_value(value).ok().map(|fork| {
            vec![
                fork.fork_session_id,
                fork.parent_session_id,
                fork.base_revision_id,
            ]
        }),
        ArchivedRevisionTable::Frontier => FRONTIER
            .decode_value(value)
            .ok()
            .map(|record| vec![record.session_id, record.revision_id]),
    }
}

/// Each entity row `revision` names (fix list row 15416): itself, its
/// session, parent and reverted-to revisions, provenance claim, import
/// anchor and commit author, and a tested queue revision's repo, each push it
/// consumed (candidate, provenance, publication, base revision and a masked
/// copy's graph and ingress), each landed source (proposal, session and
/// provenance claim) and each retired path's operation receipt and review.
pub(super) fn revision_rows(revision: &CodeRevision) -> Vec<EntityId> {
    let mut rows = vec![revision.revision_id, revision.session_id];
    rows.extend(revision.parent_revision_id);
    rows.extend(revision.reverted_to_revision_id);
    rows.extend(revision.provenance_claim_id);
    rows.extend(revision.snapshot_anchor);
    rows.extend(
        revision
            .commit_metadata
            .as_ref()
            .and_then(|metadata| metadata.author),
    );
    if let Some(tested) = &revision.tested_queue {
        rows.push(tested.repo);
        for push in &tested.received_pushes {
            rows.extend([
                push.candidate,
                push.provenance,
                push.publication,
                push.base_revision,
            ]);
            if let Some(projection) = &push.projection {
                rows.extend([projection.graph, projection.ingress]);
            }
        }
        if let crate::merge_queue::QueueTestedTarget::Landed { applied, .. } = &tested.target {
            for source in applied {
                rows.extend([source.proposal, source.session, source.provenance_claim]);
            }
        }
    }
    for retired in revision.retired_paths.values() {
        rows.extend([retired.operation_receipt, retired.review_ref]);
    }
    rows
}
