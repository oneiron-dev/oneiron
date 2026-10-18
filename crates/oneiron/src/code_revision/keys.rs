//! Typed side tables for the code-revision row families: finalized records, forks, per-revision
//! integrity folds, per-session frontiers, and the parent/session/fork indices over them.

use crate::entity_id::EntityId;
use crate::side_table::{self, Raw, SideTable};

use super::types::{
    CodeRevision, CodeRevisionFork, CodeRevisionFrontierRecord, CodeRevisionIntegrityRecord,
};

/// Finalized code-revision row (hand-rolled MessagePack map). Key: revision id.
pub(super) const RECORDS: SideTable<EntityId, CodeRevision, Raw> =
    SideTable::new(&side_table::CODE_REVISION_RECORD);

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
