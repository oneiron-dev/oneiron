//! A code revision fork's writer in its caller's transaction (moved from
//! `storage.rs`, G4 PR2), so a validated pushed candidate co-commits its
//! fork with its proposal; the public `branch_code_revision` keeps its own
//! writer and its duplicate refusal.
use heed::RwTxn;

use super::graph::{
    put_lifecycle_edge, require_entity_type, require_known_code_revision,
    require_revision_session, validate_child_of_insert,
};
use super::integrity::backfill_code_revision_integrity_for_revision_in_txn;
use super::keys::{FORK_PARENT_INDEX, FORKS};
use super::types::CodeRevisionFork;
use crate::edge::EdgeKind;
use crate::error::{ArtifactError, Error, Result};
use crate::ppr;
use crate::registry::ENTITY_TYPE_SESSION;
use crate::store::Store;

/// Records `fork` in `wtxn`: both sessions SESSIONs, its base revision a
/// known revision of the parent session, and no fork yet for its session.
///
/// # Errors
/// A shape or binding that does not hold, an existing fork, or a store
/// failure.
pub(crate) fn branch_code_revision_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    fork: &CodeRevisionFork,
) -> Result<()> {
    require_entity_type(
        store,
        wtxn,
        &fork.fork_session_id,
        ENTITY_TYPE_SESSION,
        "fork_session_id must be a SESSION entity",
    )?;
    require_entity_type(
        store,
        wtxn,
        &fork.parent_session_id,
        ENTITY_TYPE_SESSION,
        "parent_session_id must be a SESSION entity",
    )?;
    backfill_code_revision_integrity_for_revision_in_txn(
        store,
        wtxn,
        &fork.base_revision_id,
    )?;
    let base_revision =
        require_known_code_revision(store, wtxn, &fork.base_revision_id)?;
    require_revision_session(
        &base_revision,
        fork.parent_session_id,
        "base_revision_id must belong to parent_session_id",
    )?;
    if FORKS.contains(store, wtxn, &fork.fork_session_id)? {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision fork already recorded for session",
        )));
    }
    validate_child_of_insert(
        store,
        wtxn,
        &fork.fork_session_id,
        &fork.parent_session_id,
    )?;

    let mut graph_changed = false;
    put_lifecycle_edge(
        store,
        wtxn,
        &fork.fork_session_id,
        EdgeKind::ChildOf,
        &fork.parent_session_id,
        fork.forked_at,
        &mut graph_changed,
    )?;
    put_lifecycle_edge(
        store,
        wtxn,
        &fork.fork_session_id,
        EdgeKind::DerivedFrom,
        &fork.base_revision_id,
        fork.forked_at,
        &mut graph_changed,
    )?;
    FORKS.put(store, wtxn, &fork.fork_session_id, fork)?;
    FORK_PARENT_INDEX.put(
        store,
        wtxn,
        &(fork.parent_session_id, fork.fork_session_id),
        &(),
    )?;
    if graph_changed {
        ppr::increment_graph_version(store, wtxn)?;
    }
    Ok(())
}
