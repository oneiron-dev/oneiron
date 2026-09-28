//! Vault CRUD for code revisions and forks, plus record/index reads, writes and deletes.

use std::collections::{HashMap, VecDeque};

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SESSION};
use crate::side_table::{Raw, SideTable};
use crate::store::Store;

use super::codec::validate_code_revision_fork_shape;
use super::codec::validate_code_revision_shape;
use super::frontier::FrontierUpdate;
use super::frontier::{
    delete_code_revision_frontier_for_revision_in_txn, get_code_revision_frontier_in_txn,
    validate_code_revision_frontier_update, verify_code_revision_frontier_in_txn,
    verify_code_revision_session_trace_in_txn,
};
use super::graph::{
    put_lifecycle_edge, require_code_artifact_body, require_code_revision_ancestor,
    require_entity_type, require_known_code_revision, require_revision_session,
    validate_child_of_insert,
};
use super::integrity::{
    backfill_code_revision_integrity_for_revision_in_txn,
    backfill_code_revision_integrity_for_session_in_txn, build_code_revision_integrity_record,
    verify_code_revision_integrity_in_txn,
};
use super::keys::{
    FORK_PARENT_INDEX, FORKS, FRONTIER, INTEGRITY, PARENT_INDEX, RECORDS, SESSION_INDEX,
};
use super::proposals::CodeRevisionWriteOutcome;

use super::types::{CodeRevision, CodeRevisionFork, CodeRevisionFrontierRecord, CodeRevisionKind};
use crate::error::ArtifactError;

impl Vault {
    pub fn commit_code_revision(
        &self,
        revision: &CodeRevision,
    ) -> Result<CodeRevisionWriteOutcome> {
        if revision.kind != CodeRevisionKind::Commit {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "commit_code_revision requires kind commit",
            )));
        }
        write_code_revision(&self.store, revision)
    }

    pub fn revert_code_revision(
        &self,
        revision: &CodeRevision,
    ) -> Result<CodeRevisionWriteOutcome> {
        if revision.kind != CodeRevisionKind::Revert {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "revert_code_revision requires kind revert",
            )));
        }
        write_code_revision(&self.store, revision)
    }

    pub fn branch_code_revision(&self, fork: &CodeRevisionFork) -> Result<()> {
        validate_code_revision_fork_shape(fork)?;
        FORKS.encode_value(fork)?;
        let mut wtxn = self.store.env.write_txn()?;
        require_entity_type(
            &self.store,
            &wtxn,
            &fork.fork_session_id,
            ENTITY_TYPE_SESSION,
            "fork_session_id must be a SESSION entity",
        )?;
        require_entity_type(
            &self.store,
            &wtxn,
            &fork.parent_session_id,
            ENTITY_TYPE_SESSION,
            "parent_session_id must be a SESSION entity",
        )?;
        backfill_code_revision_integrity_for_revision_in_txn(
            &self.store,
            &mut wtxn,
            &fork.base_revision_id,
        )?;
        let base_revision =
            require_known_code_revision(&self.store, &wtxn, &fork.base_revision_id)?;
        require_revision_session(
            &base_revision,
            fork.parent_session_id,
            "base_revision_id must belong to parent_session_id",
        )?;
        if FORKS.contains(&self.store, &wtxn, &fork.fork_session_id)? {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision fork already recorded for session",
            )));
        }
        validate_child_of_insert(
            &self.store,
            &wtxn,
            &fork.fork_session_id,
            &fork.parent_session_id,
        )?;

        let mut graph_changed = false;
        put_lifecycle_edge(
            &self.store,
            &mut wtxn,
            &fork.fork_session_id,
            EdgeKind::ChildOf,
            &fork.parent_session_id,
            fork.forked_at,
            &mut graph_changed,
        )?;
        put_lifecycle_edge(
            &self.store,
            &mut wtxn,
            &fork.fork_session_id,
            EdgeKind::DerivedFrom,
            &fork.base_revision_id,
            fork.forked_at,
            &mut graph_changed,
        )?;
        FORKS.put(&self.store, &mut wtxn, &fork.fork_session_id, fork)?;
        FORK_PARENT_INDEX.put(
            &self.store,
            &mut wtxn,
            &(fork.parent_session_id, fork.fork_session_id),
            &(),
        )?;
        if graph_changed {
            ppr::increment_graph_version(&self.store, &mut wtxn)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_code_revision(&self, revision_id: &EntityId) -> Result<Option<CodeRevision>> {
        let rtxn = self.store.env.read_txn()?;
        get_code_revision_in_txn(&self.store, &rtxn, revision_id)
    }

    pub fn code_revisions_for_session(&self, session_id: &EntityId) -> Result<Vec<CodeRevision>> {
        let rtxn = self.store.env.read_txn()?;
        let revisions =
            collect_code_revisions_by_index_prefix(&self.store, &rtxn, SESSION_INDEX, session_id)?;
        if revisions.is_empty() {
            if get_code_revision_frontier_in_txn(&self.store, &rtxn, session_id)?.is_some() {
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision frontier exists without session index rows",
                )));
            }
        } else {
            if get_code_revision_frontier_in_txn(&self.store, &rtxn, session_id)?.is_some() {
                verify_code_revision_frontier_in_txn(&self.store, &rtxn, session_id)?;
            }
            verify_code_revision_session_trace_in_txn(&self.store, &rtxn, session_id, &revisions)?;
        }
        Ok(revisions)
    }

    pub fn child_code_revisions(&self, parent_revision_id: &EntityId) -> Result<Vec<CodeRevision>> {
        let rtxn = self.store.env.read_txn()?;
        collect_code_revisions_by_index_prefix(&self.store, &rtxn, PARENT_INDEX, parent_revision_id)
    }

    pub fn get_code_revision_fork(
        &self,
        fork_session_id: &EntityId,
    ) -> Result<Option<CodeRevisionFork>> {
        let rtxn = self.store.env.read_txn()?;
        get_code_revision_fork_in_txn(&self.store, &rtxn, fork_session_id)
    }

    pub fn code_revision_forks_from_session(
        &self,
        parent_session_id: &EntityId,
    ) -> Result<Vec<CodeRevisionFork>> {
        let rtxn = self.store.env.read_txn()?;
        let mut forks = Vec::new();
        for (_, fork_session_id) in
            FORK_PARENT_INDEX.scan_keys(&self.store, &rtxn, parent_session_id.as_bytes())?
        {
            if let Some(fork) = get_code_revision_fork_in_txn(&self.store, &rtxn, &fork_session_id)?
            {
                forks.push(fork);
            }
        }
        forks.sort_by_key(|fork| (fork.forked_at, fork.fork_session_id));
        Ok(forks)
    }
}

pub(crate) fn delete_code_revision_lifecycle_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    delete_code_revision_record_in_txn(store, wtxn, id)?;
    delete_code_revision_fork_in_txn(store, wtxn, id)?;
    FRONTIER.delete(store, wtxn, id)?;
    SESSION_INDEX.delete_from(store, wtxn, id.as_bytes())?;
    PARENT_INDEX.delete_from(store, wtxn, id.as_bytes())?;
    FORK_PARENT_INDEX.delete_from(store, wtxn, id.as_bytes())?;
    Ok(())
}

pub(crate) fn has_finalized_code_revision_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<bool> {
    RECORDS.contains(store, rtxn, revision_id)
}

fn write_code_revision(store: &Store, revision: &CodeRevision) -> Result<CodeRevisionWriteOutcome> {
    validate_code_revision_shape(revision)?;
    RECORDS.encode_value(revision)?;
    let mut wtxn = store.env.write_txn()?;
    backfill_code_revision_integrity_for_session_in_txn(store, &mut wtxn, &revision.session_id)?;
    let artifact_body = require_code_artifact_body(store, &wtxn, &revision.revision_id)?;
    // A retained proposal stays retained even if its old parent later becomes
    // the head. Resolution must submit a new revision identity explicitly.
    if let Some(existing) = super::proposals::load(store, &wtxn, &revision.revision_id)? {
        if existing.revision != *revision || existing.artifact_body != artifact_body {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "stranded revision identity reused",
            )));
        }
        return Ok(CodeRevisionWriteOutcome::Proposed(Box::new(existing)));
    }

    require_entity_type(
        store,
        &wtxn,
        &revision.session_id,
        ENTITY_TYPE_SESSION,
        "session_id must be a SESSION entity",
    )?;
    let parent_revision = revision
        .parent_revision_id
        .map(|parent_id| require_known_code_revision(store, &wtxn, &parent_id))
        .transpose()?;
    let reverted_to_revision = revision
        .reverted_to_revision_id
        .map(|reverted_to_id| require_known_code_revision(store, &wtxn, &reverted_to_id))
        .transpose()?;
    if let Some(parent_revision) = &parent_revision {
        require_revision_session(
            parent_revision,
            revision.session_id,
            "parent_revision_id must belong to session_id",
        )?;
    }
    if let Some(reverted_to_revision) = &reverted_to_revision {
        require_revision_session(
            reverted_to_revision,
            revision.session_id,
            "reverted_to_revision_id must belong to session_id",
        )?;
    }
    if let (Some(parent_id), Some(reverted_to_id)) = (
        revision.parent_revision_id,
        revision.reverted_to_revision_id,
    ) {
        require_code_revision_ancestor(store, &wtxn, &parent_id, &reverted_to_id)?;
    }
    if let Some(provenance_claim_id) = revision.provenance_claim_id {
        require_entity_type(
            store,
            &wtxn,
            &provenance_claim_id,
            ENTITY_TYPE_CLAIM,
            "provenance_claim_id must be a CLAIM entity",
        )?;
    }
    if RECORDS.contains(store, &wtxn, &revision.revision_id)? {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision is already finalized",
        )));
    }
    let integrity = build_code_revision_integrity_record(store, &wtxn, revision, &artifact_body)?;
    let update_frontier =
        match validate_code_revision_frontier_update(store, &wtxn, revision, &integrity)? {
            FrontierUpdate::Advance => true,
            FrontierUpdate::Converged => false,
            FrontierUpdate::Diverged(head) => {
                let proposal = super::proposals::retain(
                    store,
                    &mut wtxn,
                    revision,
                    &head,
                    &integrity,
                    &artifact_body,
                )?;
                wtxn.commit()?;
                return Ok(CodeRevisionWriteOutcome::Proposed(Box::new(proposal)));
            }
        };
    let frontier = CodeRevisionFrontierRecord {
        session_id: revision.session_id,
        revision_id: revision.revision_id,
        revision_fold: integrity.revision_fold,
        finalized_at: revision.finalized_at,
    };

    let mut graph_changed = false;
    put_lifecycle_edge(
        store,
        &mut wtxn,
        &revision.revision_id,
        EdgeKind::DerivedFrom,
        &revision.session_id,
        revision.finalized_at,
        &mut graph_changed,
    )?;
    if let Some(parent_id) = revision.parent_revision_id {
        put_lifecycle_edge(
            store,
            &mut wtxn,
            &revision.revision_id,
            EdgeKind::Supersedes,
            &parent_id,
            revision.finalized_at,
            &mut graph_changed,
        )?;
    }
    if let Some(reverted_to_id) = revision.reverted_to_revision_id {
        put_lifecycle_edge(
            store,
            &mut wtxn,
            &revision.revision_id,
            EdgeKind::DerivedFrom,
            &reverted_to_id,
            revision.finalized_at,
            &mut graph_changed,
        )?;
    }

    RECORDS.put(store, &mut wtxn, &revision.revision_id, revision)?;
    INTEGRITY.put(store, &mut wtxn, &revision.revision_id, &integrity)?;
    if update_frontier {
        FRONTIER.put(store, &mut wtxn, &revision.session_id, &frontier)?;
    }
    SESSION_INDEX.put(
        store,
        &mut wtxn,
        &(revision.session_id, revision.revision_id),
        &(),
    )?;
    if let Some(parent_id) = revision.parent_revision_id {
        PARENT_INDEX.put(store, &mut wtxn, &(parent_id, revision.revision_id), &())?;
    }
    if graph_changed {
        ppr::increment_graph_version(store, &mut wtxn)?;
    }
    wtxn.commit()?;
    Ok(CodeRevisionWriteOutcome::Finalized)
}

pub(super) fn get_code_revision_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Option<CodeRevision>> {
    let Some(revision) = read_code_revision_record_in_txn(store, rtxn, revision_id)? else {
        return Ok(None);
    };
    verify_code_revision_integrity_in_txn(store, rtxn, &revision)?;
    Ok(Some(revision))
}

pub(super) fn read_code_revision_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Option<CodeRevision>> {
    RECORDS.get(store, rtxn, revision_id)
}

fn get_code_revision_fork_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    fork_session_id: &EntityId,
) -> Result<Option<CodeRevisionFork>> {
    FORKS.get(store, rtxn, fork_session_id)
}

/// Collects the revisions indexed under `prefix_id` in `table` (`SESSION_INDEX` keyed by session,
/// or `PARENT_INDEX` keyed by parent revision), verifying each one's integrity fold as it loads.
pub(super) fn collect_code_revisions_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    table: SideTable<(EntityId, EntityId), (), Raw>,
    prefix_id: &EntityId,
) -> Result<Vec<CodeRevision>> {
    let mut revisions = Vec::new();
    for (_, revision_id) in table.scan_keys(store, rtxn, prefix_id.as_bytes())? {
        if let Some(revision) = get_code_revision_in_txn(store, rtxn, &revision_id)? {
            revisions.push(revision);
        }
    }
    sort_code_revisions_topologically(revisions)
}

/// Like [`collect_code_revisions_by_index_prefix`] but over `SESSION_INDEX` only, reading the
/// finalized record without re-verifying its integrity fold.
pub(super) fn collect_code_revision_records_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_id: &EntityId,
) -> Result<Vec<CodeRevision>> {
    let mut revisions = Vec::new();
    for (_, revision_id) in SESSION_INDEX.scan_keys(store, rtxn, session_id.as_bytes())? {
        if let Some(revision) = read_code_revision_record_in_txn(store, rtxn, &revision_id)? {
            revisions.push(revision);
        }
    }
    sort_code_revisions_topologically(revisions)
}

fn sort_code_revisions_topologically(
    mut revisions: Vec<CodeRevision>,
) -> Result<Vec<CodeRevision>> {
    revisions.sort_by_key(|revision| (revision.finalized_at, revision.revision_id));
    let mut index_by_id = HashMap::with_capacity(revisions.len());
    for (index, revision) in revisions.iter().enumerate() {
        if index_by_id.insert(revision.revision_id, index).is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "duplicate code revision id in trace",
            )));
        }
    }

    let mut indegree = vec![0usize; revisions.len()];
    let mut children = vec![Vec::new(); revisions.len()];
    for (index, revision) in revisions.iter().enumerate() {
        if let Some(parent_id) = revision.parent_revision_id
            && let Some(parent_index) = index_by_id.get(&parent_id).copied()
        {
            indegree[index] += 1;
            children[parent_index].push(index);
        }
    }

    let mut ready = VecDeque::new();
    for (index, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            ready.push_back(index);
        }
    }

    let mut ordered = Vec::with_capacity(revisions.len());
    while let Some(index) = ready.pop_front() {
        ordered.push(revisions[index].clone());
        for child_index in &children[index] {
            indegree[*child_index] -= 1;
            if indegree[*child_index] == 0 {
                ready.push_back(*child_index);
            }
        }
    }

    if ordered.len() != revisions.len() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision parent chain contains a cycle",
        )));
    }
    Ok(ordered)
}

fn delete_code_revision_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    match RECORDS.get(store, wtxn, revision_id) {
        Ok(None) => Ok(()),
        Ok(Some(revision)) => {
            RECORDS.delete(store, wtxn, revision_id)?;
            INTEGRITY.delete(store, wtxn, revision_id)?;
            SESSION_INDEX.delete(store, wtxn, &(revision.session_id, *revision_id))?;
            if let Some(parent_id) = revision.parent_revision_id {
                PARENT_INDEX.delete(store, wtxn, &(parent_id, *revision_id))?;
            }
            delete_code_revision_frontier_for_revision_in_txn(store, wtxn, revision_id)?;
            Ok(())
        }
        Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(_))) => {
            RECORDS.delete(store, wtxn, revision_id)?;
            INTEGRITY.delete(store, wtxn, revision_id)?;
            delete_code_revision_frontier_for_revision_in_txn(store, wtxn, revision_id)?;
            delete_index_rows_for_trailing_id(SESSION_INDEX, store, wtxn, revision_id)?;
            delete_index_rows_for_trailing_id(PARENT_INDEX, store, wtxn, revision_id)?;
            Ok(())
        }
        Err(other) => Err(other),
    }
}

fn delete_code_revision_fork_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    fork_session_id: &EntityId,
) -> Result<()> {
    match FORKS.get(store, wtxn, fork_session_id) {
        Ok(None) => Ok(()),
        Ok(Some(fork)) => {
            FORKS.delete(store, wtxn, fork_session_id)?;
            FORK_PARENT_INDEX.delete(store, wtxn, &(fork.parent_session_id, *fork_session_id))?;
            Ok(())
        }
        Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(_))) => {
            FORKS.delete(store, wtxn, fork_session_id)?;
            delete_index_rows_for_trailing_id(FORK_PARENT_INDEX, store, wtxn, fork_session_id)?;
            Ok(())
        }
        Err(other) => Err(other),
    }
}

/// Deletes every row of `table`, across every leading id it is indexed under, whose TRAILING id
/// half matches `id`. Used only when a record/fork row failed to decode, so the leading id (the
/// session/parent it was indexed under) is unknown and the whole table must be swept by suffix —
/// exactly the raw byte-suffix sweep this replaces (`key.ends_with(id.as_bytes())`).
fn delete_index_rows_for_trailing_id(
    table: SideTable<(EntityId, EntityId), (), Raw>,
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let matches: Vec<(EntityId, EntityId)> = table
        .scan_keys(store, wtxn, &[])?
        .into_iter()
        .filter(|(_, trailing)| trailing == id)
        .collect();
    for key in &matches {
        table.delete(store, wtxn, key)?;
    }
    Ok(())
}
