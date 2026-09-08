//! Vault CRUD for code revisions and forks, plus record/index reads, writes and deletes.

use std::collections::{HashMap, VecDeque};

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SESSION};
use crate::store::Store;

use super::codec::{
    decode_code_revision, decode_code_revision_fork, encode_code_revision,
    encode_code_revision_fork, validate_code_revision_fork_shape, validate_code_revision_shape,
};
use super::frontier::{
    delete_code_revision_frontier_for_revision_in_txn, encode_code_revision_frontier_record,
    get_code_revision_frontier_in_txn, validate_code_revision_frontier_update,
    verify_code_revision_frontier_in_txn, verify_code_revision_session_trace_in_txn,
};
use super::graph::{
    put_lifecycle_edge, require_code_artifact_body, require_code_revision_ancestor,
    require_entity_type, require_known_code_revision, require_revision_session,
    validate_child_of_insert,
};
use super::integrity::{
    backfill_code_revision_integrity_for_revision_in_txn,
    backfill_code_revision_integrity_for_session_in_txn, build_code_revision_integrity_record,
    encode_code_revision_integrity_record, verify_code_revision_integrity_in_txn,
};
use super::keys::{
    CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX, CODE_REVISION_PARENT_INDEX_KEY_PREFIX,
    CODE_REVISION_SESSION_INDEX_KEY_PREFIX, code_revision_fork_key,
    code_revision_fork_parent_index_key, code_revision_fork_parent_index_prefix,
    code_revision_frontier_key, code_revision_integrity_key, code_revision_parent_index_key,
    code_revision_parent_index_prefix, code_revision_record_key, code_revision_session_index_key,
    code_revision_session_index_prefix, id_from_index_key,
};
use super::types::{CodeRevision, CodeRevisionFork, CodeRevisionFrontierRecord, CodeRevisionKind};

impl Vault {
    pub fn commit_code_revision(&self, revision: &CodeRevision) -> Result<()> {
        if revision.kind != CodeRevisionKind::Commit {
            return Err(Error::InvalidCodeArtifactBody(
                "commit_code_revision requires kind commit",
            ));
        }
        write_code_revision(&self.store, revision)
    }

    pub fn revert_code_revision(&self, revision: &CodeRevision) -> Result<()> {
        if revision.kind != CodeRevisionKind::Revert {
            return Err(Error::InvalidCodeArtifactBody(
                "revert_code_revision requires kind revert",
            ));
        }
        write_code_revision(&self.store, revision)
    }

    pub fn branch_code_revision(&self, fork: &CodeRevisionFork) -> Result<()> {
        validate_code_revision_fork_shape(fork)?;
        let encoded = encode_code_revision_fork(fork)?;
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
        let key = code_revision_fork_key(&fork.fork_session_id);
        if self.store.vault_meta.get(&wtxn, &key)?.is_some() {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision fork already recorded for session",
            ));
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
        self.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &code_revision_fork_parent_index_key(&fork.parent_session_id, &fork.fork_session_id),
            &[],
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
        let prefix = code_revision_session_index_prefix(session_id);
        let revisions = collect_code_revisions_by_index_prefix(&self.store, &rtxn, &prefix)?;
        if revisions.is_empty() {
            if get_code_revision_frontier_in_txn(&self.store, &rtxn, session_id)?.is_some() {
                return Err(Error::InvalidCodeArtifactBody(
                    "code revision frontier exists without session index rows",
                ));
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
        let prefix = code_revision_parent_index_prefix(parent_revision_id);
        collect_code_revisions_by_index_prefix(&self.store, &rtxn, &prefix)
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
        let prefix = code_revision_fork_parent_index_prefix(parent_session_id);
        let mut forks = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = entry?;
            let fork_session_id =
                id_from_index_key(&key, prefix.len(), "code revision fork parent index key")?;
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
    store
        .vault_meta
        .delete(wtxn, &code_revision_frontier_key(id))?;
    delete_index_rows_with_prefix(store, wtxn, &code_revision_session_index_prefix(id))?;
    delete_index_rows_with_prefix(store, wtxn, &code_revision_parent_index_prefix(id))?;
    delete_index_rows_with_prefix(store, wtxn, &code_revision_fork_parent_index_prefix(id))?;
    Ok(())
}

pub(crate) fn has_finalized_code_revision_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &code_revision_record_key(revision_id))?
        .is_some())
}

fn write_code_revision(store: &Store, revision: &CodeRevision) -> Result<()> {
    validate_code_revision_shape(revision)?;
    let encoded = encode_code_revision(revision)?;
    let mut wtxn = store.env.write_txn()?;
    backfill_code_revision_integrity_for_session_in_txn(store, &mut wtxn, &revision.session_id)?;
    let artifact_body = require_code_artifact_body(store, &wtxn, &revision.revision_id)?;
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
    let key = code_revision_record_key(&revision.revision_id);
    if store.vault_meta.get(&wtxn, &key)?.is_some() {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision is already finalized",
        ));
    }
    let integrity = build_code_revision_integrity_record(store, &wtxn, revision, &artifact_body)?;
    let update_frontier =
        validate_code_revision_frontier_update(store, &wtxn, revision, &integrity)?;
    let encoded_integrity = encode_code_revision_integrity_record(&integrity)?;
    let frontier = CodeRevisionFrontierRecord {
        session_id: revision.session_id,
        revision_id: revision.revision_id,
        revision_fold: integrity.revision_fold,
        finalized_at: revision.finalized_at,
    };
    let encoded_frontier = encode_code_revision_frontier_record(&frontier)?;

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

    store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    store.vault_meta.put(
        &mut wtxn,
        &code_revision_integrity_key(&revision.revision_id),
        &encoded_integrity,
    )?;
    if update_frontier {
        store.vault_meta.put(
            &mut wtxn,
            &code_revision_frontier_key(&revision.session_id),
            &encoded_frontier,
        )?;
    }
    store.vault_meta.put(
        &mut wtxn,
        &code_revision_session_index_key(&revision.session_id, &revision.revision_id),
        &[],
    )?;
    if let Some(parent_id) = revision.parent_revision_id {
        store.vault_meta.put(
            &mut wtxn,
            &code_revision_parent_index_key(&parent_id, &revision.revision_id),
            &[],
        )?;
    }
    if graph_changed {
        ppr::increment_graph_version(store, &mut wtxn)?;
    }
    wtxn.commit()?;
    Ok(())
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
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &code_revision_record_key(revision_id))?
    else {
        return Ok(None);
    };
    decode_code_revision(&raw).map(Some)
}

fn get_code_revision_fork_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    fork_session_id: &EntityId,
) -> Result<Option<CodeRevisionFork>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &code_revision_fork_key(fork_session_id))?
    else {
        return Ok(None);
    };
    decode_code_revision_fork(&raw).map(Some)
}

fn collect_code_revisions_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<CodeRevision>> {
    let mut revisions = Vec::new();
    for entry in store.vault_meta.prefix_iter(rtxn, prefix)? {
        let (key, _) = entry?;
        let revision_id = id_from_index_key(&key, prefix.len(), "code revision index key")?;
        if let Some(revision) = get_code_revision_in_txn(store, rtxn, &revision_id)? {
            revisions.push(revision);
        }
    }
    sort_code_revisions_topologically(revisions)
}

pub(super) fn collect_code_revision_records_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<CodeRevision>> {
    let mut revisions = Vec::new();
    for entry in store.vault_meta.prefix_iter(rtxn, prefix)? {
        let (key, _) = entry?;
        let revision_id = id_from_index_key(&key, prefix.len(), "code revision index key")?;
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
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision id in trace",
            ));
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
        return Err(Error::InvalidCodeArtifactBody(
            "code revision parent chain contains a cycle",
        ));
    }
    Ok(ordered)
}

fn delete_code_revision_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    let key = code_revision_record_key(revision_id);
    let Some(raw) = store
        .vault_meta
        .get(wtxn, &key)?
        .map(|value| value.to_vec())
    else {
        return Ok(());
    };
    match decode_code_revision(&raw) {
        Ok(revision) => {
            store.vault_meta.delete(wtxn, &key)?;
            store
                .vault_meta
                .delete(wtxn, &code_revision_integrity_key(revision_id))?;
            store.vault_meta.delete(
                wtxn,
                &code_revision_session_index_key(&revision.session_id, revision_id),
            )?;
            if let Some(parent_id) = revision.parent_revision_id {
                store.vault_meta.delete(
                    wtxn,
                    &code_revision_parent_index_key(&parent_id, revision_id),
                )?;
            }
            delete_code_revision_frontier_for_revision_in_txn(store, wtxn, revision_id)?;
        }
        Err(_) => {
            store.vault_meta.delete(wtxn, &key)?;
            store
                .vault_meta
                .delete(wtxn, &code_revision_integrity_key(revision_id))?;
            delete_code_revision_frontier_for_revision_in_txn(store, wtxn, revision_id)?;
            delete_index_rows_for_id(
                store,
                wtxn,
                CODE_REVISION_SESSION_INDEX_KEY_PREFIX,
                revision_id,
            )?;
            delete_index_rows_for_id(
                store,
                wtxn,
                CODE_REVISION_PARENT_INDEX_KEY_PREFIX,
                revision_id,
            )?;
        }
    }
    Ok(())
}

fn delete_code_revision_fork_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    fork_session_id: &EntityId,
) -> Result<()> {
    let key = code_revision_fork_key(fork_session_id);
    let Some(raw) = store
        .vault_meta
        .get(wtxn, &key)?
        .map(|value| value.to_vec())
    else {
        return Ok(());
    };
    match decode_code_revision_fork(&raw) {
        Ok(fork) => {
            store.vault_meta.delete(wtxn, &key)?;
            store.vault_meta.delete(
                wtxn,
                &code_revision_fork_parent_index_key(&fork.parent_session_id, fork_session_id),
            )?;
        }
        Err(_) => {
            store.vault_meta.delete(wtxn, &key)?;
            delete_index_rows_for_id(
                store,
                wtxn,
                CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX,
                fork_session_id,
            )?;
        }
    }
    Ok(())
}

fn delete_index_rows_for_id(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    prefix: &[u8],
    id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(wtxn, prefix)? {
        let (key, _) = entry?;
        if key.ends_with(id.as_bytes()) {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        store.vault_meta.delete(wtxn, &key)?;
    }
    Ok(())
}

fn delete_index_rows_with_prefix(store: &Store, wtxn: &mut RwTxn<'_>, prefix: &[u8]) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(wtxn, prefix)? {
        let (key, _) = entry?;
        keys.push(key.to_vec());
    }
    for key in keys {
        store.vault_meta.delete(wtxn, &key)?;
    }
    Ok(())
}
