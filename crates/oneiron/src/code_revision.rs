use std::collections::{HashMap, HashSet, VecDeque};

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::decode_code_artifact_body;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::ppr;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_SESSION};
use crate::store::Store;
use crate::types::{EdgeKind, encode_edge_value, parse_strict_edge_record};

pub(crate) const CODE_REVISION_CLAIM_PREDICATE: &str = "code.revision";
pub const CODE_REVISION_RECORD_KEYS: [&str; 7] = [
    "revision_id",
    "kind",
    "session_id",
    "parent_revision_id",
    "reverted_to_revision_id",
    "provenance_claim_id",
    "finalized_at",
];
pub const CODE_REVISION_FORK_KEYS: [&str; 4] = [
    "fork_session_id",
    "parent_session_id",
    "base_revision_id",
    "forked_at",
];
const CODE_REVISION_INTEGRITY_KEYS: [&str; 10] = [
    "revision_id",
    "session_id",
    "parent_revision_id",
    "reverted_to_revision_id",
    "provenance_claim_id",
    "artifact_hash",
    "parent_fold",
    "reverted_to_fold",
    "revision_fold",
    "finalized_at",
];
const CODE_REVISION_FRONTIER_KEYS: [&str; 4] =
    ["session_id", "revision_id", "revision_fold", "finalized_at"];

const KEY_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[0];
const KEY_KIND: &str = CODE_REVISION_RECORD_KEYS[1];
const KEY_SESSION_ID: &str = CODE_REVISION_RECORD_KEYS[2];
const KEY_PARENT_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[3];
const KEY_REVERTED_TO_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[4];
const KEY_PROVENANCE_CLAIM_ID: &str = CODE_REVISION_RECORD_KEYS[5];
const KEY_FINALIZED_AT: &str = CODE_REVISION_RECORD_KEYS[6];

const KEY_FORK_SESSION_ID: &str = CODE_REVISION_FORK_KEYS[0];
const KEY_PARENT_SESSION_ID: &str = CODE_REVISION_FORK_KEYS[1];
const KEY_BASE_REVISION_ID: &str = CODE_REVISION_FORK_KEYS[2];
const KEY_FORKED_AT: &str = CODE_REVISION_FORK_KEYS[3];
const KEY_ARTIFACT_HASH: &str = CODE_REVISION_INTEGRITY_KEYS[5];
const KEY_PARENT_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[6];
const KEY_REVERTED_TO_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[7];
const KEY_REVISION_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[8];

const CODE_REVISION_RECORD_KEY_PREFIX: &[u8] = b"code_revision:record:v1:";
const CODE_REVISION_SESSION_INDEX_KEY_PREFIX: &[u8] = b"code_revision:session:v1:";
const CODE_REVISION_PARENT_INDEX_KEY_PREFIX: &[u8] = b"code_revision:parent:v1:";
const CODE_REVISION_FORK_KEY_PREFIX: &[u8] = b"code_revision:fork:v1:";
const CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX: &[u8] = b"code_revision:fork_parent:v1:";
const CODE_REVISION_INTEGRITY_KEY_PREFIX: &[u8] = b"code_revision:integrity:v1:";
const CODE_REVISION_FRONTIER_KEY_PREFIX: &[u8] = b"code_revision:frontier:v1:";
const CODE_REVISION_HASH_LEN: usize = 32;
const CODE_REVISION_FOLD_DOMAIN: &[u8] = b"oneiron:code-revision-fold:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeRevisionKind {
    Commit,
    Revert,
}

impl CodeRevisionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Revert => "revert",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "commit" => Ok(Self::Commit),
            "revert" => Ok(Self::Revert),
            _ => Err(Error::InvalidCodeArtifactBody(
                "code revision kind must be commit or revert",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRevision {
    pub revision_id: EntityId,
    pub kind: CodeRevisionKind,
    pub session_id: EntityId,
    pub parent_revision_id: Option<EntityId>,
    pub reverted_to_revision_id: Option<EntityId>,
    pub provenance_claim_id: Option<EntityId>,
    pub finalized_at: u64,
}

impl CodeRevision {
    #[must_use]
    pub fn commit(revision_id: EntityId, session_id: EntityId, finalized_at: u64) -> Self {
        Self {
            revision_id,
            kind: CodeRevisionKind::Commit,
            session_id,
            parent_revision_id: None,
            reverted_to_revision_id: None,
            provenance_claim_id: None,
            finalized_at,
        }
    }

    #[must_use]
    pub fn commit_child(
        revision_id: EntityId,
        session_id: EntityId,
        parent_revision_id: EntityId,
        finalized_at: u64,
    ) -> Self {
        let mut revision = Self::commit(revision_id, session_id, finalized_at);
        revision.parent_revision_id = Some(parent_revision_id);
        revision
    }

    #[must_use]
    pub fn revert(
        revision_id: EntityId,
        session_id: EntityId,
        parent_revision_id: EntityId,
        reverted_to_revision_id: EntityId,
        finalized_at: u64,
    ) -> Self {
        Self {
            revision_id,
            kind: CodeRevisionKind::Revert,
            session_id,
            parent_revision_id: Some(parent_revision_id),
            reverted_to_revision_id: Some(reverted_to_revision_id),
            provenance_claim_id: None,
            finalized_at,
        }
    }

    #[must_use]
    pub fn with_provenance_claim_id(mut self, provenance_claim_id: EntityId) -> Self {
        self.provenance_claim_id = Some(provenance_claim_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRevisionFork {
    pub fork_session_id: EntityId,
    pub parent_session_id: EntityId,
    pub base_revision_id: EntityId,
    pub forked_at: u64,
}

impl CodeRevisionFork {
    #[must_use]
    pub fn new(
        fork_session_id: EntityId,
        parent_session_id: EntityId,
        base_revision_id: EntityId,
        forked_at: u64,
    ) -> Self {
        Self {
            fork_session_id,
            parent_session_id,
            base_revision_id,
            forked_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeRevisionIntegrityRecord {
    revision_id: EntityId,
    session_id: EntityId,
    parent_revision_id: Option<EntityId>,
    reverted_to_revision_id: Option<EntityId>,
    provenance_claim_id: Option<EntityId>,
    artifact_hash: [u8; CODE_REVISION_HASH_LEN],
    parent_fold: Option<[u8; CODE_REVISION_HASH_LEN]>,
    reverted_to_fold: Option<[u8; CODE_REVISION_HASH_LEN]>,
    revision_fold: [u8; CODE_REVISION_HASH_LEN],
    finalized_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeRevisionFrontierRecord {
    session_id: EntityId,
    revision_id: EntityId,
    revision_fold: [u8; CODE_REVISION_HASH_LEN],
    finalized_at: u64,
}

pub fn encode_code_revision(revision: &CodeRevision) -> Result<Vec<u8>> {
    validate_code_revision_shape(revision)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_REVISION_ID),
            Value::Binary(revision.revision_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_KIND), Value::from(revision.kind.as_str())),
        (
            Value::from(KEY_SESSION_ID),
            Value::Binary(revision.session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PARENT_REVISION_ID),
            optional_entity_value(revision.parent_revision_id),
        ),
        (
            Value::from(KEY_REVERTED_TO_REVISION_ID),
            optional_entity_value(revision.reverted_to_revision_id),
        ),
        (
            Value::from(KEY_PROVENANCE_CLAIM_ID),
            optional_entity_value(revision.provenance_claim_id),
        ),
        (
            Value::from(KEY_FINALIZED_AT),
            Value::Integer(revision.finalized_at.into()),
        ),
    ]);
    encode_value(&value, "code revision MessagePack encode failed")
}

pub fn decode_code_revision(bytes: &[u8]) -> Result<CodeRevision> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidCodeArtifactBody("code revision is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after code revision map",
        ));
    }
    decode_code_revision_value(&value)
}

pub fn encode_code_revision_fork(fork: &CodeRevisionFork) -> Result<Vec<u8>> {
    validate_code_revision_fork_shape(fork)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_FORK_SESSION_ID),
            Value::Binary(fork.fork_session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PARENT_SESSION_ID),
            Value::Binary(fork.parent_session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_BASE_REVISION_ID),
            Value::Binary(fork.base_revision_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_FORKED_AT),
            Value::Integer(fork.forked_at.into()),
        ),
    ]);
    encode_value(&value, "code revision fork MessagePack encode failed")
}

pub fn decode_code_revision_fork(bytes: &[u8]) -> Result<CodeRevisionFork> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidCodeArtifactBody("code revision fork is not valid MessagePack")
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after code revision fork map",
        ));
    }
    decode_code_revision_fork_value(&value)
}

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
                id_from_index_key(key, prefix.len(), "code revision fork parent index key")?;
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

fn encode_code_revision_integrity_record(record: &CodeRevisionIntegrityRecord) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_REVISION_ID),
            Value::Binary(record.revision_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_SESSION_ID),
            Value::Binary(record.session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PARENT_REVISION_ID),
            optional_entity_value(record.parent_revision_id),
        ),
        (
            Value::from(KEY_REVERTED_TO_REVISION_ID),
            optional_entity_value(record.reverted_to_revision_id),
        ),
        (
            Value::from(KEY_PROVENANCE_CLAIM_ID),
            optional_entity_value(record.provenance_claim_id),
        ),
        (
            Value::from(KEY_ARTIFACT_HASH),
            Value::Binary(record.artifact_hash.to_vec()),
        ),
        (
            Value::from(KEY_PARENT_FOLD),
            optional_hash_value(record.parent_fold),
        ),
        (
            Value::from(KEY_REVERTED_TO_FOLD),
            optional_hash_value(record.reverted_to_fold),
        ),
        (
            Value::from(KEY_REVISION_FOLD),
            Value::Binary(record.revision_fold.to_vec()),
        ),
        (
            Value::from(KEY_FINALIZED_AT),
            Value::Integer(record.finalized_at.into()),
        ),
    ]);
    encode_value(&value, "code revision integrity MessagePack encode failed")
}

fn decode_code_revision_integrity_record(bytes: &[u8]) -> Result<CodeRevisionIntegrityRecord> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidCodeArtifactBody("code revision integrity is not valid MessagePack")
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after code revision integrity map",
        ));
    }
    decode_code_revision_integrity_value(&value)
}

fn encode_code_revision_frontier_record(record: &CodeRevisionFrontierRecord) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SESSION_ID),
            Value::Binary(record.session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_REVISION_ID),
            Value::Binary(record.revision_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_REVISION_FOLD),
            Value::Binary(record.revision_fold.to_vec()),
        ),
        (
            Value::from(KEY_FINALIZED_AT),
            Value::Integer(record.finalized_at.into()),
        ),
    ]);
    encode_value(&value, "code revision frontier MessagePack encode failed")
}

fn decode_code_revision_frontier_record(bytes: &[u8]) -> Result<CodeRevisionFrontierRecord> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidCodeArtifactBody("code revision frontier is not valid MessagePack")
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after code revision frontier map",
        ));
    }
    decode_code_revision_frontier_value(&value)
}

fn decode_code_revision_value(value: &Value) -> Result<CodeRevision> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision must be a MessagePack map",
        ));
    };
    let mut revision_id = None;
    let mut kind = None;
    let mut session_id = None;
    let mut parent_revision_id = None;
    let mut reverted_to_revision_id = None;
    let mut provenance_claim_id = None;
    let mut finalized_at = None;
    let mut seen = [false; CODE_REVISION_RECORD_KEYS.len()];

    for (key, value) in entries {
        let key = key.as_str().ok_or(Error::InvalidCodeArtifactBody(
            "code revision keys must be strings",
        ))?;
        let Some(index) = CODE_REVISION_RECORD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision key is not in the pinned CODE_REVISION_RECORD_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision key",
            ));
        }
        seen[index] = true;

        match CODE_REVISION_RECORD_KEYS[index] {
            KEY_REVISION_ID => revision_id = Some(entity_value(value, "revision_id")?),
            KEY_KIND => {
                let text = value.as_str().ok_or(Error::InvalidCodeArtifactBody(
                    "code revision kind must be a UTF-8 string",
                ))?;
                kind = Some(CodeRevisionKind::parse(text)?);
            }
            KEY_SESSION_ID => session_id = Some(entity_value(value, "session_id")?),
            KEY_PARENT_REVISION_ID => {
                parent_revision_id = Some(optional_entity_from_value(value, "parent_revision_id")?);
            }
            KEY_REVERTED_TO_REVISION_ID => {
                reverted_to_revision_id = Some(optional_entity_from_value(
                    value,
                    "reverted_to_revision_id",
                )?);
            }
            KEY_PROVENANCE_CLAIM_ID => {
                provenance_claim_id =
                    Some(optional_entity_from_value(value, "provenance_claim_id")?);
            }
            KEY_FINALIZED_AT => finalized_at = Some(u64_value(value, "finalized_at")?),
            _ => unreachable!("index resolved from CODE_REVISION_RECORD_KEYS"),
        }
    }

    let revision = CodeRevision {
        revision_id: revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key revision_id",
        ))?,
        kind: kind.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key kind",
        ))?,
        session_id: session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key session_id",
        ))?,
        parent_revision_id: parent_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key parent_revision_id",
        ))?,
        reverted_to_revision_id: reverted_to_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key reverted_to_revision_id",
        ))?,
        provenance_claim_id: provenance_claim_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key provenance_claim_id",
        ))?,
        finalized_at: finalized_at.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key finalized_at",
        ))?,
    };
    validate_code_revision_shape(&revision)?;
    Ok(revision)
}

fn decode_code_revision_fork_value(value: &Value) -> Result<CodeRevisionFork> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision fork must be a MessagePack map",
        ));
    };
    let mut fork_session_id = None;
    let mut parent_session_id = None;
    let mut base_revision_id = None;
    let mut forked_at = None;
    let mut seen = [false; CODE_REVISION_FORK_KEYS.len()];

    for (key, value) in entries {
        let key = key.as_str().ok_or(Error::InvalidCodeArtifactBody(
            "code revision fork keys must be strings",
        ))?;
        let Some(index) = CODE_REVISION_FORK_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision fork key is not in the pinned CODE_REVISION_FORK_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision fork key",
            ));
        }
        seen[index] = true;

        match CODE_REVISION_FORK_KEYS[index] {
            KEY_FORK_SESSION_ID => {
                fork_session_id = Some(entity_value(value, "fork_session_id")?);
            }
            KEY_PARENT_SESSION_ID => {
                parent_session_id = Some(entity_value(value, "parent_session_id")?);
            }
            KEY_BASE_REVISION_ID => {
                base_revision_id = Some(entity_value(value, "base_revision_id")?);
            }
            KEY_FORKED_AT => forked_at = Some(u64_value(value, "forked_at")?),
            _ => unreachable!("index resolved from CODE_REVISION_FORK_KEYS"),
        }
    }

    let fork = CodeRevisionFork {
        fork_session_id: fork_session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key fork_session_id",
        ))?,
        parent_session_id: parent_session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key parent_session_id",
        ))?,
        base_revision_id: base_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key base_revision_id",
        ))?,
        forked_at: forked_at.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key forked_at",
        ))?,
    };
    validate_code_revision_fork_shape(&fork)?;
    Ok(fork)
}

fn decode_code_revision_integrity_value(value: &Value) -> Result<CodeRevisionIntegrityRecord> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision integrity must be a MessagePack map",
        ));
    };
    let mut revision_id = None;
    let mut session_id = None;
    let mut parent_revision_id = None;
    let mut reverted_to_revision_id = None;
    let mut provenance_claim_id = None;
    let mut artifact_hash = None;
    let mut parent_fold = None;
    let mut reverted_to_fold = None;
    let mut revision_fold = None;
    let mut finalized_at = None;
    let mut seen = [false; CODE_REVISION_INTEGRITY_KEYS.len()];

    for (key, value) in entries {
        let key = key.as_str().ok_or(Error::InvalidCodeArtifactBody(
            "code revision integrity keys must be strings",
        ))?;
        let Some(index) = CODE_REVISION_INTEGRITY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision integrity key is not in the pinned CODE_REVISION_INTEGRITY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision integrity key",
            ));
        }
        seen[index] = true;

        match CODE_REVISION_INTEGRITY_KEYS[index] {
            KEY_REVISION_ID => revision_id = Some(entity_value(value, "revision_id")?),
            KEY_SESSION_ID => session_id = Some(entity_value(value, "session_id")?),
            KEY_PARENT_REVISION_ID => {
                parent_revision_id = Some(optional_entity_from_value(value, "parent_revision_id")?);
            }
            KEY_REVERTED_TO_REVISION_ID => {
                reverted_to_revision_id = Some(optional_entity_from_value(
                    value,
                    "reverted_to_revision_id",
                )?);
            }
            KEY_PROVENANCE_CLAIM_ID => {
                provenance_claim_id =
                    Some(optional_entity_from_value(value, "provenance_claim_id")?);
            }
            KEY_ARTIFACT_HASH => artifact_hash = Some(hash_from_value(value, "artifact_hash")?),
            KEY_PARENT_FOLD => {
                parent_fold = Some(optional_hash_from_value(value, "parent_fold")?);
            }
            KEY_REVERTED_TO_FOLD => {
                reverted_to_fold = Some(optional_hash_from_value(value, "reverted_to_fold")?);
            }
            KEY_REVISION_FOLD => revision_fold = Some(hash_from_value(value, "revision_fold")?),
            KEY_FINALIZED_AT => finalized_at = Some(u64_value(value, "finalized_at")?),
            _ => unreachable!("index resolved from CODE_REVISION_INTEGRITY_KEYS"),
        }
    }

    Ok(CodeRevisionIntegrityRecord {
        revision_id: revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key revision_id",
        ))?,
        session_id: session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key session_id",
        ))?,
        parent_revision_id: parent_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key parent_revision_id",
        ))?,
        reverted_to_revision_id: reverted_to_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key reverted_to_revision_id",
        ))?,
        provenance_claim_id: provenance_claim_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key provenance_claim_id",
        ))?,
        artifact_hash: artifact_hash.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key artifact_hash",
        ))?,
        parent_fold: parent_fold.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key parent_fold",
        ))?,
        reverted_to_fold: reverted_to_fold.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key reverted_to_fold",
        ))?,
        revision_fold: revision_fold.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key revision_fold",
        ))?,
        finalized_at: finalized_at.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision integrity key finalized_at",
        ))?,
    })
}

fn decode_code_revision_frontier_value(value: &Value) -> Result<CodeRevisionFrontierRecord> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision frontier must be a MessagePack map",
        ));
    };
    let mut session_id = None;
    let mut revision_id = None;
    let mut revision_fold = None;
    let mut finalized_at = None;
    let mut seen = [false; CODE_REVISION_FRONTIER_KEYS.len()];

    for (key, value) in entries {
        let key = key.as_str().ok_or(Error::InvalidCodeArtifactBody(
            "code revision frontier keys must be strings",
        ))?;
        let Some(index) = CODE_REVISION_FRONTIER_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision frontier key is not in the pinned CODE_REVISION_FRONTIER_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision frontier key",
            ));
        }
        seen[index] = true;

        match CODE_REVISION_FRONTIER_KEYS[index] {
            KEY_SESSION_ID => session_id = Some(entity_value(value, "session_id")?),
            KEY_REVISION_ID => revision_id = Some(entity_value(value, "revision_id")?),
            KEY_REVISION_FOLD => revision_fold = Some(hash_from_value(value, "revision_fold")?),
            KEY_FINALIZED_AT => finalized_at = Some(u64_value(value, "finalized_at")?),
            _ => unreachable!("index resolved from CODE_REVISION_FRONTIER_KEYS"),
        }
    }

    Ok(CodeRevisionFrontierRecord {
        session_id: session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision frontier key session_id",
        ))?,
        revision_id: revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision frontier key revision_id",
        ))?,
        revision_fold: revision_fold.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision frontier key revision_fold",
        ))?,
        finalized_at: finalized_at.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision frontier key finalized_at",
        ))?,
    })
}

fn validate_code_revision_shape(revision: &CodeRevision) -> Result<()> {
    if revision.parent_revision_id == Some(revision.revision_id)
        || revision.reverted_to_revision_id == Some(revision.revision_id)
    {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision cannot point at itself",
        ));
    }
    match revision.kind {
        CodeRevisionKind::Commit => {
            if revision.reverted_to_revision_id.is_some() {
                return Err(Error::InvalidCodeArtifactBody(
                    "commit code revision must not carry reverted_to_revision_id",
                ));
            }
        }
        CodeRevisionKind::Revert => {
            if revision.parent_revision_id.is_none() || revision.reverted_to_revision_id.is_none() {
                return Err(Error::InvalidCodeArtifactBody(
                    "revert code revision requires parent and reverted_to revision ids",
                ));
            }
            if revision.parent_revision_id == revision.reverted_to_revision_id {
                return Err(Error::InvalidCodeArtifactBody(
                    "revert parent and restored revision must be distinct",
                ));
            }
        }
    }
    Ok(())
}

fn validate_code_revision_fork_shape(fork: &CodeRevisionFork) -> Result<()> {
    if fork.fork_session_id == fork.parent_session_id {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision fork session cannot be its own parent",
        ));
    }
    Ok(())
}

fn require_known_code_revision(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<CodeRevision> {
    require_entity_type(
        store,
        rtxn,
        revision_id,
        ENTITY_TYPE_CODE_ARTIFACT,
        "code revision id must be a CODE_ARTIFACT entity",
    )?;
    get_code_revision_in_txn(store, rtxn, revision_id)?.ok_or(Error::InvalidCodeArtifactBody(
        "code revision must be finalized before it can be referenced",
    ))
}

fn require_code_artifact_body(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Vec<u8>> {
    code_artifact_body_bytes(store, rtxn, revision_id)
}

fn code_artifact_body_bytes(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Vec<u8>> {
    let Some(raw) = store.entities.get(rtxn, revision_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(Error::InvalidCodeArtifactBody(
            "revision_id must be a CODE_ARTIFACT entity",
        ));
    }
    decode_code_artifact_body(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?,
    )?;
    Ok(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
}

fn require_revision_session(
    revision: &CodeRevision,
    session_id: EntityId,
    context: &'static str,
) -> Result<()> {
    if revision.session_id != session_id {
        return Err(Error::InvalidCodeArtifactBody(context));
    }
    Ok(())
}

fn require_code_revision_ancestor(
    store: &Store,
    rtxn: &RoTxn<'_>,
    parent_revision_id: &EntityId,
    ancestor_revision_id: &EntityId,
) -> Result<()> {
    let mut cursor = *parent_revision_id;
    let mut visited = HashSet::new();

    for _ in 0..MAX_ANCESTOR_DEPTH {
        if cursor == *ancestor_revision_id {
            return Ok(());
        }
        if !visited.insert(cursor) {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision parent chain contains a cycle",
            ));
        }
        let revision = require_known_code_revision(store, rtxn, &cursor)?;
        let Some(parent_id) = revision.parent_revision_id else {
            break;
        };
        cursor = parent_id;
    }

    if visited.len() >= MAX_ANCESTOR_DEPTH {
        return Err(Error::IndexOverflow("code_revision_parent_chain"));
    }
    Err(Error::InvalidCodeArtifactBody(
        "reverted_to_revision_id must be an ancestor of parent_revision_id",
    ))
}

fn require_entity_type(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    expected_type: u8,
    context: &'static str,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != expected_type {
        return Err(Error::InvalidCodeArtifactBody(context));
    }
    Ok(())
}

fn get_code_revision_in_txn(
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

fn read_code_revision_record_in_txn(
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
    decode_code_revision(raw).map(Some)
}

fn backfill_code_revision_integrity_for_revision_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    let Some(revision) = read_code_revision_record_in_txn(store, wtxn, revision_id)? else {
        return Ok(());
    };
    backfill_code_revision_integrity_for_session_in_txn(store, wtxn, &revision.session_id)
}

fn backfill_code_revision_integrity_for_session_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    session_id: &EntityId,
) -> Result<()> {
    let prefix = code_revision_session_index_prefix(session_id);
    let revisions = collect_code_revision_records_by_index_prefix(store, wtxn, &prefix)?;
    let existing_frontier = get_code_revision_frontier_in_txn(store, wtxn, session_id)?;
    if revisions.is_empty() {
        if existing_frontier.is_some() {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision frontier exists without session index rows",
            ));
        }
        return Ok(());
    }

    let mut needs_backfill = existing_frontier.is_none();
    if !needs_backfill {
        for revision in &revisions {
            if load_optional_code_revision_integrity_record(store, wtxn, &revision.revision_id)?
                .is_none()
            {
                needs_backfill = true;
                break;
            }
        }
    }
    if needs_backfill {
        rebuild_code_revision_frontier_in_txn(store, wtxn, session_id)?;
    }
    Ok(())
}

fn rebuild_code_revision_frontier_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    session_id: &EntityId,
) -> Result<()> {
    let prefix = code_revision_session_index_prefix(session_id);
    let revisions = collect_code_revision_records_by_index_prefix(store, wtxn, &prefix)?;
    if revisions.is_empty() {
        store
            .vault_meta
            .delete(wtxn, &code_revision_frontier_key(session_id))?;
        return Ok(());
    }

    let mut frontier = None;
    let mut visiting = HashSet::new();
    for revision in &revisions {
        if revision.session_id != *session_id {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision session index mismatch",
            ));
        }
        let integrity = ensure_code_revision_integrity_record_in_txn(
            store,
            wtxn,
            &revision.revision_id,
            &mut visiting,
        )?;
        if code_revision_frontier_update_decision(frontier.as_ref(), revision, &integrity)? {
            frontier = Some(CodeRevisionFrontierRecord {
                session_id: revision.session_id,
                revision_id: revision.revision_id,
                revision_fold: integrity.revision_fold,
                finalized_at: revision.finalized_at,
            });
        }
    }

    let frontier = frontier.ok_or(Error::InvalidCodeArtifactBody(
        "code revision frontier record missing",
    ))?;
    let encoded = encode_code_revision_frontier_record(&frontier)?;
    store.vault_meta.put(
        wtxn,
        &code_revision_frontier_key(session_id),
        encoded.as_slice(),
    )?;
    Ok(())
}

fn ensure_code_revision_integrity_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
    visiting: &mut HashSet<EntityId>,
) -> Result<CodeRevisionIntegrityRecord> {
    let revision = read_code_revision_record_in_txn(store, wtxn, revision_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision integrity parent record missing"),
    )?;
    if !visiting.insert(*revision_id) {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision parent chain contains a cycle",
        ));
    }

    let parent_fold = revision
        .parent_revision_id
        .map(|parent_id| {
            ensure_code_revision_integrity_record_in_txn(store, wtxn, &parent_id, visiting)
                .map(|record| record.revision_fold)
        })
        .transpose()?;
    let reverted_to_fold = revision
        .reverted_to_revision_id
        .map(|reverted_to_id| {
            ensure_code_revision_integrity_record_in_txn(store, wtxn, &reverted_to_id, visiting)
                .map(|record| record.revision_fold)
        })
        .transpose()?;

    if let Some(record) =
        load_optional_code_revision_integrity_record(store, wtxn, &revision.revision_id)?
    {
        visiting.remove(revision_id);
        verify_code_revision_integrity_in_txn(store, wtxn, &revision)?;
        return Ok(record);
    }

    let artifact_body = code_artifact_body_bytes(store, wtxn, &revision.revision_id)?;
    let artifact_hash = sha256_bytes(&artifact_body);
    let revision_fold = compute_code_revision_fold(
        revision.kind,
        &artifact_hash,
        revision.provenance_claim_id,
        parent_fold,
        reverted_to_fold,
    );
    let record = CodeRevisionIntegrityRecord {
        revision_id: revision.revision_id,
        session_id: revision.session_id,
        parent_revision_id: revision.parent_revision_id,
        reverted_to_revision_id: revision.reverted_to_revision_id,
        provenance_claim_id: revision.provenance_claim_id,
        artifact_hash,
        parent_fold,
        reverted_to_fold,
        revision_fold,
        finalized_at: revision.finalized_at,
    };
    let encoded = encode_code_revision_integrity_record(&record)?;
    store.vault_meta.put(
        wtxn,
        &code_revision_integrity_key(&revision.revision_id),
        encoded.as_slice(),
    )?;
    visiting.remove(revision_id);
    Ok(record)
}

fn build_code_revision_integrity_record(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    artifact_body: &[u8],
) -> Result<CodeRevisionIntegrityRecord> {
    let artifact_hash = sha256_bytes(artifact_body);
    let parent_fold = revision
        .parent_revision_id
        .map(|parent_id| require_code_revision_fold(store, rtxn, &parent_id))
        .transpose()?;
    let reverted_to_fold = revision
        .reverted_to_revision_id
        .map(|reverted_to_id| require_code_revision_fold(store, rtxn, &reverted_to_id))
        .transpose()?;
    let revision_fold = compute_code_revision_fold(
        revision.kind,
        &artifact_hash,
        revision.provenance_claim_id,
        parent_fold,
        reverted_to_fold,
    );
    Ok(CodeRevisionIntegrityRecord {
        revision_id: revision.revision_id,
        session_id: revision.session_id,
        parent_revision_id: revision.parent_revision_id,
        reverted_to_revision_id: revision.reverted_to_revision_id,
        provenance_claim_id: revision.provenance_claim_id,
        artifact_hash,
        parent_fold,
        reverted_to_fold,
        revision_fold,
        finalized_at: revision.finalized_at,
    })
}

fn verify_code_revision_integrity_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
) -> Result<()> {
    let mut visiting = HashSet::new();
    verify_or_build_code_revision_integrity_record_in_txn(store, rtxn, revision, &mut visiting)?;
    Ok(())
}

fn verify_or_build_code_revision_integrity_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    visiting: &mut HashSet<EntityId>,
) -> Result<CodeRevisionIntegrityRecord> {
    if visiting.len() >= MAX_ANCESTOR_DEPTH {
        return Err(Error::IndexOverflow("code_revision_parent_chain"));
    }
    if !visiting.insert(revision.revision_id) {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision parent chain contains a cycle",
        ));
    }

    let result = (|| {
        let record =
            load_optional_code_revision_integrity_record(store, rtxn, &revision.revision_id)?;
        if let Some(record) = &record
            && (record.revision_id != revision.revision_id
                || record.session_id != revision.session_id
                || record.parent_revision_id != revision.parent_revision_id
                || record.reverted_to_revision_id != revision.reverted_to_revision_id
                || record.provenance_claim_id != revision.provenance_claim_id
                || record.finalized_at != revision.finalized_at
                || record.parent_fold.is_some() != revision.parent_revision_id.is_some()
                || record.reverted_to_fold.is_some() != revision.reverted_to_revision_id.is_some())
        {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision integrity record does not match revision record",
            ));
        }

        let artifact_body = code_artifact_body_bytes(store, rtxn, &revision.revision_id)?;
        let artifact_hash = sha256_bytes(&artifact_body);
        if let Some(record) = &record
            && artifact_hash != record.artifact_hash
        {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision artifact hash mismatch",
            ));
        }
        if let Some(provenance_claim_id) = revision.provenance_claim_id {
            require_entity_type(
                store,
                rtxn,
                &provenance_claim_id,
                ENTITY_TYPE_CLAIM,
                "provenance_claim_id must be a CLAIM entity",
            )?;
        }

        let parent_fold = match revision.parent_revision_id {
            Some(parent_id) => {
                let (parent_revision, parent_fold) = require_code_revision_with_fold_with_visited(
                    store, rtxn, &parent_id, visiting,
                )?;
                require_revision_session(
                    &parent_revision,
                    revision.session_id,
                    "parent_revision_id must belong to session_id",
                )?;
                if let Some(record) = &record
                    && record.parent_fold != Some(parent_fold)
                {
                    return Err(Error::InvalidCodeArtifactBody(
                        "code revision parent fold mismatch",
                    ));
                }
                Some(parent_fold)
            }
            None => None,
        };
        let reverted_to_fold = match revision.reverted_to_revision_id {
            Some(reverted_to_id) => {
                let reverted_to_fold = require_code_revision_fold_with_visited(
                    store,
                    rtxn,
                    &reverted_to_id,
                    visiting,
                )?;
                if let Some(record) = &record
                    && record.reverted_to_fold != Some(reverted_to_fold)
                {
                    return Err(Error::InvalidCodeArtifactBody(
                        "code revision reverted-to fold mismatch",
                    ));
                }
                Some(reverted_to_fold)
            }
            None => None,
        };
        if let (Some(parent_id), Some(reverted_to_id)) = (
            revision.parent_revision_id,
            revision.reverted_to_revision_id,
        ) {
            require_code_revision_ancestor(store, rtxn, &parent_id, &reverted_to_id)?;
        }

        let expected_fold = compute_code_revision_fold(
            revision.kind,
            &artifact_hash,
            revision.provenance_claim_id,
            parent_fold,
            reverted_to_fold,
        );
        if let Some(record) = record {
            if expected_fold != record.revision_fold {
                return Err(Error::InvalidCodeArtifactBody(
                    "code revision fold mismatch",
                ));
            }
            Ok(record)
        } else {
            Ok(CodeRevisionIntegrityRecord {
                revision_id: revision.revision_id,
                session_id: revision.session_id,
                parent_revision_id: revision.parent_revision_id,
                reverted_to_revision_id: revision.reverted_to_revision_id,
                provenance_claim_id: revision.provenance_claim_id,
                artifact_hash,
                parent_fold,
                reverted_to_fold,
                revision_fold: expected_fold,
                finalized_at: revision.finalized_at,
            })
        }
    })();

    visiting.remove(&revision.revision_id);
    result
}

fn validate_code_revision_frontier_update(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    integrity: &CodeRevisionIntegrityRecord,
) -> Result<bool> {
    let Some(frontier) = get_code_revision_frontier_in_txn(store, rtxn, &revision.session_id)?
    else {
        if revision.parent_revision_id.is_some() {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision frontier record missing",
            ));
        }
        return Ok(true);
    };
    if frontier.session_id != revision.session_id {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision frontier session mismatch",
        ));
    }
    verify_code_revision_frontier_record_in_txn(store, rtxn, &frontier)?;

    code_revision_frontier_update_decision(Some(&frontier), revision, integrity)
}

fn code_revision_frontier_update_decision(
    frontier: Option<&CodeRevisionFrontierRecord>,
    revision: &CodeRevision,
    integrity: &CodeRevisionIntegrityRecord,
) -> Result<bool> {
    let Some(frontier) = frontier else {
        if revision.parent_revision_id.is_some() {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision frontier record missing",
            ));
        }
        return Ok(true);
    };

    let parent_matches_frontier = integrity
        .parent_fold
        .is_some_and(|parent_fold| parent_fold == frontier.revision_fold);
    let duplicate_converges = integrity.revision_fold == frontier.revision_fold;
    if parent_matches_frontier {
        Ok(true)
    } else if duplicate_converges {
        Ok(false)
    } else {
        Err(Error::InvalidCodeArtifactBody(
            "code revision frontier conflict",
        ))
    }
}

fn verify_code_revision_frontier_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_id: &EntityId,
) -> Result<()> {
    let frontier = get_code_revision_frontier_in_txn(store, rtxn, session_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision frontier record missing"),
    )?;
    if frontier.session_id != *session_id {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision frontier session mismatch",
        ));
    }
    verify_code_revision_frontier_record_in_txn(store, rtxn, &frontier)
}

fn verify_code_revision_frontier_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    frontier: &CodeRevisionFrontierRecord,
) -> Result<()> {
    let revision = read_code_revision_record_in_txn(store, rtxn, &frontier.revision_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision frontier points at a missing revision"),
    )?;
    if revision.session_id != frontier.session_id || revision.finalized_at != frontier.finalized_at
    {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision frontier record does not match revision record",
        ));
    }
    let mut visiting = HashSet::new();
    let integrity = verify_or_build_code_revision_integrity_record_in_txn(
        store,
        rtxn,
        &revision,
        &mut visiting,
    )?;
    if integrity.revision_fold != frontier.revision_fold {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision frontier fold mismatch",
        ));
    }
    Ok(())
}

fn verify_code_revision_session_trace_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_id: &EntityId,
    revisions: &[CodeRevision],
) -> Result<()> {
    let stored_frontier = get_code_revision_frontier_in_txn(store, rtxn, session_id)?;
    let mut computed_frontier = None;
    let mut saw_stored_integrity = false;
    for revision in revisions {
        if revision.session_id != *session_id {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision session index mismatch",
            ));
        }
        saw_stored_integrity |=
            load_optional_code_revision_integrity_record(store, rtxn, &revision.revision_id)?
                .is_some();
        let mut visiting = HashSet::new();
        let integrity = verify_or_build_code_revision_integrity_record_in_txn(
            store,
            rtxn,
            revision,
            &mut visiting,
        )?;
        if code_revision_frontier_update_decision(computed_frontier.as_ref(), revision, &integrity)?
        {
            computed_frontier = Some(CodeRevisionFrontierRecord {
                session_id: revision.session_id,
                revision_id: revision.revision_id,
                revision_fold: integrity.revision_fold,
                finalized_at: revision.finalized_at,
            });
        }
    }
    let Some(stored_frontier) = stored_frontier else {
        if saw_stored_integrity {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision frontier record missing",
            ));
        }
        return Ok(());
    };
    let computed_frontier = computed_frontier.ok_or(Error::InvalidCodeArtifactBody(
        "code revision frontier record missing",
    ))?;
    if computed_frontier.revision_id != stored_frontier.revision_id
        || computed_frontier.revision_fold != stored_frontier.revision_fold
        || computed_frontier.finalized_at != stored_frontier.finalized_at
        || computed_frontier.session_id != stored_frontier.session_id
    {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision frontier record does not match session trace",
        ));
    }
    Ok(())
}

fn require_code_revision_fold(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<[u8; CODE_REVISION_HASH_LEN]> {
    let mut visiting = HashSet::new();
    require_code_revision_fold_with_visited(store, rtxn, revision_id, &mut visiting)
}

fn require_code_revision_fold_with_visited(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
    visiting: &mut HashSet<EntityId>,
) -> Result<[u8; CODE_REVISION_HASH_LEN]> {
    let (_revision, fold) =
        require_code_revision_with_fold_with_visited(store, rtxn, revision_id, visiting)?;
    Ok(fold)
}

fn require_code_revision_with_fold_with_visited(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
    visiting: &mut HashSet<EntityId>,
) -> Result<(CodeRevision, [u8; CODE_REVISION_HASH_LEN])> {
    let revision = read_code_revision_record_in_txn(store, rtxn, revision_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision integrity parent record missing"),
    )?;
    let record =
        verify_or_build_code_revision_integrity_record_in_txn(store, rtxn, &revision, visiting)?;
    Ok((revision, record.revision_fold))
}

fn load_optional_code_revision_integrity_record(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Option<CodeRevisionIntegrityRecord>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &code_revision_integrity_key(revision_id))?
    else {
        return Ok(None);
    };
    decode_code_revision_integrity_record(raw).map(Some)
}

fn get_code_revision_frontier_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_id: &EntityId,
) -> Result<Option<CodeRevisionFrontierRecord>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &code_revision_frontier_key(session_id))?
    else {
        return Ok(None);
    };
    decode_code_revision_frontier_record(raw).map(Some)
}

fn compute_code_revision_fold(
    kind: CodeRevisionKind,
    artifact_hash: &[u8; CODE_REVISION_HASH_LEN],
    provenance_claim_id: Option<EntityId>,
    parent_fold: Option<[u8; CODE_REVISION_HASH_LEN]>,
    reverted_to_fold: Option<[u8; CODE_REVISION_HASH_LEN]>,
) -> [u8; CODE_REVISION_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CODE_REVISION_FOLD_DOMAIN);
    hasher.update([match kind {
        CodeRevisionKind::Commit => 0,
        CodeRevisionKind::Revert => 1,
    }]);
    hasher.update(artifact_hash);
    update_optional_entity(&mut hasher, provenance_claim_id.as_ref());
    update_optional_hash(&mut hasher, parent_fold.as_ref());
    update_optional_hash(&mut hasher, reverted_to_fold.as_ref());
    hasher.finalize().into()
}

fn update_optional_entity(hasher: &mut Sha256, value: Option<&EntityId>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn update_optional_hash(hasher: &mut Sha256, value: Option<&[u8; CODE_REVISION_HASH_LEN]>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0]),
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; CODE_REVISION_HASH_LEN] {
    Sha256::digest(bytes).into()
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
    decode_code_revision_fork(raw).map(Some)
}

fn collect_code_revisions_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<CodeRevision>> {
    let mut revisions = Vec::new();
    for entry in store.vault_meta.prefix_iter(rtxn, prefix)? {
        let (key, _) = entry?;
        let revision_id = id_from_index_key(key, prefix.len(), "code revision index key")?;
        if let Some(revision) = get_code_revision_in_txn(store, rtxn, &revision_id)? {
            revisions.push(revision);
        }
    }
    sort_code_revisions_topologically(revisions)
}

fn collect_code_revision_records_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<CodeRevision>> {
    let mut revisions = Vec::new();
    for entry in store.vault_meta.prefix_iter(rtxn, prefix)? {
        let (key, _) = entry?;
        let revision_id = id_from_index_key(key, prefix.len(), "code revision index key")?;
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

fn put_lifecycle_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    created_at: u64,
    graph_changed: &mut bool,
) -> Result<()> {
    let weight = kind.default_weight().unwrap_or(1.0);
    let value = encode_edge_value(kind, weight, created_at, Vad::NEUTRAL, None)?;
    let key_out = Store::encode_edge_key(src, kind, tgt);
    let key_in = Store::encode_edge_key(tgt, kind, src);
    let changed = store
        .edges_out
        .get(wtxn, &key_out)?
        .is_none_or(|existing| existing != value.as_slice())
        || store
            .edges_in
            .get(wtxn, &key_in)?
            .is_none_or(|existing| existing != value.as_slice());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    if changed {
        ppr::invalidate_ppr_for_edge(store, wtxn, src, tgt)?;
        *graph_changed = true;
    }
    Ok(())
}

fn validate_child_of_insert(
    store: &Store,
    txn: &RwTxn<'_>,
    child: &EntityId,
    parent: &EntityId,
) -> Result<()> {
    let parents = child_of_parents(store, txn, child)?;
    if parents.len() > 1 || parents.first().is_some_and(|existing| existing != parent) {
        return Err(Error::ChildOfCardinality);
    }
    if child == parent || would_create_child_of_cycle(store, txn, child, parent)? {
        return Err(Error::CycleDetected);
    }
    Ok(())
}

fn would_create_child_of_cycle(
    store: &Store,
    txn: &RwTxn<'_>,
    child: &EntityId,
    parent: &EntityId,
) -> Result<bool> {
    let mut frontier = VecDeque::new();
    frontier.push_back(*parent);
    let mut visited = HashSet::new();
    visited.insert(*parent);
    let mut traversed_steps = 0usize;

    while let Some(node) = frontier.pop_front() {
        for next_parent in child_of_parents(store, txn, &node)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
            if next_parent == *child {
                return Ok(true);
            }
            if visited.insert(next_parent) {
                frontier.push_back(next_parent);
            }
        }
    }

    Ok(false)
}

fn child_of_parents(store: &Store, txn: &RwTxn<'_>, child: &EntityId) -> Result<Vec<EntityId>> {
    let prefix = child_of_prefix(child);
    let mut parents = Vec::new();
    for entry in store.edges_out.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        let edge = parse_strict_edge_record(key, value)?;
        if edge.kind != EdgeKind::ChildOf {
            return Err(Error::CorruptedIndex("edge record"));
        }
        parents.push(edge.target);
    }
    parents.sort_unstable();
    parents.dedup();
    Ok(parents)
}

fn child_of_prefix(child: &EntityId) -> [u8; ENTITY_ID_LEN + 1] {
    let mut prefix = [0u8; ENTITY_ID_LEN + 1];
    prefix[..ENTITY_ID_LEN].copy_from_slice(child.as_bytes());
    prefix[ENTITY_ID_LEN] = EdgeKind::ChildOf as u8;
    prefix
}

fn delete_code_revision_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    let key = code_revision_record_key(revision_id);
    let Some(raw) = store.vault_meta.get(wtxn, &key)?.map(<[u8]>::to_vec) else {
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

fn delete_code_revision_frontier_for_revision_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    let mut sessions = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(wtxn, CODE_REVISION_FRONTIER_KEY_PREFIX)?
    {
        let (key, value) = entry?;
        match decode_code_revision_frontier_record(value) {
            Ok(frontier) if frontier.revision_id == *revision_id => {
                keys.push(key.to_vec());
                sessions.push(frontier.session_id);
            }
            Ok(_) => {}
            Err(_) => {
                let session_id = id_from_index_key(
                    key,
                    CODE_REVISION_FRONTIER_KEY_PREFIX.len(),
                    "code revision frontier key",
                )?;
                keys.push(key.to_vec());
                sessions.push(session_id);
            }
        }
    }
    for key in keys {
        store.vault_meta.delete(wtxn, &key)?;
    }
    sessions.sort_unstable();
    sessions.dedup();
    for session_id in sessions {
        rebuild_code_revision_frontier_in_txn(store, wtxn, &session_id)?;
    }
    Ok(())
}

fn delete_code_revision_fork_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    fork_session_id: &EntityId,
) -> Result<()> {
    let key = code_revision_fork_key(fork_session_id);
    let Some(raw) = store.vault_meta.get(wtxn, &key)?.map(<[u8]>::to_vec) else {
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

fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

fn optional_entity_value(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

fn optional_hash_value(hash: Option<[u8; CODE_REVISION_HASH_LEN]>) -> Value {
    hash.map_or(Value::Nil, |hash| Value::Binary(hash.to_vec()))
}

fn entity_value(value: &Value, field: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeArtifactBody(field));
    };
    entity_from_bytes(bytes, field)
}

fn optional_entity_from_value(value: &Value, field: &'static str) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => entity_from_bytes(bytes, field).map(Some),
        _ => Err(Error::InvalidCodeArtifactBody(field)),
    }
}

fn entity_from_bytes(bytes: &[u8], field: &'static str) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidCodeArtifactBody(field))?;
    EntityId::from_bytes(raw).map_err(|_| Error::InvalidCodeArtifactBody(field))
}

fn hash_from_value(value: &Value, field: &'static str) -> Result<[u8; CODE_REVISION_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeArtifactBody(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCodeArtifactBody(field))
}

fn optional_hash_from_value(
    value: &Value,
    field: &'static str,
) -> Result<Option<[u8; CODE_REVISION_HASH_LEN]>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(_) => hash_from_value(value, field).map(Some),
        _ => Err(Error::InvalidCodeArtifactBody(field)),
    }
}

fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value.as_u64().ok_or(Error::InvalidCodeArtifactBody(field))
}

fn id_from_index_key(key: &[u8], offset: usize, context: &'static str) -> Result<EntityId> {
    parse_entity_id(key.get(offset..).unwrap_or_default(), context)
}

fn code_revision_record_key(id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_RECORD_KEY_PREFIX, id)
}

fn code_revision_integrity_key(id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_INTEGRITY_KEY_PREFIX, id)
}

fn code_revision_frontier_key(session_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_FRONTIER_KEY_PREFIX, session_id)
}

fn code_revision_session_index_prefix(session_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_SESSION_INDEX_KEY_PREFIX, session_id)
}

fn code_revision_session_index_key(session_id: &EntityId, revision_id: &EntityId) -> Vec<u8> {
    keyed_pair(
        CODE_REVISION_SESSION_INDEX_KEY_PREFIX,
        session_id,
        revision_id,
    )
}

fn code_revision_parent_index_prefix(parent_revision_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_PARENT_INDEX_KEY_PREFIX, parent_revision_id)
}

fn code_revision_parent_index_key(
    parent_revision_id: &EntityId,
    revision_id: &EntityId,
) -> Vec<u8> {
    keyed_pair(
        CODE_REVISION_PARENT_INDEX_KEY_PREFIX,
        parent_revision_id,
        revision_id,
    )
}

fn code_revision_fork_key(fork_session_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_FORK_KEY_PREFIX, fork_session_id)
}

fn code_revision_fork_parent_index_prefix(parent_session_id: &EntityId) -> Vec<u8> {
    keyed_id(
        CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX,
        parent_session_id,
    )
}

fn code_revision_fork_parent_index_key(
    parent_session_id: &EntityId,
    fork_session_id: &EntityId,
) -> Vec<u8> {
    keyed_pair(
        CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX,
        parent_session_id,
        fork_session_id,
    )
}

fn keyed_id(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn keyed_pair(prefix: &[u8], first: &EntityId, second: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 2 * ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(first.as_bytes());
    key.extend_from_slice(second.as_bytes());
    key
}

#[cfg(test)]
mod tests;
