use std::collections::{HashSet, VecDeque};

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::decode_code_artifact_body;
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::ppr;
use crate::store::Store;
use crate::types::{
    EDGE_KEY_LEN, ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_SESSION,
    EdgeKind, EntityId, Vad, decode_edge_value_for_kind, encode_edge_value, parse_entity_id,
};

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
const CODE_REVISION_INTEGRITY_KEYS: [&str; 9] = [
    "revision_id",
    "session_id",
    "parent_revision_id",
    "reverted_to_revision_id",
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
const KEY_ARTIFACT_HASH: &str = CODE_REVISION_INTEGRITY_KEYS[4];
const KEY_PARENT_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[5];
const KEY_REVERTED_TO_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[6];
const KEY_REVISION_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[7];

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
        backfill_code_revision_integrity_for_revision(&self.store, revision_id)?;
        let rtxn = self.store.env.read_txn()?;
        get_code_revision_in_txn(&self.store, &rtxn, revision_id)
    }

    pub fn code_revisions_for_session(&self, session_id: &EntityId) -> Result<Vec<CodeRevision>> {
        backfill_code_revision_integrity_for_session(&self.store, session_id)?;
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
            verify_code_revision_frontier_in_txn(&self.store, &rtxn, session_id)?;
            verify_code_revision_session_trace_in_txn(&self.store, &rtxn, session_id, &revisions)?;
        }
        Ok(revisions)
    }

    pub fn child_code_revisions(&self, parent_revision_id: &EntityId) -> Result<Vec<CodeRevision>> {
        backfill_code_revision_integrity_for_parent_children(&self.store, parent_revision_id)?;
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

fn backfill_code_revision_integrity_for_revision(
    store: &Store,
    revision_id: &EntityId,
) -> Result<()> {
    let mut wtxn = store.env.write_txn()?;
    backfill_code_revision_integrity_for_revision_in_txn(store, &mut wtxn, revision_id)?;
    wtxn.commit()?;
    Ok(())
}

fn backfill_code_revision_integrity_for_session(
    store: &Store,
    session_id: &EntityId,
) -> Result<()> {
    let mut wtxn = store.env.write_txn()?;
    backfill_code_revision_integrity_for_session_in_txn(store, &mut wtxn, session_id)?;
    wtxn.commit()?;
    Ok(())
}

fn backfill_code_revision_integrity_for_parent_children(
    store: &Store,
    parent_revision_id: &EntityId,
) -> Result<()> {
    let mut wtxn = store.env.write_txn()?;
    let prefix = code_revision_parent_index_prefix(parent_revision_id);
    let revisions = collect_code_revision_records_by_index_prefix(store, &wtxn, &prefix)?;
    for revision in revisions {
        backfill_code_revision_integrity_for_session_in_txn(
            store,
            &mut wtxn,
            &revision.session_id,
        )?;
    }
    wtxn.commit()?;
    Ok(())
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
    if revisions.is_empty() {
        return Ok(());
    }

    let mut needs_backfill = get_code_revision_frontier_in_txn(store, wtxn, session_id)?.is_none();
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
    let revision_fold =
        compute_code_revision_fold(revision.kind, &artifact_hash, parent_fold, reverted_to_fold);
    let record = CodeRevisionIntegrityRecord {
        revision_id: revision.revision_id,
        session_id: revision.session_id,
        parent_revision_id: revision.parent_revision_id,
        reverted_to_revision_id: revision.reverted_to_revision_id,
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
    let revision_fold =
        compute_code_revision_fold(revision.kind, &artifact_hash, parent_fold, reverted_to_fold);
    Ok(CodeRevisionIntegrityRecord {
        revision_id: revision.revision_id,
        session_id: revision.session_id,
        parent_revision_id: revision.parent_revision_id,
        reverted_to_revision_id: revision.reverted_to_revision_id,
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
    let record = load_code_revision_integrity_record(store, rtxn, &revision.revision_id)?;
    if record.revision_id != revision.revision_id
        || record.session_id != revision.session_id
        || record.parent_revision_id != revision.parent_revision_id
        || record.reverted_to_revision_id != revision.reverted_to_revision_id
        || record.finalized_at != revision.finalized_at
        || record.parent_fold.is_some() != revision.parent_revision_id.is_some()
        || record.reverted_to_fold.is_some() != revision.reverted_to_revision_id.is_some()
    {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision integrity record does not match revision record",
        ));
    }
    let artifact_body = code_artifact_body_bytes(store, rtxn, &revision.revision_id)?;
    let artifact_hash = sha256_bytes(&artifact_body);
    if artifact_hash != record.artifact_hash {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision artifact hash mismatch",
        ));
    }
    let parent_fold = match revision.parent_revision_id {
        Some(parent_id) => {
            let parent_fold = require_code_revision_fold(store, rtxn, &parent_id)?;
            if record.parent_fold != Some(parent_fold) {
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
            let reverted_to_fold = require_code_revision_fold(store, rtxn, &reverted_to_id)?;
            if record.reverted_to_fold != Some(reverted_to_fold) {
                return Err(Error::InvalidCodeArtifactBody(
                    "code revision reverted-to fold mismatch",
                ));
            }
            Some(reverted_to_fold)
        }
        None => None,
    };
    let expected_fold =
        compute_code_revision_fold(revision.kind, &artifact_hash, parent_fold, reverted_to_fold);
    if expected_fold != record.revision_fold {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision fold mismatch",
        ));
    }
    Ok(())
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
    verify_code_revision_integrity_in_txn(store, rtxn, &revision)?;
    let integrity = load_code_revision_integrity_record(store, rtxn, &frontier.revision_id)?;
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
    let stored_frontier = get_code_revision_frontier_in_txn(store, rtxn, session_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision frontier record missing"),
    )?;
    let mut computed_frontier = None;
    for revision in revisions {
        if revision.session_id != *session_id {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision session index mismatch",
            ));
        }
        let integrity = load_code_revision_integrity_record(store, rtxn, &revision.revision_id)?;
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
    let revision = read_code_revision_record_in_txn(store, rtxn, revision_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision integrity parent record missing"),
    )?;
    verify_code_revision_integrity_in_txn(store, rtxn, &revision)?;
    let record = load_code_revision_integrity_record(store, rtxn, revision_id)?;
    Ok(record.revision_fold)
}

fn load_code_revision_integrity_record(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<CodeRevisionIntegrityRecord> {
    load_optional_code_revision_integrity_record(store, rtxn, revision_id)?.ok_or(
        Error::InvalidCodeArtifactBody("code revision integrity record missing"),
    )
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
    update_optional_hash(&mut hasher, parent_fold.as_ref());
    update_optional_hash(&mut hasher, reverted_to_fold.as_ref());
    hasher.finalize().into()
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
    revisions.sort_by_key(|revision| (revision.finalized_at, revision.revision_id));
    Ok(revisions)
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
    revisions.sort_by_key(|revision| (revision.finalized_at, revision.revision_id));
    Ok(revisions)
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
        validate_child_of_edge_record(key, value)?;
        parents.push(parse_entity_id(
            key.get(ENTITY_ID_LEN + 1..EDGE_KEY_LEN)
                .ok_or(Error::CorruptedIndex("edge record"))?,
            "ChildOf edge key",
        )?);
    }
    parents.sort_unstable();
    parents.dedup();
    Ok(parents)
}

fn validate_child_of_edge_record(key: &[u8], value: &[u8]) -> Result<()> {
    if key.len() != EDGE_KEY_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }
    if key[ENTITY_ID_LEN] != EdgeKind::ChildOf as u8 {
        return Err(Error::CorruptedIndex("edge record"));
    }
    decode_edge_value_for_kind(EdgeKind::ChildOf, value)
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
    Ok(())
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
        if let Ok(frontier) = decode_code_revision_frontier_record(value)
            && frontier.revision_id == *revision_id
        {
            keys.push(key.to_vec());
            sessions.push(frontier.session_id);
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
mod tests {
    use super::*;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        encode_claim_body,
    };
    use crate::code_artifact::{
        CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, encode_code_artifact_body,
    };
    use crate::error::ErrorKind;
    use crate::types::{ENTITY_TYPE_CLAIM, HnswConfig, TextAnalyzerConfig, TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config.text_analyzer = TextAnalyzerConfig::default();
        config
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; ENTITY_ID_LEN]).expect("valid entity id")
    }

    fn artifact_body(tag: u8) -> CodeArtifactBody {
        CodeArtifactBody::new(
            format!("Summarize code revision {tag}."),
            [tag; CODE_ARTIFACT_SUMMARY_HASH_LEN],
            "github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277",
        )
    }

    fn put_session(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
        vault.put_entity(
            &id,
            ENTITY_TYPE_SESSION,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"session",
        )
    }

    fn put_artifact(vault: &Vault, id: EntityId, tag: u8, learned_at: u64) -> Result<()> {
        vault.put_code_artifact(
            &id,
            &artifact_body(tag),
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
    }

    fn put_claim_entity(
        vault: &Vault,
        id: EntityId,
        subject: EntityId,
        learned_at: u64,
    ) -> Result<()> {
        put_claim_entity_with_source(vault, id, subject, None, learned_at)
    }

    fn put_claim_entity_with_source(
        vault: &Vault,
        id: EntityId,
        subject: EntityId,
        source: Option<ClaimSource>,
        learned_at: u64,
    ) -> Result<()> {
        let body = ClaimBody::new(
            CODE_REVISION_CLAIM_PREDICATE,
            ClaimSubject::Entity(subject),
            Value::from("finalized"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let mut body = body;
        body.source = source;
        let data = encode_claim_body(&body)?;
        vault.put_entity(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &data,
        )
    }

    fn replace_entity_with_header_shell(vault: &Vault, id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        let raw = vault
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?
            .to_vec();
        let shell = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
        vault.store.entities.put(&mut wtxn, id.as_bytes(), &shell)?;
        wtxn.commit()?;
        Ok(())
    }

    fn replace_code_artifact_body_unchecked(
        vault: &Vault,
        id: &EntityId,
        body: &CodeArtifactBody,
    ) -> Result<()> {
        let encoded = encode_code_artifact_body(body)?;
        let mut wtxn = vault.store.env.write_txn()?;
        let raw = vault
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let mut next = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
        next.extend_from_slice(&encoded);
        vault.store.entities.put(&mut wtxn, id.as_bytes(), &next)?;
        wtxn.commit()?;
        Ok(())
    }

    fn corrupt_code_revision_frontier_fold(vault: &Vault, session_id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        let key = code_revision_frontier_key(session_id);
        let raw = vault
            .store
            .vault_meta
            .get(&wtxn, &key)?
            .ok_or(Error::EntityNotFound)?;
        let mut frontier = decode_code_revision_frontier_record(raw)?;
        frontier.revision_fold[0] ^= 0x80;
        let encoded = encode_code_revision_frontier_record(&frontier)?;
        vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(())
    }

    fn remove_code_revision_integrity_sidecars(
        vault: &Vault,
        revision_ids: &[EntityId],
        session_id: &EntityId,
    ) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        for revision_id in revision_ids {
            vault
                .store
                .vault_meta
                .delete(&mut wtxn, &code_revision_integrity_key(revision_id))?;
        }
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, &code_revision_frontier_key(session_id))?;
        wtxn.commit()?;
        Ok(())
    }

    fn delete_code_revision_session_index_row(
        vault: &Vault,
        session_id: &EntityId,
        revision_id: &EntityId,
    ) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.delete(
            &mut wtxn,
            &code_revision_session_index_key(session_id, revision_id),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn corrupt_code_revision_parent_fold_self_consistent(
        vault: &Vault,
        revision_id: &EntityId,
    ) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        let revision = read_code_revision_record_in_txn(&vault.store, &wtxn, revision_id)?
            .ok_or(Error::EntityNotFound)?;
        let key = code_revision_integrity_key(revision_id);
        let raw = vault
            .store
            .vault_meta
            .get(&wtxn, &key)?
            .ok_or(Error::EntityNotFound)?;
        let mut record = decode_code_revision_integrity_record(raw)?;
        let parent_fold = record
            .parent_fold
            .as_mut()
            .ok_or(Error::InvalidCodeArtifactBody(
                "test revision must have a parent fold",
            ))?;
        parent_fold[0] ^= 0x40;
        record.revision_fold = compute_code_revision_fold(
            revision.kind,
            &record.artifact_hash,
            record.parent_fold,
            record.reverted_to_fold,
        );
        let encoded = encode_code_revision_integrity_record(&record)?;
        vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(())
    }

    fn corrupt_code_revision_record_bytes(vault: &Vault, revision_id: &EntityId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &code_revision_record_key(revision_id),
            b"not-a-code-revision",
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn code_revision_integrity_sidecars_exist(
        vault: &Vault,
        revision_ids: &[EntityId],
        session_id: &EntityId,
    ) -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        for revision_id in revision_ids {
            if vault
                .store
                .vault_meta
                .get(&rtxn, &code_revision_integrity_key(revision_id))?
                .is_none()
            {
                return Ok(false);
            }
        }
        Ok(vault
            .store
            .vault_meta
            .get(&rtxn, &code_revision_frontier_key(session_id))?
            .is_some())
    }

    #[test]
    fn code_revision_codec_round_trips_commit_revert_and_fork() -> Result<()> {
        let session = entity(0x11);
        let first = entity(0x21);
        let second = entity(0x22);
        let third = entity(0x23);
        let provenance = entity(0x31);

        let commit = CodeRevision::commit_child(second, session, first, 2_000)
            .with_provenance_claim_id(provenance);
        let decoded = decode_code_revision(&encode_code_revision(&commit)?)?;
        assert_eq!(decoded, commit);

        let revert = CodeRevision::revert(third, session, second, first, 3_000);
        let decoded = decode_code_revision(&encode_code_revision(&revert)?)?;
        assert_eq!(decoded, revert);

        let fork = CodeRevisionFork::new(entity(0x41), session, second, 4_000);
        let decoded = decode_code_revision_fork(&encode_code_revision_fork(&fork)?)?;
        assert_eq!(decoded, fork);
        Ok(())
    }

    #[test]
    fn code_revision_commit_finalizes_session_revision_and_links_parent() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let first = entity(0x21);
        let second = entity(0x22);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, first, 0xA1, 20)?;
        put_artifact(&vault, second, 0xA2, 30)?;

        let first_revision = CodeRevision::commit(first, session, 100);
        let second_revision = CodeRevision::commit_child(second, session, first, 200);
        vault.commit_code_revision(&first_revision)?;
        vault.commit_code_revision(&second_revision)?;

        assert_eq!(
            vault.get_code_revision(&first)?,
            Some(first_revision.clone())
        );
        assert_eq!(
            vault.get_code_revision(&second)?,
            Some(second_revision.clone())
        );
        assert_eq!(
            vault.code_revisions_for_session(&session)?,
            vec![first_revision, second_revision.clone()]
        );
        assert_eq!(vault.child_code_revisions(&first)?, vec![second_revision]);

        let supersedes = vault.targets(&second, EdgeKind::Supersedes, None)?;
        assert!(supersedes.contains(&first));
        let derived = vault.targets(&second, EdgeKind::DerivedFrom, None)?;
        assert!(derived.contains(&session));
        Ok(())
    }

    #[test]
    fn code_revision_branch_records_session_dag_fork() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let parent_session = entity(0x11);
        let fork_session = entity(0x12);
        let base_revision = entity(0x21);
        put_session(&vault, parent_session, 10)?;
        put_session(&vault, fork_session, 11)?;
        put_artifact(&vault, base_revision, 0xA1, 20)?;
        vault.commit_code_revision(&CodeRevision::commit(base_revision, parent_session, 100))?;

        let fork = CodeRevisionFork::new(fork_session, parent_session, base_revision, 150);
        vault.branch_code_revision(&fork)?;

        assert_eq!(
            vault.get_code_revision_fork(&fork_session)?,
            Some(fork.clone())
        );
        assert_eq!(
            vault.code_revision_forks_from_session(&parent_session)?,
            vec![fork]
        );
        let parents = vault.targets(&fork_session, EdgeKind::ChildOf, None)?;
        assert!(parents.contains(&parent_session));
        let base = vault.targets(&fork_session, EdgeKind::DerivedFrom, None)?;
        assert!(base.contains(&base_revision));
        Ok(())
    }

    #[test]
    fn code_revision_branch_rejects_base_revision_from_unrelated_session() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let parent_session = entity(0x11);
        let fork_session = entity(0x12);
        let other_session = entity(0x13);
        let base_revision = entity(0x21);
        put_session(&vault, parent_session, 10)?;
        put_session(&vault, fork_session, 11)?;
        put_session(&vault, other_session, 12)?;
        put_artifact(&vault, base_revision, 0xA1, 20)?;
        vault.commit_code_revision(&CodeRevision::commit(base_revision, other_session, 100))?;

        let err = vault
            .branch_code_revision(&CodeRevisionFork::new(
                fork_session,
                parent_session,
                base_revision,
                150,
            ))
            .expect_err("fork base revision must belong to the declared parent session");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("base_revision_id must belong to parent_session_id")
        );
        assert!(vault.get_code_revision_fork(&fork_session)?.is_none());
        assert!(
            vault
                .code_revision_forks_from_session(&parent_session)?
                .is_empty()
        );
        assert!(
            vault
                .targets(&fork_session, EdgeKind::ChildOf, None)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn code_revision_branch_rejects_corrupt_child_of_edge_row() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let parent_session = entity(0x11);
        let fork_session = entity(0x12);
        let base_revision = entity(0x21);
        put_session(&vault, parent_session, 10)?;
        put_session(&vault, fork_session, 11)?;
        put_artifact(&vault, base_revision, 0xA1, 20)?;
        vault.commit_code_revision(&CodeRevision::commit(base_revision, parent_session, 100))?;

        let edge_key = Store::encode_edge_key(&fork_session, EdgeKind::ChildOf, &parent_session);
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.edges_out.put(&mut wtxn, &edge_key, b"bad")?;
        wtxn.commit()?;

        let err = vault
            .branch_code_revision(&CodeRevisionFork::new(
                fork_session,
                parent_session,
                base_revision,
                150,
            ))
            .expect_err("corrupt ChildOf rows must fail closed before logical validation");

        assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
        assert!(vault.get_code_revision_fork(&fork_session)?.is_none());
        Ok(())
    }

    #[test]
    fn code_revision_revert_appends_superseding_revision_and_keeps_history() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let original = entity(0x21);
        let current = entity(0x22);
        let reverted = entity(0x23);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, original, 0xA1, 20)?;
        put_artifact(&vault, current, 0xA2, 30)?;
        put_artifact(&vault, reverted, 0xA3, 40)?;

        let original_revision = CodeRevision::commit(original, session, 100);
        let current_revision = CodeRevision::commit_child(current, session, original, 200);
        let reverted_revision = CodeRevision::revert(reverted, session, current, original, 300);
        vault.commit_code_revision(&original_revision)?;
        vault.commit_code_revision(&current_revision)?;
        vault.revert_code_revision(&reverted_revision)?;

        assert_eq!(vault.get_code_revision(&original)?, Some(original_revision));
        assert_eq!(vault.get_code_revision(&current)?, Some(current_revision));
        assert_eq!(
            vault.get_code_revision(&reverted)?,
            Some(reverted_revision.clone())
        );
        assert_eq!(
            vault.code_revisions_for_session(&session)?,
            vec![
                CodeRevision::commit(original, session, 100),
                CodeRevision::commit_child(current, session, original, 200),
                reverted_revision,
            ]
        );

        let supersedes = vault.targets(&reverted, EdgeKind::Supersedes, None)?;
        assert!(supersedes.contains(&current));
        let derived = vault.targets(&reverted, EdgeKind::DerivedFrom, None)?;
        assert!(derived.contains(&session));
        assert!(derived.contains(&original));
        Ok(())
    }

    #[test]
    fn code_revision_batch_delete_removes_lifecycle_sidecars() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;

        let revision = CodeRevision::commit(revision_id, session, 100);
        vault.commit_code_revision(&revision)?;
        vault.batch().delete(&revision_id).commit()?;

        assert!(vault.get_code_revision(&revision_id)?.is_none());
        assert!(vault.code_revisions_for_session(&session)?.is_empty());

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &code_revision_record_key(&revision_id))?
                .is_none()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(
                    &rtxn,
                    &code_revision_session_index_key(&session, &revision_id)
                )?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn code_revision_delete_corrupt_record_removes_frontier_sidecar() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;
        vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
        corrupt_code_revision_record_bytes(&vault, &revision_id)?;

        vault.batch().delete(&revision_id).commit()?;

        assert!(vault.code_revisions_for_session(&session)?.is_empty());
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &code_revision_frontier_key(&session))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn code_revision_delete_frontier_head_rebuilds_predecessor_frontier() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let first = entity(0x21);
        let second = entity(0x22);
        let first_revision = CodeRevision::commit(first, session, 100);
        let second_revision = CodeRevision::commit_child(second, session, first, 200);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, first, 0xA1, 20)?;
        put_artifact(&vault, second, 0xA2, 30)?;
        vault.commit_code_revision(&first_revision)?;
        vault.commit_code_revision(&second_revision)?;

        vault.batch().delete(&second).commit()?;

        assert_eq!(
            vault.code_revisions_for_session(&session)?,
            vec![first_revision]
        );
        Ok(())
    }

    #[test]
    fn code_revision_batch_delete_session_removes_reverse_indexes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let parent_session = entity(0x11);
        let fork_session = entity(0x12);
        let revision_id = entity(0x21);
        put_session(&vault, parent_session, 10)?;
        put_session(&vault, fork_session, 11)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;

        let revision = CodeRevision::commit(revision_id, parent_session, 100);
        let fork = CodeRevisionFork::new(fork_session, parent_session, revision_id, 150);
        vault.commit_code_revision(&revision)?;
        vault.branch_code_revision(&fork)?;
        vault.batch().delete(&parent_session).commit()?;

        assert!(
            vault
                .code_revisions_for_session(&parent_session)?
                .is_empty()
        );
        assert!(
            vault
                .code_revision_forks_from_session(&parent_session)?
                .is_empty()
        );
        assert_eq!(vault.get_code_revision(&revision_id)?, Some(revision));
        assert_eq!(vault.get_code_revision_fork(&fork_session)?, Some(fork));

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(
                    &rtxn,
                    &code_revision_session_index_key(&parent_session, &revision_id)
                )?
                .is_none()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(
                    &rtxn,
                    &code_revision_fork_parent_index_key(&parent_session, &fork_session)
                )?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn code_revision_batch_delete_parent_removes_child_index_rows() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let parent = entity(0x21);
        let child = entity(0x22);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, parent, 0xA1, 20)?;
        put_artifact(&vault, child, 0xA2, 30)?;

        let parent_revision = CodeRevision::commit(parent, session, 100);
        let child_revision = CodeRevision::commit_child(child, session, parent, 200);
        vault.commit_code_revision(&parent_revision)?;
        vault.commit_code_revision(&child_revision)?;
        vault.batch().delete(&parent).commit()?;

        assert!(vault.get_code_revision(&parent)?.is_none());
        let err = vault
            .get_code_revision(&child)
            .expect_err("child must fail closed when its parent revision is deleted");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("code revision integrity parent record missing")
        );
        assert!(vault.child_code_revisions(&parent)?.is_empty());

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &code_revision_parent_index_key(&parent, &child))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn code_revision_finalized_artifact_rejects_body_mutation() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;

        let revision = CodeRevision::commit(revision_id, session, 100);
        vault.commit_code_revision(&revision)?;

        let err = vault
            .put_code_artifact(
                &revision_id,
                &artifact_body(0xA2),
                TimeRange { start: 30, end: 30 },
                30,
            )
            .expect_err("finalized code revision bytes must be immutable");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert_eq!(vault.get_code_revision(&revision_id)?, Some(revision));
        assert_eq!(
            vault.get_code_artifact(&revision_id)?,
            Some(artifact_body(0xA1))
        );
        Ok(())
    }

    #[test]
    fn code_revision_finalization_rejects_header_only_artifact_shell() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;
        replace_entity_with_header_shell(&vault, &revision_id)?;

        let err = vault
            .commit_code_revision(&CodeRevision::commit(revision_id, session, 100))
            .expect_err("header-only CODE_ARTIFACT shells must not be finalized");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(vault.get_code_revision(&revision_id)?.is_none());
        Ok(())
    }

    #[test]
    fn code_integrity_revision_fold_mismatch_fails_closed() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;

        let revision = CodeRevision::commit(revision_id, session, 100);
        vault.commit_code_revision(&revision)?;
        replace_code_artifact_body_unchecked(&vault, &revision_id, &artifact_body(0xA2))?;

        let err = vault
            .get_code_revision(&revision_id)
            .expect_err("artifact bytes diverging from the stored fold must fail closed");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("code revision artifact hash mismatch")
        );
        Ok(())
    }

    #[test]
    fn code_integrity_frontier_record_mismatch_fails_closed() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let first = entity(0x21);
        let second = entity(0x22);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, first, 0xA1, 20)?;
        put_artifact(&vault, second, 0xA2, 30)?;

        vault.commit_code_revision(&CodeRevision::commit(first, session, 100))?;
        vault.commit_code_revision(&CodeRevision::commit_child(second, session, first, 200))?;
        corrupt_code_revision_frontier_fold(&vault, &session)?;

        let err = vault
            .code_revisions_for_session(&session)
            .expect_err("frontier fold tampering must fail closed");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("code revision frontier fold mismatch")
        );
        Ok(())
    }

    #[test]
    fn code_integrity_parent_fold_mismatch_fails_closed() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let parent = entity(0x21);
        let child = entity(0x22);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, parent, 0xA1, 20)?;
        put_artifact(&vault, child, 0xA2, 30)?;

        vault.commit_code_revision(&CodeRevision::commit(parent, session, 100))?;
        vault.commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))?;
        corrupt_code_revision_parent_fold_self_consistent(&vault, &child)?;

        let err = vault
            .get_code_revision(&child)
            .expect_err("descendant must verify the current parent fold");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("code revision parent fold mismatch")
        );
        Ok(())
    }

    #[test]
    fn code_integrity_empty_session_index_with_frontier_fails_closed() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;

        vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
        delete_code_revision_session_index_row(&vault, &session, &revision_id)?;

        let err = vault
            .code_revisions_for_session(&session)
            .expect_err("frontier without session index rows must fail closed");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("code revision frontier exists without session index rows")
        );
        Ok(())
    }

    #[test]
    fn code_integrity_legacy_revision_sidecars_are_lazily_backfilled() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let first = entity(0x21);
        let second = entity(0x22);
        let first_revision = CodeRevision::commit(first, session, 100);
        let second_revision = CodeRevision::commit_child(second, session, first, 200);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, first, 0xA1, 20)?;
        put_artifact(&vault, second, 0xA2, 30)?;
        vault.commit_code_revision(&first_revision)?;
        vault.commit_code_revision(&second_revision)?;
        remove_code_revision_integrity_sidecars(&vault, &[first, second], &session)?;

        assert_eq!(
            vault.code_revisions_for_session(&session)?,
            vec![first_revision, second_revision]
        );
        assert!(code_revision_integrity_sidecars_exist(
            &vault,
            &[first, second],
            &session
        )?);
        Ok(())
    }

    #[test]
    fn code_integrity_divergent_root_conflicts_after_frontier_exists() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let first = entity(0x21);
        let second_root = entity(0x22);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, first, 0xA1, 20)?;
        put_artifact(&vault, second_root, 0xA2, 30)?;

        vault.commit_code_revision(&CodeRevision::commit(first, session, 100))?;
        let err = vault
            .commit_code_revision(&CodeRevision::commit(second_root, session, 200))
            .expect_err("second divergent root must report a frontier conflict");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(err.to_string().contains("code revision frontier conflict"));
        assert!(vault.get_code_revision(&second_root)?.is_none());
        Ok(())
    }

    #[test]
    fn code_integrity_independent_trace_entries_converge_or_conflict() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let root = entity(0x21);
        let first_child = entity(0x22);
        let convergent_child = entity(0x23);
        let conflicting_child = entity(0x24);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, root, 0xA1, 20)?;
        put_artifact(&vault, first_child, 0xA2, 30)?;
        put_artifact(&vault, convergent_child, 0xA2, 40)?;
        put_artifact(&vault, conflicting_child, 0xA4, 50)?;

        vault.commit_code_revision(&CodeRevision::commit(root, session, 100))?;
        vault.commit_code_revision(&CodeRevision::commit_child(first_child, session, root, 200))?;
        vault.commit_code_revision(&CodeRevision::commit_child(
            convergent_child,
            session,
            root,
            300,
        ))?;

        let err = vault
            .commit_code_revision(&CodeRevision::commit_child(
                conflicting_child,
                session,
                root,
                400,
            ))
            .expect_err("same-parent divergent trace must report a conflict");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(err.to_string().contains("code revision frontier conflict"));
        assert_eq!(
            vault.get_code_revision(&convergent_child)?,
            Some(CodeRevision::commit_child(
                convergent_child,
                session,
                root,
                300
            ))
        );
        assert!(vault.get_code_revision(&conflicting_child)?.is_none());
        Ok(())
    }

    #[test]
    fn code_revision_revert_rejects_unrelated_restored_revision() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let original = entity(0x21);
        let current = entity(0x22);
        let unrelated = entity(0x23);
        let reverted = entity(0x24);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, original, 0xA1, 20)?;
        put_artifact(&vault, current, 0xA2, 30)?;
        put_artifact(&vault, unrelated, 0xA2, 40)?;
        put_artifact(&vault, reverted, 0xA4, 50)?;

        vault.commit_code_revision(&CodeRevision::commit(original, session, 100))?;
        vault.commit_code_revision(&CodeRevision::commit_child(current, session, original, 200))?;
        vault.commit_code_revision(&CodeRevision::commit_child(
            unrelated, session, original, 300,
        ))?;

        let err = vault
            .revert_code_revision(&CodeRevision::revert(
                reverted, session, current, unrelated, 400,
            ))
            .expect_err("revert target must be an ancestor of the current revision");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(vault.get_code_revision(&reverted)?.is_none());
        assert!(
            vault
                .targets(&reverted, EdgeKind::Supersedes, None)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn code_revision_rejects_parent_revision_from_different_session() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let other_session = entity(0x12);
        let parent = entity(0x21);
        let child = entity(0x22);
        put_session(&vault, session, 10)?;
        put_session(&vault, other_session, 11)?;
        put_artifact(&vault, parent, 0xA1, 20)?;
        put_artifact(&vault, child, 0xA2, 30)?;
        vault.commit_code_revision(&CodeRevision::commit(parent, other_session, 100))?;

        let err = vault
            .commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))
            .expect_err("parent revision must belong to the new revision session");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("parent_revision_id must belong to session_id")
        );
        assert!(vault.get_code_revision(&child)?.is_none());
        assert!(
            vault
                .targets(&child, EdgeKind::Supersedes, None)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn code_revision_rejects_restored_revision_from_different_session() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let other_session = entity(0x12);
        let original = entity(0x21);
        let current = entity(0x22);
        let restored = entity(0x23);
        let reverted = entity(0x24);
        put_session(&vault, session, 10)?;
        put_session(&vault, other_session, 11)?;
        put_artifact(&vault, original, 0xA1, 20)?;
        put_artifact(&vault, current, 0xA2, 30)?;
        put_artifact(&vault, restored, 0xA3, 40)?;
        put_artifact(&vault, reverted, 0xA4, 50)?;
        vault.commit_code_revision(&CodeRevision::commit(original, session, 100))?;
        vault.commit_code_revision(&CodeRevision::commit_child(current, session, original, 200))?;
        vault.commit_code_revision(&CodeRevision::commit(restored, other_session, 300))?;

        let err = vault
            .revert_code_revision(&CodeRevision::revert(
                reverted, session, current, restored, 400,
            ))
            .expect_err("restored revision must belong to the new revision session");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("reverted_to_revision_id must belong to session_id")
        );
        assert!(vault.get_code_revision(&reverted)?.is_none());
        assert!(
            vault
                .targets(&reverted, EdgeKind::Supersedes, None)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn code_revision_requires_claim_typed_provenance() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let first = entity(0x21);
        let second = entity(0x22);
        let provenance_claim = entity(0x31);
        let non_claim = entity(0x32);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, first, 0xA1, 20)?;
        put_artifact(&vault, second, 0xA2, 30)?;
        put_claim_entity(&vault, provenance_claim, first, 40)?;
        put_session(&vault, non_claim, 50)?;

        let first_revision =
            CodeRevision::commit(first, session, 100).with_provenance_claim_id(provenance_claim);
        vault.commit_code_revision(&first_revision)?;

        let err = vault
            .commit_code_revision(
                &CodeRevision::commit_child(second, session, first, 200)
                    .with_provenance_claim_id(non_claim),
            )
            .expect_err("provenance_claim_id must point at a CLAIM entity");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(vault.get_code_revision(&second)?.is_none());
        Ok(())
    }

    #[test]
    fn code_integrity_generated_apply_cannot_supersede_user_stated_revision_truth() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let revision_id = entity(0x21);
        let user_truth = entity(0x31);
        let generated_apply = entity(0x32);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, revision_id, 0xA1, 20)?;
        vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
        put_claim_entity_with_source(
            &vault,
            user_truth,
            revision_id,
            Some(ClaimSource::UserStated),
            200,
        )?;
        put_claim_entity_with_source(
            &vault,
            generated_apply,
            revision_id,
            Some(ClaimSource::Generated),
            300,
        )?;

        let err = vault
            .supersede_claim(&generated_apply, &user_truth, 400)
            .expect_err("generated apply must not supersede user-stated revision truth");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(
            err.to_string()
                .contains("generated code revision claim cannot supersede user-stated truth")
        );
        assert_eq!(
            vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
            ClaimLifecycleStatus::Active
        );
        assert!(
            vault
                .targets(&generated_apply, EdgeKind::Supersedes, None)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn code_integrity_generated_apply_with_missing_subject_is_not_false_failure() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let revision_id = entity(0x21);
        let user_truth = entity(0x31);
        let generated_apply = entity(0x32);
        put_artifact(&vault, revision_id, 0xA1, 20)?;
        put_claim_entity_with_source(
            &vault,
            user_truth,
            revision_id,
            Some(ClaimSource::UserStated),
            200,
        )?;
        put_claim_entity_with_source(
            &vault,
            generated_apply,
            revision_id,
            Some(ClaimSource::Generated),
            300,
        )?;
        vault.batch().delete(&revision_id).commit()?;

        vault.supersede_claim(&generated_apply, &user_truth, 400)?;

        assert_eq!(
            vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
            ClaimLifecycleStatus::Superseded
        );
        assert!(
            vault
                .targets(&generated_apply, EdgeKind::Supersedes, None)?
                .contains(&user_truth)
        );
        Ok(())
    }

    #[test]
    fn code_revision_rejects_unfinalized_parent_without_writing() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = entity(0x11);
        let parent = entity(0x21);
        let child = entity(0x22);
        put_session(&vault, session, 10)?;
        put_artifact(&vault, parent, 0xA1, 20)?;
        put_artifact(&vault, child, 0xA2, 30)?;

        let err = vault
            .commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))
            .expect_err("unfinalized parent revision must fail closed");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
        assert!(vault.get_code_revision(&child)?.is_none());
        assert!(
            vault
                .targets(&child, EdgeKind::Supersedes, None)?
                .is_empty()
        );
        Ok(())
    }
}
