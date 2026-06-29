use std::collections::{HashSet, VecDeque};

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::ppr;
use crate::store::Store;
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_SESSION, EdgeKind,
    EntityId, Vad, encode_edge_value, parse_entity_id,
};

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

const CODE_REVISION_RECORD_KEY_PREFIX: &[u8] = b"code_revision:record:v1:";
const CODE_REVISION_SESSION_INDEX_KEY_PREFIX: &[u8] = b"code_revision:session:v1:";
const CODE_REVISION_PARENT_INDEX_KEY_PREFIX: &[u8] = b"code_revision:parent:v1:";
const CODE_REVISION_FORK_KEY_PREFIX: &[u8] = b"code_revision:fork:v1:";
const CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX: &[u8] = b"code_revision:fork_parent:v1:";

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
        require_known_code_revision(&self.store, &wtxn, &fork.base_revision_id)?;
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
        collect_code_revisions_by_index_prefix(&self.store, &rtxn, &prefix)
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
    require_entity_type(
        store,
        &wtxn,
        &revision.revision_id,
        ENTITY_TYPE_CODE_ARTIFACT,
        "revision_id must be a CODE_ARTIFACT entity",
    )?;
    require_entity_type(
        store,
        &wtxn,
        &revision.session_id,
        ENTITY_TYPE_SESSION,
        "session_id must be a SESSION entity",
    )?;
    if let Some(parent_id) = revision.parent_revision_id {
        require_known_code_revision(store, &wtxn, &parent_id)?;
    }
    if let Some(reverted_to_id) = revision.reverted_to_revision_id {
        require_known_code_revision(store, &wtxn, &reverted_to_id)?;
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
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &code_revision_record_key(revision_id))?
    else {
        return Ok(None);
    };
    decode_code_revision(raw).map(Some)
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
        let (key, _) = entry?;
        parents.push(parse_entity_id(
            key.get(ENTITY_ID_LEN + 1..).unwrap_or_default(),
            "ChildOf edge key",
        )?);
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
        }
        Err(_) => {
            store.vault_meta.delete(wtxn, &key)?;
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

fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

fn optional_entity_value(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
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

fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value.as_u64().ok_or(Error::InvalidCodeArtifactBody(field))
}

fn id_from_index_key(key: &[u8], offset: usize, context: &'static str) -> Result<EntityId> {
    parse_entity_id(key.get(offset..).unwrap_or_default(), context)
}

fn code_revision_record_key(id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_RECORD_KEY_PREFIX, id)
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
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
    };
    use crate::code_artifact::{CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody};
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
        let body = ClaimBody::new(
            "code.revision",
            ClaimSubject::Entity(subject),
            Value::from("finalized"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
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
        put_artifact(&vault, unrelated, 0xA3, 40)?;
        put_artifact(&vault, reverted, 0xA4, 50)?;

        vault.commit_code_revision(&CodeRevision::commit(original, session, 100))?;
        vault.commit_code_revision(&CodeRevision::commit_child(current, session, original, 200))?;
        vault.commit_code_revision(&CodeRevision::commit(unrelated, session, 300))?;

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
