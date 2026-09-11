//! Per-revision integrity records and the fold chain proving a revision's ancestry.

use std::collections::HashSet;

use heed::{RoTxn, RwTxn};
use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::codec::{
    CODE_REVISION_HASH_LEN, KEY_FINALIZED_AT, KEY_PARENT_REVISION_ID, KEY_PROVENANCE_CLAIM_ID,
    KEY_REVERTED_TO_REVISION_ID, KEY_REVISION_ID, KEY_SESSION_ID, encode_value, entity_value,
    hash_from_value, optional_entity_from_value, optional_entity_value, optional_hash_from_value,
    optional_hash_value, u64_value,
};
use super::frontier::{get_code_revision_frontier_in_txn, rebuild_code_revision_frontier_in_txn};
use super::graph::{
    code_artifact_body_bytes, require_code_revision_ancestor, require_entity_type,
    require_revision_session,
};
use super::keys::{code_revision_integrity_key, code_revision_session_index_prefix};
use super::storage::{
    collect_code_revision_records_by_index_prefix, read_code_revision_record_in_txn,
};
use super::types::{CodeRevision, CodeRevisionIntegrityRecord, CodeRevisionKind};
use crate::error::ArtifactError;

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

const KEY_ARTIFACT_HASH: &str = CODE_REVISION_INTEGRITY_KEYS[5];

const KEY_PARENT_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[6];

const KEY_REVERTED_TO_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[7];

pub(super) const KEY_REVISION_FOLD: &str = CODE_REVISION_INTEGRITY_KEYS[8];

const CODE_REVISION_FOLD_DOMAIN: &[u8] = b"oneiron:code-revision-fold:v1";

pub(super) fn encode_code_revision_integrity_record(
    record: &CodeRevisionIntegrityRecord,
) -> Result<Vec<u8>> {
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

pub(super) fn decode_code_revision_integrity_record(
    bytes: &[u8],
) -> Result<CodeRevisionIntegrityRecord> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision integrity is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "trailing bytes after code revision integrity map",
        )));
    }
    decode_code_revision_integrity_value(&value)
}

fn decode_code_revision_integrity_value(value: &Value) -> Result<CodeRevisionIntegrityRecord> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision integrity must be a MessagePack map",
        )));
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
        let key = key
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision integrity keys must be strings",
            )))?;
        let Some(index) = CODE_REVISION_INTEGRITY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision integrity key is not in the pinned CODE_REVISION_INTEGRITY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "duplicate code revision integrity key",
            )));
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
        revision_id: revision_id.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision integrity key revision_id",
        )))?,
        session_id: session_id.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision integrity key session_id",
        )))?,
        parent_revision_id: parent_revision_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key parent_revision_id",
            ),
        ))?,
        reverted_to_revision_id: reverted_to_revision_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key reverted_to_revision_id",
            ),
        ))?,
        provenance_claim_id: provenance_claim_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key provenance_claim_id",
            ),
        ))?,
        artifact_hash: artifact_hash.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key artifact_hash",
            ),
        ))?,
        parent_fold: parent_fold.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision integrity key parent_fold",
        )))?,
        reverted_to_fold: reverted_to_fold.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key reverted_to_fold",
            ),
        ))?,
        revision_fold: revision_fold.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key revision_fold",
            ),
        ))?,
        finalized_at: finalized_at.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision integrity key finalized_at",
            ),
        ))?,
    })
}

pub(super) fn backfill_code_revision_integrity_for_revision_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    let Some(revision) = read_code_revision_record_in_txn(store, wtxn, revision_id)? else {
        return Ok(());
    };
    backfill_code_revision_integrity_for_session_in_txn(store, wtxn, &revision.session_id)
}

pub(super) fn backfill_code_revision_integrity_for_session_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    session_id: &EntityId,
) -> Result<()> {
    let prefix = code_revision_session_index_prefix(session_id);
    let revisions = collect_code_revision_records_by_index_prefix(store, wtxn, &prefix)?;
    let existing_frontier = get_code_revision_frontier_in_txn(store, wtxn, session_id)?;
    if revisions.is_empty() {
        if existing_frontier.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision frontier exists without session index rows",
            )));
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

pub(super) fn ensure_code_revision_integrity_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
    visiting: &mut HashSet<EntityId>,
) -> Result<CodeRevisionIntegrityRecord> {
    let revision =
        read_code_revision_record_in_txn(store, wtxn, revision_id)?.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("code revision integrity parent record missing"),
        ))?;
    if !visiting.insert(*revision_id) {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision parent chain contains a cycle",
        )));
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

pub(super) fn build_code_revision_integrity_record(
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

pub(super) fn verify_code_revision_integrity_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
) -> Result<()> {
    let mut visiting = HashSet::new();
    verify_or_build_code_revision_integrity_record_in_txn(store, rtxn, revision, &mut visiting)?;
    Ok(())
}

pub(super) fn verify_or_build_code_revision_integrity_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    visiting: &mut HashSet<EntityId>,
) -> Result<CodeRevisionIntegrityRecord> {
    if visiting.len() >= MAX_ANCESTOR_DEPTH {
        return Err(Error::IndexOverflow("code_revision_parent_chain"));
    }
    if !visiting.insert(revision.revision_id) {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision parent chain contains a cycle",
        )));
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
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision integrity record does not match revision record",
            )));
        }

        let artifact_body = code_artifact_body_bytes(store, rtxn, &revision.revision_id)?;
        let artifact_hash = sha256_bytes(&artifact_body);
        if let Some(record) = &record
            && artifact_hash != record.artifact_hash
        {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision artifact hash mismatch",
            )));
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
                    return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                        "code revision parent fold mismatch",
                    )));
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
                    return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                        "code revision reverted-to fold mismatch",
                    )));
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
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "code revision fold mismatch",
                )));
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
    let revision =
        read_code_revision_record_in_txn(store, rtxn, revision_id)?.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("code revision integrity parent record missing"),
        ))?;
    let record =
        verify_or_build_code_revision_integrity_record_in_txn(store, rtxn, &revision, visiting)?;
    Ok((revision, record.revision_fold))
}

pub(super) fn load_optional_code_revision_integrity_record(
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
    decode_code_revision_integrity_record(&raw).map(Some)
}

pub(super) fn compute_code_revision_fold(
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
