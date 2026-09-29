//! Per-session frontier rows and session-trace verification over them.

use std::collections::HashSet;

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{CodecError, RawValue};
use crate::store::Store;

use super::codec::{
    KEY_FINALIZED_AT, KEY_REVISION_ID, KEY_SESSION_ID, encode_value, entity_value, hash_from_value,
    u64_value,
};
use super::integrity::{
    KEY_REVISION_FOLD, ensure_code_revision_integrity_record_in_txn,
    load_optional_code_revision_integrity_record,
    verify_or_build_code_revision_integrity_record_in_txn,
};
use super::keys::FRONTIER;
use super::storage::{
    collect_code_revision_records_by_index_prefix, read_code_revision_record_in_txn,
};
use super::types::{CodeRevision, CodeRevisionFrontierRecord, CodeRevisionIntegrityRecord};
use crate::error::ArtifactError;

/// The side table's declared codec is `Raw`: [`encode_code_revision_frontier_record`]/
/// [`decode_code_revision_frontier_record`] already spell this row's on-disk shape.
impl RawValue for CodeRevisionFrontierRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_code_revision_frontier_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_code_revision_frontier_record(bytes)?)
    }
}

const CODE_REVISION_FRONTIER_KEYS: [&str; 4] =
    ["session_id", "revision_id", "revision_fold", "finalized_at"];

pub(super) fn encode_code_revision_frontier_record(
    record: &CodeRevisionFrontierRecord,
) -> Result<Vec<u8>> {
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

pub(super) fn decode_code_revision_frontier_record(
    bytes: &[u8],
) -> Result<CodeRevisionFrontierRecord> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "trailing bytes after code revision frontier map",
        )));
    }
    decode_code_revision_frontier_value(&value)
}

fn decode_code_revision_frontier_value(value: &Value) -> Result<CodeRevisionFrontierRecord> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier must be a MessagePack map",
        )));
    };
    let mut session_id = None;
    let mut revision_id = None;
    let mut revision_fold = None;
    let mut finalized_at = None;
    let mut seen = [false; CODE_REVISION_FRONTIER_KEYS.len()];

    for (key, value) in entries {
        let key = key
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision frontier keys must be strings",
            )))?;
        let Some(index) = CODE_REVISION_FRONTIER_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision frontier key is not in the pinned CODE_REVISION_FRONTIER_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "duplicate code revision frontier key",
            )));
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
        session_id: session_id.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision frontier key session_id",
        )))?,
        revision_id: revision_id.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision frontier key revision_id",
        )))?,
        revision_fold: revision_fold.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision frontier key revision_fold",
            ),
        ))?,
        finalized_at: finalized_at.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision frontier key finalized_at",
            ),
        ))?,
    })
}

pub(super) fn rebuild_code_revision_frontier_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    session_id: &EntityId,
) -> Result<()> {
    let revisions = collect_code_revision_records_by_index_prefix(store, wtxn, session_id)?;
    if revisions.is_empty() {
        FRONTIER.delete(store, wtxn, session_id)?;
        return Ok(());
    }

    let mut frontier = None;
    let mut visiting = HashSet::new();
    for revision in &revisions {
        if revision.session_id != *session_id {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision session index mismatch",
            )));
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

    let frontier = frontier.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "code revision frontier record missing",
    )))?;
    FRONTIER.put(store, wtxn, session_id, &frontier)?;
    Ok(())
}

/// Only admission converts an otherwise valid divergent frontier to a proposal.
/// Trace rebuild and read verification keep treating divergent finalized rows
/// as corruption.
pub(super) enum FrontierUpdate {
    Advance,
    Converged,
    Diverged(CodeRevisionFrontierRecord),
}

pub(super) fn validate_code_revision_frontier_update(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision: &CodeRevision,
    integrity: &CodeRevisionIntegrityRecord,
) -> Result<FrontierUpdate> {
    let Some(frontier) = get_code_revision_frontier_in_txn(store, rtxn, &revision.session_id)?
    else {
        if revision.parent_revision_id.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision frontier record missing",
            )));
        }
        return Ok(FrontierUpdate::Advance);
    };
    if frontier.session_id != revision.session_id {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier session mismatch",
        )));
    }
    verify_code_revision_frontier_record_in_txn(store, rtxn, &frontier)?;
    if integrity.parent_fold == Some(frontier.revision_fold) {
        Ok(FrontierUpdate::Advance)
    } else if integrity.revision_fold == frontier.revision_fold {
        Ok(FrontierUpdate::Converged)
    } else {
        Ok(FrontierUpdate::Diverged(frontier))
    }
}

fn code_revision_frontier_update_decision(
    frontier: Option<&CodeRevisionFrontierRecord>,
    revision: &CodeRevision,
    integrity: &CodeRevisionIntegrityRecord,
) -> Result<bool> {
    let Some(frontier) = frontier else {
        if revision.parent_revision_id.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision frontier record missing",
            )));
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
        Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier conflict",
        )))
    }
}

pub(super) fn verify_code_revision_frontier_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_id: &EntityId,
) -> Result<()> {
    let frontier =
        get_code_revision_frontier_in_txn(store, rtxn, session_id)?.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("code revision frontier record missing"),
        ))?;
    if frontier.session_id != *session_id {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier session mismatch",
        )));
    }
    verify_code_revision_frontier_record_in_txn(store, rtxn, &frontier)
}

fn verify_code_revision_frontier_record_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    frontier: &CodeRevisionFrontierRecord,
) -> Result<()> {
    let revision = read_code_revision_record_in_txn(store, rtxn, &frontier.revision_id)?.ok_or(
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier points at a missing revision",
        )),
    )?;
    if revision.session_id != frontier.session_id || revision.finalized_at != frontier.finalized_at
    {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier record does not match revision record",
        )));
    }
    let mut visiting = HashSet::new();
    let integrity = verify_or_build_code_revision_integrity_record_in_txn(
        store,
        rtxn,
        &revision,
        &mut visiting,
    )?;
    if integrity.revision_fold != frontier.revision_fold {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier fold mismatch",
        )));
    }
    Ok(())
}

pub(super) fn verify_code_revision_session_trace_in_txn(
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
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision session index mismatch",
            )));
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
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision frontier record missing",
            )));
        }
        return Ok(());
    };
    let computed_frontier = computed_frontier.ok_or(Error::Artifact(
        ArtifactError::InvalidCodeArtifactBody("code revision frontier record missing"),
    ))?;
    if computed_frontier.revision_id != stored_frontier.revision_id
        || computed_frontier.revision_fold != stored_frontier.revision_fold
        || computed_frontier.finalized_at != stored_frontier.finalized_at
        || computed_frontier.session_id != stored_frontier.session_id
    {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision frontier record does not match session trace",
        )));
    }
    Ok(())
}

pub(super) fn get_code_revision_frontier_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    session_id: &EntityId,
) -> Result<Option<CodeRevisionFrontierRecord>> {
    FRONTIER.get(store, rtxn, session_id)
}

/// Sweeps every frontier row for the session(s) that pointed at `revision_id`, then rebuilds
/// each affected session's frontier from its remaining revisions.
///
/// A row that fails to decode is treated the same way a decodable-but-matching row is: deleted by
/// its OWN key (the session id it is actually stored under), and its session queued for rebuild —
/// but the rebuild target for a decodable match is the DECODED `frontier.session_id` field, not
/// necessarily the row's own key. Preserved exactly from the pre-side-table code: a corrupted row
/// whose value's `session_id` disagrees with its own storage key rebuilds the decoded session, not
/// the key's session (see the migration report).
pub(super) fn delete_code_revision_frontier_for_revision_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    let mut sessions = Vec::new();
    for key_session_id in FRONTIER.scan_keys(store, wtxn, &[])? {
        match FRONTIER.get(store, wtxn, &key_session_id) {
            Ok(Some(frontier)) => {
                if frontier.revision_id == *revision_id {
                    keys.push(key_session_id);
                    sessions.push(frontier.session_id);
                }
            }
            Ok(None) => {}
            Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(_))) => {
                keys.push(key_session_id);
                sessions.push(key_session_id);
            }
            Err(other) => return Err(other),
        }
    }
    for key_session_id in &keys {
        FRONTIER.delete(store, wtxn, key_session_id)?;
    }
    sessions.sort_unstable();
    sessions.dedup();
    for session_id in sessions {
        rebuild_code_revision_frontier_in_txn(store, wtxn, &session_id)?;
    }
    Ok(())
}
