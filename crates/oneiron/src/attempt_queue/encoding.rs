//! Storage key derivation and LMDB row encode/decode for the attempt queue.
//!
//! The row header is pinned by [`ATTEMPT_RECORD_VERSION`] (declared in
//! [`super::types`], whose ABI-pin rule governs any change here); the field
//! validators [`decode_record`] fails closed on live in [`super::validate`].

use crate::error::{Error, Result};

use super::types::{ATTEMPT_RECORD_VERSION, AttemptId, AttemptRecord, AttemptState};
use crate::error::ArtifactError;
pub(crate) use crate::store::attempt_record_codec::decode_record;
pub(super) use crate::store::attempt_record_codec::{
    MAX_DEDUPE_ACTOR_REF_LEN, encode_admitted_record, encode_record, waiting_on_backoff,
};

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub(super) const DEDUPE_DOMAIN_V1: &[u8] = b"oneiron.job_queue.dedupe.v1\0";
/// Domain of the actor-scoped key family. It sits BESIDE v1 rather than
/// replacing it: an actorless caller keeps the exact v1 bytes, so no live
/// entry is orphaned and no migration is required.
pub(super) const DEDUPE_DOMAIN_V2: &[u8] = b"oneiron.job_queue.dedupe.v2\0";
pub(super) const DEDUPE_INDEX_KEY_LEN: usize = 32;
pub(super) const READY_KEY_LEN: usize = 24;
const ERR_DEDUPE_KIND_MISMATCH: &str = "dedupe index points at a different attempt kind";
const ERR_READY_KEY_LEN: &str = "ready index key must be 24 bytes";

/// Checks the two axes every dedupe hit shares, on every key family.
///
/// The actor axis is deliberately NOT checked here: it is per-path in the
/// caller, because a v2 hit must carry the requested actor while a legal v1
/// fallback hit must carry none. A blanket equality check would misread the
/// compatibility fallback as corruption.
pub(super) fn validate_dedupe_record(
    record: &AttemptRecord,
    kind: &str,
    dedupe_key: &str,
) -> Result<()> {
    if record.kind != kind {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_DEDUPE_KIND_MISMATCH,
        )));
    }
    if record.dedupe_key.as_deref() != Some(dedupe_key) {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            "dedupe index points at an attempt with a different dedupe key",
        )));
    }
    Ok(())
}

/// The index keys one enqueue may legitimately consult, in family order.
///
/// An actor-scoped request owns a v2 `primary` and may READ the actorless v1
/// key as bounded compatibility; an actorless request's `primary` IS the v1
/// key and it has no fallback of this kind at all.
pub(super) struct DedupeIndexKeys {
    pub(super) primary: [u8; DEDUPE_INDEX_KEY_LEN],
    pub(super) fallback_v1: Option<[u8; DEDUPE_INDEX_KEY_LEN]>,
}

impl DedupeIndexKeys {
    pub(super) fn new(kind: &str, actor_ref: Option<&str>, dedupe_key: &str) -> Self {
        let v1 = dedupe_index_key(kind, dedupe_key);
        match actor_ref {
            Some(actor_ref) => Self {
                primary: dedupe_index_key_v2(kind, actor_ref, dedupe_key),
                fallback_v1: Some(v1),
            },
            None => Self {
                primary: v1,
                fallback_v1: None,
            },
        }
    }
}

pub(super) fn dedupe_index_key(kind: &str, dedupe_key: &str) -> [u8; DEDUPE_INDEX_KEY_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DEDUPE_DOMAIN_V1);
    hasher.update(&(kind.len() as u16).to_be_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(&(dedupe_key.len() as u16).to_be_bytes());
    hasher.update(dedupe_key.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The actor-scoped key: same length-prefix discipline as v1, with the actor
/// segment between the kind and the caller's key.
///
/// Every segment is length-delimited, so `(kind, actor, key)` cannot collide
/// with a different split of the same bytes — which is exactly why the actor
/// axis belongs in the key derivation and not concatenated into a caller's
/// `dedupe_key`. Each segment is length-validated at its own door before it
/// reaches this function (kind ≤ 128, actor ≤ [`MAX_DEDUPE_ACTOR_REF_LEN`],
/// dedupe key ≤ 512), so no prefix is written through a lossy cast.
pub(super) fn dedupe_index_key_v2(
    kind: &str,
    actor_ref: &str,
    dedupe_key: &str,
) -> [u8; DEDUPE_INDEX_KEY_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DEDUPE_DOMAIN_V2);
    for segment in [kind, actor_ref, dedupe_key] {
        hasher.update(&(segment.len() as u16).to_be_bytes());
        hasher.update(segment.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Readiness instant for a ready-indexed row. New rows carry `scheduled_at`;
/// `backoff_until` is the pre-ONE-1795 spelling and stays readable so a legacy
/// `Queued + backoff_until` row keeps its exact original readiness instant
/// without a bulk rewrite.
pub(super) fn ready_at(record: &AttemptRecord) -> u64 {
    record.scheduled_at.or(record.backoff_until).unwrap_or(0)
}

pub(super) fn lease_expired(record: &AttemptRecord, now: u64, lease_timeout_secs: u64) -> bool {
    now.checked_sub(record.updated_at)
        .is_some_and(|age| age >= lease_timeout_secs)
}

pub(super) fn ready_key(ready_at: u64, id: AttemptId) -> [u8; READY_KEY_LEN] {
    let mut key = [0_u8; READY_KEY_LEN];
    key[..8].copy_from_slice(&ready_at.to_be_bytes());
    key[8..].copy_from_slice(id.as_bytes());
    key
}

pub(super) fn decode_ready_key(bytes: &[u8]) -> Result<(u64, AttemptId)> {
    if bytes.len() != READY_KEY_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_READY_KEY_LEN,
        )));
    }
    let mut created_at = [0_u8; 8];
    created_at.copy_from_slice(&bytes[..8]);
    Ok((
        u64::from_be_bytes(created_at),
        AttemptId::from_bytes(&bytes[8..])?,
    ))
}

/// Reconstruct disposable queue indexes after a canonical restore: the ready,
/// dedupe, run, kind, retry-child and annotation-hold indexes, from the
/// attempt rows that landed. A restore over a live vault lands the free-time
/// tries as the live vault holds them beside the image's other attempts (FIX
/// 6577), so the run index the image carried is rebuilt with the others, as
/// the open-time backfill builds it. A row in `opaque` (an agent dispatch's
/// row that never decoded and landed as it rested) and the erased marker of
/// a retired one stay as they are, indexed nowhere, so none of them runs, and
/// the restore names how many (FIX 9390).
pub(crate) fn rebuild_checkpoint_indexes(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    opaque: &std::collections::BTreeSet<Vec<u8>>,
) -> Result<()> {
    let rows: Vec<_> = store
        .attempt_records
        .iter(txn)?
        .map(|row| row.map(|(key, value)| (key.to_vec(), value.to_vec())))
        .collect::<std::result::Result<_, _>>()?;
    store.clear_attempt_run_index_in_txn(txn)?;
    super::index::clear_in_txn(store, txn)?;
    let mut unindexed = 0_usize;
    for (key, value) in rows {
        let id = AttemptId::from_bytes(&key)?;
        let record = match decode_record(&value, id) {
            Ok(record) => record,
            Err(_) if crate::store::is_opaque_erased(&value) || opaque.contains(&key) => {
                unindexed += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if matches!(record.state, AttemptState::Queued | AttemptState::Scheduled) {
            store
                .attempt_ready
                .put(txn, &ready_key(ready_at(&record), id), id.as_bytes())?;
        }
        if record.state.is_pending()
            && let Some(dedupe) = record.dedupe_key.as_deref()
        {
            store.attempt_dedupe.put(
                txn,
                &DedupeIndexKeys::new(&record.kind, record.dedupe_actor_ref.as_deref(), dedupe)
                    .primary,
                id.as_bytes(),
            )?;
        }
        store.put_attempt_run_index_in_txn(txn, record.run_id.as_deref(), id.as_bytes())?;
        super::index::put_created_in_txn(store, txn, &record)?;
        if record.annotation_hold().is_some() {
            super::index::put_annotation_hold_in_txn(store, txn, id)?;
        }
    }
    if unindexed > 0 {
        tracing::warn!(
            unindexed,
            "agent dispatch rows that never decoded landed as they rested, indexed nowhere"
        );
    }
    Ok(())
}
