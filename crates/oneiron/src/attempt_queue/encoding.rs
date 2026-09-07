//! Storage key derivation and LMDB row encode/decode for the attempt queue.
//!
//! The row header is pinned by [`ATTEMPT_RECORD_VERSION`] (declared in
//! [`super::types`], whose ABI-pin rule governs any change here); the field
//! validators [`decode_record`] fails closed on live in [`super::validate`].

use crate::error::{Error, Result};

use super::types::{ATTEMPT_RECORD_VERSION, AttemptId, AttemptRecord, AttemptState};
use super::validate::{
    ERR_CANCELLATION_MISPLACED, ERR_DEDUPE_ACTOR_WITHOUT_KEY, ERR_LANDING_RECORD_MISPLACED,
    ERR_LANDING_WITH_BACKOFF, ERR_LANDING_WITHOUT_LEASE, ERR_LANDING_WITHOUT_RECORD,
    validate_attempt_events, validate_attempt_manifest, validate_cancel_state, validate_kind,
    validate_lease_owner, validate_optional_dedupe, validate_optional_dedupe_actor_ref,
    validate_optional_failure_reason, validate_optional_run_id,
};

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub(super) const DEDUPE_DOMAIN_V1: &[u8] = b"oneiron.job_queue.dedupe.v1\0";
/// Domain of the actor-scoped key family. It sits BESIDE v1 rather than
/// replacing it: an actorless caller keeps the exact v1 bytes, so no live
/// entry is orphaned and no migration is required.
pub(super) const DEDUPE_DOMAIN_V2: &[u8] = b"oneiron.job_queue.dedupe.v2\0";
pub(super) const DEDUPE_INDEX_KEY_LEN: usize = 32;
/// Longest actor scope the dedupe index admits. It bounds the length prefix
/// the v2 hash writes, so the segment can never be truncated into ambiguity.
pub(super) const MAX_DEDUPE_ACTOR_REF_LEN: usize = 128;
pub(super) const READY_KEY_LEN: usize = 24;
const ERR_DEDUPE_KIND_MISMATCH: &str = "dedupe index points at a different attempt kind";
const ERR_READY_KEY_LEN: &str = "ready index key must be 24 bytes";

/// Checks the two axes every dedupe hit shares, on every key family.
///
/// The actor axis is deliberately NOT checked here: it is per-path in the
/// caller, because a v2 hit must carry the requested actor while a legal v1 or
/// pre-v1 raw fallback hit must carry none. A blanket equality check would
/// misread the compatibility fallback as corruption.
pub(super) fn validate_dedupe_record(
    record: &AttemptRecord,
    kind: &str,
    dedupe_key: &str,
) -> Result<()> {
    if record.kind != kind {
        return Err(Error::InvalidAttemptQueueRecord(ERR_DEDUPE_KIND_MISMATCH));
    }
    if record.dedupe_key.as_deref() != Some(dedupe_key) {
        return Err(Error::InvalidAttemptQueueRecord(
            "dedupe index points at an attempt with a different dedupe key",
        ));
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

pub(super) fn legacy_dedupe_index_key(kind: &str, dedupe_key: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + kind.len() + dedupe_key.len());
    key.extend_from_slice(&(kind.len() as u16).to_be_bytes());
    key.extend_from_slice(kind.as_bytes());
    key.extend_from_slice(dedupe_key.as_bytes());
    key
}

/// Readiness instant for a ready-indexed row. New rows carry `scheduled_at`;
/// `backoff_until` is the pre-ONE-1795 spelling and stays readable so a legacy
/// `Queued + backoff_until` row keeps its exact original readiness instant
/// without a bulk rewrite.
pub(super) fn ready_at(record: &AttemptRecord) -> u64 {
    record.scheduled_at.or(record.backoff_until).unwrap_or(0)
}

/// True when a pending row is waiting on a retry backoff, in either the new
/// `scheduled_at` spelling or the legacy `backoff_until` one.
pub(super) fn waiting_on_backoff(record: &AttemptRecord) -> bool {
    record.scheduled_at.is_some() || record.backoff_until.is_some()
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
        return Err(Error::InvalidAttemptQueueRecord(ERR_READY_KEY_LEN));
    }
    let mut created_at = [0_u8; 8];
    created_at.copy_from_slice(&bytes[..8]);
    Ok((
        u64::from_be_bytes(created_at),
        AttemptId::from_bytes(&bytes[8..])?,
    ))
}

pub(super) fn encode_record(record: &AttemptRecord) -> Result<Vec<u8>> {
    let mut encoded = vec![ATTEMPT_RECORD_VERSION];
    let mut body = rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvalidAttemptQueueRecord("failed to encode attempt record"))?;
    encoded.append(&mut body);
    Ok(encoded)
}

pub(crate) fn decode_record(raw: &[u8], expected_id: AttemptId) -> Result<AttemptRecord> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(Error::InvalidAttemptQueueRecord(
            "missing attempt record version",
        ));
    };
    if version != ATTEMPT_RECORD_VERSION {
        return Err(Error::InvalidAttemptQueueRecord(
            "unsupported attempt record version",
        ));
    }
    let record: AttemptRecord = rmp_serde::from_slice(body)
        .map_err(|_| Error::InvalidAttemptQueueRecord("failed to decode attempt record"))?;
    if record.id != expected_id {
        return Err(Error::InvalidAttemptQueueRecord(
            "job_records key/id mismatch",
        ));
    }
    validate_kind(&record.kind)?;
    validate_optional_dedupe(record.dedupe_key.as_deref())?;
    validate_optional_dedupe_actor_ref(record.dedupe_actor_ref.as_deref())?;
    // An actor scope with nothing to scope is a corrupted row, not a quirk:
    // it would name an index entry that cannot exist, so no-key rows are
    // always actorless on both the write and the read side.
    if record.dedupe_actor_ref.is_some() && record.dedupe_key.is_none() {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_DEDUPE_ACTOR_WITHOUT_KEY,
        ));
    }
    validate_optional_run_id(record.run_id.as_deref())?;
    validate_optional_failure_reason(record.last_error.as_deref())?;
    validate_attempt_events(&record.events)?;
    validate_attempt_manifest(&record.manifest)?;
    validate_cancel_state(&record.cancel_state)?;
    if let Some(lease_owner) = record.lease_owner.as_deref() {
        validate_lease_owner(lease_owner)?;
    }
    // ONE-1896 placement rules, independent of the state-shape match below: a
    // landing record outside a landing/landed row, or a cancellation receipt on
    // a row that is not cancelled, would let a read surface report a landing
    // that never happened.
    if record.cancel_state.landing.is_some()
        && !matches!(
            record.state,
            AttemptState::Landing | AttemptState::Cancelled
        )
    {
        return Err(Error::InvalidAttemptQueueRecord(
            ERR_LANDING_RECORD_MISPLACED,
        ));
    }
    if record.cancel_state.cancellation.is_some() && record.state != AttemptState::Cancelled {
        return Err(Error::InvalidAttemptQueueRecord(ERR_CANCELLATION_MISPLACED));
    }
    match record.state {
        AttemptState::Queued if record.lease_owner.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "queued attempt must not have a lease owner",
            ));
        }
        AttemptState::Leased if record.lease_owner.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "leased attempt must have a lease owner",
            ));
        }
        AttemptState::Leased if waiting_on_backoff(&record) => {
            return Err(Error::InvalidAttemptQueueRecord(
                "leased attempt must not have backoff state",
            ));
        }
        AttemptState::Paused if record.lease_owner.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "paused attempt must not have a lease owner",
            ));
        }
        AttemptState::Scheduled if record.lease_owner.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "scheduled attempt must not have a lease owner",
            ));
        }
        AttemptState::Scheduled if record.scheduled_at.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "scheduled attempt must have a scheduled instant",
            ));
        }
        // A landing row still OWNS its lease — that is what buys it the bounded
        // time to finish — so it is shaped like a leased row plus its landing
        // record, never like a queued or terminal one.
        AttemptState::Landing if record.lease_owner.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(ERR_LANDING_WITHOUT_LEASE));
        }
        AttemptState::Landing if waiting_on_backoff(&record) => {
            return Err(Error::InvalidAttemptQueueRecord(ERR_LANDING_WITH_BACKOFF));
        }
        AttemptState::Landing if record.cancel_state.landing.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(ERR_LANDING_WITHOUT_RECORD));
        }
        AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled
            if record.lease_owner.is_some() =>
        {
            return Err(Error::InvalidAttemptQueueRecord(
                "terminal attempt must not have a lease owner",
            ));
        }
        AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled
            if waiting_on_backoff(&record) =>
        {
            return Err(Error::InvalidAttemptQueueRecord(
                "terminal attempt must not have backoff state",
            ));
        }
        AttemptState::Completed | AttemptState::Cancelled if record.last_error.is_some() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "non-failed terminal attempt must not have a failure reason",
            ));
        }
        AttemptState::Failed if record.last_error.is_none() => {
            return Err(Error::InvalidAttemptQueueRecord(
                "failed attempt must have a failure reason",
            ));
        }
        _ => {}
    }
    Ok(record)
}
