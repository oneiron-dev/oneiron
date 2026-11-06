//! The sync queue's rows in a checkpoint (KS7-3a), read with the queue's own
//! key and value codecs. A queued window update's Loro bytes are split with
//! its window's (KS7-3b, [`queued_update`]), and put back at its own
//! sequence ([`queued_row`]); placed alone it stays under the vault-wide
//! seal, named. Its delete-bearing marker is structure beside it, so the
//! pair keeps its confirmed-clear rule. A quarantine record holds hashes, lengths and a
//! reason, never the rejected bytes, and a counter is a number: both are
//! structure. An embedding job without a carried copy is structure too;
//! a copy-bearing job needs its owned projection, never a raw metadata claim.
//! Any other row of the database (the deletion sweep's jobs) is no sync
//! family's, and stays as it is.
#![allow(
    dead_code,
    reason = "KS7-5 drives the projection; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::UPDATE_PREFIX;
use super::codec::{
    decode_delete_bearing_key, decode_embed_job_row, decode_update_key, decode_update_value_parts,
    embed_job_home_claim_copy, encode_embed_job_value, encode_update_value, validate_update_row,
};
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{Captured, OwnerRef, RowDb, RowLocator, bad_part};
use crate::sync::QuarantineRecord;
use crate::sync::checkpoint_payload::{Placement, SyncUnclassified};

/// A quarantine record's key: this prefix, then its sequence (u64be).
const QUARANTINE_PREFIX: &[u8] = b"x:";

/// A counter's key prefix: the queue's and the quarantine's, eight bytes.
const COUNTER_PREFIX: &[u8] = b"m:";

/// The marker a delete-bearing update's sidecar row holds.
const DELETE_BEARING_MARKER: &[u8] = &[1];

/// Where the queue row `key` goes.
pub(in crate::sync) fn place(key: &[u8], value: &[u8]) -> Placement {
    let structure = || Placement::Structure {
        dependencies: Vec::new(),
    };
    let undecodable = || Placement::unclassified(None, SyncUnclassified::Undecodable);
    if key.starts_with(UPDATE_PREFIX) {
        return match validate_update_row(key, value) {
            Ok(()) => Placement::unclassified(None, SyncUnclassified::PendingLoroProjection),
            Err(_) => undecodable(),
        };
    }
    if decode_delete_bearing_key(key).is_some() {
        return if value == DELETE_BEARING_MARKER {
            structure()
        } else {
            undecodable()
        };
    }
    if let Some(seq) = key.strip_prefix(QUARANTINE_PREFIX) {
        let record = rmp_serde::from_slice::<QuarantineRecord>(value);
        return if seq.len() == 8 && record.is_ok() {
            structure()
        } else {
            undecodable()
        };
    }
    if key.starts_with(COUNTER_PREFIX) && value.len() == 8 {
        return structure();
    }
    if key.starts_with(super::EMBED_PREFIX) {
        return match embed_job(key, value) {
            Ok((_, None)) => structure(),
            Ok((_, Some(_))) => Placement::unclassified(None, SyncUnclassified::NoOwner),
            Err(_) => undecodable(),
        };
    }
    Placement::unclassified(None, SyncUnclassified::NoOwner)
}

/// A queued window update's sequence, window and Loro bytes, when `key`
/// and `value` read as one.
pub(in crate::sync) fn queued_update<'v>(
    key: &[u8],
    value: &'v [u8],
) -> Option<(u64, &'v str, &'v [u8])> {
    let seq = decode_update_key(key).ok()?;
    let (window, update) = decode_update_value_parts(value).ok()?;
    Some((seq, window, update))
}

/// The queue row's value that carries `update` for `window` again.
pub(in crate::sync) fn queued_row(window: &str, update: &[u8]) -> Result<Vec<u8>> {
    encode_update_value(window, update)
}

/// One embedding job split with its own codec. The skeleton keeps the job,
/// not an opaque copy's length header or any of its bytes.
pub(in crate::sync) fn embed_job<'v>(
    key: &[u8],
    value: &'v [u8],
) -> Result<(super::QueuedEmbedJob, Option<&'v [u8]>)> {
    Ok((
        decode_embed_job_row(key, value)?,
        embed_job_home_claim_copy(value)?,
    ))
}

/// A pending job's metadata-only image, derived from the full row rather
/// than taking a prefix whose copy length would still be nonzero.
pub(in crate::sync) fn embed_job_skeleton(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let (job, _) = embed_job(key, value)?;
    Ok(encode_embed_job_value(job.priority, job.queued_at))
}

/// Whether an opened copy-bearing row belongs to the metadata job already
/// restored at this key. Unavailable content leaves that job intact.
pub(in crate::sync) fn embed_job_matches_skeleton(
    key: &[u8],
    value: &[u8],
    skeleton: &[u8],
) -> Result<bool> {
    let (job, copy) = embed_job(key, value)?;
    let (pending, pending_copy) = embed_job(key, skeleton)?;
    Ok(copy.is_some()
        && pending_copy.is_none()
        && job.priority == pending.priority
        && job.queued_at == pending.queued_at)
}

/// Captures one copy-bearing job after its receive-time source custody was
/// resolved. The caller supplies that captured home and its dependencies,
/// never owners inferred from a later current entity row.
pub(in crate::sync) fn capture_embed_job_copy(
    key: &[u8],
    value: &[u8],
    owner: OwnerRef,
    dependencies: &[OwnerRef],
    out: &mut Captured,
) -> Result<()> {
    let (_, copy) = embed_job(key, value)?;
    if copy.is_none() {
        return Err(bad_part());
    }
    let skeleton = embed_job_skeleton(key, value)?;
    let at = RowLocator::row(RowDb::SyncQueue, key.to_vec());
    out.projected_exact(owner, at.clone(), value.to_vec(), skeleton);
    for on in dependencies {
        out.depends(owner, &at, *on);
    }
    Ok(())
}
