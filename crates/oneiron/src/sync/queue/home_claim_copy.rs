//! One native embedding job's retained StepClaim response copy.
//! The metadata skeleton and the original response's instance are separate
//! from the copied stream's own bytes, length and digest.

use heed::RoTxn;

use super::{EMBED_PREFIX, checkpoint, codec};
use crate::embed::home_vectors::retained::RetainedHomeClaimResponse;
use crate::embed::home_vectors::retained_copy::RetainedHomeClaimCopy;
use crate::store::{ResponseDb, Store, response_carrier, response_instance_owner_in_txn};
use crate::{EntityId, Error, Result};

pub(crate) struct HomeClaimCopy {
    pub(crate) instance: [u8; 16],
    pub(crate) keep: usize,
    pub(crate) skeleton: Vec<u8>,
    pub(crate) body: Vec<u8>,
}

fn invalid() -> Error {
    Error::CorruptedIndex("retained home CLAIM response")
}

/// The original pending job, with no retained copy. Its last four bytes are
/// the native zero length, not a prefix copied from a full row's header.
pub(crate) fn home_claim_copy_skeleton(key: &[u8], value: &[u8]) -> Result<(EntityId, usize)> {
    let (job, copy) = checkpoint::embed_job(key, value)?;
    if copy.is_some() {
        return Err(invalid());
    }
    Ok((job.entity_id, value.len() - size_of::<u32>()))
}

/// Splits a retained copy once, before the checkpoint's payload getter sees
/// the job. The original source need not still be the current entity row.
pub(crate) fn capture_home_claim_copy(
    store: &Store,
    txn: &RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Option<HomeClaimCopy>> {
    if !key.starts_with(EMBED_PREFIX) {
        return Ok(None);
    }
    let (job, copy) = checkpoint::embed_job(key, value)?;
    let Some(bytes) = copy else {
        return Ok(None);
    };
    let RetainedHomeClaimCopy::Response(copy) =
        RetainedHomeClaimCopy::decode(&job.entity_id, bytes)?
    else {
        return Ok(None);
    };
    copy.validate(store, &job.entity_id)?;
    let carrier = response_carrier(ResponseDb::Entities, job.entity_id.as_bytes());
    if !response_instance_owner_in_txn(store, txn, job.entity_id, copy.response.instance, &carrier)?
    {
        return Err(invalid());
    }
    let skeleton = checkpoint::embed_job_skeleton(key, value)?;
    let (_, keep) = home_claim_copy_skeleton(key, &skeleton)?;
    Ok(Some(HomeClaimCopy {
        instance: copy.response.instance,
        keep,
        skeleton,
        // Carry the native length too; the skeleton's zero must not become
        // a nonempty copy with a stale zero length when it lands.
        body: value[keep..].to_vec(),
    }))
}

/// Rebuilds one opened copy over its exact pending metadata. The stream was
/// already checked against its own digest and length by the body reader.
pub(crate) fn restore_home_claim_copy(
    store: &Store,
    key: &[u8],
    skeleton: &[u8],
    instance: [u8; 16],
    body: &[u8],
) -> Result<Vec<u8>> {
    let (id, keep) = home_claim_copy_skeleton(key, skeleton)?;
    let mut value = skeleton[..keep].to_vec();
    value.extend_from_slice(body);
    if !checkpoint::embed_job_matches_skeleton(key, &value, skeleton)? {
        return Err(invalid());
    }
    let bytes = codec::embed_job_home_claim_copy(&value)?.ok_or_else(invalid)?;
    let copy = RetainedHomeClaimResponse::decode(store, &id, bytes)?;
    if copy.response.instance != instance {
        return Err(invalid());
    }
    Ok(value)
}
