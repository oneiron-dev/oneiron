//! Ordinary origin copies keep their own frozen actor custody, not a response instance.

use super::{EMBED_PREFIX, checkpoint};
use crate::Result;
use crate::embed::home_vectors::retained_copy::RetainedHomeClaimCopy;
use crate::store::CustodyPlan;
use crate::store::checkpoint_payload::rows::{Captured, OwnerRef};
use crate::store::restore_admission::Rejected;

/// Captures the ciphertext under its source, with a genuine metadata-only job.
/// Current owner compartments do not replace the copy's original generations.
pub(crate) fn capture_home_claim_actor_copy(
    key: &[u8],
    value: &[u8],
    out: &mut Captured,
) -> Result<bool> {
    if !key.starts_with(EMBED_PREFIX) {
        return Ok(false);
    }
    let (job, bytes) = checkpoint::embed_job(key, value)?;
    let Some(bytes) = bytes else {
        return Ok(false);
    };
    let RetainedHomeClaimCopy::OriginActors(copy) =
        RetainedHomeClaimCopy::decode(&job.entity_id, bytes)?
    else {
        return Ok(false);
    };
    let dependencies: Vec<_> = copy
        .required()?
        .into_iter()
        .map(|(item, _)| OwnerRef {
            subtype: item.subtype(),
            owner32: *item.owner(),
        })
        .collect();
    checkpoint::capture_embed_job_copy(
        key,
        value,
        OwnerRef::entity(&job.entity_id),
        &dependencies,
        out,
    )?;
    Ok(true)
}

/// Runs before custody finalization and any destination rows land.
/// A retired ORIGINAL leaf drops only this copy, not a current owner's rows.
pub(crate) fn open_home_claim_actor_copy_for_restore(
    key: &[u8],
    value: &[u8],
    vault_id: &[u8; 32],
    plan: &mut CustodyPlan,
) -> std::result::Result<bool, Rejected> {
    let (job, bytes) = checkpoint::embed_job(key, value)?;
    let Some(bytes) = bytes else {
        return Err(crate::store::checkpoint_payload::rows::bad_part().into());
    };
    match RetainedHomeClaimCopy::decode(&job.entity_id, bytes)? {
        RetainedHomeClaimCopy::OriginActors(copy) => {
            Ok(copy.open_for_restore(vault_id, plan)?.is_some())
        }
        RetainedHomeClaimCopy::Response(_) => Ok(true),
    }
}
