//! The small records the runner seat route keeps beside its attempts
//! (OF-137): a bound work's hops ([`super::work_binding`]) and each seat's
//! quota ([`super::seat_quota`]).
//!
//! Each record is a version of one BLOB_ARTIFACT whose id is derived from
//! what it records, made on first use, as an exhaust or a staged job is
//! stored. Its head version is the record. References and numbers only: no
//! task text, login or key ever rides one.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Vault;
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body,
    read_blob_artifact_head_in_txn,
};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;

use super::error::{ByoaResult, ERR_ARTIFACT_COLLISION, ERR_RUNNER_RECORD, invalid};
use super::exhaust::ensure_byoa_runtime_actor;

/// The record `id`'s head version holds, if `id` holds one. A head that does
/// not decode as `T` reads as absent, under a key-only WARN, never a failed
/// read.
///
/// # Errors
/// A store failure.
pub(super) fn head_record<T: DeserializeOwned>(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> ByoaResult<Option<T>> {
    Ok(head_record_checked(vault, rtxn, id)?.and_then(Result::ok))
}

/// The record `id`'s head version holds, if `id` holds one, with a corrupt
/// head told apart from a missing one (FIX 11651): truly absent reads
/// `None`; a head that does not decode as `T` reads `Some(Err(_))`, under
/// the same key-only WARN as [`head_record`], never a failed read.
///
/// # Errors
/// A store failure.
pub(super) fn head_record_checked<T: DeserializeOwned>(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> ByoaResult<Option<ByoaResult<T>>> {
    if vault.get_entity_type_in_txn(rtxn, id)?.is_none() {
        return Ok(None);
    }
    let Some(head) = read_blob_artifact_head_in_txn(&vault.store, rtxn, id)? else {
        return Ok(None);
    };
    let Some(bytes) = vault.read_blob_artifact_version_in_txn(rtxn, id, head.version)? else {
        return Ok(None);
    };
    match rmp_serde::from_slice(&bytes) {
        Ok(record) => Ok(Some(Ok(record))),
        Err(_) => {
            tracing::warn!(
                record = %id.to_hex(),
                "byoa runner seat record head does not decode: read as absent"
            );
            Ok(Some(Err(invalid(ERR_RUNNER_RECORD))))
        }
    }
}

/// Appends `record` as the head of `id`, made on first use as the artifact
/// `name` of `media_type`. A record equal to the head is the head.
///
/// # Errors
/// [`ERR_ARTIFACT_COLLISION`] when `id` holds another artifact; a record
/// that does not encode; a store failure.
pub(super) fn append_record_in_txn<T: Serialize>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    name: String,
    media_type: &str,
    record: &T,
    now: u64,
) -> ByoaResult<()> {
    let body = BlobArtifactBody::new(name, media_type);
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    // The id is the record's: anything else already there is a collision.
    if vault.get_entity_type_in_txn(wtxn, id)?.is_none() {
        vault
            .batch_in()
            .put(
                id,
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                now,
                &encode_blob_artifact_body(&body)?,
            )
            .apply(wtxn)?;
    } else if vault
        .get_blob_artifact_in_txn(wtxn, id)
        .ok()
        .flatten()
        .as_ref()
        != Some(&body)
    {
        return Err(invalid(ERR_ARTIFACT_COLLISION));
    }
    let bytes = rmp_serde::to_vec_named(record).map_err(|_| invalid(ERR_RUNNER_RECORD))?;
    let actor = ensure_byoa_runtime_actor(vault, wtxn, occurred, now)?;
    vault.append_blob_artifact_version_in_txn(
        wtxn,
        id,
        &bytes,
        &BlobVersionProvenance::AgentRun {
            run_ref: id.to_hex(),
        },
        actor,
        occurred,
        now,
    )?;
    Ok(())
}
